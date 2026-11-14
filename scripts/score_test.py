"""Score test once: C1 and C2 with their verdicts, EPSS beside, the secondary measures and the slices.

    uv run python scripts/score_test.py [--models data/models] [--sets data/sets] [--bronze data/bronze]

The one script that opens the test labels (scripts/check_test_labels.py). It runs only when
config/operating_points.yaml is hashed into the registration as the operating_points stage, only
when every test prediction file has the digest the operating points froze, and only once: if
results/models/test_scoring.json exists it stops, since a second run on different model digests
needs a change request that keeps both results (evaluation/phase2_plan.yaml, test_scoring). Writes
results/models/c1.json, results/models/c2.json, results/models/test_scoring.json and the manifest
part results/parts/test.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import numpy as np
import polars as pl
import yaml
from sklearn.metrics import average_precision_score, roc_auc_score
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import calibrate, conformal, evaluate, floors, product, rank, sets, survival

from scripts.train_floors import plan_seed

ORIGIN = "scripts/score_test.py"
EPSS_DAYS = (1, 7, 30)
SLICE_MIN_ROWS = 30
SLICE_TOP = 20


def operating_points(root: Path) -> dict[str, Any]:
    path = root / "config" / "operating_points.yaml"
    record = json.loads((root / "evaluation" / "registration.json").read_text(encoding="utf-8"))
    if not path.exists() or not any(s["stage"] == "operating_points" for s in record["stages"]):
        raise SystemExit(
            "score: config/operating_points.yaml is not hashed into the registration; freeze it first"
        )
    points: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return points


def check_frozen(points: dict[str, Any], models: Path) -> None:
    from scripts.choose_operating_points import TEST_FILES

    for name, path in TEST_FILES.items():
        if sets.content_digest(models / path) != points["test_predictions"][name]:
            raise SystemExit(f"score: {path} is not the file the operating points froze")


def matrix(frame: pl.DataFrame, task: str) -> tuple[np.ndarray, list[str]]:
    columns = [c for c in frame.columns if c.startswith(f"{task}__")]
    return frame.select(columns).to_numpy().astype(np.float64), [c.split("__", 1)[1] for c in columns]


def c1(
    test: pl.DataFrame,
    points: dict[str, Any],
    primary: pl.DataFrame,
    floor: pl.DataFrame,
    seed: int,
    criteria: dict[str, Any],
) -> dict[str, Any]:
    """The band on test CVEs with an NVD band: the primary's kappa against the floor's, paired, and
    the primary's ECE after its frozen temperature, by the cluster bootstrap by filer."""
    population = test.filter(pl.col("band").is_in(list(sets.BANDS))).select("cve_id", "band", "filer")
    p_model, classes = matrix(population.join(primary, on="cve_id", how="left"), "band")
    p_floor, floor_classes = matrix(population.join(floor, on="cve_id", how="left"), "band")
    order = {b: i for i, b in enumerate(sets.BANDS)}
    truth = np.array([order[b] for b in population.get_column("band").to_list()])
    model_guess = np.array([order[classes[i]] for i in p_model.argmax(axis=1)])
    floor_guess = np.array([order[floor_classes[i]] for i in p_floor.argmax(axis=1)])
    keys = [str(f) for f in population.get_column("filer").fill_null("(none)").to_list()]
    kappas = evaluate.kappa_paired(keys, truth, model_guess, floor_guess, len(sets.BANDS), seed)
    scaled = calibrate.scale(p_model, float(points["temperatures"][points["primary"]["fill"]]["band"]))
    class_truth = np.array([classes.index(b) for b in population.get_column("band").to_list()])
    confidence, correct = calibrate.top_label(scaled, class_truth)
    ece = evaluate.ece_clustered(keys, confidence, correct, seed)
    threshold = criteria["threshold"]
    met = (
        kappas["model"]["value"] >= threshold["kappa_min"]
        and kappas["difference"]["low"] > threshold["floor_margin_lower_bound_min"]
        and ece["value"] <= threshold["ece_max"]
    )
    return {
        "criterion": "C1",
        "population": criteria["population"],
        "model": points["primary"]["fill"],
        "comparator": points["primary"]["fill_comparator"],
        "kappa": kappas,
        "ece": ece,
        "threshold": threshold,
        "verdict": "met" if met else "not met",
    }


def epss_scores(bronze: Path, ids: list[str]) -> dict[int, np.ndarray]:
    glob = (bronze / "epss_offsets" / "**" / "*.parquet").as_posix()
    offsets = pl.read_parquet(glob, hive_partitioning=False).filter(
        pl.col("offset_days").is_in(list(EPSS_DAYS))
    )
    spine = pl.DataFrame({"cve_id": ids})
    out = {}
    for day in EPSS_DAYS:
        one = offsets.filter(pl.col("offset_days") == day).select("cve_id", "epss").unique("cve_id")
        out[day] = spine.join(one, on="cve_id", how="left").get_column("epss").fill_null(-1.0).to_numpy()
    return out


def c2(
    test: pl.DataFrame,
    points: dict[str, Any],
    scores: pl.DataFrame,
    bronze: Path,
    seed: int,
    criteria: dict[str, Any],
) -> dict[str, Any]:
    """Recall of KEV within 180 days among the top 5 percent of the test population by the raw
    LightGBM score, EPSS at days 1, 7 and 30 beside, paired by a row bootstrap."""
    population = test.filter(~pl.col("kev_q03").fill_null(False)).select("cve_id", "kev_180").sort("cve_id")
    joined = population.join(scores, on="cve_id", how="left")
    truth = joined.get_column("kev_180").fill_null(False).cast(pl.Int8).to_numpy()
    model = joined.get_column(points["primary"]["exploitation"]).cast(pl.Float64).to_numpy()
    epss = epss_scores(bronze, joined.get_column("cve_id").to_list())
    by = {"model": model, **{f"epss_day_{d}": epss[d] for d in EPSS_DAYS}}
    recalls = evaluate.recall_paired(truth, by, seed, reference="model")
    met = recalls["model"]["value"] >= criteria["threshold"]["recall_at_top5_min"]
    return {
        "criterion": "C2",
        "population": criteria["population"],
        "model": points["primary"]["exploitation"],
        "rank_by": points["c2"]["rank_by"],
        "recall_at_top5": recalls,
        "epss_missing": {f"day_{d}": int(np.sum(epss[d] < 0)) for d in EPSS_DAYS},
        "epss_rule": "a CVE with no EPSS score at the offset ranks below every scored one",
        "note": "EPSS at days 7 and 30 has seen days the model has not",
        "threshold": criteria["threshold"],
        "verdict": "met" if met else "not met",
    }


def secondary(
    test: pl.DataFrame, points: dict[str, Any], models: Path, folder: Path, root: Path
) -> dict[str, Any]:
    from scripts.choose_operating_points import TEST_FILES

    out: dict[str, Any] = {"fill": {}, "exploitation": {}, "survival": {}, "product": {}, "conformal": {}}
    for model in ("fallback", "fallback_text", "floors"):
        proba = pl.read_parquet(models / TEST_FILES[model])
        joined = test.join(proba, on="cve_id", how="inner")
        per: dict[str, Any] = {}
        for task in floors.TASKS:
            m, classes = matrix(joined, task.name)
            values = joined.get_column(task.label).cast(pl.String).to_list()
            keep = [i for i, v in enumerate(values) if v]
            guess = [classes[j] for j in m[keep].argmax(axis=1)]
            truth = [values[i] for i in keep]
            entry: dict[str, Any] = {
                "rows": len(keep),
                task.metric: floors.score(task.metric, truth, guess),
                "macro_f1": floors.score("macro_f1", truth, guess),
            }
            if task.name == "cwe":
                top5 = np.argsort(-m[keep], axis=1)[:, :5]
                entry["top1_accuracy"] = float(np.mean([g == t for g, t in zip(guess, truth, strict=True)]))
                entry["top5_accuracy"] = float(
                    np.mean([truth[i] in {classes[j] for j in top5[i]} for i in range(len(keep))])
                )
            per[task.name] = entry
        # The band computed from the eight predicted metrics, beside the band head, never primary.
        bands = joined.get_column("band").cast(pl.String).to_list()
        rated = floors.band_from_metrics(joined)
        keep = [i for i, v in enumerate(bands) if v in sets.BANDS]
        per["band_from_metrics"] = {
            "rows": len(keep),
            "qwk": floors.score("qwk", [bands[i] for i in keep], [rated[i] for i in keep]),
        }
        out["fill"][model] = per
    calibration = json.loads((root / "results" / "models" / "calibration.json").read_text(encoding="utf-8"))
    population = rank.population(test)
    scores = population.join(
        pl.read_parquet(models / "rank" / "test_scores.parquet"), on="cve_id", how="left"
    )
    listed = scores.get_column("kev_180").cast(pl.Int8).to_numpy()
    for model in ("exploit_lgbm", "exploit_floor"):
        raw = scores.get_column(model).cast(pl.Float64).to_numpy()
        iso = calibration["exploitation"][model]["map"]
        if (
            hashlib.sha256(json.dumps(iso, sort_keys=True).encode()).hexdigest()
            != points["isotonic_maps_sha256"][model]
        ):
            raise SystemExit(f"score: the isotonic map of {model} differs from the one frozen")
        calibrated = calibrate.Isotonic(np.asarray(iso["x"]), np.asarray(iso["y"])).predict(raw)
        out["exploitation"][model] = {
            "rows": len(listed),
            "positives": int(listed.sum()),
            "average_precision": float(average_precision_score(listed, raw)),
            "auroc": float(roc_auc_score(listed, raw)),
            "brier_calibrated": float(np.mean((calibrated - listed) ** 2)),
        }
    surv = population.join(
        pl.read_parquet(models / "survival" / "test_survival.parquet"), on="cve_id", how="left"
    )
    d, e = survival.duration(surv), survival.event(surv)
    for model in ("cox", "forest"):
        out["survival"][model] = {
            "concordance": survival.concordance(d, e, surv.get_column(f"{model}_listed_by_180").to_numpy())
        }
    labels = sets.load_product_labels(folder, "test", unsealed=True).select("cve_id", "nvd_products")
    cands = labels.join(
        pl.read_parquet(models / "product" / "test_candidates.parquet"), on="cve_id", how="left"
    )
    truth_pairs = cands.get_column("nvd_products").to_list()
    threshold = float(points["product_floor_threshold"])
    for name, keys_col, scores_col in (
        ("floor", "floor_keys", "floor_scores"),
        ("retrieval", "retrieval_keys", "retrieval_scores"),
    ):
        ranked = [
            list(zip(k or [], s or [], strict=True))
            for k, s in zip(
                cands.get_column(keys_col).to_list(), cands.get_column(scores_col).to_list(), strict=True
            )
        ]
        out["product"][name] = product.recall(ranked, truth_pairs)
        if name == "floor":
            out["product"]["floor_at_threshold"] = product.recall(
                product.at_threshold(ranked, threshold), truth_pairs
            )
    primary = pl.read_parquet(models / points["primary"]["fill"] / "test_probabilities.parquet")
    joined = test.join(primary, on="cve_id", how="inner")
    for head, cutoff in points["conformal"]["cutoffs"].items():
        m, classes = matrix(joined, head)
        label = "band" if head == "band" else f"nvd_{head.split('_', 1)[1]}"
        values = joined.get_column(label).cast(pl.String).to_list()
        keep = [i for i, v in enumerate(values) if v in classes]
        scaled = calibrate.scale(m[keep], float(points["temperatures"][points["primary"]["fill"]][head]))
        truth_idx = np.array([classes.index(values[i]) for i in keep])
        member = conformal.sets(scaled, float(cutoff))
        entry = dict(conformal.coverage(member, truth_idx))
        types = joined.get_column("filer_type").fill_null("(none)").to_list()
        entry["by_filer_type"] = {
            t: conformal.coverage(
                member[[j for j, i in enumerate(keep) if types[i] == t]],
                truth_idx[[j for j, i in enumerate(keep) if types[i] == t]],
            )
            for t in sorted({types[i] for i in keep})
        }
        out["conformal"][head] = entry
    return out


def slices(test: pl.DataFrame, models: Path, points: dict[str, Any], seed: int) -> dict[str, Any]:
    """Band kappa of the primary against its floor, and average precision of LightGBM against its
    floor, per slice of each family, Benjamini-Hochberg at 0.05 within each family."""
    primary = pl.read_parquet(models / points["primary"]["fill"] / "test_probabilities.parquet")
    floor = pl.read_parquet(models / "floors" / "test_probabilities.parquet")
    banded = test.filter(pl.col("band").is_in(list(sets.BANDS)))
    a = floors.band_from(banded.select("cve_id").join(primary, on="cve_id", how="left"))
    b = floors.band_from(banded.select("cve_id").join(floor, on="cve_id", how="left"))
    truth = banded.get_column("band").to_list()

    def qwk(t: list[str], g: list[str]) -> float:
        return floors.score("qwk", t, g)

    out: dict[str, Any] = {"fill": {}, "exploitation": {}}
    families = {
        "filer": banded.get_column("filer").fill_null("(none)").to_list(),
        "filer_type": banded.get_column("filer_type").fill_null("(none)").to_list(),
        "cwe": banded.get_column("cwe").fill_null("(none)").to_list(),
        "vendor": banded.get_column("vendor").fill_null("(none)").to_list(),
        "published_year": [str(y) for y in banded.get_column("published_year").to_list()],
    }
    for family, groups in families.items():
        counts: dict[str, int] = {}
        for g in groups:
            counts[g] = counts.get(g, 0) + 1
        chosen = sorted(counts, key=lambda g: (-counts[g], g))
        chosen = chosen if family in ("filer_type", "published_year") else chosen[:SLICE_TOP]
        out["fill"][family] = evaluate.slice_differences(
            groups, chosen, qwk, a, b, truth, seed, SLICE_MIN_ROWS
        )
    population = rank.population(test)
    scores = population.join(
        pl.read_parquet(models / "rank" / "test_scores.parquet"), on="cve_id", how="left"
    )
    listed = scores.get_column("kev_180").cast(pl.Int8).to_list()

    def ap(t: list[int], s: list[float]) -> float:
        return float(average_precision_score(t, s)) if 0 < sum(t) < len(t) else float("nan")

    lgbm, base = scores.get_column("exploit_lgbm").to_list(), scores.get_column("exploit_floor").to_list()
    for family in ("filer_type", "published_year"):
        groups = scores.get_column(family).fill_null("(none)").cast(pl.String).to_list()
        chosen = sorted(set(groups))
        out["exploitation"][family] = evaluate.slice_differences(
            groups, chosen, ap, lgbm, base, listed, seed, SLICE_MIN_ROWS
        )
    return out


def manifest_part(c1r: dict[str, Any], c2r: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    pop1, pop2 = "test window CVEs with an NVD CVSS 3.1 band", "test window CVEs, Q03 left out"
    for key, value, fmt, population in (
        ("c1.kappa", c1r["kappa"]["model"]["value"], "float3", pop1),
        ("c1.kappa_low", c1r["kappa"]["model"]["low"], "float3", pop1),
        ("c1.kappa_high", c1r["kappa"]["model"]["high"], "float3", pop1),
        ("c1.floor_kappa", c1r["kappa"]["floor"]["value"], "float3", pop1),
        ("c1.difference", c1r["kappa"]["difference"]["value"], "sfloat3", pop1),
        ("c1.difference_low", c1r["kappa"]["difference"]["low"], "sfloat3", pop1),
        ("c1.difference_high", c1r["kappa"]["difference"]["high"], "sfloat3", pop1),
        ("c1.ece", c1r["ece"]["value"], "float3", pop1),
        ("c1.rows", c1r["kappa"]["rows"], "int", pop1),
        ("c1.verdict", c1r["verdict"], "text", pop1),
        ("c2.recall", c2r["recall_at_top5"]["model"]["value"], "pct1", pop2),
        ("c2.recall_low", c2r["recall_at_top5"]["model"]["low"], "pct1", pop2),
        ("c2.recall_high", c2r["recall_at_top5"]["model"]["high"], "pct1", pop2),
        ("c2.positives", c2r["recall_at_top5"]["positives"], "int", pop2),
        ("c2.verdict", c2r["verdict"], "text", pop2),
    ):
        m.value(f"models.test.{key}", value, fmt, origin=ORIGIN, population=population, source="models")
    for d in EPSS_DAYS:
        m.value(
            f"models.test.c2.epss_day_{d}",
            c2r["recall_at_top5"][f"epss_day_{d}"]["value"],
            "pct1",
            origin=ORIGIN,
            population=f"{pop2}: EPSS at day {d}",
            source="models",
        )
        m.value(
            f"models.test.c2.reading_day_{d}",
            c2r["recall_at_top5"][f"model_minus_epss_day_{d}"]["reading"],
            "text",
            origin=ORIGIN,
            population=f"{pop2}: the model against EPSS at day {d}",
            source="models",
        )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", type=Path, default=root / "data" / "models")
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--bronze", type=Path, default=root / "data" / "bronze")
    args = parser.parse_args(argv)
    out = root / "results" / "models"
    if (out / "test_scoring.json").exists():
        raise SystemExit(
            "score: test was scored already (results/models/test_scoring.json); a second run needs a change request"
        )
    points = operating_points(root)
    check_frozen(points, args.models)
    seed = plan_seed(root)
    criteria = {
        c["id"]: c
        for c in yaml.safe_load((root / "config" / "criteria.yaml").read_text(encoding="utf-8"))["criteria"]
    }
    labels = sets.load_labels(args.sets, "test", unsealed=True)
    inputs = pl.read_parquet(args.sets / sets.inputs_name("test")).select(
        "cve_id", "published", "published_year", "filer", "filer_type"
    )
    vendors = pl.read_parquet(args.sets / sets.product_inputs_name("test")).select(
        "cve_id", pl.col("filer_pairs").list.first().struct.field("vendor").str.to_lowercase().alias("vendor")
    )
    test = labels.join(inputs, on="cve_id").join(vendors, on="cve_id", how="left").sort("cve_id")
    primary = pl.read_parquet(args.models / points["primary"]["fill"] / "test_probabilities.parquet")
    floor = pl.read_parquet(args.models / "floors" / "test_probabilities.parquet")
    c1r = c1(test, points, primary, floor, seed, criteria["C1"])
    c2r = c2(
        test,
        points,
        pl.read_parquet(args.models / "rank" / "test_scores.parquet"),
        args.bronze,
        seed,
        criteria["C2"],
    )
    record = {
        "scored_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "operating_points_sha256": hashlib.sha256(
            (root / "config" / "operating_points.yaml").read_bytes()
        ).hexdigest(),
        "test_predictions": points["test_predictions"],
        "seed": seed,
        "secondary": secondary(test, points, args.models, args.sets, root),
        "slices": slices(test, args.models, points, seed),
        "c1_verdict": c1r["verdict"],
        "c2_verdict": c2r["verdict"],
    }
    (out / "c1.json").write_text(json.dumps(c1r, indent=1) + "\n", encoding="utf-8")
    (out / "c2.json").write_text(json.dumps(c2r, indent=1) + "\n", encoding="utf-8")
    (out / "test_scoring.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    sets_record = json.loads((out / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(c1r, c2r, str(sets_record["lake_cut"])[:10])
    (root / "results" / "parts" / "test.json").write_text(json.dumps(part, indent=1) + "\n", encoding="utf-8")
    print(
        f"score: C1 {c1r['verdict']} (kappa {c1r['kappa']['model']['value']:.3f}), C2 {c2r['verdict']} (recall {c2r['recall_at_top5']['model']['value']:.3f})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
