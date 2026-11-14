"""Calibrate on development, fit the conformal sets, weigh the shadow CVEs, and freeze the operating
points of Phase 2 before test is scored.

    uv run python scripts/choose_operating_points.py [--models data/models] [--draft]

Reads the development and shadow predictions every model step left in --models (the floors, the
fallback, the exploitation models and the affected product), the development and shadow labels, and
the lake's domain shift mart. Fits a temperature per head of the fill models and an isotonic map per
exploitation model on development; fits the APS sets of the primary fill model's band and metric
heads on the calibrated development probabilities; weighs the shadow CVEs the NVD analyzed by the
domain classifier's odds and reports the band kappa plain and weighted. Writes
results/models/calibration.json, results/models/conformal.json, results/models/reweighting.json,
the manifest part results/parts/choose.json and config/operating_points.yaml, which names the
primary models, every calibration parameter and the content digest of every test prediction file,
and is then hashed into the registration (scripts/register.py operating_points) before
scripts/score_test.py runs. --draft writes the results without the operating points, when a model
step has not left its test predictions yet.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import duckdb
import numpy as np
import polars as pl
import yaml
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import calibrate, conformal, floors, rank, reweight, sets

from scripts.train_floors import plan_seed

ORIGIN = "scripts/choose_operating_points.py"
FILL_MODELS = ("floors", "fallback")
PRIMARY_FILL = "fallback"
CONFORMAL_HEADS = ("band", *(f"metric_{m}" for m in sets.METRICS))
EXPLOIT_MODELS = ("exploit_lgbm", "exploit_floor")
PRIMARY_EXPLOIT = "exploit_lgbm"
TEST_FILES = {
    "floors": "floors/test_probabilities.parquet",
    "fallback": "fallback/test_probabilities.parquet",
    # The fallback's text alone, the ablation the scorer reports beside the model (DECISIONS.md).
    "fallback_text": "fallback/test_text_probabilities.parquet",
    "rank": "rank/test_scores.parquet",
    "survival": "survival/test_survival.parquet",
    "product": "product/test_candidates.parquet",
}


def head_matrix(proba: pl.DataFrame, task: str) -> tuple[np.ndarray, list[str]]:
    columns = [c for c in proba.columns if c.startswith(f"{task}__")]
    return proba.select(columns).to_numpy().astype(np.float64), [c.split("__", 1)[1] for c in columns]


def calibrate_fill(
    proba: pl.DataFrame, labels: pl.DataFrame, seed: int
) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    """A temperature per head, fit on the development rows with the label; the calibrated
    development probabilities of each head, for the conformal sets."""
    joined = labels.join(proba, on="cve_id", how="inner")
    out: dict[str, Any] = {}
    calibrated: dict[str, np.ndarray] = {}
    for task in floors.TASKS:
        matrix, classes = head_matrix(joined, task.name)
        values = joined.get_column(task.label).cast(pl.String).to_list()
        keep = np.array([v in classes for v in values])
        index = {c: i for i, c in enumerate(classes)}
        truth = np.array([index[v] for v, k in zip(values, keep, strict=True) if k])
        p = matrix[keep]
        t = calibrate.fit_temperature(p, truth)
        scaled = calibrate.scale(p, t)
        entry: dict[str, Any] = {
            "classes": classes,
            "temperature": t,
            "rows": int(keep.sum()),
            "nll_before": calibrate.nll(p, truth),
            "nll_after": calibrate.nll(scaled, truth),
        }
        if task.name == "band":
            for when, q in (("before", p), ("after", scaled)):
                conf, correct = calibrate.top_label(q, truth)
                point, low, high = calibrate.ece_interval(conf, correct, seed)
                entry[f"ece_{when}"] = {"value": point, "low": low, "high": high}
                entry[f"reliability_{when}"] = calibrate.reliability(conf, correct)
        out[task.name] = entry
        calibrated[task.name] = scaled
        calibrated[f"{task.name}__truth"] = truth
    return out, calibrated


def calibrate_exploit(scores: pl.DataFrame, labels: pl.DataFrame) -> dict[str, Any]:
    joined = rank.population(labels).join(scores, on="cve_id", how="inner")
    truth = joined.get_column("kev_180").cast(pl.Float64).to_numpy()
    out: dict[str, Any] = {}
    for model in EXPLOIT_MODELS:
        raw = joined.get_column(model).cast(pl.Float64).to_numpy()
        fitted = calibrate.fit_isotonic(raw, truth).compact()
        out[model] = {
            "rows": len(truth),
            "positives": int(truth.sum()),
            "brier_before": float(np.mean((raw - truth) ** 2)),
            "brier_after": float(np.mean((fitted.predict(raw) - truth) ** 2)),
            "map": {"x": fitted.x.tolist(), "y": fitted.y.tolist()},
        }
    return out


def fit_conformal(
    calibrated: dict[str, np.ndarray], seed: int, heads: tuple[str, ...] = CONFORMAL_HEADS
) -> dict[str, Any]:
    out = {}
    for head in heads:
        p, truth = calibrated[head], calibrated[f"{head}__truth"]
        fitted = conformal.fit(p, truth, seed)
        out[head] = {
            "cutoff": fitted.cutoff,
            "target": fitted.target,
            "rows": fitted.calibration_rows,
            **{f"dev_{k}": v for k, v in conformal.coverage(fitted.predict(p), truth).items()},
        }
    return out


def shadow_weights(lake: Path, models: Path, folder: Path) -> dict[str, Any]:
    con = duckdb.connect(str(lake), read_only=True)
    try:
        con.execute("set TimeZone = 'UTC'")
        units = con.sql("select * from gold.mart_domain_shift order by position").pl()
    finally:
        con.close()
    odds = reweight.cross_fitted_odds(units)
    labels = sets.load_labels(folder, "shadow").select("cve_id", "band").drop_nulls("band")
    out: dict[str, Any] = {
        "shadow_cves": units.height,
        "analyzed": int(units.get_column("nvd_analyzed").sum()),
    }
    for model in FILL_MODELS:
        proba = pl.read_parquet(models / model / "shadow_probabilities.parquet")
        predicted = proba.select("cve_id", pl.Series("predicted_band", floors.band_from(proba)))
        frame = labels.join(odds.filter(pl.col("nvd_analyzed")), on="cve_id").join(predicted, on="cve_id")
        out[model] = reweight.plain_and_weighted(frame)
    return out


def digest_text(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def manifest_part(
    calibration: dict[str, Any], conformal_record: dict[str, Any], weights: dict[str, Any], as_of: str
) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    band = calibration["fill"][PRIMARY_FILL]["band"]
    m.value(
        "models.calibration.band_temperature",
        float(band["temperature"]),
        "float2",
        origin=ORIGIN,
        population="development window CVEs with an NVD band: the temperature of the primary band head",
        source="models",
    )
    for when in ("before", "after"):
        m.value(
            f"models.calibration.band_dev_ece_{when}",
            float(band[f"ece_{when}"]["value"]),
            "float3",
            origin=ORIGIN,
            population=f"development window CVEs with an NVD band: the expected calibration error of the primary band head {when} temperature scaling",
            source="models",
        )
    m.value(
        "models.conformal.band_dev_mean_size",
        float(conformal_record["heads"]["band"]["dev_mean_size"]),
        "float2",
        origin=ORIGIN,
        population="development window CVEs with an NVD band: the mean size of the band sets at the target coverage",
        source="models",
    )
    for model in FILL_MODELS:
        w = weights[model]
        m.value(
            f"models.reweighting.{model}.plain_qwk",
            float(w["plain_qwk"]),
            "float3",
            origin=ORIGIN,
            population="shadow CVEs the NVD analyzed with a band: plain",
            source="models",
        )
        m.value(
            f"models.reweighting.{model}.weighted_qwk",
            float(w["weighted_qwk"]),
            "float3",
            origin=ORIGIN,
            population="shadow CVEs the NVD analyzed with a band: weighted toward the skipped",
            source="models",
        )
        m.value(
            f"models.reweighting.{model}.ess",
            float(w["effective_sample_size"]),
            "int",
            origin=ORIGIN,
            population="shadow CVEs the NVD analyzed with a band: Kish effective sample size of the weights",
            source="models",
        )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", type=Path, default=root / "data" / "models")
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--lake", type=Path, default=root / "data" / "lake" / "unscheduled.duckdb")
    parser.add_argument("--draft", action="store_true", help="write the results without the operating points")
    args = parser.parse_args(argv)
    seed = plan_seed(root)
    dev_labels = sets.load_labels(args.sets, "development")
    dev_inputs = pl.read_parquet(args.sets / sets.inputs_name("development")).select(
        "cve_id", "published", "filer_type"
    )
    dev = dev_labels.join(dev_inputs, on="cve_id")
    fill: dict[str, Any] = {}
    calibrated: dict[str, np.ndarray] = {}
    floor_calibrated: dict[str, np.ndarray] = {}
    from_metrics: dict[str, Any] = {}
    for model in FILL_MODELS:
        proba = pl.read_parquet(args.models / model / "development_probabilities.parquet")
        fill[model], cal = calibrate_fill(proba, dev, seed)
        if model == PRIMARY_FILL:
            calibrated = cal
        else:
            floor_calibrated = cal
        # The plan's band_from_metrics, reported beside the band head and never the primary.
        banded = dev.join(proba, on="cve_id", how="inner")
        truth = banded.get_column("band").cast(pl.String).to_list()
        rated = floors.band_from_metrics(banded)
        keep = [i for i, v in enumerate(truth) if v in sets.BANDS]
        from_metrics[model] = {
            "rows": len(keep),
            "dev_qwk": floors.score("qwk", [truth[i] for i in keep], [rated[i] for i in keep]),
        }
    exploit = calibrate_exploit(pl.read_parquet(args.models / "rank" / "development_scores.parquet"), dev)
    calibration = {
        "seed": seed,
        "fill": fill,
        "band_from_metrics": from_metrics,
        "exploitation": exploit,
        "primary_fill": PRIMARY_FILL,
        "primary_exploitation": PRIMARY_EXPLOIT,
    }
    conformal_record: dict[str, Any] = {
        "model": PRIMARY_FILL,
        "method": "split conformal, APS, the class crossing the threshold included",
        "seed": seed,
        "heads": fit_conformal(calibrated, seed),
        # The band floor serves POST /v1/predict, so its band head gets sets of its own.
        "floor_band": fit_conformal(floor_calibrated, seed, heads=("band",))["band"],
    }
    weights = shadow_weights(args.lake, args.models, args.sets)
    out = root / "results" / "models"
    for name, record in (
        ("calibration", calibration),
        ("conformal", conformal_record),
        ("reweighting", weights),
    ):
        (out / f"{name}.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    sets_record = json.loads((out / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(calibration, conformal_record, weights, str(sets_record["lake_cut"])[:10])
    (root / "results" / "parts" / "choose.json").write_text(
        json.dumps(part, indent=1) + "\n", encoding="utf-8"
    )
    if args.draft:
        print("choose: draft written, no operating points")
        return 0
    missing = [name for name, path in TEST_FILES.items() if not (args.models / path).exists()]
    if missing:
        raise SystemExit(
            f"choose: no test predictions yet from {', '.join(missing)}; run again with --draft or wait"
        )
    points = {
        "frozen_for": "Phase 2, before scripts/score_test.py scores test once",
        "primary": {
            "fill": PRIMARY_FILL,
            "fill_design": json.loads((out / "fallback.json").read_text(encoding="utf-8"))["primary"],
            "fill_comparator": "floors",
            "exploitation": PRIMARY_EXPLOIT,
            "exploitation_comparator": "exploit_floor",
        },
        "temperatures": {
            model: {task: round(entry["temperature"], 6) for task, entry in heads.items()}
            for model, heads in fill.items()
        },
        "isotonic_maps_sha256": {model: digest_text(entry["map"]) for model, entry in exploit.items()},
        "conformal": {
            "target": conformal.TARGET,
            "cutoffs": {h: round(e["cutoff"], 9) for h, e in conformal_record["heads"].items()},
            "floor_band_cutoff": round(conformal_record["floor_band"]["cutoff"], 9),
        },
        "c2": {
            "top_share": rank.TOP_SHARE,
            "rank_by": f"the raw {PRIMARY_EXPLOIT} score, ties by position in CVE id order",
            "population": "test window CVEs, Q03 left out",
        },
        "reweighting": {"clip": reweight.CLIP},
        "product_floor_threshold": json.loads((out / "product.json").read_text(encoding="utf-8"))["floor"][
            "threshold"
        ],
        "test_predictions": {
            name: sets.content_digest(args.models / path) for name, path in TEST_FILES.items()
        },
    }
    target = root / "config" / "operating_points.yaml"
    header = "# The operating points of Phase 2, frozen and hashed into evaluation/registration.json before test is\n# scored. Written by scripts/choose_operating_points.py; a change after the hash is a change request.\n"
    target.write_text(header + yaml.safe_dump(points, sort_keys=False, width=100), encoding="utf-8")
    print(f"choose: operating points written to {target.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
