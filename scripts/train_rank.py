"""Fit the exploitation models of Phase 2 on the point in time sets and choose them on development.

    uv run python scripts/train_rank.py [--sets data/sets] [--out data/models/rank] [--jobs N]
    uv run python scripts/train_rank.py --sample 6000 --trials 3    # a smoke run, nothing committed

Checks the set files it reads against results/models/sets.json, takes the seed and the trial count
from evaluation/phase2_plan.yaml and the band floor's representation and C from
results/models/floors.json, builds the band floor text projection (out of fold for the train CVEs the
band floor was fit on), fits the logistic floor and the LightGBM search of unscheduled_models.rank on
the train population, and scores development. Test and shadow get scores for every CVE, Q03 included,
since whether a test CVE was listed before publication is a label: scripts/score_test.py leaves those
out when it scores. Writes the models and the scores to --out (never committed) and commits
results/models/rank.json and the manifest part results/parts/rank.json. Runs in the models workflow
beside the floors, on a runner with the memory the band floor's text needs. A full run refuses to
start unless the numeric pins of unscheduled_models.numerics are in its environment, as the models
workflow and reset and rederive set them, since without them the search lands elsewhere on another
machine; the record keeps the kernels and threads the process actually ran with.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import joblib
import lightgbm
import numpy as np
import optuna
import polars as pl
import sklearn
import yaml
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import numerics, rank, sets

from scripts.train_floors import file_sha256, models_stage_hash, plan_seed, verify_sets

ORIGIN = "scripts/train_rank.py"


def plan_trials(root: Path) -> int:
    plan = yaml.safe_load((root / "evaluation" / "phase2_plan.yaml").read_text(encoding="utf-8"))
    return int(plan["models"]["exploit_lgbm"]["search"].split(",")[1].split()[0])


def band_floor(root: Path) -> tuple[str, float]:
    path = root / "results" / "models" / "floors.json"
    if not path.exists():
        raise SystemExit(
            "rank: results/models/floors.json is missing; the floors come first (scripts/train_floors.py)"
        )
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("sample"):
        raise SystemExit("rank: results/models/floors.json is a sample run; commit the full floors first")
    band = record["chosen"]["band"]
    return str(band["variant"]), float(band["C"])


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    dev = "development window CVEs published, Q03 left out"
    for model in ("floor", "lgbm"):
        name = "the logistic floor" if model == "floor" else "LightGBM"
        for key, fmt in (("average_precision", "float3"), ("auroc", "float3"), ("recall_at_top5", "pct1")):
            m.value(
                f"models.rank.{model}.dev_{key}",
                float(record["dev"][model][key]),
                fmt,
                origin=ORIGIN,
                population=f"{dev}: {name}, KEV within 180 days",
                source="models",
            )
    for key, value in (
        ("dev_rows", record["dev"]["floor"]["rows"]),
        ("dev_positives", record["dev"]["floor"]["positives"]),
        ("train_rows", record["population"]["train_rows"]),
        ("train_positives", record["population"]["train_positives"]),
        ("trials", record["lgbm"]["trials"]),
        ("trees", record["lgbm"]["trees"]),
    ):
        m.value(
            f"models.rank.{key}",
            int(value),
            "int",
            origin=ORIGIN,
            population="the exploitation models: the rank population from 7 May 2021, Q03 left out",
            source="models",
        )
    m.value(
        "models.rank.floor.C",
        f"{record['floor']['C']:g}",
        "text",
        origin=ORIGIN,
        population="the regularization the exploitation floor chose on development",
        source="models",
    )
    m.table(
        "models.rank.folds",
        [
            "Fit on CVEs published before",
            "Validated on",
            "Fit rows",
            "Fit listed",
            "Validation rows",
            "Validation listed",
            "Average precision",
        ],
        ["text", "text", "int", "int", "int", "int", "float3"],
        [
            [
                f["fit_before"],
                f["validate"],
                f["fit_rows"],
                f["fit_positives"],
                f["validate_rows"],
                f["validate_positives"],
                f["best_trial_ap"],
            ]
            for f in record["lgbm"]["folds"]
        ],
        origin=ORIGIN,
        population="the train part of the rank population, by the half years of the change request",
        source="models",
    )
    return m.dump()


def committed_floor(
    root: Path, path: Path, sample: int | None
) -> tuple[tuple[Any, Any] | None, dict[str, Any]]:
    """The floors step's features and band model, the floor the API serves, checked by digest. A smoke
    run refits it instead; a full run without the file stops, so the projection LightGBM learns from
    is always the one it gets at serving time (DECISIONS.md, the exploitation run reads the committed
    band floor)."""
    record = json.loads((root / "results" / "models" / "floors.json").read_text(encoding="utf-8"))
    if not path.exists():
        if sample:
            return None, {"kind": "refit for a smoke run"}
        raise SystemExit(f"rank: {path} is missing; restore the floors step's model file first")
    if file_sha256(path) != record["model_file"]["sha256"]:
        raise SystemExit(f"rank: {path} is not the model file results/models/floors.json names")
    saved = joblib.load(path)
    return (saved["features"], saved["models"]["band"]), {
        "kind": "the committed band floor",
        "file": record["model_file"]["path"],
        "sha256": record["model_file"]["sha256"],
    }


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--sample", type=int, default=None, help="rows per window, for a smoke run")
    parser.add_argument(
        "--trials", type=int, default=None, help="a smoke run only: fewer trials than the plan"
    )
    parser.add_argument("--variant", default=None, help="a smoke run only: the band floor representation")
    parser.add_argument("--band-c", type=float, default=None, help="a smoke run only: the band floor C")
    parser.add_argument(
        "--floors",
        type=Path,
        default=root / "data" / "models" / "floors" / "floors.joblib",
        help="the floors step's model file, checked against the SHA-256 results/models/floors.json names",
    )
    args = parser.parse_args(argv)
    if not args.sample and (args.trials or args.variant or args.band_c):
        raise SystemExit("rank: --trials, --variant and --band-c are for a smoke run with --sample only")
    gaps = numerics.missing()
    if not args.sample and gaps:
        settings = " ".join(f"{name}={value!r}" for name, value in gaps.items())
        raise SystemExit(f"rank: the numeric pins are not set; start the run with {settings}")
    started = time.monotonic()
    out = args.out or root / "data" / "models" / ("rank-sample" if args.sample else "rank")
    seed = plan_seed(root)
    trials = args.trials or plan_trials(root)
    stage = models_stage_hash(root)
    variant, band_c = (args.variant, args.band_c) if args.sample else band_floor(root)
    assert variant is not None and band_c is not None
    digests = verify_sets(root, args.sets)
    from scripts.train_floors import load

    frames = load(args.sets, args.sample, seed)
    committed, floor_source = committed_floor(root, args.floors, args.sample)
    projection = rank.band_projection(
        frames["train"],
        {k: frames[k] for k in ("development", "test", "shadow")},
        variant,
        band_c,
        seed,
        committed=committed,
    )
    frames = {k: rank.with_projection(f, projection[k]) for k, f in frames.items()}
    train = rank.population(frames["train"])
    dev = rank.population(frames["development"])
    design = rank.DayZero().fit(train)
    floor = rank.fit_floor_search(design, train, dev, seed)
    print(f"rank: floor C={floor.c:g}, development average precision {floor.dev['average_precision']:.4f}")
    lgbm = rank.fit_lgbm_search(design, train, seed, trials, args.jobs)
    dev_lgbm = rank.scores(rank.truth(dev), rank.predict(lgbm.model, design.dense(dev)))
    out.mkdir(parents=True, exist_ok=True)
    predictions: dict[str, Any] = {}
    for split, frame in (("development", dev), ("test", frames["test"]), ("shadow", frames["shadow"])):
        table = pl.DataFrame(
            {
                "cve_id": frame.get_column("cve_id"),
                "exploit_floor": floor.model.predict_proba(design.sparse(frame))[:, 1].astype(np.float32),
                "exploit_lgbm": rank.predict(lgbm.model, design.dense(frame)).astype(np.float32),
                **{name: frame.get_column(name) for name in rank.PROJECTION},
            }
        )
        path = out / f"{split}_scores.parquet"
        table.write_parquet(path, compression="zstd", statistics=True)
        predictions[split] = {"rows": table.height, "content_digest": sets.content_digest(path)}
    model_file = out / "rank.joblib"
    joblib.dump(
        {
            "design": design,
            "floor": floor.model,
            "lgbm": lgbm.model.model_to_string(),
            "band_floor": [variant, band_c],
        },
        model_file,
        compress=3,
    )
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    record: dict[str, Any] = {
        "plan": "evaluation/phase2_plan.yaml",
        "models_stage_hash": stage,
        "sample": args.sample,
        "sets": digests,
        "lake_release": sets_record.get("lake_release"),
        "seed": seed,
        "band_floor": {
            "variant": variant,
            "C": band_c,
            "projection_folds": rank.PROJECTION_FOLDS,
            "source": floor_source,
        },
        "population": {
            "start": str(rank.RANK_START),
            "rule": "published from the start, Q03 left out (DECISIONS.md, 14 November 2026)",
            "train_rows": train.height,
            "train_positives": int(rank.truth(train).sum()),
            "dev_rows": dev.height,
        },
        "features": design.names(),
        "floor": {"C": floor.c, "class_weight": "balanced", "search": floor.search},
        "lgbm": {
            "trials": trials,
            "sampler": "TPE",
            "params": lgbm.params,
            "trees": lgbm.trees,
            "max_trees": rank.MAX_TREES,
            "early_stopping_rounds": rank.EARLY_STOP,
            "folds": lgbm.folds,
            "search": lgbm.trials,
        },
        "dev": {"floor": floor.dev, "lgbm": dev_lgbm},
        "predictions": predictions,
        "model_file": {
            "path": model_file.relative_to(root).as_posix()
            if model_file.is_relative_to(root)
            else model_file.name,
            "sha256": file_sha256(model_file),
            "bytes": model_file.stat().st_size,
        },
        "environment": {
            "python": platform.python_version(),
            "lightgbm": lightgbm.__version__,
            "optuna": optuna.__version__,
            "scikit-learn": sklearn.__version__,
            "numpy": np.__version__,
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "threads": args.jobs,
            "numerics": numerics.describe(),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "trained_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "seconds": round(time.monotonic() - started, 1),
    }
    text = json.dumps(record, indent=1, default=float) + "\n"
    if args.sample:
        (out / "rank.json").write_text(text, encoding="utf-8")
    else:
        (root / "results" / "models" / "rank.json").write_text(text, encoding="utf-8")
        part = manifest_part(record, str(sets_record["lake_cut"])[:10])
        (root / "results" / "parts" / "rank.json").write_text(
            json.dumps(part, indent=1) + "\n", encoding="utf-8"
        )
    print(
        f"rank: LightGBM {trials} trials, {lgbm.trees} trees, development average precision "
        f"{dev_lgbm['average_precision']:.4f} against the floor's {floor.dev['average_precision']:.4f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
