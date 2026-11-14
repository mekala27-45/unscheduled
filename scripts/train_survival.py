"""Fit the time to KEV models of Phase 2 on the point in time sets, and check the Cox model in R.

    uv run python scripts/train_survival.py [--sets data/sets] [--out data/models/survival] [--r-check]
    uv run python scripts/train_survival.py --sample 8000                 # a smoke run, nothing committed

Checks the set files it reads against results/models/sets.json, takes the seed and the R tolerances
from evaluation/phase2_plan.yaml, fits the penalized Cox model and the random survival forest of
unscheduled_models.survival on the train population and chooses each on development by concordance.
With --r-check it writes the design matrix of the train population, fits it in R (R/check_cox.R)
and compares R's coefficients and concordance with lifelines' unpenalized fit; the models workflow
runs it that way, with R installed. Development, test and shadow get the probability of a listing
by 30, 90 and 180 days from both models, for every CVE, Q03 included. Writes the models and the
probabilities to --out (never committed) and commits results/models/survival.json and the manifest
part results/parts/survival.json.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import joblib
import lifelines
import numpy as np
import polars as pl
import sksurv
import yaml
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import rank, sets, survival

from scripts.train_floors import file_sha256, load, models_stage_hash, plan_seed, verify_sets

ORIGIN = "scripts/train_survival.py"


def r_tolerances(root: Path) -> tuple[float, float]:
    plan = yaml.safe_load((root / "evaluation" / "phase2_plan.yaml").read_text(encoding="utf-8"))
    text = str(plan["models"]["survival_r_check"]["tolerance"])
    found = re.search(r"within ([0-9.]+) absolute and concordance within ([0-9.]+)", text)
    if found is None:
        raise SystemExit(f"survival: the plan's R tolerance does not read as two numbers: {text!r}")
    return float(found.group(1)), float(found.group(2))


def run_r_check(out: Path, design: survival.Design, train: pl.DataFrame) -> dict[str, Any]:
    matrix = out / "r_design.csv"
    survival.r_design(design, train).to_csv(matrix, index=False, float_format="%.17g")
    result = out / "r_result.json"
    subprocess.run(["Rscript", str(ROOT / "R" / "check_cox.R"), str(matrix), str(result)], check=True)
    loaded: dict[str, Any] = json.loads(result.read_text(encoding="utf-8"))
    return loaded


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    dev = "development window CVEs published, Q03 left out"
    for key, value, fmt, population in (
        ("cox.dev_concordance", record["dev"]["cox"]["concordance"], "float3", f"{dev}: the Cox model"),
        (
            "forest.dev_concordance",
            record["dev"]["forest"]["concordance"],
            "float3",
            f"{dev}: the survival forest",
        ),
        (
            "train_events",
            record["population"]["train_events"],
            "int",
            "the train population: listings by the cut",
        ),
        ("columns", len(record["design"]["columns"]), "int", "the survival design: columns kept"),
    ):
        m.value(f"models.survival.{key}", value, fmt, origin=ORIGIN, population=population, source="models")
    m.value(
        "models.survival.cox.penalizer",
        f"{record['cox']['penalizer']:g}",
        "text",
        origin=ORIGIN,
        population="the ridge penalty the Cox model chose on development",
        source="models",
    )
    m.value(
        "models.survival.forest.min_samples_leaf",
        int(record["forest"]["min_samples_leaf"]),
        "int",
        origin=ORIGIN,
        population="the leaf size the survival forest chose on development",
        source="models",
    )
    check = record.get("r_check")
    if check:
        m.value(
            "models.survival.r_check.max_coefficient_difference",
            float(check["max_coefficient_difference"]),
            "float4",
            origin=ORIGIN,
            population="the train population: lifelines without a penalty against R's coxph on the same matrix",
            source="models",
        )
        m.value(
            "models.survival.r_check.concordance_difference",
            float(check["concordance_difference"]),
            "float4",
            origin=ORIGIN,
            population="the train population: lifelines without a penalty against R's coxph on the same matrix",
            source="models",
        )
        m.value(
            "models.survival.r_check.result",
            str(check["result"]),
            "text",
            origin=ORIGIN,
            population="the R check of the Cox model, within the plan's tolerances",
            source="models",
        )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--r-check", action="store_true", help="fit the Cox model in R too (needs Rscript)")
    parser.add_argument("--sample", type=int, default=None, help="rows per window, for a smoke run")
    args = parser.parse_args(argv)
    started = time.monotonic()
    out = args.out or root / "data" / "models" / ("survival-sample" if args.sample else "survival")
    out.mkdir(parents=True, exist_ok=True)
    seed = plan_seed(root)
    coef_tol, conc_tol = r_tolerances(root)
    stage = models_stage_hash(root)
    digests = verify_sets(root, args.sets)
    frames = load(args.sets, args.sample, seed)
    train, dev = rank.population(frames["train"]), rank.population(frames["development"])
    result = survival.search(train, dev, seed, args.jobs)
    design = result.design
    dev_x, dev_d, dev_e = design.matrix(dev), survival.duration(dev), survival.event(dev)
    dev_scores = {
        "cox": {"concordance": survival.concordance(dev_d, dev_e, survival.cox_risk(result.cox, dev_x))},
        "forest": {
            "concordance": survival.concordance(
                dev_d, dev_e, np.asarray(result.forest.predict(dev_x.to_numpy()), dtype=np.float64)
            )
        },
    }
    predictions: dict[str, Any] = {}
    for split, frame in (("development", dev), ("test", frames["test"]), ("shadow", frames["shadow"])):
        x = design.matrix(frame)
        cox = survival.cox_listing(result.cox, x)
        forest = survival.forest_listing(result.forest, x)
        columns: dict[str, Any] = {"cve_id": frame.get_column("cve_id")}
        for j, h in enumerate(survival.HORIZONS):
            columns[f"cox_listed_by_{h}"] = cox[:, j].astype(np.float32)
            columns[f"forest_listed_by_{h}"] = forest[:, j].astype(np.float32)
        table = pl.DataFrame(columns)
        path = out / f"{split}_survival.parquet"
        table.write_parquet(path, compression="zstd", statistics=True)
        predictions[split] = {"rows": table.height, "content_digest": sets.content_digest(path)}
    check = None
    if args.r_check:
        check = survival.compare_with_r(
            result.unpenalized, run_r_check(out, design, train), coef_tol, conc_tol
        )
        print(
            f"survival: R check {check['result']}, largest coefficient difference "
            f"{check['max_coefficient_difference']:.2e}, concordance difference {check['concordance_difference']:.2e}"
        )
    model_file = out / "survival.joblib"
    joblib.dump(
        {"design": design, "cox": result.cox, "forest_leaf": result.forest_leaf}, model_file, compress=3
    )
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    record: dict[str, Any] = {
        "plan": "evaluation/phase2_plan.yaml",
        "models_stage_hash": stage,
        "sample": args.sample,
        "sets": digests,
        "lake_release": sets_record.get("lake_release"),
        "seed": seed,
        "population": {
            "start": str(rank.RANK_START),
            "train_rows": train.height,
            "train_events": int(survival.event(train).sum()),
            "dev_rows": dev.height,
            "dev_events": int(dev_e.sum()),
            "time": "days from publication to the KEV listing, censored at the lake cut, plus one",
        },
        "design": {"columns": design.columns, "dropped": design.dropped, "min_events": survival.MIN_EVENTS},
        "cox": {
            "penalizer": result.cox_penalizer,
            "search": result.cox_search,
            "coefficients": {str(k): float(v) for k, v in result.cox.params_.items()},
            "unpenalized": {str(k): float(v) for k, v in result.unpenalized.params_.items()},
        },
        "forest": {
            "trees": survival.TREES,
            "min_samples_leaf": result.forest_leaf,
            "search": result.forest_search,
        },
        "dev": dev_scores,
        "horizons_days": list(survival.HORIZONS),
        "predictions": predictions,
        "r_check": check,
        "model_file": {
            "path": model_file.relative_to(root).as_posix()
            if model_file.is_relative_to(root)
            else model_file.name,
            "sha256": file_sha256(model_file),
            "bytes": model_file.stat().st_size,
            "note": "the forest is refit from the record's leaf size and the seed; its trees are too large to keep",
        },
        "environment": {
            "python": platform.python_version(),
            "lifelines": lifelines.__version__,
            "scikit-survival": sksurv.__version__,
            "numpy": np.__version__,
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "threads": args.jobs,
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "trained_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "seconds": round(time.monotonic() - started, 1),
    }
    text = json.dumps(record, indent=1, default=float) + "\n"
    if args.sample:
        (out / "survival.json").write_text(text, encoding="utf-8")
    else:
        (root / "results" / "models" / "survival.json").write_text(text, encoding="utf-8")
        part = manifest_part(record, str(sets_record["lake_cut"])[:10])
        (root / "results" / "parts" / "survival.json").write_text(
            json.dumps(part, indent=1) + "\n", encoding="utf-8"
        )
    print(
        f"survival: Cox penalizer {result.cox_penalizer:g}, concordance {dev_scores['cox']['concordance']:.4f}; "
        f"forest leaf {result.forest_leaf}, concordance {dev_scores['forest']['concordance']:.4f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
