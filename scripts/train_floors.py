"""Fit the fill floors of Phase 2 on the point in time sets and choose them on development.

    uv run python scripts/train_floors.py [--sets data/sets] [--out data/models/floors] [--jobs N] [--heavy N]
    uv run python scripts/train_floors.py --sample 4000      # a smoke run on a sample, nothing committed

Checks every set file it reads against the content digest in results/models/sets.json, so the floors
are fit on the committed sets and no other; takes the seed from evaluation/phase2_plan.yaml; runs the
search of unscheduled_models.floors; writes the models and the development, test and shadow
probabilities to --out (never committed); and commits what describes them, results/models/floors.json
and the manifest part results/parts/floors.json. The test labels are not read. The full search runs in
GitHub Actions (.github/workflows/models.yml), on a runner with the memory the character grams need.
"""

from __future__ import annotations

import argparse
import hashlib
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
import numpy as np
import polars as pl
import scipy
import sklearn
import yaml
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import floors, sets

ORIGIN = "scripts/train_floors.py"
READ = (
    *(sets.inputs_name(s) for s in sets.SPLITS),
    sets.labels_name("train"),
    sets.labels_name("development"),
)
METRIC_NAMES = {"qwk": "quadratic weighted kappa", "kappa": "Cohen kappa", "macro_f1": "macro F1"}
TASK_NAMES = {
    "band": "Severity band",
    "metric_AV": "Attack vector",
    "metric_AC": "Attack complexity",
    "metric_PR": "Privileges required",
    "metric_UI": "User interaction",
    "metric_S": "Scope",
    "metric_C": "Confidentiality",
    "metric_I": "Integrity",
    "metric_A": "Availability",
    "cwe": "Weakness (CWE)",
}


def plan_seed(root: Path) -> int:
    plan = yaml.safe_load((root / "evaluation" / "phase2_plan.yaml").read_text(encoding="utf-8"))
    return int(plan["defaults"]["seed"])


def models_stage_hash(root: Path) -> str:
    record = json.loads((root / "evaluation" / "registration.json").read_text(encoding="utf-8"))
    stage = next((s for s in record["stages"] if s["stage"] == "models"), None)
    if stage is None:
        raise SystemExit("the models stage is not registered: register the Phase 2 plan before any model")
    return str(stage["hash"])


def verify_sets(root: Path, folder: Path) -> dict[str, str]:
    """The content digest of every set file the floors read, checked against the committed record."""
    committed = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))["files"]
    digests: dict[str, str] = {}
    for name in READ:
        digest = sets.content_digest(folder / name)
        if digest != committed[name]["content_digest"]:
            raise SystemExit(
                f"{name} differs from results/models/sets.json: rebuild the sets (scripts/build_sets.py) "
                "from the lake release the record names"
            )
        digests[name] = digest
    return digests


def load(folder: Path, sample: int | None, seed: int) -> dict[str, pl.DataFrame]:
    def inputs(split: str) -> pl.DataFrame:
        return pl.read_parquet(folder / sets.inputs_name(split))

    frames = {
        "train": inputs("train").join(sets.load_labels(folder, "train"), on=["cve_id", "split"]),
        "development": inputs("development").join(
            sets.load_labels(folder, "development"), on=["cve_id", "split"]
        ),
        "test": inputs("test"),
        "shadow": inputs("shadow"),
    }
    if sample is not None:
        frames = {k: f.sample(n=min(sample, f.height), seed=seed).sort("cve_id") for k, f in frames.items()}
    return frames


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    dev_population = "development window CVEs with the label"
    chosen = record["chosen"]
    m.value(
        "models.floors.representation",
        floors.VARIANT_NAMES[record["representation"]["chosen"]],
        "text",
        origin=ORIGIN,
        population="the text representation the band floor chose on development",
        source="models",
    )
    for task, entry in chosen.items():
        m.value(
            f"models.floors.{task}.dev",
            float(entry["dev"][entry["metric"]]),
            "float3",
            origin=ORIGIN,
            population=f"{dev_population}: {TASK_NAMES[task]}, {METRIC_NAMES[entry['metric']]}",
            source="models",
        )
        m.value(
            f"models.floors.{task}.C",
            f"{entry['C']:g}",
            "text",
            origin=ORIGIN,
            population=f"the regularization the {TASK_NAMES[task]} floor chose on development",
            source="models",
        )
        m.value(
            f"models.floors.{task}.dev_rows",
            int(entry["dev_rows"]),
            "int",
            origin=ORIGIN,
            population=f"{dev_population}: {TASK_NAMES[task]}",
            source="models",
        )
    m.value(
        "models.floors.band.dev_accuracy",
        float(chosen["band"]["dev"]["accuracy"]),
        "pct1",
        origin=ORIGIN,
        population=f"{dev_population}: the severity band, share predicted exactly",
        source="models",
    )
    for key in [k for k in ("accuracy", "top5_accuracy") if k in chosen["cwe"]["dev"]]:
        m.value(
            f"models.floors.cwe.dev_{key}",
            float(chosen["cwe"]["dev"][key]),
            "pct1",
            origin=ORIGIN,
            population=f"{dev_population}: the CWE, share with the label first"
            + (" or in the first five" if key == "top5_accuracy" else ""),
            source="models",
        )
    metric_tasks = [t for t in chosen if t.startswith("metric_")]
    m.value(
        "models.floors.metrics.mean_kappa",
        float(np.mean([chosen[t]["dev"]["kappa"] for t in metric_tasks])),
        "float3",
        origin=ORIGIN,
        population=f"{dev_population}: the mean Cohen kappa of the eight base metric floors",
        source="models",
    )
    ref = record["reference"]
    for key, value, fmt, population in (
        ("filer_rows", ref["with_filer_band"]["rows"], "int", "with an NVD band and a filer band at day 0"),
        (
            "filer_qwk",
            ref["with_filer_band"]["filer_qwk"],
            "float3",
            "with both bands: the filer band against the NVD band",
        ),
        (
            "floor_qwk_with_filer",
            ref["with_filer_band"]["floor_qwk"],
            "float3",
            "with both bands: the band floor against the NVD band",
        ),
        (
            "without_rows",
            ref["without_filer_band"]["rows"],
            "int",
            "with an NVD band and no filer band at day 0",
        ),
        (
            "floor_qwk_without_filer",
            ref["without_filer_band"]["floor_qwk"],
            "float3",
            "with no filer band: the band floor against the NVD band",
        ),
    ):
        m.value(
            f"models.floors.reference.{key}",
            value,
            fmt,
            origin=ORIGIN,
            population=f"development window CVEs {population}",
            source="models",
        )
    m.table(
        "models.floors.chosen",
        ["Task", "Chosen by", "C", "Development score", "Train rows", "Development rows"],
        ["text", "text", "text", "float3", "int", "int"],
        [
            [
                TASK_NAMES[task],
                METRIC_NAMES[entry["metric"]],
                f"{entry['C']:g}",
                float(entry["dev"][entry["metric"]]),
                int(entry["train_rows"]),
                int(entry["dev_rows"]),
            ]
            for task, entry in chosen.items()
        ],
        origin=ORIGIN,
        population=dev_population,
        source="models",
    )
    m.table(
        "models.floors.band_search",
        ["Text", "C", "Development kappa"],
        ["text", "text", "float3"],
        [
            [floors.VARIANT_NAMES[row["variant"]], f"{row['C']:g}", float(row["qwk"])]
            for row in record["search"]
            if row["task"] == "band"
        ],
        origin=ORIGIN,
        population="development window CVEs with an NVD band: the band floor grid",
        source="models",
    )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--heavy", type=int, default=None, help="CWE fits at once (default half the jobs)")
    parser.add_argument("--sample", type=int, default=None, help="rows per window, for a smoke run")
    args = parser.parse_args(argv)
    started = time.monotonic()
    out = args.out or root / "data" / "models" / ("floors-sample" if args.sample else "floors")
    heavy = args.heavy or max(1, args.jobs // 2)
    seed = plan_seed(root)
    stage = models_stage_hash(root)
    digests = verify_sets(root, args.sets)
    frames = load(args.sets, args.sample, seed)
    print(
        f"floors: train {frames['train'].height}, development {frames['development'].height} rows, "
        f"{args.jobs} threads, {heavy} CWE fits at once"
    )
    result = floors.search(frames["train"], frames["development"], seed=seed, workers=args.jobs, heavy=heavy)
    out.mkdir(parents=True, exist_ok=True)
    predictions: dict[str, Any] = {}
    dev_proba: pl.DataFrame | None = None
    for split in ("development", "test", "shadow"):
        proba = floors.probabilities(result.features, result.models, frames[split])
        path = out / f"{split}_probabilities.parquet"
        proba.write_parquet(path, compression="zstd", statistics=True)
        predictions[split] = {"rows": proba.height, "content_digest": sets.content_digest(path)}
        if split == "development":
            dev_proba = proba
    assert dev_proba is not None
    model_file = out / "floors.joblib"
    joblib.dump(
        {"features": result.features, "models": result.models, "record": result.record},
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
        "lake_content_digest": sets_record.get("lake_content_digest"),
        **result.record,
        "reference": floors.reference(frames["development"], dev_proba),
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
            "scikit-learn": sklearn.__version__,
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "threads": args.jobs,
            "cwe_fits_at_once": heavy,
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "trained_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "seconds": round(time.monotonic() - started, 1),
    }
    text = json.dumps(record, indent=1) + "\n"
    if args.sample:
        (out / "floors.json").write_text(text, encoding="utf-8")
    else:
        target = root / "results" / "models" / "floors.json"
        target.write_text(text, encoding="utf-8")
        part = manifest_part(record, str(sets_record["lake_cut"])[:10])
        (root / "results" / "parts" / "floors.json").write_text(
            json.dumps(part, indent=1) + "\n", encoding="utf-8"
        )
    band = record["chosen"]["band"]
    print(
        f"floors: {floors.VARIANT_NAMES[record['representation']['chosen']]}, band C={band['C']:g}, "
        f"development kappa {band['dev']['qwk']:.4f}, in {record['seconds']:.0f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
