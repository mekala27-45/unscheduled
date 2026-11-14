"""Measure what serving the predictions costs, for ADR 0008.

    uv run python scripts/measure_serving.py [--runs 5] [--warm 50]

Builds the API's virtual environment the way Dockerfile.vercel does (uv sync --frozen --no-dev
--package unscheduled-api) in a temporary folder and measures it, measures the files the image
copies for POST /v1/predict, then starts a fresh Python from that environment --runs times, each
loading the two ONNX sessions and the floor's spec and answering one prediction, and times --warm
predictions in the last of them. The embedding weights the text model would need on a request are
measured from the cache the fallback step reads, when it is on this machine. Writes
results/models/serving.json and the manifest part results/parts/serving.json. It times this machine,
which the record names; the live check times the deployed API.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.manifest import ManifestBuilder

ORIGIN = "scripts/measure_serving.py"
# What /v1/predict reads from models/serving; predictions.parquet travels in the bundle instead.
PREDICT_FILES = (
    "band_floor.onnx",
    "band_floor.json.gz",
    "exploit_lgbm.onnx",
    "exploit_day0.json",
    "serving.json",
)
# The pinned embedding model and tokenizer, where the fallback and product steps keep them.
EMBEDDING = Path("data") / "models" / "weights"

PROBE = r"""
import json, sys, time
started = time.perf_counter()
from datetime import UTC, datetime
from pathlib import Path
from unscheduled_api.schemas import PredictRequest
from unscheduled_api.scoring import Scorer
imported = time.perf_counter()
scorer = Scorer(Path(sys.argv[1]))
scorer._load()
loaded = time.perf_counter()
body = PredictRequest(
    description="A crafted request to the upload handler of the web console allows an unauthenticated attacker to run commands as the service account.",
    filer="example",
    filer_type="vendor",
    cvss31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwes=["CWE-78"],
    vendor="example",
    product="console",
)
now = datetime.now(UTC)
scorer.score(body, now)
first = time.perf_counter()
warm = []
for _ in range(int(sys.argv[2])):
    t = time.perf_counter()
    scorer.score(body, now)
    warm.append((time.perf_counter() - t) * 1000)
print(json.dumps({
    "import_ms": (imported - started) * 1000,
    "load_ms": (loaded - imported) * 1000,
    "first_ms": (first - loaded) * 1000,
    "warm_ms": warm,
}))
"""


def folder_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def build_environment(root: Path, target: Path) -> float:
    env = {
        **os.environ,
        "UV_PROJECT_ENVIRONMENT": str(target),
        "UV_LINK_MODE": "copy",
        "UV_COMPILE_BYTECODE": "1",
    }
    subprocess.run(
        ["uv", "sync", "--frozen", "--no-dev", "--package", "unscheduled-api", "--quiet"],
        cwd=root,
        env=env,
        check=True,
    )
    return folder_bytes(target) / 1e6


def time_requests(root: Path, python: Path, runs: int, warm: int) -> list[dict[str, Any]]:
    out = []
    for i in range(runs):
        done = subprocess.run(
            [str(python), "-c", PROBE, str(root), str(warm if i == runs - 1 else 0)],
            cwd=root,
            env={**os.environ, "UNSCHED_ROOT": str(root)},
            capture_output=True,
            text=True,
            check=True,
        )
        out.append(json.loads(done.stdout.strip().splitlines()[-1]))
    return out


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    machine = f"{record['machine']['cpus']} CPUs, {record['machine']['system']}"
    for key, value, fmt, population in (
        (
            "environment_megabytes",
            record["environment_megabytes"],
            "float1",
            "the API's virtual environment as Dockerfile.vercel builds it",
        ),
        (
            "predict_megabytes",
            record["predict_megabytes"],
            "float1",
            "the files POST /v1/predict reads from models/serving",
        ),
        (
            "load_ms",
            record["load_ms_median"],
            "int",
            f"loading the two ONNX sessions and the floor's spec in a fresh process, median of {record['runs']}, on {machine}",
        ),
        (
            "first_ms",
            record["first_ms_median"],
            "int",
            f"the first prediction after loading, median of {record['runs']}, on {machine}",
        ),
        (
            "warm_p50_ms",
            record["warm_ms_p50"],
            "float1",
            f"{record['warm']} warm predictions in one process, the median, on {machine}",
        ),
    ):
        m.value(f"models.serving.{key}", value, fmt, origin=ORIGIN, population=population, source="models")
    if record.get("embedding_megabytes") is not None:
        m.value(
            "models.serving.embedding_megabytes",
            record["embedding_megabytes"],
            "float1",
            origin=ORIGIN,
            population="the pinned embedding model and tokenizer the text model would need on a request",
            source="models",
        )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warm", type=int, default=50)
    args = parser.parse_args(argv)
    serving = root / "models" / "serving"
    missing = [name for name in PREDICT_FILES if not (serving / name).exists()]
    if missing:
        raise SystemExit(
            f"serving: models/serving lacks {missing}; run export_onnx.py and predict_serving.py first"
        )
    scratch = Path(tempfile.mkdtemp(prefix="unscheduled-env-"))
    try:
        environment = build_environment(root, scratch / ".venv")
        timings = time_requests(root, scratch / ".venv" / "bin" / "python", args.runs, args.warm)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    warm = timings[-1]["warm_ms"]
    embedding = root / EMBEDDING
    record = {
        "machine": {
            "system": platform.platform(),
            "cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "environment_megabytes": round(environment, 1),
        "predict_megabytes": round(sum((serving / n).stat().st_size for n in PREDICT_FILES) / 1e6, 1),
        "embedding_megabytes": round(folder_bytes(embedding) / 1e6, 1) if embedding.exists() else None,
        "runs": args.runs,
        "warm": args.warm,
        "import_ms_median": round(statistics.median(t["import_ms"] for t in timings)),
        "load_ms_median": round(statistics.median(t["load_ms"] for t in timings)),
        "first_ms_median": round(statistics.median(t["first_ms"] for t in timings)),
        "warm_ms_p50": round(statistics.median(warm), 1) if warm else None,
        "timings": timings,
    }
    (root / "results" / "models" / "serving.json").write_text(
        json.dumps(record, indent=1) + "\n", encoding="utf-8"
    )
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(record, str(sets_record["lake_cut"])[:10])
    (root / "results" / "parts" / "serving.json").write_text(
        json.dumps(part, indent=1) + "\n", encoding="utf-8"
    )
    print(
        f"serving: environment {record['environment_megabytes']} MB, predict files {record['predict_megabytes']} MB, "
        f"load {record['load_ms_median']} ms, first {record['first_ms_median']} ms, warm {record['warm_ms_p50']} ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
