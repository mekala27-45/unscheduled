"""Fit the CPU fallback for ModernBERT: frozen embeddings with a logistic head per fill task.

    uv run python scripts/train_fallback.py [--sets data/sets] [--out data/models/fallback] [--jobs N]
    uv run python scripts/train_fallback.py --sample 3000            # a smoke run, nothing committed

The plan runs ModernBERT on a Kaggle GPU at step eight and names this fallback for when the Kaggle
secrets are absent (evaluation/phase2_plan.yaml, fallback_text): the joined text of every set row is
embedded with the pinned weights of config/models.yaml (embedding), and each fill task gets a
logistic regression on those embeddings, its C chosen on development by the metric of its floor.
Checks the set files it reads against results/models/sets.json; writes the embeddings, the heads and
the development, test and shadow probabilities to --out (never committed) and commits
results/models/fallback.json and the manifest part results/parts/fallback.json. The test labels are
not read. Runs in the models workflow as the fallback step.
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
import numpy as np
import polars as pl
import sklearn
from sklearn.linear_model import LogisticRegression
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import embed, floors, sets

from scripts.train_floors import (
    METRIC_NAMES,
    TASK_NAMES,
    file_sha256,
    load,
    models_stage_hash,
    plan_seed,
    verify_sets,
)

ORIGIN = "scripts/train_fallback.py"
MODEL_NAME = "frozen BAAI/bge-small-en-v1.5 embeddings with a logistic head per task"
CHOICES_C = floors.CHOICES_C


def embeddings(embedder: embed.Embedder, frames: dict[str, pl.DataFrame], out: Path) -> dict[str, np.ndarray]:
    """The embedding of every row's joined text, per window, kept in --out as float16 so a later
    step can read them again; a window already embedded with the same rows is read back."""
    vectors: dict[str, np.ndarray] = {}
    for split, frame in frames.items():
        path = out / f"{split}_embeddings.npz"
        ids = frame.get_column("cve_id").to_numpy().astype(str)
        if path.exists():
            kept = np.load(path)
            if np.array_equal(kept["cve_id"], ids):
                vectors[split] = kept["vectors"].astype(np.float32)
                continue
        texts = [str(t) for t in frame.get_column("text").fill_null("").to_list()]
        started = time.monotonic()
        matrix = embedder.embed(texts, log=print)
        print(f"fallback: {split}, {len(texts)} texts in {time.monotonic() - started:.0f}s")
        np.savez(path, cve_id=ids, vectors=matrix.astype(np.float16))
        vectors[split] = matrix.astype(np.float16).astype(np.float32)
    return vectors


def head(x: np.ndarray, y: list[str], c: float, seed: int) -> LogisticRegression:
    model = LogisticRegression(C=c, max_iter=2000, random_state=seed)
    model.fit(x, np.asarray(y))
    return model


def evaluate(model: LogisticRegression, x: np.ndarray, y: list[str], metric: str) -> dict[str, float]:
    proba = model.predict_proba(x)
    guess = [str(v) for v in model.classes_[np.argmax(proba, axis=1)]]
    out = {metric: floors.score(metric, y, guess), "macro_f1": floors.score("macro_f1", y, guess)}
    out["accuracy"] = float(np.mean([a == b for a, b in zip(y, guess, strict=True)]))
    if len(model.classes_) > 5:
        top5 = np.argsort(-proba, axis=1)[:, :5]
        classes = [str(v) for v in model.classes_]
        out["top5_accuracy"] = float(np.mean([y[i] in {classes[j] for j in top5[i]} for i in range(len(y))]))
    return out


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    m.value(
        "models.fallback.name",
        MODEL_NAME,
        "text",
        origin=ORIGIN,
        population="the deep fill model this phase ran: ModernBERT waits for the Kaggle secrets",
        source="models",
    )
    for task, entry in record["chosen"].items():
        m.value(
            f"models.fallback.{task}.dev",
            float(entry["dev"][entry["metric"]]),
            "float3",
            origin=ORIGIN,
            population=f"development window CVEs with the label: {TASK_NAMES[task]}, {METRIC_NAMES[entry['metric']]}",
            source="models",
        )
    m.table(
        "models.fallback.chosen",
        ["Task", "Chosen by", "C", "Development score"],
        ["text", "text", "text", "float3"],
        [
            [TASK_NAMES[t], METRIC_NAMES[e["metric"]], f"{e['C']:g}", float(e["dev"][e["metric"]])]
            for t, e in record["chosen"].items()
        ],
        origin=ORIGIN,
        population="development window CVEs with the label",
        source="models",
    )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--weights", type=Path, default=root / "data" / "models" / "weights")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--sample", type=int, default=None, help="rows per window, for a smoke run")
    args = parser.parse_args(argv)
    started = time.monotonic()
    out = args.out or root / "data" / "models" / ("fallback-sample" if args.sample else "fallback")
    out.mkdir(parents=True, exist_ok=True)
    seed = plan_seed(root)
    stage = models_stage_hash(root)
    digests = verify_sets(root, args.sets)
    frames = load(args.sets, args.sample, seed)
    files = embed.fetch(root, args.weights)
    embedder = embed.Embedder(files, threads=args.jobs)
    t0 = time.monotonic()
    vectors = embeddings(embedder, frames, out)
    embed_seconds = round(time.monotonic() - t0, 1)
    train, dev = frames["train"], frames["development"]
    search: list[dict[str, Any]] = []
    chosen: dict[str, Any] = {}
    models: dict[str, LogisticRegression] = {}
    for task in floors.TASKS:
        rows, dev_rows = floors.labelled(train, task.label), floors.labelled(dev, task.label)
        y, y_dev = floors.labels_at(train, task.label, rows), floors.labels_at(dev, task.label, dev_rows)
        best: tuple[float, float, LogisticRegression, dict[str, float]] | None = None
        for c in CHOICES_C:
            t = time.monotonic()
            model = head(vectors["train"][rows], y, c, seed)
            result = evaluate(model, vectors["development"][dev_rows], y_dev, task.metric)
            search.append(
                {
                    "task": task.name,
                    "C": c,
                    **{k: round(v, 6) for k, v in result.items()},
                    "seconds": round(time.monotonic() - t, 1),
                }
            )
            print(f"fallback: {task.name} C={c} dev {task.metric} {result[task.metric]:.4f}")
            if best is None or result[task.metric] > best[0]:
                best = (result[task.metric], c, model, result)
        assert best is not None
        models[task.name] = best[2]
        chosen[task.name] = {
            "label": task.label,
            "metric": task.metric,
            "C": best[1],
            "at_grid_edge": best[1] in (min(CHOICES_C), max(CHOICES_C)),
            "classes": [str(v) for v in best[2].classes_],
            "train_rows": len(rows),
            "dev_rows": len(dev_rows),
            "dev": {k: round(v, 6) for k, v in best[3].items()},
        }
    predictions: dict[str, Any] = {}
    for split in ("development", "test", "shadow"):
        columns: dict[str, Any] = {"cve_id": frames[split].get_column("cve_id")}
        for name, model in models.items():
            proba = model.predict_proba(vectors[split]).astype(np.float32)
            for j, cls in enumerate(model.classes_):
                columns[f"{name}__{cls}"] = proba[:, j]
        table = pl.DataFrame(columns)
        path = out / f"{split}_probabilities.parquet"
        table.write_parquet(path, compression="zstd", statistics=True)
        predictions[split] = {"rows": table.height, "content_digest": sets.content_digest(path)}
    model_file = out / "fallback.joblib"
    joblib.dump({"heads": models}, model_file, compress=3)
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    model_id, revision = embed.pinned(root)
    record: dict[str, Any] = {
        "plan": "evaluation/phase2_plan.yaml",
        "models_stage_hash": stage,
        "sample": args.sample,
        "model": MODEL_NAME,
        "why": "the Kaggle secrets were absent at step eight (results/probe.json, phase2.kaggle)",
        "embedding": {
            "id": model_id,
            "revision": revision,
            "file_sha256": {name: file_sha256(path) for name, path in files.items()},
            "max_tokens": embed.MAX_TOKENS,
            "pooling": "the first token, scaled to unit length",
            "seconds": embed_seconds,
        },
        "sets": digests,
        "lake_release": sets_record.get("lake_release"),
        "seed": seed,
        "grid": {"C": list(CHOICES_C)},
        "search": search,
        "chosen": chosen,
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
            "onnxruntime": embed.runtime_version(),
            "scikit-learn": sklearn.__version__,
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
    text = json.dumps(record, indent=1) + "\n"
    if args.sample:
        (out / "fallback.json").write_text(text, encoding="utf-8")
    else:
        (root / "results" / "models" / "fallback.json").write_text(text, encoding="utf-8")
        part = manifest_part(record, str(sets_record["lake_cut"])[:10])
        (root / "results" / "parts" / "fallback.json").write_text(
            json.dumps(part, indent=1) + "\n", encoding="utf-8"
        )
    band = chosen["band"]
    print(
        f"fallback: band C={band['C']:g}, development kappa {band['dev']['qwk']:.4f}, in {record['seconds']:.0f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
