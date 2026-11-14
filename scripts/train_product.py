"""Fit the affected product models of Phase 2 and measure them on development.

    uv run python scripts/train_product.py [--sets data/sets] [--bronze data/bronze] [--out data/models/product]
    uv run python scripts/train_product.py --sample 2000                  # a smoke run, nothing committed

Checks the set files it reads against results/models/sets.json, builds the vendor and product pairs
of the CPE dictionary from bronze cpe_names (restored from a lake release with restore_release.py
--table cpe_names, whose note it copies into the record), runs the string floor and the embedding
retrieval of unscheduled_models.product for development, test and shadow, chooses the floor's
threshold by F1 at 1 on development, and measures recall and hit rate at 1, 5 and 10 on development.
Test gets the ranked candidates for every CVE and is judged once by scripts/score_test.py; shadow
gets them for the batch the API serves, with no accuracy claim. Writes the
candidates to --out (never committed) and commits results/models/product.json and the manifest part
results/parts/product.json. Runs in the models workflow as the product step.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
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

import numpy as np
import polars as pl
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import embed, product, sets

from scripts.train_floors import file_sha256, models_stage_hash, plan_seed, verify_sets

ORIGIN = "scripts/train_product.py"
# Shadow gets candidates too: the batch serves its five most likely products for every CVE of the
# development, test and shadow windows (scripts/predict_serving.py), and shadow has no label here.
SPLITS = ("development", "test", "shadow")
READ = (
    *(sets.inputs_name(s) for s in SPLITS),
    *(sets.product_inputs_name(s) for s in SPLITS),
    sets.product_labels_name("development"),
)

_FLOOR: product.Floor | None = None


def _floor_chunk(rows: list[tuple[Any, np.datetime64]]) -> list[list[tuple[str, float]]]:
    assert _FLOOR is not None
    return [_FLOOR.candidates(pairs, t0) for pairs, t0 in rows]


def floor_candidates(
    floor: product.Floor, frame: pl.DataFrame, workers: int
) -> list[list[tuple[str, float]]]:
    """The floor's candidates for every row, in row order, on forked worker processes."""
    global _FLOOR
    _FLOOR = floor
    rows = list(zip(frame.get_column("filer_pairs").to_list(), product.day0(frame), strict=True))
    chunks = [rows[i : i + 500] for i in range(0, len(rows), 500)]
    if workers <= 1:
        return [c for chunk in chunks for c in _floor_chunk(chunk)]
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        return [c for part in pool.map(_floor_chunk, chunks) for c in part]


def load(folder: Path, sample: int | None, seed: int) -> dict[str, pl.DataFrame]:
    frames = {}
    for split in SPLITS:
        inputs = pl.read_parquet(folder / sets.inputs_name(split)).select("cve_id", "published", "text")
        frame = inputs.join(
            pl.read_parquet(folder / sets.product_inputs_name(split)).drop("split"), on="cve_id"
        )
        if split == "development":
            frame = frame.join(
                sets.load_product_labels(folder, "development").select("cve_id", "nvd_products"), on="cve_id"
            )
        if sample is not None:
            frame = frame.sample(n=min(sample, frame.height), seed=seed)
        frames[split] = frame.sort("cve_id")
    return frames


def query_vectors(
    embedder: embed.Embedder, frame: pl.DataFrame, split: str, cached: Path | None
) -> tuple[np.ndarray, str]:
    """The joined text's embeddings, read from the fallback's file when it holds the same rows."""
    ids = frame.get_column("cve_id").to_numpy().astype(str)
    if cached is not None and (cached / f"{split}_embeddings.npz").exists():
        kept = np.load(cached / f"{split}_embeddings.npz")
        index = {cve: i for i, cve in enumerate(kept["cve_id"].astype(str))}
        if all(cve in index for cve in ids):
            return kept["vectors"][[index[c] for c in ids]].astype(np.float32), "the fallback's embeddings"
    texts = [str(t) for t in frame.get_column("text").fill_null("").to_list()]
    return embedder.embed(texts, log=print), "embedded here"


def candidates_frame(frame: pl.DataFrame, floor: list[Any], retrieval: list[Any]) -> pl.DataFrame:
    def keys(ranked: list[list[tuple[str, float]]]) -> list[list[str]]:
        return [[k for k, _ in r] for r in ranked]

    def scores(ranked: list[list[tuple[str, float]]]) -> list[list[float]]:
        return [[float(s) for _, s in r] for r in ranked]

    return pl.DataFrame(
        {
            "cve_id": frame.get_column("cve_id"),
            "floor_keys": keys(floor),
            "floor_scores": scores(floor),
            "retrieval_keys": keys(retrieval),
            "retrieval_scores": scores(retrieval),
        },
        schema={
            "cve_id": pl.String,
            "floor_keys": pl.List(pl.String),
            "floor_scores": pl.List(pl.Float32),
            "retrieval_keys": pl.List(pl.String),
            "retrieval_scores": pl.List(pl.Float32),
        },
    )


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    dev = "development window CVEs with a vulnerable product in their NVD configurations"
    for model, name in (
        ("floor", "the string floor"),
        ("floor_at_threshold", "the string floor at its threshold"),
        ("retrieval", "the retrieval"),
    ):
        for k in product.KS:
            m.value(
                f"models.product.{model}.dev_recall_at_{k}",
                float(record["dev"][model][f"recall_at_{k}"]),
                "pct1",
                origin=ORIGIN,
                population=f"{dev}: {name}, share of a CVE's pairs among the first {k}",
                source="models",
            )
    m.value(
        "models.product.dictionary_pairs",
        int(record["dictionary"]["pairs"]),
        "int",
        origin=ORIGIN,
        population="the vendor and product pairs of the NVD CPE dictionary",
        source="models",
    )
    m.value(
        "models.product.floor.threshold",
        int(record["floor"]["threshold"]),
        "int",
        origin=ORIGIN,
        population="the token set ratio the string floor chose on development by F1 at 1",
        source="models",
    )
    m.value(
        "models.product.dev_cves",
        int(record["dev"]["retrieval"]["cves"]),
        "int",
        origin=ORIGIN,
        population=dev,
        source="models",
    )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--bronze", type=Path, default=root / "data" / "bronze")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--weights", type=Path, default=root / "data" / "models" / "weights")
    parser.add_argument(
        "--embeddings", type=Path, default=None, help="the fallback's folder of text embeddings"
    )
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--sample", type=int, default=None, help="rows per window, for a smoke run")
    args = parser.parse_args(argv)
    started = time.monotonic()
    out = args.out or root / "data" / "models" / ("product-sample" if args.sample else "product")
    out.mkdir(parents=True, exist_ok=True)
    seed = plan_seed(root)
    stage = models_stage_hash(root)
    digests = verify_sets(root, args.sets, READ)
    note_path = args.bronze / "cpe_names.release.json"
    release = json.loads(note_path.read_text(encoding="utf-8")) if note_path.exists() else None
    if release is None and not args.sample:
        raise SystemExit(
            "product: bronze cpe_names has no release note; restore it with restore_release.py --table"
        )
    frames = load(args.sets, args.sample, seed)
    pairs = product.dictionary(args.bronze)
    dictionary_file = out / "dictionary.parquet"
    pairs.write_parquet(dictionary_file, compression="zstd", statistics=True)
    floor = product.Floor(pairs)
    t = time.monotonic()
    floors = {split: floor_candidates(floor, frame, args.jobs) for split, frame in frames.items()}
    floor_seconds = round(time.monotonic() - t, 1)
    print(f"product: floor candidates in {floor_seconds:.0f}s")
    files = embed.fetch(root, args.weights)
    embedder = embed.Embedder(files, threads=args.jobs)
    t = time.monotonic()
    names = embedder.embed(pairs.get_column("words").to_list(), log=print)
    retrieval = product.Retrieval(
        pairs.get_column("key").to_list(),
        names,
        pairs.get_column("first_created").dt.replace_time_zone(None).to_numpy(),
    )
    retrieved, sources = {}, {}
    for split, frame in frames.items():
        vectors, sources[split] = query_vectors(embedder, frame, split, args.embeddings)
        retrieved[split] = retrieval.candidates(vectors, product.day0(frame))
    retrieval_seconds = round(time.monotonic() - t, 1)
    labels = frames["development"].get_column("nvd_products").to_list()
    threshold, threshold_search = product.choose_threshold(floors["development"], labels, log=print)
    dev = {
        "floor": product.recall(floors["development"], labels),
        "floor_at_threshold": product.recall(product.at_threshold(floors["development"], threshold), labels),
        "retrieval": product.recall(retrieved["development"], labels),
    }
    predictions: dict[str, Any] = {}
    for split, frame in frames.items():
        table = candidates_frame(frame, floors[split], retrieved[split])
        path = out / f"{split}_candidates.parquet"
        table.write_parquet(path, compression="zstd", statistics=True)
        predictions[split] = {"rows": table.height, "content_digest": sets.content_digest(path)}
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    model_id, revision = embed.pinned(root)
    first = pairs.get_column("first_created")
    record: dict[str, Any] = {
        "plan": "evaluation/phase2_plan.yaml",
        "models_stage_hash": stage,
        "sample": args.sample,
        "sets": digests,
        "lake_release": sets_record.get("lake_release"),
        "cpe_release": release,
        "dictionary": {
            "pairs": pairs.height,
            "names": int(pairs.get_column("names").sum()),
            "vendors": int(pairs.get_column("vendor").n_unique()),
            "all_deprecated_pairs": int(pairs.get_column("all_deprecated").sum()),
            "first_created": str(first.min()),
            "last_created": str(first.max()),
            "content_digest": sets.content_digest(dictionary_file),
            "rule": "a CVE is offered only the pairs the NVD had created a name for by the end of its publication day",
        },
        "floor": {
            "normalize": "lower case, the CPE quoting undone, punctuation to spaces, trailing company suffixes dropped",
            "suffixes": sorted(product.SUFFIXES),
            "vendor_neighbours": product.VENDOR_NEIGHBOURS,
            "threshold": threshold,
            "threshold_search": threshold_search,
            "seconds": floor_seconds,
        },
        "retrieval": {
            "embedding": {"id": model_id, "revision": revision},
            "queries": sources,
            "pool": product.POOL,
            "seconds": retrieval_seconds,
        },
        "dev": dev,
        "metric": "recall at k: per CVE with a label, the share of its pairs among the first k, averaged; "
        "hit at k: the share of those CVEs with any of its pairs among the first k",
        "predictions": predictions,
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
            "threads": args.jobs,
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "trained_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "seconds": round(time.monotonic() - started, 1),
        "weights_sha256": {name: file_sha256(path) for name, path in files.items()},
    }
    text = json.dumps(record, indent=1, default=str) + "\n"
    if args.sample:
        (out / "product.json").write_text(text, encoding="utf-8")
    else:
        (root / "results" / "models" / "product.json").write_text(text, encoding="utf-8")
        part = manifest_part(record, str(sets_record["lake_cut"])[:10])
        (root / "results" / "parts" / "product.json").write_text(
            json.dumps(part, indent=1) + "\n", encoding="utf-8"
        )
    print(
        f"product: floor recall at 1 {dev['floor']['recall_at_1']:.3f}, retrieval recall at 1 "
        f"{dev['retrieval']['recall_at_1']:.3f} on {dev['retrieval']['cves']} development CVEs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
