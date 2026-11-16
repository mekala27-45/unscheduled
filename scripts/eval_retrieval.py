"""The retrieval evaluation of the Phase 3 plan on the development window (step 5).

    python scripts/eval_retrieval.py --corpus data/corpus --database-url postgresql://...

Reads the corpus that scripts/build_corpus.py wrote (checked against its manifest), embeds every chunk
and every development query with the pinned embedding model, loads them into a Postgres schema with a
text index and an HNSW index, and runs every configuration of evaluation/phase3_plan.yaml on every
development query at its day 0:

1. ef_search, the smallest of 40, 80, 160 and 320 whose HNSW recall at 10 against the exact list is
   at least 0.98;
2. the floor, BM25 where pg_search is installed, dense, exact, hybrid and rerank, each scored at the
   grain of documents with 2000 paired bootstrap resamples;
3. the choice by the plan's rule, written to config/retrieval.yaml for the agent_points stage;
4. the index comparison (HNSW against the flat index: recall, latency, bytes), and the chosen
   configuration again without the time condition, to show what leakage would add.

Writes results/retrieval/eval.json, results/retrieval/index.json, config/retrieval.yaml and
results/parts/retrieval.json. The shadow window is not read here: it is scored once, after the
agent_points stage is hashed (scripts/register.py).
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import polars as pl
import psycopg
import yaml
from unscheduled_core.hashing import sha256_file
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_retrieval import embed, metrics, search

ROOT = Path(__file__).resolve().parents[1]
EF_SEARCH = (40, 80, 160, 320)
INDEX_RECALL = 0.98
SCHEMA = "retrieval_eval"
OUT = ROOT / "results" / "retrieval"
PART = ROOT / "results" / "parts" / "retrieval.json"
FROZEN = ROOT / "config" / "retrieval.yaml"


def read_corpus(folder: Path) -> tuple[dict[str, Any], pl.DataFrame, pl.DataFrame]:
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "built":
        raise SystemExit(f"eval: the corpus in {folder} is not built ({manifest.get('status')})")
    for name, entry in manifest["files"].items():
        if sha256_file(folder / name) != entry["sha256"]:
            raise SystemExit(f"eval: {folder / name} does not match its digest in the manifest")
    return manifest, pl.read_parquet(folder / "chunks.parquet"), pl.read_parquet(folder / "queries.parquet")


def vectors(chunks: pl.DataFrame, encoder: embed.Encoder, cache: Path) -> np.ndarray:
    if cache.exists():
        stored: np.ndarray = np.load(cache)
        if stored.shape == (chunks.height, embed.DIMENSIONS):
            return stored
    out = encoder.encode(chunks.get_column("text").to_list())
    cache.parent.mkdir(parents=True, exist_ok=True)
    np.save(cache, out)
    return out


def ms(seconds: list[float]) -> dict[str, float]:
    ordered = sorted(seconds)
    p95 = ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]
    return {"p50": round(statistics.median(ordered) * 1000, 2), "p95": round(p95 * 1000, 2)}


def overlap(found: list[search.Hit], exact: list[search.Hit], k: int = 10) -> float:
    reference = {c for c, _, _ in exact[:k]}
    return len(reference & {c for c, _, _ in found[:k]}) / len(reference) if reference else 1.0


def run(args: argparse.Namespace) -> dict[str, Any]:
    manifest, chunks, queries = read_corpus(args.corpus)
    dev = queries.filter(pl.col("window") == "development").sort("cve_id")
    if dev.height == 0:
        raise SystemExit("eval: the corpus has no development queries")
    pins = embed.pins(ROOT)
    emb = embed.fetch(
        pins["embedding"]["id"],
        pins["embedding"]["revision"],
        ["tokenizer.json", pins["embedding"]["onnx"]],
        ROOT,
    )
    rer = embed.fetch(
        pins["reranker"]["id"],
        pins["reranker"]["revision"],
        ["tokenizer.json", pins["reranker"]["onnx"]],
        ROOT,
    )
    encoder = embed.Encoder(
        emb.files["tokenizer.json"], emb.files[pins["embedding"]["onnx"]], threads=args.threads
    )
    cross = embed.CrossEncoder(
        rer.files["tokenizer.json"], rer.files[pins["reranker"]["onnx"]], threads=args.threads
    )

    started = time.perf_counter()
    cache = (
        ROOT
        / "data"
        / "cache"
        / "retrieval"
        / f"vectors-{manifest['content_digest'][:16]}-{emb.revision[:12]}.npy"
    )
    chunk_vectors = vectors(chunks, encoder, cache)
    embed_s = time.perf_counter() - started
    query_vectors = encoder.encode_queries(dev.get_column("query").to_list())

    with psycopg.connect(args.database_url) as conn:
        store = search.Store(conn, SCHEMA)
        store.create()
        store.load(chunks, chunk_vectors)
        built = store.index()
        sizes = store.sizes()
        bm25 = store.bm25_available()
        server = conn.execute("show server_version").fetchone()
        pgvector = conn.execute("select extversion from pg_extension where extname = 'vector'").fetchone()
        flat = search.Flat(chunks, chunk_vectors)
        texts = dict(
            zip(chunks.get_column("chunk_id").to_list(), chunks.get_column("text").to_list(), strict=True)
        )

        rows = list(dev.iter_rows(named=True))
        floor_hits: list[list[search.Hit]] = []
        exact_hits: list[list[search.Hit]] = []
        timing: dict[str, list[float]] = {"floor": [], "exact": [], "rerank": []}
        by_ef: dict[int, list[list[search.Hit]]] = {ef: [] for ef in EF_SEARCH}
        ef_timing: dict[int, list[float]] = {ef: [] for ef in EF_SEARCH}
        for i, q in enumerate(rows):
            at = q["day0"]
            t0 = time.perf_counter()
            floor_hits.append(store.floor(q["query"], at))
            timing["floor"].append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            exact_hits.append(flat.search(query_vectors[i], at))
            timing["exact"].append(time.perf_counter() - t0)
            for ef in EF_SEARCH:
                t0 = time.perf_counter()
                by_ef[ef].append(store.dense(query_vectors[i], at, ef))
                ef_timing[ef].append(time.perf_counter() - t0)

        sweep = {
            ef: round(float(np.mean([overlap(h, e) for h, e in zip(by_ef[ef], exact_hits, strict=True)])), 4)
            for ef in EF_SEARCH
        }
        passing = [ef for ef in EF_SEARCH if sweep[ef] >= INDEX_RECALL]
        ef_search = passing[0] if passing else EF_SEARCH[-1]
        dense_hits = by_ef[ef_search]

        def ranked(name: str, floor: list[search.Hit], dense: list[search.Hit], query: str) -> list[str]:
            """The documents a configuration returns for one query, in order."""
            if name == "floor":
                return search.documents(floor)
            if name == "dense":
                return search.documents(dense)
            fused = search.rrf([search.documents(floor), search.documents(dense)])
            if name == "hybrid":
                return fused
            candidates = search.hybrid_chunks(fused, [floor, dense])
            return search.documents(
                search.rerank(candidates, texts, lambda passages: cross.score(query, passages))
            )

        docs: dict[str, list[list[str]]] = {
            name: [] for name in ("floor", "dense", "exact", "hybrid", "rerank")
        }
        for i, q in enumerate(rows):
            docs["floor"].append(ranked("floor", floor_hits[i], dense_hits[i], q["query"]))
            docs["dense"].append(ranked("dense", floor_hits[i], dense_hits[i], q["query"]))
            docs["exact"].append(search.documents(exact_hits[i]))
            docs["hybrid"].append(ranked("hybrid", floor_hits[i], dense_hits[i], q["query"]))
            t0 = time.perf_counter()
            docs["rerank"].append(ranked("rerank", floor_hits[i], dense_hits[i], q["query"]))
            timing["rerank"].append(time.perf_counter() - t0)

        scored = {
            name: [
                metrics.per_query(d, q["relevant"], q["relevant_advisories"])
                for d, q in zip(lists, rows, strict=True)
            ]
            for name, lists in docs.items()
        }
        draws = metrics.resamples(len(rows))
        summary = metrics.summarize(scored, draws)
        summary["rerank"]["minus_hybrid"] = metrics.paired(scored["rerank"], scored["hybrid"], draws)
        choice = metrics.choose(summary)

        # The chosen configuration again with no time condition: what documents known only after
        # day 0 would add to the metrics, and how many of them reach the first ten.
        untimed: list[dict[str, float]] = []
        later = 0
        for i, q in enumerate(rows):
            floor_all = store.floor(q["query"], q["day0"], timed=False)
            dense_all = store.dense(query_vectors[i], q["day0"], ef_search, timed=False)
            found = ranked(choice["chosen"], floor_all, dense_all, q["query"])
            visible_then = set(flat.docs[flat.mask(q["day0"])].tolist())
            later += sum(1 for d in found[:10] if d not in visible_then)
            untimed.append(metrics.per_query(found, q["relevant"], q["relevant_advisories"]))

    leak = metrics.summarize({"floor": scored[choice["chosen"]], "untimed": untimed}, draws)["untimed"]
    if bm25:
        raise SystemExit("eval: pg_search is installed on this Postgres; wire BM25 before scoring here")
    measured_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    environment = {
        "python": platform.python_version(),
        "machine": platform.machine(),
        "postgres": server[0] if server else None,
        "pgvector": pgvector[0] if pgvector else None,
        "threads": args.threads,
    }
    eval_record = {
        "phase": 3,
        "window": "development",
        "measured_at": measured_at,
        "corpus": {
            "content_digest": manifest["content_digest"],
            "chunks": chunks.height,
            "files": manifest["files"],
            "published": manifest.get("published"),
        },
        "queries": {
            "development": dev.height,
            "relevant_per_query": round(float(np.mean(dev.get_column("relevant").list.len().to_numpy())), 3),
        },
        "models": {
            "embedding": {**pins["embedding"], "sha256": emb.digests()},
            "reranker": {**pins["reranker"], "sha256": rer.digests()},
        },
        "configurations": summary,
        "bm25": {"run": False, "reason": "pg_search is not installed on the Postgres of this run"},
        "ef_search": ef_search,
        "choice": choice,
        "leakage": {
            "configuration": choice["chosen"],
            "without_time_condition": leak,
            "later_documents_in_top_10": later,
            "note": "the chosen configuration run again with no time condition: what the metrics would gain from documents known only after day 0",
        },
        "environment": environment,
        "result": "pass",
    }
    index_record = {
        "phase": 3,
        "measured_at": measured_at,
        "hnsw": {
            "m": search.HNSW_M,
            "ef_construction": search.HNSW_EF_CONSTRUCTION,
            "build_s": round(built["hnsw"], 2),
        },
        "ef_search_sweep": {
            str(ef): {"recall_at_10_vs_exact": sweep[ef], "latency_ms": ms(ef_timing[ef])} for ef in EF_SEARCH
        },
        "ef_search": ef_search,
        "rule": f"the smallest ef_search whose HNSW recall at 10 against the exact list is at least {INDEX_RECALL}",
        "compared": {
            "hnsw": {
                "recall_at_10_vs_exact": sweep[ef_search],
                "latency_ms": ms(ef_timing[ef_search]),
                "bytes": sizes["chunk_hnsw"],
            },
            "flat": {"recall_at_10_vs_exact": 1.0, "latency_ms": ms(timing["exact"]), "bytes": flat.bytes},
            "floor": {"latency_ms": ms(timing["floor"]), "index_bytes": sizes["chunk_text"]},
            "rerank": {"latency_ms": ms(timing["rerank"]), "chunks": search.RERANKED},
        },
        "sizes": sizes,
        "embedding_s": round(embed_s, 1),
        "environment": environment,
        "result": "pass",
    }
    return {"eval": eval_record, "index": index_record}


def frozen(record: dict[str, Any]) -> dict[str, Any]:
    ev = record["eval"]
    return {
        "chosen": ev["choice"]["chosen"],
        "chosen_on": "development",
        "chosen_at": ev["measured_at"],
        "ef_search": ev["ef_search"],
        "hnsw": {"m": search.HNSW_M, "ef_construction": search.HNSW_EF_CONSTRUCTION},
        "fusion": {"rrf_k": search.RRF_K, "documents": search.FUSED},
        "rerank": {"chunks": search.RERANKED},
        "models": ev["models"],
        "corpus_content_digest": ev["corpus"]["content_digest"],
    }


def part(record: dict[str, Any]) -> dict[str, Any]:
    ev, ix = record["eval"], record["index"]
    m = ManifestBuilder(ev["measured_at"][:10])
    population = f"the {ev['queries']['development']} development queries of corpus {ev['corpus']['content_digest'][:12]}"
    for name, entry in ev["configurations"].items():
        for metric in ("recall_at_10", "mrr_at_10", "ndcg_at_10"):
            m.value(
                f"retrieval.{name}.{metric}",
                round(entry[metric]["mean"], 4),
                "float3",
                origin="scripts/eval_retrieval.py",
                population=population,
                source="build",
            )
    m.value(
        "retrieval.queries.development",
        ev["queries"]["development"],
        "int",
        origin="scripts/eval_retrieval.py",
        population=population,
        source="build",
    )
    m.value(
        "retrieval.ef_search",
        ev["ef_search"],
        "int",
        origin="scripts/eval_retrieval.py",
        population=population,
        source="build",
    )
    m.value(
        "retrieval.hnsw.recall_vs_exact",
        ix["compared"]["hnsw"]["recall_at_10_vs_exact"],
        "float3",
        origin="scripts/eval_retrieval.py",
        population=population,
        source="build",
    )
    return m.dump()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--corpus", type=Path, default=ROOT / "data" / "corpus")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument(
        "--write", action="store_true", help="write the results, the part and config/retrieval.yaml"
    )
    args = parser.parse_args(argv)
    record = run(args)
    print(
        json.dumps({"choice": record["eval"]["choice"], "ef_search": record["eval"]["ef_search"]}, indent=1)
    )
    if args.write:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "eval.json").write_text(
            json.dumps(record["eval"], indent=1, default=str) + "\n", encoding="utf-8"
        )
        (OUT / "index.json").write_text(
            json.dumps(record["index"], indent=1, default=str) + "\n", encoding="utf-8"
        )
        FROZEN.write_text(yaml.safe_dump(frozen(record), sort_keys=False), encoding="utf-8")
        PART.write_text(json.dumps(part(record), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
