"""The retrieval configuration config/retrieval.yaml froze, loaded for the agent: the corpus chunks and
their vectors in a Postgres schema with both indexes, and the one search function the retrieve node
calls, returning evidence with each chunk's document, version, sections and known_from."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import numpy as np
import polars as pl
import psycopg
import yaml
from unscheduled_agent.schemas import Evidence
from unscheduled_retrieval import embed, search

Retrieve = Callable[[str, datetime, int], list[Evidence]]


def searcher_from_frozen(
    root: Path, corpus_dir: Path, database_url: str, schema: str = "agent_eval"
) -> tuple[Retrieve, Callable[[], None]]:
    frozen_path = root / "config" / "retrieval.yaml"
    if not frozen_path.exists():
        raise SystemExit(
            "agent: config/retrieval.yaml does not exist; the retrieval choice of step 5 comes first"
        )
    frozen = yaml.safe_load(frozen_path.read_text(encoding="utf-8"))
    chunks = pl.read_parquet(corpus_dir / "chunks.parquet")
    pins = embed.pins(root)
    emb = embed.fetch(
        pins["embedding"]["id"],
        pins["embedding"]["revision"],
        ["tokenizer.json", pins["embedding"]["onnx"]],
        root,
    )
    encoder = embed.Encoder(emb.files["tokenizer.json"], emb.files[pins["embedding"]["onnx"]])
    cache = (
        root
        / "data"
        / "cache"
        / "retrieval"
        / f"vectors-{frozen['corpus_content_digest'][:16]}-{emb.revision[:12]}.npy"
    )
    vectors = np.load(cache) if cache.exists() else encoder.encode(chunks.get_column("text").to_list())
    if not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        np.save(cache, vectors)
    cross = None
    if frozen["chosen"] == "rerank":
        rer = embed.fetch(
            pins["reranker"]["id"],
            pins["reranker"]["revision"],
            ["tokenizer.json", pins["reranker"]["onnx"]],
            root,
        )
        cross = embed.CrossEncoder(rer.files["tokenizer.json"], rer.files[pins["reranker"]["onnx"]])
    conn = psycopg.connect(database_url)
    store = search.Store(conn, schema)
    store.create()
    store.load(chunks, vectors)
    store.index()
    texts = dict(
        zip(chunks.get_column("chunk_id").to_list(), chunks.get_column("text").to_list(), strict=True)
    )
    rows = {
        r["chunk_id"]: r
        for r in chunks.select("chunk_id", "doc_id", "version", "sections", "known_from").iter_rows(
            named=True
        )
    }
    searcher = search.Searcher(
        str(frozen["chosen"]),
        store,
        search.Flat(chunks, vectors),
        lambda q: encoder.encode_queries([q])[0],
        cross.score if cross is not None else None,
        texts,
        int(frozen["ef_search"]),
    )

    def retrieve(query: str, at: datetime, k: int) -> list[Evidence]:
        out: list[Evidence] = []
        for chunk_id, doc_id, value in searcher(query, at, k):
            row = rows[chunk_id]
            out.append(
                Evidence(
                    chunk_id=chunk_id,
                    doc_id=doc_id,
                    version=row["version"],
                    sections=list(row["sections"]),
                    known_from=row["known_from"],
                    text=texts[chunk_id],
                    score=float(value),
                )
            )
        return out

    return retrieve, conn.close
