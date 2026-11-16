"""The search configurations of the plan, each reading only the chunks visible at the query's time.

- floor: Postgres full text search, websearch_to_tsquery('english', query) against
  to_tsvector('english', text) through a GIN index on that expression, ranked by ts_rank_cd.
- bm25: BM25 from pg_search over the same text, where the extension is installed.
- dense: the cosine distance between halfvec(384) vectors through an HNSW index (m 16,
  ef_construction 64), with pgvector's iterative scan so the time condition is applied inside the
  scan and a filtered query still returns its limit.
- exact: the same vectors in a flat NumPy array with exact cosine, the reference the HNSW recall is
  measured against.
- hybrid: reciprocal rank fusion of the floor and dense document lists, k 60.
- rerank: the cross-encoder reorders the first 50 chunks of the hybrid list.

Every configuration ranks chunks; the evaluation reads a ranked list of chunks as the list of their
documents in order of first appearance (documents()). The time condition is corpus.VISIBLE_SQL in
SQL and corpus.visible in NumPy, the same condition the leakage test holds every index to.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import numpy as np
import polars as pl
import psycopg
from pgvector import HalfVector
from pgvector.psycopg import register_vector
from psycopg import sql

from unscheduled_retrieval.corpus import VISIBLE_SQL

RRF_K = 60
FUSED = 100
RERANKED = 50
HNSW_M = 16
HNSW_EF_CONSTRUCTION = 64

Hit = tuple[str, str, float]  # chunk id, document id, score (higher ranks first)


def documents(hits: Sequence[Hit], k: int | None = None) -> list[str]:
    """The documents of a ranked chunk list in order of first appearance, cut at k."""
    seen: dict[str, None] = {}
    for _, doc, _ in hits:
        if doc not in seen:
            seen[doc] = None
            if k is not None and len(seen) == k:
                break
    return list(seen)


def rrf(rankings: Sequence[Sequence[str]], k: int = RRF_K, limit: int = FUSED) -> list[str]:
    """Reciprocal rank fusion: each list adds 1 / (k + rank) to an item; ties go to the item id."""
    score: dict[str, float] = {}
    for ranking in rankings:
        for rank, item in enumerate(ranking, start=1):
            score[item] = score.get(item, 0.0) + 1.0 / (k + rank)
    return sorted(score, key=lambda item: (-score[item], item))[:limit]


def hybrid_chunks(fused: Sequence[str], lists: Sequence[Sequence[Hit]], limit: int = RERANKED) -> list[Hit]:
    """The chunks of the fused documents in fused order, each document's chunks in the order the two
    retrievers ranked them, best rank first: the list the reranker reorders."""
    best: dict[str, dict[str, int]] = {}
    for hits in lists:
        for rank, (chunk, doc, _) in enumerate(hits):
            ranks = best.setdefault(doc, {})
            ranks[chunk] = min(rank, ranks.get(chunk, rank))
    out: list[Hit] = []
    for position, doc in enumerate(fused):
        for chunk in sorted(best.get(doc, {}), key=lambda c: (best[doc][c], c)):
            out.append((chunk, doc, float(-position)))
            if len(out) == limit:
                return out
    return out


@dataclass
class Store:
    """The corpus in one Postgres schema: the chunks with their times, a text index and an HNSW index."""

    conn: psycopg.Connection[Any]
    schema: str
    # The table of chunks; its indexes are named after it (chunk_text and chunk_hnsw for the evals,
    # corpus_chunk_text and corpus_chunk_hnsw in Neon, migration 0005).
    chunks: str = "chunk"

    def table(self, name: str) -> sql.Composed:
        return sql.SQL("{}.{}").format(sql.Identifier(self.schema), sql.Identifier(name))

    def create(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute("create extension if not exists vector")
            cur.execute(sql.SQL("create schema if not exists {}").format(sql.Identifier(self.schema)))
            cur.execute(sql.SQL("drop table if exists {}").format(self.table(self.chunks)))
            cur.execute(
                sql.SQL(
                    "create table {} (chunk_id text primary key, doc_id text not null, source text not null, "
                    "version text not null, known_from timestamptz not null, known_to timestamptz, "
                    "withdrawn timestamptz, ordinal integer not null, text text not null, embedding halfvec(384))"
                ).format(self.table(self.chunks))
            )
        self.conn.commit()
        register_vector(self.conn)

    def load(self, chunks: pl.DataFrame, vectors: np.ndarray | None) -> None:
        columns = [
            "chunk_id",
            "doc_id",
            "source",
            "version",
            "known_from",
            "known_to",
            "withdrawn",
            "ordinal",
            "text",
        ]
        copy = sql.SQL("copy {} ({}) from stdin").format(
            self.table(self.chunks),
            sql.SQL(", ").join(sql.Identifier(c) for c in [*columns, "embedding"]),
        )
        with self.conn.cursor() as cur, cur.copy(copy) as out:
            for i, row in enumerate(chunks.select(columns).iter_rows()):
                vector = HalfVector(vectors[i].astype(np.float32)) if vectors is not None else None
                out.write_row((*row, vector))
        self.conn.commit()

    def index(self) -> dict[str, float]:
        """Builds the two indexes and returns the seconds each took."""
        took: dict[str, float] = {}
        with self.conn.cursor() as cur:
            start = time.perf_counter()
            cur.execute(
                sql.SQL("create index {} on {} using gin (to_tsvector('english', text))").format(
                    sql.Identifier(f"{self.chunks}_text"), self.table(self.chunks)
                )
            )
            took["text"] = time.perf_counter() - start
            start = time.perf_counter()
            cur.execute(
                sql.SQL(
                    "create index {} on {} using hnsw (embedding halfvec_cosine_ops) "
                    "with (m = {}, ef_construction = {})"
                ).format(
                    sql.Identifier(f"{self.chunks}_hnsw"),
                    self.table(self.chunks),
                    sql.Literal(HNSW_M),
                    sql.Literal(HNSW_EF_CONSTRUCTION),
                )
            )
            took["hnsw"] = time.perf_counter() - start
            cur.execute(sql.SQL("analyze {}").format(self.table(self.chunks)))
        self.conn.commit()
        return took

    def sizes(self) -> dict[str, int]:
        with self.conn.cursor() as cur:
            out: dict[str, int] = {}
            for name, relation in (
                ("chunk", self.chunks),
                ("chunk_text", f"{self.chunks}_text"),
                ("chunk_hnsw", f"{self.chunks}_hnsw"),
            ):
                cur.execute("select pg_relation_size(%s::regclass)", (f'"{self.schema}"."{relation}"',))
                row = cur.fetchone()
                out[name] = int(row[0]) if row else 0
            cur.execute("select pg_total_relation_size(%s::regclass)", (f'"{self.schema}"."{self.chunks}"',))
            row = cur.fetchone()
            out["total"] = int(row[0]) if row else 0
            return out

    def _visible(self, timed: bool) -> sql.Composable:
        return sql.SQL(VISIBLE_SQL.format(t="%(t)s")) if timed else sql.SQL("true")

    def floor(self, query: str, at: datetime, limit: int = FUSED, timed: bool = True) -> list[Hit]:
        statement = sql.SQL(
            "select chunk_id, doc_id, ts_rank_cd(to_tsvector('english', text), q) as score "
            "from {}, websearch_to_tsquery('english', %(query)s) as q "
            "where to_tsvector('english', text) @@ q and {} "
            "order by score desc, chunk_id limit %(limit)s"
        ).format(self.table(self.chunks), self._visible(timed))
        with self.conn.cursor() as cur:
            cur.execute(statement, {"query": query, "t": at, "limit": limit})
            return [(str(c), str(d), float(s)) for c, d, s in cur.fetchall()]

    def bm25_available(self) -> bool:
        with self.conn.cursor() as cur:
            cur.execute("select count(*) from pg_available_extensions where name = 'pg_search'")
            row = cur.fetchone()
            return bool(row and row[0])

    def dense(
        self, vector: np.ndarray, at: datetime, ef_search: int, limit: int = FUSED, timed: bool = True
    ) -> list[Hit]:
        statement = sql.SQL(
            "select chunk_id, doc_id, embedding <=> %(v)s as distance from {} where {} "
            "order by embedding <=> %(v)s limit %(limit)s"
        ).format(self.table(self.chunks), self._visible(timed))
        with self.conn.cursor() as cur:
            cur.execute(sql.SQL("set local hnsw.ef_search = {}").format(sql.Literal(int(ef_search))))
            cur.execute("set local hnsw.iterative_scan = relaxed_order")
            cur.execute(statement, {"v": HalfVector(vector.astype(np.float32)), "t": at, "limit": limit})
            rows = cur.fetchall()
        self.conn.commit()
        # relaxed_order may return a few rows out of order; the distances put them back.
        ranked = sorted(((float(dist), str(c), str(d)) for c, d, dist in rows), key=lambda r: (r[0], r[1]))
        return [(c, d, -dist) for dist, c, d in ranked]


class Flat:
    """Exact cosine over every visible chunk: the reference list for the HNSW recall."""

    def __init__(self, chunks: pl.DataFrame, vectors: np.ndarray) -> None:
        self.ids = chunks.get_column("chunk_id").to_numpy()
        self.docs = chunks.get_column("doc_id").to_numpy()
        self.matrix = vectors.astype(np.float32)
        far = np.iinfo(np.int64).max
        self.known_from = chunks.get_column("known_from").dt.epoch("us").to_numpy()
        self.known_to = chunks.get_column("known_to").dt.epoch("us").fill_null(far).to_numpy()
        self.withdrawn = chunks.get_column("withdrawn").dt.epoch("us").fill_null(far).to_numpy()

    def mask(self, at: datetime) -> np.ndarray:
        t = int(at.timestamp() * 1_000_000)
        return (self.known_from <= t) & (self.known_to > t) & (self.withdrawn > t)

    def search(self, vector: np.ndarray, at: datetime, limit: int = FUSED, timed: bool = True) -> list[Hit]:
        rows = np.flatnonzero(self.mask(at)) if timed else np.arange(len(self.ids))
        if rows.size == 0:
            return []
        scores = self.matrix[rows] @ vector.astype(np.float32)
        take = min(limit, rows.size)
        top = np.argpartition(-scores, take - 1)[:take]
        order = sorted(top.tolist(), key=lambda i: (-float(scores[i]), str(self.ids[rows[i]])))
        return [(str(self.ids[rows[i]]), str(self.docs[rows[i]]), float(scores[i])) for i in order]

    @property
    def bytes(self) -> int:
        return int(self.matrix.astype(np.float16).nbytes)


def rerank(
    hits: Sequence[Hit], texts: dict[str, str], score: Callable[[Sequence[str]], np.ndarray]
) -> list[Hit]:
    """The hits reordered by the cross-encoder's scores; ties keep their earlier order."""
    if not hits:
        return []
    scores = score([texts[c] for c, _, _ in hits])
    order = sorted(range(len(hits)), key=lambda i: (-float(scores[i]), i))
    return [(hits[i][0], hits[i][1], float(scores[i])) for i in order]


class Searcher:
    """The configuration config/retrieval.yaml froze, as one function from a query and a time to the
    chunks it returns, for the agent's retrieve node."""

    def __init__(
        self,
        chosen: str,
        store: Store,
        flat: Flat,
        encode: Callable[[str], np.ndarray],
        score: Callable[[str, Sequence[str]], np.ndarray] | None,
        texts: dict[str, str],
        ef_search: int,
    ) -> None:
        self.chosen = chosen
        self.store = store
        self.flat = flat
        self.encode = encode
        self.score = score
        self.texts = texts
        self.ef_search = ef_search

    def __call__(self, query: str, at: datetime, k: int) -> list[Hit]:
        floor = self.store.floor(query, at) if self.chosen != "dense" else []
        if self.chosen == "floor":
            return floor[:k]
        dense = self.store.dense(self.encode(query), at, self.ef_search)
        if self.chosen == "dense":
            return dense[:k]
        fused = rrf([documents(floor), documents(dense)])
        candidates = hybrid_chunks(fused, [floor, dense])
        if self.chosen == "rerank" and self.score is not None:
            scorer = self.score
            candidates = rerank(candidates, self.texts, lambda passages: scorer(query, passages))
        return candidates[:k]
