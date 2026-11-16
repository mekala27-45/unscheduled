"""The search configurations and the metrics: the document grain, the fusion, the scores, the choice
rule, and the planted document test of tests/retrieval/test_corpus.py held against every index,
the Postgres text index, the HNSW index and the flat one.

The Postgres tests need pgvector with halfvec (0.7 or later). CI installs it and sets
UNSCHED_REQUIRE_PGVECTOR=1, which turns a missing extension into a failure instead of a skip.
"""

from __future__ import annotations

import hashlib
import math
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import numpy as np
import polars as pl
import psycopg
import pytest
from unscheduled_retrieval import corpus, metrics, search
from unscheduled_retrieval.documents import from_osv

from tests.api import postgres as _postgres
from tests.retrieval.corpus_fixture import words

postgres_url = _postgres.postgres_url
T = datetime(2024, 3, 1, 23, 59, 59, tzinfo=UTC)


def test_a_chunk_list_is_read_as_its_documents_in_order_of_first_appearance() -> None:
    hits = [("c1", "a", 0.9), ("c2", "b", 0.8), ("c3", "a", 0.7), ("c4", "c", 0.6)]
    assert search.documents(hits) == ["a", "b", "c"]
    assert search.documents(hits, k=2) == ["a", "b"]


def test_reciprocal_rank_fusion_adds_the_ranks_and_breaks_ties_by_id() -> None:
    fused = search.rrf([["a", "b", "c"], ["b", "d"]], k=60)
    assert fused[0] == "b" and set(fused) == {"a", "b", "c", "d"}
    assert search.rrf([["x"], ["y"]], k=60) == ["x", "y"]


def test_the_hybrid_chunks_follow_the_fused_documents() -> None:
    floor = [("f1", "a", 1.0), ("f2", "b", 0.5)]
    dense = [("d1", "b", 0.9), ("d2", "a", 0.8), ("f1", "a", 0.7)]
    out = search.hybrid_chunks(["b", "a"], [floor, dense], limit=3)
    assert [c for c, _, _ in out] == ["d1", "f2", "f1"]


def test_the_metrics_at_the_document_grain() -> None:
    ranked = ["x", "a", "y", "b"]
    assert metrics.recall_at(ranked, ["a", "b", "c"], 2) == pytest.approx(1 / 3)
    assert metrics.mrr_at(ranked, ["a", "b"], 10) == 0.5
    ideal = 1 + 1 / math.log2(3)
    assert metrics.ndcg_at(ranked, ["a", "b"], 10) == pytest.approx(
        (1 / math.log2(3) + 1 / math.log2(5)) / ideal
    )
    assert math.isnan(metrics.per_query(ranked, ["a"], [])["advisory_recall_at_10"])


def test_the_intervals_are_the_same_for_the_same_seed_and_pair_every_configuration() -> None:
    draws = metrics.resamples(50)
    assert np.array_equal(draws, metrics.resamples(50))
    rows = {
        "floor": [
            metrics.per_query(["a"], ["a"], ["a"]) if i % 2 else metrics.per_query(["z"], ["a"], ["a"])
            for i in range(50)
        ],
        "dense": [metrics.per_query(["a"], ["a"], ["a"]) for _ in range(50)],
    }
    summary = metrics.summarize(rows, draws)
    assert summary["floor"]["recall_at_10"]["mean"] == 0.5 and summary["dense"]["recall_at_10"]["mean"] == 1.0
    assert summary["dense"]["minus_floor"]["recall_at_10"]["low"] > 0


def _entry(mean: float, low: float) -> dict[str, object]:
    return {"recall_at_10": {"mean": mean}, "minus_floor": {"recall_at_10": {"low": low}}}


def test_the_choice_rule_needs_a_lower_bound_above_zero_and_prefers_the_simpler_on_a_tie() -> None:
    summary = {
        "floor": {"recall_at_10": {"mean": 0.30}},
        "dense": _entry(0.60, -0.01),
        "hybrid": _entry(0.55, 0.02),
    }
    assert metrics.choose(summary)["chosen"] == "hybrid"
    summary = {
        "floor": {"recall_at_10": {"mean": 0.30}},
        "dense": _entry(0.6001, 0.1),
        "hybrid": _entry(0.6004, 0.1),
    }
    assert metrics.choose(summary)["chosen"] == "dense"
    summary = {
        "floor": {"recall_at_10": {"mean": 0.30}},
        "dense": _entry(0.31, -0.2),
        "hybrid": _entry(0.32, -0.1),
    }
    assert metrics.choose(summary)["chosen"] == "floor"
    rerank = {**_entry(0.9, 0.2), "minus_hybrid": {"recall_at_10": {"low": -0.01}}}
    summary = {"floor": {"recall_at_10": {"mean": 0.3}}, "hybrid": _entry(0.6, 0.1), "rerank": rerank}
    assert metrics.choose(summary)["chosen"] == "hybrid"


def vector_of(text: str) -> np.ndarray:
    """A unit vector from the words of a text, so texts that share words lie close."""
    v = np.zeros(384, dtype=np.float32)
    for word in text.lower().split():
        v[int(hashlib.sha256(word.strip(".,").encode()).hexdigest(), 16) % 384] += 1.0
    return (v / (np.linalg.norm(v) or 1.0)).astype(np.float16)


def _doc(i: str, text: str, modified: str) -> corpus.Document:
    return from_osv(
        {"id": f"GHSA-{i}", "modified": modified, "aliases": ["CVE-2024-1"], "details": text},
        source="ghsa",
        known_from="x",
    )


QUERY = "archive extractor writes files outside the target folder"


def _chunks(planted_at: datetime) -> pl.DataFrame:
    versions = [
        corpus.Version(
            _doc("old1", "the archive extractor writes files outside the folder", "2024-01-01T00:00:00Z"),
            T - timedelta(days=30),
        ),
        corpus.Version(
            _doc("old2", "a header parser exhausts memory on a crafted request", "2024-01-02T00:00:00Z"),
            T - timedelta(days=20),
        ),
        corpus.Version(_doc("plnt", QUERY, "2026-01-01T00:00:00Z"), planted_at),
    ]
    return corpus.chunk_frame(versions, words)


@pytest.fixture
def store(postgres_url: str) -> Iterator[search.Store]:
    url = postgres_url.replace("postgresql+psycopg://", "postgresql://")
    with psycopg.connect(url) as conn:
        found = conn.execute(
            "select default_version from pg_available_extensions where name = 'vector'"
        ).fetchone()
        version = tuple(int(p) for p in str(found[0]).split(".")[:2]) if found else (0, 0)
        if version < (0, 7):
            message = f"pgvector 0.7 or later is needed for halfvec, found {found[0] if found else 'none'}"
            if os.environ.get("UNSCHED_REQUIRE_PGVECTOR") == "1":
                pytest.fail(message)
            pytest.skip(message)
        yield search.Store(conn, "retrieval_test")


@pytest.mark.parametrize(
    "planted_after", [timedelta(days=1), timedelta(days=1, minutes=1), timedelta(days=30)]
)
def test_a_document_planted_after_the_query_time_is_returned_by_no_index(
    store: search.Store, planted_after: timedelta
) -> None:
    chunks = _chunks(T + planted_after)
    vectors = np.stack([vector_of(t) for t in chunks.get_column("text").to_list()])
    store.create()
    store.load(chunks, vectors)
    store.index()
    q = vector_of(QUERY)
    floor = store.floor(QUERY, T)
    dense = store.dense(q, T, ef_search=40)
    flat = search.Flat(chunks, vectors).search(q, T)
    for hits in (floor, dense, flat):
        assert "ghsa:GHSA-plnt" not in search.documents(hits)
    assert search.documents(dense)[0] == "ghsa:GHSA-old1" and search.documents(flat)[0] == "ghsa:GHSA-old1"
    # Without the time condition the planted document is the best match of each: the leak the
    # condition prevents.
    assert search.documents(store.floor(QUERY, T, timed=False))[0] == "ghsa:GHSA-plnt"
    assert search.documents(store.dense(q, T, ef_search=40, timed=False))[0] == "ghsa:GHSA-plnt"
    assert search.documents(search.Flat(chunks, vectors).search(q, T, timed=False))[0] == "ghsa:GHSA-plnt"
    later = T + planted_after
    assert search.documents(store.dense(q, later, ef_search=40))[0] == "ghsa:GHSA-plnt"
    sizes = store.sizes()
    assert sizes["chunk_hnsw"] > 0 and sizes["chunk_text"] > 0
