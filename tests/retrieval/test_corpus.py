"""The corpus point in time: each version dated by the lake's rules, the queries labelled from the
aliases as of day 0, the leakage test that plants a document known a day after the query, and the
same digests under two hash seeds.

Step 5 builds every search configuration from corpus.as_of and extends the planted document test to
each of them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from unscheduled_lake.engine import Engine
from unscheduled_retrieval import corpus
from unscheduled_retrieval.documents import from_osv

from tests.retrieval import corpus_fixture
from tests.retrieval.corpus_fixture import QUERY_1, words

ROOT = Path(__file__).resolve().parents[2]
DAY0_1 = datetime(2024, 3, 1, 23, 59, 59, 999999, tzinfo=UTC)


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    folder = tmp_path_factory.mktemp("corpus")
    work = corpus_fixture.build(folder / "work.duckdb")
    con = corpus.connect(str(work))
    scope = corpus.scope_cves(con, ["CVE-2023-7777"])
    adv = corpus.advisories(con, scope)
    kev = corpus.kev(con)
    cwe = corpus.cwe(con)
    chunks = corpus.chunk_frame([*adv.versions, *kev.versions, *cwe.versions], words)
    corpus.description_facts(con)
    engine = Engine(con, facts=corpus.DESCRIPTION_FACTS)
    texts = corpus.query_texts(corpus.query_population(con), lambda ids, day: engine.asof(ids, day))
    queries, summary = corpus.label(texts, chunks)
    con.close()
    return {"adv": adv, "kev": kev, "cwe": cwe, "chunks": chunks, "queries": queries, "summary": summary}


def test_advisories_are_dated_by_the_lake_and_need_their_text(built: dict[str, object]) -> None:
    adv = built["adv"]
    assert isinstance(adv, corpus.Corpus)
    ids = sorted({(v.doc.doc_id, v.doc.version) for v in adv.versions})
    # The OSV copy of the GitHub advisory is left to the GitHub record; PYSEC-2024-7 has no text.
    assert ids == [
        ("ghsa:GHSA-aaaa-bbbb-cccc", "2024-03-01T12:00:00Z"),
        ("ghsa:GHSA-aaaa-bbbb-cccc", "2025-06-01T00:00:00Z"),
        ("osv:PYSEC-2023-5", "2023-02-01T10:00:00Z"),
        ("osv:PYSEC-2024-1", "2024-03-01T15:00:00Z"),
        ("osv:PYSEC-2024-9", "2025-01-10T00:00:00Z"),
    ]
    assert adv.counts["versions_without_text"] == 1 and adv.counts["documents"] == 4
    first = next(v for v in adv.versions if v.doc.version == "2024-03-01T12:00:00Z")
    sections = {s.name: s.text for s in first.doc.sections}
    assert sections["affected"] == "PyPI/example-lib: from 0 fixed in 2.4.1"
    assert first.known_from == datetime(2024, 3, 1, 12, tzinfo=UTC)


def test_kev_texts_keep_their_capture_and_the_first_reads_from_the_listing(built: dict[str, object]) -> None:
    kev = built["kev"]
    assert isinstance(kev, corpus.Corpus)
    known = {(v.doc.doc_id, v.doc.version): v.known_from for v in kev.versions}
    assert known == {
        ("kev:CVE-2026-1000", "d1"): datetime(2026, 5, 1, 12, tzinfo=UTC),
        ("kev:CVE-2021-44228", "d2"): datetime(2021, 12, 10, tzinfo=UTC),
        ("kev:CVE-2021-44228", "d3"): datetime(2026, 2, 1, tzinfo=UTC),
    }
    assert kev.counts == {
        "texts": 3,
        "documents": 2,
        "edited": 1,
        "first_text_read_from_listing": 1,
        "never_in_a_lake_catalog": 1,
    }
    log4j = next(v for v in kev.versions if v.doc.version == "d2")
    assert not any("ransomware" in s.text.lower() for s in log4j.doc.sections)


def test_a_cwe_text_is_a_new_version_only_when_it_changes(built: dict[str, object]) -> None:
    cwe = built["cwe"]
    assert isinstance(cwe, corpus.Corpus)
    versions = sorted((v.doc.doc_id, v.doc.version, v.known_from.date().isoformat()) for v in cwe.versions)
    assert versions == [
        ("cwe:CWE-22", "4.13", "2023-10-26"),
        ("cwe:CWE-22", "5.0", "2026-10-28"),
        ("cwe:CWE-77", "4.13", "2023-10-26"),
    ]
    assert cwe.counts == {"catalog_versions": 3, "texts": 3, "documents": 2}


def test_the_queries_are_labelled_from_the_aliases_as_of_day_0(built: dict[str, object]) -> None:
    queries = built["queries"]
    assert isinstance(queries, pl.DataFrame)
    rows = {r["cve_id"]: r for r in queries.iter_rows(named=True)}
    assert sorted(rows) == ["CVE-2024-0001", "CVE-2026-1000"]
    first = rows["CVE-2024-0001"]
    assert first["query"] == QUERY_1 and first["day0"] == DAY0_1
    # PYSEC-2024-7 was known a minute after day 0 and its text was never captured either way.
    assert first["relevant"] == ["cwe:CWE-22", "ghsa:GHSA-aaaa-bbbb-cccc", "osv:PYSEC-2024-1"]
    assert rows["CVE-2026-1000"]["relevant"] == ["cwe:CWE-77", "kev:CVE-2026-1000"]
    assert rows["CVE-2026-1000"]["relevant_advisories"] == [] and rows["CVE-2026-1000"]["relevant_kev"]
    summary = built["summary"]
    assert isinstance(summary, dict)
    assert summary["development"]["left_out"] == {
        "no_advisory_or_kev_at_day0": 1,
        "no_description_at_day0": 1,
    }
    assert summary["development"]["queries"] == 1 and summary["shadow"]["queries"] == 1


def test_the_search_view_holds_the_newest_version_known_and_nothing_later(built: dict[str, object]) -> None:
    chunks = built["chunks"]
    assert isinstance(chunks, pl.DataFrame)
    view = corpus.as_of(chunks, DAY0_1)
    versions = {(r["doc_id"], r["version"]) for r in view.iter_rows(named=True)}
    assert versions == {
        ("ghsa:GHSA-aaaa-bbbb-cccc", "2024-03-01T12:00:00Z"),
        ("osv:PYSEC-2023-5", "2023-02-01T10:00:00Z"),
        ("osv:PYSEC-2024-1", "2024-03-01T15:00:00Z"),
        ("kev:CVE-2021-44228", "d2"),
        ("cwe:CWE-22", "4.13"),
        ("cwe:CWE-77", "4.13"),
    }
    later = corpus.as_of(chunks, datetime(2026, 11, 1, tzinfo=UTC))
    assert ("cwe:CWE-22", "5.0") in {(r["doc_id"], r["version"]) for r in later.iter_rows(named=True)}
    assert later.filter(pl.col("doc_id") == "kev:CVE-2021-44228").get_column(
        "version"
    ).unique().to_list() == ["d3"]


def test_a_withdrawn_advisory_leaves_the_view_from_its_withdrawal() -> None:
    record = {"id": "GHSA-wwww-xxxx-yyyy", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2024-5"]}
    doc = from_osv(
        {**record, "summary": "Withdrawn advisory"}, source="ghsa", known_from="2024-01-01T00:00:00Z"
    )
    withdrawn = datetime(2024, 2, 1, tzinfo=UTC)
    chunks = corpus.chunk_frame([corpus.Version(doc, datetime(2024, 1, 1, tzinfo=UTC), withdrawn)], words)
    assert corpus.as_of(chunks, datetime(2024, 1, 15, tzinfo=UTC)).height == 1
    assert corpus.as_of(chunks, withdrawn).height == 0


QUERY_TIMES = st.datetimes(
    min_value=datetime(2024, 1, 1), max_value=datetime(2026, 10, 1), timezones=st.just(UTC)
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    t=QUERY_TIMES,
    others=st.lists(st.integers(min_value=-2000, max_value=2000), min_size=0, max_size=6),
    planted_after=st.integers(min_value=1, max_value=3 * 24 * 60),
)
def test_a_document_planted_after_the_query_time_is_never_returned(
    t: datetime, others: list[int], planted_after: int
) -> None:
    """The leakage test: an advisory that says exactly what the query says, known one day after the
    query time (or later), is in no view and no label as of the query time, however the other
    documents of the corpus are dated."""
    versions = []
    for i, minutes in enumerate(others):
        record = {
            "id": f"GHSA-{i:04d}-other",
            "modified": f"2024-01-01T00:{i:02d}:00Z",
            "aliases": ["CVE-2024-1"],
        }
        doc = from_osv({**record, "details": f"Other advisory {i}."}, source="ghsa", known_from="x")
        versions.append(corpus.Version(doc, t + timedelta(minutes=minutes)))
    planted_record = {
        "id": "GHSA-plnt-plnt-plnt",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2024-1"],
    }
    planted = from_osv({**planted_record, "details": QUERY_1}, source="ghsa", known_from="x")
    planted_at = t + timedelta(days=1) + timedelta(minutes=planted_after - 1)
    versions.append(corpus.Version(planted, planted_at))
    chunks = corpus.chunk_frame(versions, words)
    view = corpus.as_of(chunks, t)
    assert "ghsa:GHSA-plnt-plnt-plnt" not in view.get_column("doc_id").to_list()
    assert view.filter(pl.col("known_from") > t).height == 0
    queries = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1"],
            "window": ["development"],
            "day0": [t],
            "query": [QUERY_1],
            "filer_cwes": [[]],
        },
        schema={
            "cve_id": pl.String,
            "window": pl.String,
            "day0": pl.Datetime("us", "UTC"),
            "query": pl.String,
            "filer_cwes": pl.List(pl.String),
        },
    )
    labelled, _ = corpus.label(queries, chunks)
    relevant = labelled.get_column("relevant").to_list()
    assert all("ghsa:GHSA-plnt-plnt-plnt" not in r for r in relevant)
    expected = sorted(f"ghsa:GHSA-{i:04d}-other" for i, m in enumerate(others) if m <= 0)
    assert (relevant[0] if relevant else []) == expected
    # Once its time has come, the planted document is in both.
    assert "ghsa:GHSA-plnt-plnt-plnt" in corpus.as_of(chunks, planted_at).get_column("doc_id").to_list()


def test_the_corpus_has_the_same_digests_under_two_hash_seeds(tmp_path: Path) -> None:
    found = []
    for seed in ("1", "2"):
        folder = tmp_path / f"seed{seed}"
        folder.mkdir()
        env = {**os.environ, "PYTHONHASHSEED": seed}
        done = subprocess.run(
            [sys.executable, "-m", "tests.retrieval.corpus_fixture", str(folder)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        found.append(json.loads(done.stdout.strip().splitlines()[-1]))
    assert found[0] == found[1]
    assert set(found[0]["files"]) == {"chunks.parquet", "queries.parquet"}
