"""The sources the agent evals run on, over the corpus fixture's work database: every answer as known
at the run time, the match from a product's finding before any advisory, and the fixed version read
from the advisory text the verifier checks."""

from __future__ import annotations

from datetime import UTC, datetime

import polars as pl
import pytest

from scripts.agent_sources import LakeSources, listings, version_key
from scripts.build_corpus import build as build_corpus
from tests.retrieval import corpus_fixture


@pytest.fixture(scope="module")
def sources(tmp_path_factory: pytest.TempPathFactory) -> LakeSources:
    folder = tmp_path_factory.mktemp("lake")
    work = corpus_fixture.build(folder / "work.duckdb")
    build_corpus(
        work,
        corpus_fixture.findings(folder / "finding.parquet"),
        folder / "corpus",
        corpus_fixture.words,
        {"model": "words"},
    )
    findings = folder / "products.parquet"
    pl.DataFrame(
        {
            "product_id": ["python-data-jobs"],
            "package": ["example-lib"],
            "ecosystem": ["PyPI"],
            "version": ["2.4.0"],
            "cve_aliases": [["CVE-2024-0001"]],
            "upstream_cves": [[]],
        },
        schema={
            "product_id": pl.String,
            "package": pl.String,
            "ecosystem": pl.String,
            "version": pl.String,
            "cve_aliases": pl.List(pl.String),
            "upstream_cves": pl.List(pl.String),
        },
    ).write_parquet(findings)
    return LakeSources(work, folder / "corpus", findings, lambda q, at, k: [])


DAY0 = datetime(2024, 3, 1, 23, 59, 59, tzinfo=UTC)


def test_the_description_is_the_one_known_then(sources: LakeSources) -> None:
    assert sources.description("CVE-2024-0001", DAY0) == corpus_fixture.QUERY_1
    assert sources.description("CVE-2024-0002", DAY0) is None


def test_a_product_finding_is_the_match_and_its_fix_comes_from_the_advisory_text(
    sources: LakeSources,
) -> None:
    match = sources.match("CVE-2024-0001", DAY0)
    assert match == {
        "product": "python-data-jobs",
        "component": "example-lib",
        "ecosystem": "PyPI",
        "installed_version": "2.4.0",
    }
    fixed = sources.fixed_versions("CVE-2024-0001", match, DAY0)
    assert [f.version for f in fixed] == ["2.4.1"] and fixed[0].source.startswith(("ghsa:", "osv:"))
    assert sources.fixed_versions("CVE-2024-0001", match, datetime(2024, 1, 1, tzinfo=UTC)) == []


def test_kev_exploits_and_epss_as_of(sources: LakeSources) -> None:
    before = datetime(2026, 5, 1, 11, tzinfo=UTC)
    after = datetime(2026, 5, 2, 12, tzinfo=UTC)
    assert sources.kev("CVE-2026-1000", before) is None
    listed = sources.kev("CVE-2026-1000", after)
    assert listed is not None and listed.vulnerability_name == "Example Gateway Command Injection"
    assert listed.date_added is not None and listed.date_added.isoformat() == "2026-05-01"
    assert sources.exploits("CVE-2026-1000", after) == []
    assert [s.source for s in sources.exploits("CVE-2026-1000", datetime(2026, 5, 4, tzinfo=UTC))] == [
        "metasploit"
    ]
    assert sources.epss("CVE-2026-1000", datetime(2026, 5, 1, 12, tzinfo=UTC)) == 0.01
    assert sources.epss("CVE-2026-1000", after) == 0.42


def test_the_listings_are_the_kev_entries_listed_after_publication(sources: LakeSources) -> None:
    found = listings(sources.con)
    assert found.get_column("cve_id").to_list() == ["CVE-2026-1000"] and found.get_column(
        "window"
    ).to_list() == ["shadow"]


def test_versions_compare_by_their_numbers() -> None:
    assert version_key("2.10.0") > version_key("2.9.9") and version_key("1.0.0-rc1") < version_key(
        "1.0.0-rc2"
    )
