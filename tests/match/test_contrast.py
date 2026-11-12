"""The CPE contrast from bronze nvd_cves: pending without the table, exact shares with it."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import duckdb
from unscheduled_match import contrast
from unscheduled_match.matcher import AdvisoryMatch, Finding

T = datetime(2026, 11, 7, tzinfo=UTC)


def finding(cves: tuple[str, ...], primary: str) -> Finding:
    m = AdvisoryMatch(
        advisory_id=primary,
        source="osv",
        sources=("osv",),
        via="range",
        modified=T,
        known_from=T,
        known_from_rule="modified",
    )
    return Finding(
        product="p",
        component="c",
        purl="pkg:npm/x@1.0.0",
        ecosystem="npm",
        package="x",
        version="1.0.0",
        primary_id=primary,
        advisory_ids=(primary,),
        cve_aliases=cves,
        matches=(m,),
        fixed_versions=(),
        fix_available=False,
        known_from=T,
        known_from_rule="modified",
        as_of=T,
    )


def bronze(root: Path) -> Path:
    table = root / "nvd_cves"
    (table / "year=2024").mkdir(parents=True)
    con = duckdb.connect()
    con.execute(
        """
        create table t as select * from (values
          ('CVE-2024-0001', 'Received', false, 0, timestamp '2024-01-01', timestamp '2026-11-01'),
          ('CVE-2024-0001', 'Analyzed', true, 3, timestamp '2024-02-01', timestamp '2026-11-02'),
          ('CVE-2024-0002', 'Deferred', false, 0, timestamp '2024-03-01', timestamp '2026-11-02'),
          ('CVE-2024-0003', 'Modified', true, 1, timestamp '2024-04-01', timestamp '2026-11-02')
        ) v(cve_id, vuln_status, has_cpe, cpe_count, last_modified, fetched_at)
        """
    )
    con.execute(f"copy t to '{table / 'year=2024' / 'part.parquet'}' (format parquet)")
    con.close()
    return table


def test_the_contrast_is_pending_while_the_table_does_not_exist(tmp_path: Path) -> None:
    out = contrast.contrast(
        {"p": [finding(("CVE-2024-0001",), "GHSA-1")]}, tmp_path / "nvd_cves", nvd_complete=False
    )
    assert out["status"] == "pending"


def test_the_newest_state_of_each_cve_decides(tmp_path: Path) -> None:
    states = contrast.load_states(bronze(tmp_path), ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-9999"])
    assert states is not None
    assert states["CVE-2024-0001"].vuln_status == "Analyzed" and states["CVE-2024-0001"].has_cpe
    assert "CVE-2024-9999" not in states


def test_the_shares_a_cpe_matcher_could_not_make(tmp_path: Path) -> None:
    findings = [
        finding(("CVE-2024-0001",), "GHSA-1"),  # analyzed, configured
        finding(("CVE-2024-0002",), "GHSA-2"),  # deferred, no CPE configuration
        finding(("CVE-2024-0003",), "GHSA-3"),  # modified after analysis, configured
        finding((), "RUSTSEC-2024-0001"),  # no CVE at all
    ]
    out = contrast.contrast({"p": findings}, bronze(tmp_path), nvd_complete=True)
    product = out["products"]["p"]
    assert out["status"] == "complete"
    assert product["findings_a_cpe_matcher_could_make"] == 2
    assert product["share_a_cpe_matcher_could_not_make"] == 0.5
    assert product["share_without_nvd_analysis"] == 0.5
    assert product["cves_by_nvd_status"] == {"Analyzed": 1, "Deferred": 1, "Modified": 1}
    assert product["findings_without_cve"] == 1
