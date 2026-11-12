"""The baseline as of a time: exploit code seen, NVD status dated by rule, and the C9 severity shares."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import duckdb
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_match import baseline
from unscheduled_match.baseline import ExploitSeen, NvdRecord, StatusEvent
from unscheduled_match.matcher import AdvisoryMatch, Finding

from tests.match import helpers

T = datetime(2024, 12, 31, tzinfo=UTC)
NOW = datetime(2026, 11, 8, tzinfo=UTC)


def at(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


def finding(*cves: str, primary: str = "GHSA-x") -> Finding:
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
        cve_aliases=tuple(cves),
        matches=(m,),
        fixed_versions=(),
        fix_available=False,
        known_from=T,
        known_from_rule="modified",
        as_of=T,
    )


def test_change_events_become_statuses_by_the_lake_rule() -> None:
    raw = [
        ("CVE-1", at(2024, 1, 1), "a", "New CVE Received"),
        ("CVE-1", at(2024, 1, 2), "b", "CVE Modified"),  # before any analysis: no status change
        ("CVE-1", at(2024, 2, 1), "c", "Initial Analysis"),
        ("CVE-1", at(2024, 3, 1), "d", "CWE Remap"),  # does not move the status
        ("CVE-1", at(2024, 4, 1), "e", "CVE Modified"),
        ("CVE-1", at(2024, 5, 1), "f", "CVE Rejected"),
        ("CVE-1", at(2024, 6, 1), "g", "CVE Unrejected"),
        ("CVE-2", at(2024, 1, 1), "h", "CVE Rejected"),
        ("CVE-2", at(2024, 2, 1), "i", "CVE Unrejected"),
    ]
    events = baseline.statuses_from_events(reversed(raw))
    assert [(e.cve_id, e.change_id, e.status) for e in events] == [
        ("CVE-1", "a", "Received"),
        ("CVE-1", "c", "Analyzed"),
        ("CVE-1", "e", "Modified"),
        ("CVE-1", "f", "Rejected"),
        ("CVE-1", "g", "Modified"),
        ("CVE-2", "h", "Rejected"),
        ("CVE-2", "i", "Received"),
    ]


RECORDS = {
    "CVE-NOW": NvdRecord(cve_id="CVE-NOW", vuln_status="Deferred", published=at(2024, 3, 1), fetched_at=NOW),
    "CVE-LATE": NvdRecord(
        cve_id="CVE-LATE", vuln_status="Awaiting Analysis", published=at(2025, 6, 1), fetched_at=NOW
    ),
    "CVE-OLD": NvdRecord(cve_id="CVE-OLD", vuln_status="Modified", published=at(2016, 3, 1), fetched_at=NOW),
}
EVENTS = {
    "CVE-NOW": [
        StatusEvent(
            cve_id="CVE-NOW",
            created=at(2024, 3, 1),
            change_id="1",
            event_name="New CVE Received",
            status="Received",
        ),
        StatusEvent(
            cve_id="CVE-NOW",
            created=at(2025, 2, 1),
            change_id="2",
            event_name="Initial Analysis",
            status="Analyzed",
        ),
    ]
}


def test_each_rule_dates_the_status_it_can() -> None:
    def status(cve: str, t: datetime) -> tuple[str, str]:
        dated = baseline.status_at(cve, t, RECORDS, EVENTS)
        return dated.status, dated.rule

    assert status("CVE-NONE", T) == ("No NVD record", "no_nvd_record")
    assert status("CVE-LATE", T) == ("Not in the NVD yet", "published_after")
    assert status("CVE-NOW", NOW) == ("Deferred", "current_record")
    assert status("CVE-NOW", T) == ("Received", "change_history"), "the analysis came after T"
    assert status("CVE-OLD", T) == ("Modified", "current_status_fallback")


def test_a_finding_counts_once_under_its_most_advanced_status() -> None:
    by_cve = {
        "CVE-A": baseline.DatedStatus(status="Deferred", rule="current_record", cve_id="CVE-A"),
        "CVE-B": baseline.DatedStatus(status="Analyzed", rule="change_history", cve_id="CVE-B"),
    }
    assert baseline.finding_status(finding("CVE-A", "CVE-B"), by_cve).status == "Analyzed"
    assert baseline.finding_status(finding(), by_cve).status == "No CVE"


def test_status_rows_add_up_to_the_findings_and_their_cves() -> None:
    findings = [finding("CVE-NOW"), finding("CVE-NOW", "CVE-OLD"), finding("CVE-LATE"), finding()]
    rows = baseline.status_rows("p", "pin", T, findings, RECORDS, EVENTS)
    assert sum(int(r[5]) for r in rows) == len(findings)
    assert sum(int(r[6]) for r in rows) == 3
    assert {(r[3], r[4]) for r in rows} >= {("No CVE", "no_cve"), ("Not in the NVD yet", "published_after")}
    assert [r[3] for r in rows] == sorted((r[3] for r in rows), key=baseline.STATUS_ORDER.index)


def test_exploit_code_counts_only_what_was_first_seen_by_t() -> None:
    seen = {
        "CVE-A": ExploitSeen(cve_id="CVE-A", first_seen=at(2023, 1, 1), metasploit=at(2023, 1, 1)),
        "CVE-B": ExploitSeen(cve_id="CVE-B", first_seen=at(2025, 5, 1), nuclei=at(2025, 5, 1)),
    }
    findings = [finding("CVE-A"), finding("CVE-B"), finding("CVE-A", "CVE-B"), finding("CVE-C")]
    assert baseline.exploit_counts(findings, T, seen) == (2, 1)
    assert baseline.exploit_counts(findings, NOW, seen) == (3, 2)


def write_parquet(path: Path, select: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"copy ({select}) to '{path}' (format parquet)")
    con.close()


def test_usable_severity_from_the_nvd_alone_and_from_any_source(tmp_path: Path) -> None:
    table = tmp_path / "cve_metrics"
    write_parquet(
        table / "year=2024" / "part.parquet",
        """
        select * from (values
          ('CVE-1', 'nvd@nist.gov', 'nvd', '3.1', 9.8),
          ('CVE-2', 'filer', 'cna', '4.0', 8.7),
          ('CVE-3', 'nvd@nist.gov', 'nvd', '2.0', 7.5),
          ('CVE-4', 'CISA-ADP', 'adp', '3.1', 6.5),
          ('CVE-5', 'someone', 'secondary', '3.1', 5.0),
          ('CVE-6', 'nvd@nist.gov', 'nvd', '3.1', null)
        ) v(cve_id, source, source_type, version, base_score)
        """,
    )
    usable = baseline.usable_severity(table, [f"CVE-{i}" for i in range(1, 8)])
    assert usable is not None
    assert {c: (u.nvd_v3, u.any_source) for c, u in usable.items()} == {
        "CVE-1": (True, True),
        "CVE-2": (False, True),
        "CVE-4": (False, True),
    }
    counts = baseline.severity_counts(
        [finding("CVE-1"), finding("CVE-2"), finding("CVE-3"), finding()], usable
    )
    assert counts == {"findings": 4, "nvd_only_usable": 1, "any_source_usable": 2}


def test_bronze_readers_say_none_when_a_table_does_not_exist(tmp_path: Path) -> None:
    assert baseline.exploit_first_seen(tmp_path / "exploit_signals", ["CVE-1"]) is None
    assert baseline.nvd_records(tmp_path / "nvd_cves", ["CVE-1"]) is None
    assert baseline.status_events(tmp_path / "nvd_changes", ["CVE-1"]) is None
    assert baseline.usable_severity(tmp_path / "cve_metrics", ["CVE-1"]) is None


def test_the_bronze_readers_take_the_newest_state_and_the_earliest_signal(tmp_path: Path) -> None:
    write_parquet(
        tmp_path / "exploit_signals" / "metasploit.parquet",
        """
        select * from (values
          ('CVE-1', 'metasploit', 'modules/a.rb', timestamptz '2023-01-01 00:00:00+00'),
          ('CVE-1', 'nuclei', 'cves/a.yaml', timestamptz '2022-06-01 00:00:00+00')
        ) v(cve_id, source, path, first_seen)
        """,
    )
    seen = baseline.exploit_first_seen(tmp_path / "exploit_signals", ["CVE-1", "CVE-2"])
    assert seen is not None and set(seen) == {"CVE-1"}
    assert seen["CVE-1"].first_seen == at(2022, 6, 1) and seen["CVE-1"].metasploit == at(2023, 1, 1)
    write_parquet(
        tmp_path / "nvd_cves" / "year=2024" / "part.parquet",
        """
        select * from (values
          ('CVE-1', 'Received', timestamptz '2024-01-01 00:00:00+00', timestamptz '2024-01-01 00:00:00+00', timestamptz '2026-11-01 00:00:00+00'),
          ('CVE-1', 'Deferred', timestamptz '2024-01-01 00:00:00+00', timestamptz '2026-04-20 00:00:00+00', timestamptz '2026-11-07 00:00:00+00')
        ) v(cve_id, vuln_status, published, last_modified, fetched_at)
        """,
    )
    records = baseline.nvd_records(tmp_path / "nvd_cves", ["CVE-1"])
    assert records is not None and records["CVE-1"].vuln_status == "Deferred"


EXPOSURE = helpers.ROOT / "results" / "exposure"
PART = helpers.ROOT / "results" / "parts" / "exposure.json"


def test_the_committed_part_merges_and_its_status_table_adds_up() -> None:
    part = json.loads(PART.read_text(encoding="utf-8"))
    builder = ManifestBuilder("2026-11-08")
    builder.merge(part)
    manifest = builder.build()
    summary = json.loads((EXPOSURE / "summary.json").read_text(encoding="utf-8"))
    table = manifest.tables["exposure.nvd_status"]
    for product, both in summary["products"].items():
        for when in ("pin", "today"):
            rows = [r for r in table.rows if r[0] == product and r[1] == when]
            assert sum(int(r[5] or 0) for r in rows) == both[when]["findings"], (product, when)
            assert sum(int(r[6] or 0) for r in rows) == both[when]["distinct_cves"], (product, when)
            key = product.replace("-", "_")
            assert (
                manifest.raw(f"exposure.{key}.exploit_findings_{when}") == both[when]["exploit_code_findings"]
            )
            assert manifest.raw(f"exposure.{key}.exploit_cves_{when}") == both[when]["exploit_code_cves"]
    assert {str(r[4]) for r in table.rows} <= set(baseline.RULES)
    nvd = manifest.raw("exposure.c9.nvd_only_usable_share")
    anywhere = manifest.raw("exposure.c9.any_source_usable_share")
    assert isinstance(nvd, float) and isinstance(anywhere, float) and 0 <= nvd <= anywhere <= 1
    assert manifest.values["exposure.c9.nvd_only_usable_share"].fmt == "pct1"
    assert manifest.raw("exposure.c9.findings_today") == sum(
        b["today"]["findings"] for b in summary["products"].values()
    )
    assert not (EXPOSURE / "manifest_entries.json").exists(), "the part moved to results/parts/exposure.json"
