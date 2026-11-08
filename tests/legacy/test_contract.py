"""The adapter keeps the old report's contract: the header byte for byte and every column's type.

The golden master is what the legacy script writes (tests/characterization/golden). The header-only
file it writes on retired feeds is the header exactly, so the adapter's header must equal those
bytes. Every cell of the script's sample report satisfies the column types the contract states, and
so must every cell the adapter writes from real findings.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from unscheduled_legacy_adapter import adapter, contract
from unscheduled_match.matcher import AdvisoryMatch, Finding
from unscheduled_match.osv import Severity

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "characterization" / "golden"
FINDINGS = ROOT / "results" / "exposure" / "findings_today.json"
T = datetime(2026, 11, 7, tzinfo=UTC)


def rows_of(data: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))


def test_the_header_is_byte_for_byte_the_legacy_header() -> None:
    golden = (GOLDEN / "retired_feeds.csv").read_bytes()
    assert adapter.render([]) == golden
    assert golden == contract.HEADER


def test_the_contract_describes_every_cell_of_the_golden_master() -> None:
    golden = (GOLDEN / "sample_feeds.csv").read_bytes()
    rows = rows_of(golden)
    assert tuple(rows[0]) == contract.COLUMNS
    assert len(rows) > 10
    for row in rows[1:]:
        assert contract.row_problems(row) == [], row[:3]
    assert golden.count(b"\r\n") >= len(rows), "CRLF line ends"


def finding(**overrides: object) -> Finding:
    match = AdvisoryMatch(
        advisory_id="GHSA-35jh-r3h4-6jhm",
        source="osv",
        sources=("ghsa", "osv"),
        via="range",
        modified=datetime(2024, 3, 1, tzinfo=UTC),
        published=datetime(2021, 2, 15, tzinfo=UTC),
        known_from=datetime(2024, 3, 1, tzinfo=UTC),
        known_from_rule="modified",
    )
    values: dict[str, object] = {
        "product": "cloud-dashboard",
        "component": "c",
        "purl": "pkg:npm/lodash@4.17.20",
        "ecosystem": "npm",
        "package": "lodash",
        "version": "4.17.20",
        "primary_id": "GHSA-35jh-r3h4-6jhm",
        "advisory_ids": ("GHSA-35jh-r3h4-6jhm",),
        "cve_aliases": ("CVE-2021-23337",),
        "matches": (match,),
        "fixed_versions": ("4.17.21",),
        "fix_available": True,
        "severity": (Severity(type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),),
        "summary": "Command Injection in lodash",
        "known_from": datetime(2024, 3, 1, tzinfo=UTC),
        "known_from_rule": "modified",
        "as_of": T,
    }
    values.update(overrides)
    return Finding.model_validate(values)


def test_a_finding_becomes_a_row_in_the_legacy_types() -> None:
    data = adapter.report([finding()])
    rows = rows_of(data)
    assert rows[1] == [
        "CVE-2021-23337",
        "15/02/2021",
        "01/03/2024",
        "lodash",
        "lodash",
        "7.2",
        "HIGH",
        "",
        "Command Injection in lodash",
    ]
    assert contract.row_problems(rows[1]) == []


def test_vendor_and_product_follow_the_package_url() -> None:
    cases = {
        ("Maven", "org.apache.logging.log4j:log4j-core"): ("org.apache.logging.log4j", "log4j-core"),
        ("npm", "@babel/core"): ("babel", "core"),
        ("Go", "golang.org/x/net"): ("golang.org/x", "net"),
        ("Debian:12", "glibc"): ("glibc", "glibc"),
        ("crates.io", "anyhow"): ("anyhow", "anyhow"),
    }
    for (ecosystem, package), expected in cases.items():
        assert adapter.vendor_product(finding(ecosystem=ecosystem, package=package)) == expected


def test_facts_from_the_record_take_the_place_of_advisory_dates_and_scores() -> None:
    facts = {
        "CVE-2021-23337": adapter.CveFacts(
            published=date(2021, 2, 15),
            last_modified=date(2026, 6, 17),
            cvss3_score=7.2,
            cvss3_severity="HIGH",
            cvss2_score=6.5,
            summary="from the record",
        )
    }
    row = rows_of(adapter.report([finding()], facts))[1]
    assert row[1:3] == ["15/02/2021", "17/06/2026"] and row[5:9] == ["7.2", "HIGH", "6.5", "from the record"]


def test_rows_are_deduplicated_like_the_old_script() -> None:
    twice = adapter.rows_from_findings([finding(), finding(component="c2")])
    assert len(twice) == 1


@pytest.mark.skipif(not FINDINGS.exists(), reason="results/exposure has not been written")
def test_every_cell_written_from_the_real_findings_keeps_the_contract() -> None:
    products = json.loads(FINDINGS.read_text(encoding="utf-8"))["products"]
    findings = [Finding.model_validate(f) for body in products.values() for f in body["findings"]]
    data = adapter.report(findings)
    rows = rows_of(data)
    assert data.startswith(contract.HEADER)
    assert len(rows) > 100
    problems = [p for row in rows[1:] for p in contract.row_problems(row)]
    assert problems == []
