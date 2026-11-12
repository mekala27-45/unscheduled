"""The legacy report written from findings, in exactly the CSV the old script writes.

The strangler for customer/legacy/vuln_report.py: the spreadsheet downstream keeps its columns,
their order, their types and the date format, while the rows now come from the matcher's findings
instead of a CPE vendor filter over feeds that no longer exist. The API serves the same bytes later.

One row per CVE, vendor and product, as the old script deduplicated. A finding names a package, not
a CPE, so vendor and product come from the package URL the way CPE names usually spell open source
packages: the Maven group and artifact, the npm scope and name, the Go module path and its last
element, and for a package with no namespace (PyPI, crates.io, a Debian source package) the name
twice. Dates and scores come from the CVE facts when the caller has them (the API passes the NVD
and CVE List record); otherwise from the advisories that made the finding, the score computed from
their CVSS vector by the cvss library.
"""

from __future__ import annotations

import csv
import importlib
import io
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

from unscheduled_core.model import StrictModel
from unscheduled_match.matcher import Finding

from unscheduled_legacy_adapter.contract import COLUMNS, DATE_FORMAT, LINE_END

# The cvss library ships no type information; it is loaded as a plain module and its answers are
# turned into floats and strings at once.
_cvss: Any = importlib.import_module("cvss")


class CveFacts(StrictModel):
    """What the old report showed about a CVE, from the record the API holds."""

    published: date
    last_modified: date
    cvss3_score: float | None = None
    cvss3_severity: str | None = None
    cvss2_score: float | None = None
    summary: str = ""


class LegacyRow(StrictModel):
    cve: str
    published: date
    last_modified: date
    vendor: str
    product: str
    cvss3_score: float | None = None
    cvss3_severity: str | None = None
    cvss2_score: float | None = None
    summary: str = ""

    def cells(self) -> list[str]:
        return [
            self.cve,
            self.published.strftime(DATE_FORMAT),
            self.last_modified.strftime(DATE_FORMAT),
            self.vendor,
            self.product,
            _score(self.cvss3_score),
            self.cvss3_severity or "",
            _score(self.cvss2_score),
            " ".join(self.summary.split()),
        ]


def _score(value: float | None) -> str:
    return "" if value is None else f"{value:.1f}"


def vendor_product(finding: Finding) -> tuple[str, str]:
    base = finding.ecosystem.split(":", 1)[0]
    name = finding.package
    if base == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return group, artifact
    if base == "npm" and name.startswith("@") and "/" in name:
        scope, package = name[1:].split("/", 1)
        return scope, package
    if base == "Go" and "/" in name:
        head, _, tail = name.rpartition("/")
        return head, tail
    return name, name


def cvss3_of(finding: Finding) -> tuple[float | None, str | None]:
    for severity in finding.severity:
        if severity.type == "CVSS_V3" and severity.score.startswith("CVSS:3"):
            parsed = _cvss.CVSS3(severity.score)
            return float(parsed.base_score), str(parsed.severities()[0]).upper()
    return None, None


def cvss2_of(finding: Finding) -> float | None:
    for severity in finding.severity:
        if severity.type == "CVSS_V2":
            return float(_cvss.CVSS2(severity.score).base_score)
    return None


def _advisory_dates(finding: Finding) -> tuple[date, date]:
    published = [m.published for m in finding.matches if m.published is not None]
    first: datetime = min(published) if published else finding.known_from
    last: datetime = max(m.modified for m in finding.matches)
    return first.date(), last.date()


def _reading_order(finding: Finding) -> tuple[bool, str, str, str]:
    """The order findings are read in: one with a CVSS 3 score first, then by advisory and package.

    Several findings can name the same CVE for the same vendor and product (the binary packages of
    one Debian source package, say), and the old script kept the first. Reading them in a fixed
    order makes the row kept the same whatever order the findings arrive in, from the matcher's
    files or from the API's tables.
    """
    score, _ = cvss3_of(finding)
    return (score is None, finding.primary_id, finding.purl, finding.version)


def rows_from_findings(
    findings: Iterable[Finding], facts: Mapping[str, CveFacts] | None = None
) -> list[LegacyRow]:
    rows: dict[tuple[str, str, str], LegacyRow] = {}
    for finding in sorted(findings, key=_reading_order):
        vendor, product = vendor_product(finding)
        for cve in finding.cves:
            key = (cve, vendor, product)
            if key in rows:
                continue
            known = (facts or {}).get(cve)
            if known is not None:
                rows[key] = LegacyRow(
                    cve=cve,
                    published=known.published,
                    last_modified=known.last_modified,
                    vendor=vendor,
                    product=product,
                    cvss3_score=known.cvss3_score,
                    cvss3_severity=known.cvss3_severity,
                    cvss2_score=known.cvss2_score,
                    summary=known.summary or finding.summary,
                )
                continue
            published, modified = _advisory_dates(finding)
            score3, severity3 = cvss3_of(finding)
            rows[key] = LegacyRow(
                cve=cve,
                published=published,
                last_modified=modified,
                vendor=vendor,
                product=product,
                cvss3_score=score3,
                cvss3_severity=severity3,
                cvss2_score=cvss2_of(finding),
                summary=finding.summary,
            )
    return [rows[k] for k in sorted(rows, key=_order)]


def _order(key: tuple[str, str, str]) -> tuple[int, int, str, str]:
    _, year, number = key[0].split("-")
    return int(year), int(number), key[1], key[2]


def render(rows: Iterable[LegacyRow]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator=LINE_END)
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow(row.cells())
    return buffer.getvalue().encode("utf-8")


def report(findings: Iterable[Finding], facts: Mapping[str, CveFacts] | None = None) -> bytes:
    """The bytes /v1/legacy/report.csv will serve."""
    return render(rows_from_findings(findings, facts))
