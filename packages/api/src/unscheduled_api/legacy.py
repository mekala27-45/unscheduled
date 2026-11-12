"""GET /v1/legacy/report.csv and `unsched legacy-report`: the customer's nightly CSV, from the new data.

The customer's 2019 job wrote this report from the retired NVD 1.1 feeds and has written a header
only file every night since the feeds went away. packages/legacy_adapter writes the same CSV, the
same columns in the same order with the same types and date format, from matcher findings, so the
spreadsheet downstream keeps working while the old job is retired.

The seam: unscheduled_legacy_adapter.adapter.report(findings, facts) returns the CSV bytes. The API
hands it every finding of the newest snapshot of each product, rebuilt as packages/match Finding
records from the stored rows, and for each CVE in them the facts the old report showed, read from
the serving slice: the publication and modification dates, the description, and a CVSS 3 score and
severity. The old job read the score from the NVD feed; the NVD now scores few new CVEs, so the NVD
score is used where there is one and the filer's CVSS 3.1 score otherwise, the two sources the
adapter's own docstring names. Until the adapter exposes report the route answers
legacy-unavailable rather than inventing a format.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol

import sqlalchemy as sa

from unscheduled_api import db
from unscheduled_api.problems import ProblemError

SEVERITIES = frozenset({"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


class LegacyWriter(Protocol):
    def available(self) -> str | None:
        """None when the writer can run; otherwise why it cannot."""

    def write(
        self, findings: Sequence[Mapping[str, Any]], cves: Mapping[str, Mapping[str, Any]]
    ) -> bytes: ...


def _decoded(value: Any) -> Any:
    if isinstance(value, str) and value.strip()[:1] in {"[", "{"}:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def finding_record(body: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    """A served finding row as the matcher's Finding.

    The serving bundle keeps a finding as one flat row (scripts/build_serving_bundle.py): its first
    match's range, the fixes, the severity as JSON and the first publication and last change of the
    advisories it matched. A row that already carries the Finding fields is taken as it is; a flat
    row is mapped back, field by field, to the one match the adapter needs for its dates.
    """
    names = set(fields)
    data = {name: _decoded(body[name]) for name in names if name in body}
    data.setdefault("product", body.get("product_id"))
    data.setdefault("package", body.get("package") or body.get("component"))
    fixed = _decoded(body.get("fixed")) or []
    data.setdefault("fixed_versions", fixed)
    data.setdefault("severity", _decoded(body.get("severity_json")) or [])
    known_from = body.get("known_from") or body.get("advisory_known_from")
    rule = body.get("known_from_rule") or body.get("advisory_known_from_rule") or "unknown"
    data.setdefault("known_from", known_from)
    data.setdefault("known_from_rule", rule)
    if "matches" not in data:
        sources = [s for s in str(body.get("source") or "").split(",") if s]
        data["matches"] = [
            {
                "advisory_id": body.get("primary_id"),
                "source": sources[0] if sources else "unknown",
                "sources": sources,
                "via": "range" if body.get("matched_range") else "versions",
                "matched_range": body.get("matched_range"),
                "fixed": fixed,
                "modified": body.get("advisory_modified") or known_from,
                "published": body.get("advisory_published"),
                "known_from": known_from,
                "known_from_rule": rule,
            }
        ]
    return {name: value for name, value in data.items() if name in names}


class AdapterWriter:
    """packages/legacy_adapter, looked up when first used so a deployment without it still starts."""

    def available(self) -> str | None:
        try:
            from unscheduled_legacy_adapter import adapter
            from unscheduled_match.matcher import Finding  # noqa: F401
        except ImportError as err:
            return f"packages/legacy_adapter is not importable here ({err.name})"
        missing = [name for name in ("report", "CveFacts") if not hasattr(adapter, name)]
        if missing:
            return "packages/legacy_adapter does not expose " + ", ".join(f"adapter.{m}" for m in missing)
        return None

    def write(self, findings: Sequence[Mapping[str, Any]], cves: Mapping[str, Mapping[str, Any]]) -> bytes:
        from pydantic import ValidationError
        from unscheduled_legacy_adapter import adapter
        from unscheduled_match.matcher import Finding

        records = []
        for body in findings:
            data = finding_record(body, Finding.model_fields)
            try:
                records.append(Finding.model_validate(data))
            except ValidationError as err:
                first = err.errors()[0]
                where = ".".join(str(p) for p in first.get("loc", ()))
                raise ProblemError(
                    "legacy-unavailable",
                    f"a finding row does not carry the matcher's Finding fields (first problem at {where})",
                ) from err
        facts = {}
        for cve_id, record in cves.items():
            published, modified = (
                record.get("published"),
                record.get("last_modified") or record.get("published"),
            )
            if published is None or modified is None:
                continue
            score = record.get("nvd_cvss31_score")
            band = record.get("nvd_cvss31_band")
            if score is None:
                score, band = record.get("filer_cvss31_score"), record.get("filer_cvss31_band")
            severity = str(band).upper() if band else None
            facts[cve_id] = adapter.CveFacts(
                published=published.date(),
                last_modified=modified.date(),
                cvss3_score=score,
                cvss3_severity=severity if severity in SEVERITIES else None,
                cvss2_score=None,
                summary=str(record.get("description") or ""),
            )
        text = adapter.report(records, facts)
        if not isinstance(text, bytes):
            raise ProblemError(
                "legacy-unavailable", f"adapter.report returned {type(text).__name__}, not bytes"
            )
        return text


def report_inputs(conn: sa.Connection) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Every finding of the newest snapshot of each product, and the current record of each CVE in them."""
    f = db.finding.c
    newest = (
        sa.select(f.product_id, sa.func.max(f.as_of).label("as_of")).group_by(f.product_id).subquery("newest")
    )
    rows = conn.execute(
        sa.select(f.product_id, f.as_of, f.cve_ids, f.body)
        .join(newest, sa.and_(newest.c.product_id == f.product_id, newest.c.as_of == f.as_of))
        .order_by(f.product_id, f.finding_id)
    ).all()
    findings = [{**dict(r.body or {}), "product_id": str(r.product_id)} for r in rows]
    ids = sorted({str(c) for r in rows for c in (r.cve_ids or [])})
    cves: dict[str, dict[str, Any]] = {}
    if ids:
        for record in conn.execute(sa.select(db.cve).where(db.cve.c.cve_id.in_(ids))).mappings():
            cves[str(record["cve_id"])] = dict(record)
    return findings, cves


def report_csv(conn: sa.Connection, writer: LegacyWriter) -> bytes:
    reason = writer.available()
    if reason is not None:
        raise ProblemError("legacy-unavailable", reason)
    findings, cves = report_inputs(conn)
    return writer.write(findings, cves)
