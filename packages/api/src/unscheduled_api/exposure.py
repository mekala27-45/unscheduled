"""The stand in products, their exposure on a snapshot date, and the backlog values.

The exposure builder writes findings for each product at two snapshot dates: the pin date and the
day of the build. A request names one: `pin` is the earliest snapshot, `today` (the default) the
newest, and a date picks the newest snapshot on or before it. Each finding is joined to its CVE as
that CVE was known at the end of the snapshot day, through the same as-of rule as GET /v1/cves/{id},
so the exposure on the pin date never shows an NVD status or a KEV listing that came later.
"""

from __future__ import annotations

from collections import Counter
from datetime import date
from typing import Any

import sqlalchemy as sa
from pydantic import JsonValue

from unscheduled_api import db
from unscheduled_api.asof import end_of_day, facts_as_of
from unscheduled_api.cves import cve_rows, field_events
from unscheduled_api.problems import ProblemError
from unscheduled_api.schemas import (
    Backlog,
    CveAsOf,
    Exposure,
    ExposureFinding,
    ExposureSummary,
    Product,
    Products,
)

NO_STATUS = "no NVD status"
NOT_IN_SLICE = "not in the serving slice"
NOT_YET_PUBLISHED = "not yet published on the snapshot day"


def _product(row: Any) -> Product:
    body: dict[str, JsonValue] = dict(row.body or {})
    attributes = {k: v for k, v in body.items() if k not in {"product_id", "name"}}
    return Product(product_id=str(row.product_id), name=str(row.name), attributes=attributes)


def list_products(conn: sa.Connection, *, statement: str, data_version: str) -> Products:
    rows = conn.execute(
        sa.select(db.product.c.product_id, db.product.c.name, db.product.c.body).order_by(
            db.product.c.product_id
        )
    ).all()
    return Products(statement=statement, data_version=data_version, products=[_product(r) for r in rows])


def resolve_snapshot(snapshots: list[date], requested: str) -> date:
    if not snapshots:
        raise ProblemError("not-found", "this product has no exposure snapshot in the serving slice")
    if requested == "today":
        return snapshots[-1]
    if requested == "pin":
        return snapshots[0]
    try:
        day = date.fromisoformat(requested)
    except ValueError as err:
        raise ProblemError("invalid-request", "as_of is pin, today or a date (YYYY-MM-DD)") from err
    earlier = [s for s in snapshots if s <= day]
    if not earlier:
        raise ProblemError(
            "not-found",
            f"no exposure snapshot on or before {day.isoformat()}; the first is {snapshots[0].isoformat()}",
        )
    return earlier[-1]


def exposure(
    conn: sa.Connection, product_id: str, as_of: str | None, *, statement: str, data_version: str
) -> Exposure:
    row = conn.execute(
        sa.select(db.product.c.product_id, db.product.c.name, db.product.c.body).where(
            db.product.c.product_id == product_id
        )
    ).first()
    if row is None:
        raise ProblemError(
            "not-found", f"no stand in product {product_id!r}", context={"product_id": product_id}
        )
    product = _product(row)
    f = db.finding.c
    snapshots = [
        r[0]
        for r in conn.execute(
            sa.select(f.as_of).where(f.product_id == product_id).distinct().order_by(f.as_of)
        ).all()
    ]
    requested = as_of or "today"
    snapshot = resolve_snapshot(snapshots, requested)
    rows = conn.execute(
        sa.select(f.finding_id, f.cve_ids, f.body)
        .where(f.product_id == product_id, f.as_of == snapshot)
        .order_by(f.finding_id)
    ).all()
    cve_ids = sorted({str(c) for r in rows for c in (r.cve_ids or [])})
    records = cve_rows(conn, cve_ids)
    events = field_events(conn, cve_ids)
    moment = end_of_day(snapshot)
    states: list[CveAsOf] = []
    for cve_id in cve_ids:
        record = records.get(cve_id)
        known, facts = (
            facts_as_of(record, record.get("provenance") or {}, events.get(cve_id, []), moment)
            if record is not None
            else (False, {})
        )

        def value(name: str, facts: dict[str, Any] = facts) -> Any:
            fact = facts.get(name)
            return fact.value if fact is not None else None

        states.append(
            CveAsOf(
                cve_id=cve_id,
                in_slice=record is not None,
                known=known,
                nvd_status=value("nvd_status"),
                nvd_cvss31_band=value("nvd_cvss31_band"),
                filer_cvss31_band=value("filer_cvss31_band"),
                filer_cvss40_band=value("filer_cvss40_band"),
                kev_listed=value("kev_date_added") is not None,
                exploit_code_seen=value("exploit_first_seen") is not None,
            )
        )
    findings: list[ExposureFinding] = []
    fixable: int | None = None
    for r in rows:
        body: dict[str, JsonValue] = dict(r.body or {})
        findings.append(
            ExposureFinding(
                finding_id=str(r.finding_id), cve_ids=[str(c) for c in r.cve_ids or []], attributes=body
            )
        )
        if "fix_available" in body:
            fixable = (fixable or 0) + (1 if body.get("fix_available") is True else 0)
    statuses: Counter[str] = Counter()
    for state in states:
        if not state.in_slice:
            statuses[NOT_IN_SLICE] += 1
        elif not state.known:
            statuses[NOT_YET_PUBLISHED] += 1
        else:
            statuses[state.nvd_status or NO_STATUS] += 1
    summary = ExposureSummary(
        findings=len(findings),
        findings_without_cve=sum(1 for item in findings if not item.cve_ids),
        findings_fix_available=fixable,
        distinct_cves=len(states),
        cves_by_nvd_status=dict(sorted(statuses.items())),
        cves_kev_listed=sum(1 for state in states if state.kev_listed),
        cves_with_exploit_code=sum(1 for state in states if state.exploit_code_seen),
    )
    return Exposure(
        statement=statement,
        data_version=data_version,
        product=product,
        as_of_requested=requested,
        snapshot=snapshot,
        snapshots=snapshots,
        summary=summary,
        findings=findings,
        cves=states,
    )


def backlog(conn: sa.Connection, *, statement: str, data_version: str) -> Backlog:
    value = conn.execute(sa.select(db.settings.c.value).where(db.settings.c.key == "backlog")).scalar()
    if value is None:
        raise ProblemError("data-not-loaded", "the backlog values arrive with the first serving bundle")
    return Backlog(statement=statement, data_version=data_version, backlog=value)
