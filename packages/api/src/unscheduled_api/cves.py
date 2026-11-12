"""Reading CVEs from the Neon slice: one record with every field sourced, a filtered page, a timeline.

The list is ordered newest published first and paged by keyset, never by offset: the cursor holds
the published time and the id of the last row served, and a digest of the filters, so a cursor
cannot be replayed against a different filter and a page never repeats or skips a row while the
sync writes underneath it. A page holds at most 100 rows.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import sqlalchemy as sa
from unscheduled_core.hashing import sha256_json

from unscheduled_api import db
from unscheduled_api.asof import Event, Fact, current_facts, end_of_day, facts_as_of
from unscheduled_api.bundle import jsonable
from unscheduled_api.problems import ProblemError
from unscheduled_api.schemas import CvePage, CveRecord, CveSummary, FieldValue, Timeline, TimelineEvent

PAGE_MAX = 100
PAGE_DEFAULT = 50
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CVE_ID_PATTERN = r"^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,12}$"
CWE_PATTERN = r"^([Cc][Ww][Ee]-[0-9]{1,5}|NVD-CWE-Other|NVD-CWE-noinfo)$"
TEXT_PATTERN = r"^[ -~]+$"  # printable ASCII: filer names, statuses and types are written in it


def normalize_cwe(value: str) -> str:
    return "CWE-" + value[4:] if value[:4].lower() == "cwe-" else value


DESCRIPTION_FROM = date(2021, 1, 1)
SUMMARY_COLUMNS = tuple(CveSummary.model_fields)


def normalize_id(cve_id: str) -> str:
    value = cve_id.strip().upper()
    if not CVE_ID.match(value):
        raise ProblemError("invalid-request", f"{cve_id!r} is not a CVE id (CVE-YYYY-NNNN)")
    return value


def links(cve_id: str) -> dict[str, str]:
    return {
        "cve_org": f"https://www.cve.org/CVERecord?id={cve_id}",
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _field_values(facts: dict[str, Fact]) -> dict[str, FieldValue]:
    return {
        name: FieldValue(value=f.value, source=f.source, known_from=f.known_from, rule=f.rule)
        for name, f in facts.items()
    }


def field_events(conn: sa.Connection, cve_ids: Sequence[str]) -> dict[str, list[Event]]:
    """The events that set a field, for the as-of view, keyed by CVE."""
    if not cve_ids:
        return {}
    table = db.cve_event
    rows = conn.execute(
        sa.select(table.c.event_id, table.c.cve_id, table.c.at, table.c.kind, table.c.source, table.c.detail)
        .where(table.c.cve_id.in_(list(cve_ids)))
        .where(table.c.detail.has_key("field"))
    ).all()
    out: dict[str, list[Event]] = {}
    for r in rows:
        out.setdefault(str(r.cve_id), []).append(
            Event(event_id=str(r.event_id), at=r.at, kind=str(r.kind), source=r.source, detail=dict(r.detail))
        )
    return out


def cve_rows(conn: sa.Connection, cve_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}
    rows = conn.execute(sa.select(db.cve).where(db.cve.c.cve_id.in_(list(cve_ids)))).mappings().all()
    return {str(r["cve_id"]): dict(r) for r in rows}


def get_cve(
    conn: sa.Connection, cve_id: str, as_of: date | None, *, statement: str, data_version: str
) -> CveRecord:
    cve = normalize_id(cve_id)
    row = cve_rows(conn, [cve]).get(cve)
    if row is None:
        raise ProblemError("not-found", f"{cve} is not in the serving slice", context={"cve_id": cve})
    provenance = row.get("provenance") or {}
    note: str | None = None
    if as_of is None:
        known, facts = True, current_facts(row, provenance)
    else:
        events = field_events(conn, [cve]).get(cve, [])
        known, facts = facts_as_of(row, provenance, events, end_of_day(as_of))
        if not known:
            note = f"{cve} was not yet published on {as_of.isoformat()}; nothing about it was public that day"
    published = row.get("published")
    description = facts.get("description")
    if (
        known
        and description is not None
        and description.value is None
        and isinstance(published, datetime)
        and published.date() < DESCRIPTION_FROM
    ):
        note = "descriptions are held for CVEs published since 1 January 2021; read this one at cve.org"
    return CveRecord(
        statement=statement,
        data_version=data_version,
        cve_id=cve,
        as_of=as_of,
        known=known,
        fields=_field_values(facts),
        links=links(cve),
        note=note,
    )


@dataclass(frozen=True)
class CveFilters:
    published_from: date | None = None
    published_to: date | None = None
    nvd_status: str | None = None
    kev: bool | None = None
    filer: str | None = None
    filer_type: str | None = None
    cwe: str | None = None
    has_filer_score: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: jsonable(v) for k, v in asdict(self).items() if v is not None}

    def digest(self) -> str:
        return sha256_json(self.as_dict())[:16]


def encode_cursor(published: datetime | None, cve_id: str, filters: CveFilters) -> str:
    payload = {"p": jsonable(published), "id": cve_id, "f": filters.digest()}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str, filters: CveFilters) -> tuple[datetime | None, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        published_text = payload["p"]
        cve_id = str(payload["id"])
        digest = str(payload["f"])
        published = None if published_text is None else datetime.fromisoformat(str(published_text))
    except (ValueError, KeyError, TypeError, UnicodeEncodeError, binascii.Error) as err:
        raise ProblemError("invalid-cursor", "the cursor is not one this listing issued") from err
    if digest != filters.digest():
        raise ProblemError(
            "invalid-cursor", "the cursor was issued for different filters; start again without it"
        )
    if not CVE_ID.match(cve_id):
        raise ProblemError("invalid-cursor", "the cursor is not one this listing issued")
    if published is not None and published.tzinfo is None:
        published = published.replace(tzinfo=UTC)
    return published, cve_id


def list_cves(
    conn: sa.Connection,
    filters: CveFilters,
    *,
    cursor: str | None,
    limit: int,
    statement: str,
    data_version: str,
) -> CvePage:
    if not 1 <= limit <= PAGE_MAX:
        raise ProblemError("invalid-request", f"limit is between 1 and {PAGE_MAX}")
    c = db.cve.c
    query = sa.select(*[c[name] for name in SUMMARY_COLUMNS])
    if filters.published_from is not None:
        query = query.where(c.published >= datetime.combine(filters.published_from, time.min, tzinfo=UTC))
    if filters.published_to is not None:
        upper = datetime.combine(filters.published_to + timedelta(days=1), time.min, tzinfo=UTC)
        query = query.where(c.published < upper)
    if filters.nvd_status is not None:
        query = query.where(c.nvd_status == filters.nvd_status)
    if filters.kev is not None:
        query = query.where(c.kev_date_added.isnot(None) if filters.kev else c.kev_date_added.is_(None))
    if filters.filer is not None:
        query = query.where(c.filer == filters.filer)
    if filters.filer_type is not None:
        query = query.where(c.filer_type == filters.filer_type)
    if filters.cwe is not None:
        query = query.where(c.cwes.contains([normalize_cwe(filters.cwe)]))
    if filters.has_filer_score is not None:
        scored = sa.or_(c.filer_cvss31_score.isnot(None), c.filer_cvss40_score.isnot(None))
        query = query.where(scored if filters.has_filer_score else sa.not_(scored))
    if cursor:
        after_published, after_id = decode_cursor(cursor, filters)
        if after_published is None:
            query = query.where(c.published.is_(None), c.cve_id < after_id)
        else:
            query = query.where(
                sa.or_(
                    c.published < after_published,
                    sa.and_(c.published == after_published, c.cve_id < after_id),
                    c.published.is_(None),
                )
            )
    query = query.order_by(c.published.desc().nulls_last(), c.cve_id.desc()).limit(limit + 1)
    rows = conn.execute(query).mappings().all()
    page = rows[:limit]
    items = [
        CveSummary.model_validate({k: (list(v) if k == "cwes" else v) for k, v in r.items()}) for r in page
    ]
    next_cursor = None
    if len(rows) > limit and page:
        last = page[-1]
        next_cursor = encode_cursor(last["published"], str(last["cve_id"]), filters)
    return CvePage(
        statement=statement,
        data_version=data_version,
        items=items,
        limit=limit,
        next_cursor=next_cursor,
        filters=filters.as_dict(),
    )


def timeline(conn: sa.Connection, cve_id: str, *, statement: str, data_version: str) -> Timeline:
    cve = normalize_id(cve_id)
    published = conn.execute(sa.select(db.cve.c.published).where(db.cve.c.cve_id == cve)).first()
    if published is None:
        raise ProblemError("not-found", f"{cve} is not in the serving slice", context={"cve_id": cve})
    t = db.cve_event.c
    rows = conn.execute(
        sa.select(t.event_id, t.at, t.kind, t.source, t.detail)
        .where(t.cve_id == cve)
        .order_by(t.at, t.kind, t.event_id)
    ).all()
    return Timeline(
        statement=statement,
        data_version=data_version,
        cve_id=cve,
        published=published[0],
        events=[
            TimelineEvent(
                event_id=str(r.event_id), at=r.at, kind=str(r.kind), source=r.source, detail=dict(r.detail)
            )
            for r in rows
        ],
    )
