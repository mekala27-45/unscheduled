"""The state of one CVE as it was known at a time T, from the Neon slice and nothing later.

Two kinds of fact are on hand for a CVE. The current value of each field, with the source and the
known_from the lake gave it (the provenance column, from provenance_json in the bundle), and the
ruler events, some of which set a field: their detail names the field and the value, as
{"field": "nvd_status", "value": "Analyzed"}. The rule is the one the lake's as-of engine follows:

- A field that has events takes the value of its newest event at or before T. If every event for
  the field is after T, the field was not yet known at T.
- A field without events takes its current value when that value's known_from is at or before T,
  and is not yet known otherwise.
- A current value with no known_from is left out of every as-of view: nothing says when it became
  known, so it cannot be placed before T.
- Before the CVE was published nothing about it was public, so an as-of view before publication
  is empty and says so.

A date asks for the end of that day in UTC: the state once everything known that day is in.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any

from unscheduled_api.bundle import CVE_FIELDS, jsonable

NOT_YET_KNOWN = "not yet known"
UNDATED = "undated"


@dataclass(frozen=True)
class Event:
    event_id: str
    at: datetime
    kind: str
    source: str | None
    detail: Mapping[str, Any]

    @property
    def sets(self) -> str | None:
        field = self.detail.get("field")
        return field if isinstance(field, str) and field in CVE_FIELDS else None


@dataclass(frozen=True)
class Fact:
    value: Any
    source: str | None
    known_from: datetime | None
    rule: str


def end_of_day(day: date) -> datetime:
    return datetime.combine(day, time.max, tzinfo=UTC)


def _parse(text: Any) -> datetime | None:
    if isinstance(text, datetime):
        return text if text.tzinfo else text.replace(tzinfo=UTC)
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _provenance(provenance: Mapping[str, Any], field: str) -> tuple[str | None, datetime | None, str]:
    entry = provenance.get(field)
    if not isinstance(entry, Mapping):
        return None, None, UNDATED
    source = entry.get("source")
    rule = entry.get("rule")
    return (
        str(source) if source is not None else None,
        _parse(entry.get("known_from")),
        str(rule) if rule else "provenance",
    )


def current_facts(row: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Fact]:
    """Every field with its current value, its source and since when, as the lake dated it."""
    out: dict[str, Fact] = {}
    for field in CVE_FIELDS:
        source, known_from, rule = _provenance(provenance, field)
        published = row.get("published")
        if field == "published" and known_from is None and isinstance(published, datetime):
            known_from, rule = published, "published"
        out[field] = Fact(jsonable(row.get(field)), source, known_from, rule)
    return out


def facts_as_of(
    row: Mapping[str, Any],
    provenance: Mapping[str, Any],
    events: Sequence[Event],
    t: datetime,
) -> tuple[bool, dict[str, Fact]]:
    """(known, facts): whether the CVE was public at t, and every field as it stood at t."""
    published = row.get("published")
    if not isinstance(published, datetime) or published > t:
        return False, {}
    by_field: dict[str, list[Event]] = {}
    for event in events:
        field = event.sets
        if field is not None:
            by_field.setdefault(field, []).append(event)
    out: dict[str, Fact] = {}
    for field in CVE_FIELDS:
        dated = by_field.get(field)
        if dated:
            known = [e for e in dated if e.at <= t]
            if not known:
                out[field] = Fact(None, None, None, NOT_YET_KNOWN)
                continue
            newest = max(known, key=lambda e: (e.at, e.event_id))
            source = newest.detail.get("source", newest.source)
            out[field] = Fact(
                jsonable(newest.detail.get("value")),
                str(source) if source is not None else None,
                newest.at,
                f"event {newest.kind}",
            )
            continue
        source, known_from, rule = _provenance(provenance, field)
        if field == "published" and known_from is None:
            known_from, rule = published, "published"
        if known_from is None:
            out[field] = Fact(None, None, None, UNDATED)
        elif known_from <= t:
            out[field] = Fact(jsonable(row.get(field)), source, known_from, rule)
        else:
            out[field] = Fact(None, None, None, NOT_YET_KNOWN)
    return True, out
