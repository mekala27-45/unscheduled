"""The state of one CVE as it was known at a time T, from the Neon slice and nothing later.

Two kinds of fact are on hand for a CVE. The current value of each field, with the source and the
known_from the lake gave it (the provenance column, from provenance_json in the bundle), and the
ruler events, some of which set a field: their detail names the field and the value, as
{"field": "nvd_status", "value": "Analyzed"}. The rule is the one the lake's as-of engine follows:

- A field that has events takes the value of its newest event at or before T. If every event for
  the field is after T, the field was not yet known at T. An event names the fields it sets either
  as {"field": name, "value": v} or, when it sets several at once (a vector with its score and
  band), as {"sets": {name: v, ...}}; a value of null there means the source removed it.
- A field without events takes its current value when that value's known_from is at or before T,
  and is not yet known otherwise.
- A field the record itself dates needs no provenance entry: the publication, the state, the filer,
  its type and the description are known from the publication (unless an event set them); the
  last change is known from itself; the EPSS score and its date from the day of the score; the
  NVD status is known since the event that set it (DERIVED below).
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
NVD_SOURCE = "nvd@nist.gov"
# Fields known from the publication of the CVE record, dated by the published column.
FROM_PUBLICATION = ("published", "state", "filer", "filer_type", "description")


@dataclass(frozen=True)
class Event:
    event_id: str
    at: datetime
    kind: str
    source: str | None
    detail: Mapping[str, Any]

    @property
    def rule(self) -> str:
        """How a field this event sets is dated: the event, and the lake's rule for its time.

        The bundle leaves dated_by out when the time is the NVD's own change history, the usual
        case for an event from the NVD, so its absence there reads as that rule.
        """
        dated_by = self.detail.get("dated_by")
        if not (isinstance(dated_by, str) and dated_by) and self.source == NVD_SOURCE:
            dated_by = "nvd_history"
        return (
            f"event {self.kind}, {dated_by}"
            if isinstance(dated_by, str) and dated_by
            else f"event {self.kind}"
        )

    @property
    def sets(self) -> dict[str, Any]:
        """The served fields this event gives a value to, with the value; empty when it sets none."""
        many = self.detail.get("sets")
        out: dict[str, Any] = {}
        if isinstance(many, Mapping):
            out = {str(k): v for k, v in many.items() if k in CVE_FIELDS}
        else:
            field = self.detail.get("field")
            if isinstance(field, str) and field in CVE_FIELDS:
                out = {field: self.detail.get("value")}
        # A status is held since the event that set it, so the event need not say so twice.
        if "nvd_status" in out and "nvd_status_since" not in out:
            out["nvd_status_since"] = jsonable(self.at)
        return out


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


def _derived(row: Mapping[str, Any], field: str) -> tuple[str | None, datetime | None, str] | None:
    """The source and known_from of a field the row dates by itself, or None when it does not."""
    published = _parse(row.get("published"))
    if field in FROM_PUBLICATION and published is not None:
        filer = row.get("filer")
        return (str(filer) if filer else None, published, "publication")
    if field == "last_modified":
        return ("cvelist", _parse(row.get("last_modified")), "last change seen")
    if field in ("epss_score", "epss_percentile", "epss_date"):
        day = row.get("epss_date")
        if isinstance(day, str):
            try:
                day = date.fromisoformat(day[:10])
            except ValueError:
                day = None
        if isinstance(day, date) and not isinstance(day, datetime):
            return ("epss", datetime.combine(day, time.min, tzinfo=UTC), "epss score date")
    return None


def _provenance(
    provenance: Mapping[str, Any], field: str, row: Mapping[str, Any] | None = None
) -> tuple[str | None, datetime | None, str]:
    entry = provenance.get(field)
    if not isinstance(entry, Mapping):
        derived = _derived(row, field) if row is not None else None
        return derived if derived is not None else (None, None, UNDATED)
    source = entry.get("source")
    rule = entry.get("rule")
    return (
        str(source) if source is not None else None,
        _parse(entry.get("known_from")),
        str(rule) if rule else "provenance",
    )


def _newest(events: Sequence[Event], t: datetime | None = None) -> dict[str, tuple[Event, Any]]:
    """For each field an event sets, the newest such event at or before t (any time when t is None)."""
    out: dict[str, tuple[Event, Any]] = {}
    for event in events:
        if t is not None and event.at > t:
            continue
        for field, value in event.sets.items():
            held = out.get(field)
            if held is None or (event.at, event.event_id) > (held[0].at, held[0].event_id):
                out[field] = (event, value)
    return out


def current_facts(
    row: Mapping[str, Any], provenance: Mapping[str, Any], events: Sequence[Event] = ()
) -> dict[str, Fact]:
    """Every field with its current value, its source and since when.

    A field an event sets is dated by the newest such event; the bundle carries provenance only for
    the fields no event sets (publication, the description, the CWEs, EPSS), so the two never
    disagree about the same field.
    """
    newest = _newest(events)
    out: dict[str, Fact] = {}
    for field in CVE_FIELDS:
        if field in newest:
            event, _ = newest[field]
            source = event.detail.get("source", event.source)
            out[field] = Fact(
                jsonable(row.get(field)),
                str(source) if source is not None else None,
                event.at,
                event.rule,
            )
            continue
        source, known_from, rule = _provenance(provenance, field, row)
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
    by_field: dict[str, list[tuple[Event, Any]]] = {}
    for event in events:
        for field, value in event.sets.items():
            by_field.setdefault(field, []).append((event, value))
    out: dict[str, Fact] = {}
    for field in CVE_FIELDS:
        dated = by_field.get(field)
        if dated:
            known = [(e, v) for e, v in dated if e.at <= t]
            if not known:
                out[field] = Fact(None, None, None, NOT_YET_KNOWN)
                continue
            newest, value = max(known, key=lambda pair: (pair[0].at, pair[0].event_id))
            source = newest.detail.get("source", newest.source)
            out[field] = Fact(
                jsonable(value),
                str(source) if source is not None else None,
                newest.at,
                newest.rule,
            )
            continue
        source, known_from, rule = _provenance(provenance, field, row)
        if known_from is None:
            out[field] = Fact(None, None, None, UNDATED)
        elif known_from <= t:
            out[field] = Fact(jsonable(row.get(field)), source, known_from, rule)
        else:
            out[field] = Fact(None, None, None, NOT_YET_KNOWN)
    return True, out
