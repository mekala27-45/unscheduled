"""The as-of rule as a property: a fact planted after T never appears at T, and none known by T is lost.

hypothesis draws a CVE's fields, their provenance, the events that set them and a time T, then
plants a sentinel value known strictly after T, once as an event and once as a provenance date. The
engine must never return the sentinel, and every field's newest event at or before T must be what it
returns for that field.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from unscheduled_api.asof import NOT_YET_KNOWN, Event, end_of_day, facts_as_of
from unscheduled_api.bundle import CVE_FIELDS

START = datetime(2017, 1, 1, tzinfo=UTC)
FIELDS = [f for f in CVE_FIELDS if f != "published"]
SENTINEL = "planted-after-t"

moments = st.integers(min_value=0, max_value=3650 * 24).map(lambda h: START + timedelta(hours=h))


@st.composite
def cases(draw: st.DrawFn) -> dict[str, Any]:
    published = draw(moments)
    t = draw(moments.filter(lambda m: m >= published))
    with_events = draw(st.sets(st.sampled_from(FIELDS), max_size=6))
    events: list[Event] = []
    for i, field in enumerate(sorted(with_events)):
        for j, offset in enumerate(draw(st.lists(st.integers(0, 2000 * 24), min_size=1, max_size=4))):
            at = published + timedelta(hours=offset)
            events.append(
                Event(f"e{i}-{j}", at, "change", "src", {"field": field, "value": f"{field}-{offset}"})
            )
    dated = draw(st.sets(st.sampled_from([f for f in FIELDS if f not in with_events]), max_size=6))
    provenance = {
        f: {
            "source": "src",
            "known_from": (published + timedelta(hours=draw(st.integers(0, 2000 * 24)))).isoformat(),
        }
        for f in sorted(dated)
    }
    row: dict[str, Any] = {f: f"{f}-current" for f in FIELDS}
    row["published"] = published
    return {"row": row, "provenance": provenance, "events": events, "t": t}


@settings(max_examples=300, deadline=None)
@given(cases(), st.sampled_from(FIELDS), st.integers(min_value=1, max_value=5000))
def test_a_fact_planted_after_t_never_appears(case: dict[str, Any], field: str, hours_after: int) -> None:
    t = case["t"]
    planted_event = Event(
        "planted", t + timedelta(hours=hours_after), "change", "src", {"field": field, "value": SENTINEL}
    )
    known, facts = facts_as_of(case["row"], case["provenance"], [*case["events"], planted_event], t)
    assert known
    assert all(f.value != SENTINEL for f in facts.values())
    assert all(f.known_from is None or f.known_from <= t for f in facts.values())

    row = dict(case["row"], **{field: SENTINEL})
    provenance = dict(
        case["provenance"],
        **{field: {"source": "src", "known_from": (t + timedelta(hours=hours_after)).isoformat()}},
    )
    events = [e for e in case["events"] if e.sets != field]
    known, facts = facts_as_of(row, provenance, events, t)
    assert facts[field].value is None and facts[field].rule == NOT_YET_KNOWN


@settings(max_examples=300, deadline=None)
@given(cases())
def test_every_fact_known_by_t_is_returned(case: dict[str, Any]) -> None:
    t = case["t"]
    known, facts = facts_as_of(case["row"], case["provenance"], case["events"], t)
    assert known
    for field in FIELDS:
        dated = [e for e in case["events"] if e.sets == field]
        if dated:
            before = [e for e in dated if e.at <= t]
            if before:
                newest = max(before, key=lambda e: (e.at, e.event_id))
                assert facts[field].value == newest.detail["value"] and facts[field].known_from == newest.at
            else:
                assert facts[field].value is None
        elif field in case["provenance"]:
            known_from = datetime.fromisoformat(case["provenance"][field]["known_from"])
            assert (facts[field].value is not None) == (known_from <= t)
        else:
            assert facts[field].value is None and facts[field].rule == "undated"


@given(moments, st.integers(min_value=1, max_value=10_000))
def test_nothing_is_known_before_publication(published: datetime, hours_before: int) -> None:
    row = {f: "x" for f in FIELDS} | {"published": published}
    known, facts = facts_as_of(row, {}, [], published - timedelta(hours=hours_before))
    assert known is False and facts == {}


def test_a_date_means_the_end_of_that_day_in_utc() -> None:
    assert end_of_day(date(2026, 4, 15)) == datetime(2026, 4, 15, 23, 59, 59, 999999, tzinfo=UTC)
