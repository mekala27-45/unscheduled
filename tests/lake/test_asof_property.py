"""The as-of rule as a property, on facts generated at random.

At any time t the engine returns exactly the facts with known_from at or before t that had not ended
by t. A fact planted one microsecond after t, or a day after, never appears at t, and planting it
changes nothing that was known at t.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import duckdb
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from unscheduled_lake.engine import Engine, as_time

from tests.lake.conftest import Fact, make_table

START = datetime(2017, 1, 1, tzinfo=UTC)
CVES = [f"CVE-2026-{n:04d}" for n in range(1, 6)]

times = st.integers(min_value=0, max_value=10 * 365 * 24 * 3600).map(lambda s: START + timedelta(seconds=s))
facts = st.lists(
    st.builds(
        Fact,
        cve_id=st.sampled_from(CVES),
        field=st.sampled_from(["cvss_v3_vector", "severity", "nvd_status", "cwe"]),
        source=st.sampled_from(["nvd", "filer", "cisa_adp"]),
        value=st.text(alphabet="ABCDEFGHIJ0123456789:/.", min_size=1, max_size=12),
        known_from=times,
        known_to=st.none(),
    ).flatmap(
        lambda f: st.one_of(st.none(), st.integers(min_value=1, max_value=400 * 24 * 3600)).map(
            lambda d: Fact(
                f.cve_id,
                f.field,
                f.source,
                f.value,
                f.known_from,
                None if d is None else f.known_from + timedelta(seconds=d),
            )
        )
    ),
    max_size=40,
)


def reference(rows: list[Fact], ids: list[str], t: datetime) -> list[tuple[object, ...]]:
    kept = [
        f for f in rows if f.cve_id in ids and f.known_from <= t and (f.known_to is None or f.known_to > t)
    ]
    return sorted(((f.cve_id, f.field, f.source, f.value, f.known_from, f.known_to) for f in kept), key=_key)


def returned(engine: Engine, ids: list[str], t: datetime) -> list[tuple[object, ...]]:
    frame = engine.asof(ids, t)
    return sorted(
        (
            (r["cve_id"], r["field"], r["source"], r["value"], r["known_from"], r["known_to"])
            for r in frame.iter_rows(named=True)
        ),
        key=_key,
    )


def _key(row: tuple[object, ...]) -> tuple[str, ...]:
    return tuple("" if x is None else (x.isoformat() if isinstance(x, datetime) else str(x)) for x in row)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(rows=facts, t=times, ids=st.lists(st.sampled_from(CVES), min_size=1, max_size=5, unique=True))
def test_the_engine_returns_exactly_what_was_known_at_t(
    con: duckdb.DuckDBPyConnection, rows: list[Fact], t: datetime, ids: list[str]
) -> None:
    make_table(con, rows)
    assert returned(Engine(con), ids, t) == reference(rows, ids, t)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(rows=facts, t=times, ids=st.lists(st.sampled_from(CVES), min_size=1, max_size=5, unique=True))
def test_a_fact_planted_after_t_never_appears_and_changes_nothing(
    con: duckdb.DuckDBPyConnection, rows: list[Fact], t: datetime, ids: list[str]
) -> None:
    make_table(con, rows)
    engine = Engine(con)
    before = returned(engine, ids, t)
    planted = [
        Fact(cve, "nvd_status", "nvd", f"PLANTED-{n}", t + delay, None, "planted")
        for cve in ids
        for n, delay in enumerate((timedelta(microseconds=1), timedelta(days=1)))
    ]
    make_table(con, rows + planted)
    after = returned(engine, ids, t)
    assert not [r for r in after if str(r[3]).startswith("PLANTED")]
    assert after == before


def test_a_day_means_the_end_of_that_day_in_utc() -> None:
    assert as_time(date(2026, 4, 15)) == datetime(2026, 4, 15, 23, 59, 59, 999999, tzinfo=UTC)
    assert as_time("2026-04-15") == as_time(date(2026, 4, 15))
    with pytest.raises(ValueError, match="zone"):
        as_time(datetime(2026, 4, 15, 12, 0))


def test_a_fact_ending_at_t_is_no_longer_current(con: duckdb.DuckDBPyConnection) -> None:
    t = datetime(2026, 4, 15, tzinfo=UTC)
    rows = [
        Fact("CVE-2026-0001", "nvd_status", "nvd", "Received", t - timedelta(days=3), t),
        Fact("CVE-2026-0001", "nvd_status", "nvd", "Deferred", t, None),
    ]
    make_table(con, rows)
    values = [r["value"] for r in Engine(con).asof(["CVE-2026-0001"], t).iter_rows(named=True)]
    assert values == ["Deferred"]
