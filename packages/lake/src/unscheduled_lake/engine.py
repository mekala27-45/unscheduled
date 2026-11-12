"""The as-of engine: what was known about a CVE at a time t, from facts known at or before t.

A fact is in the state at t when known_from <= t and it had not ended by t (known_to is null or
after t). Nothing else is read, so a fact that became known after t cannot appear, however it is
dated otherwise. dbt/macros/asof.sql holds the same query as a macro, and
tests/lake/test_asof_parity.py requires both to return identical frames; the planted future fact
property test in tests/lake/test_asof_property.py proves that nothing known after t leaks in and
that nothing known before it is lost.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, date, datetime, time

import duckdb
import polars as pl

from unscheduled_lake.db import frame

FACTS = "silver.cve_fact"
COLUMNS = ("cve_id", "field", "source", "value", "known_from", "known_to", "dated_by")

ASOF_SQL = """
select f.cve_id, f.field, f.source, f.value, f.known_from, f.known_to, f.dated_by
from {facts} as f
where f.known_from <= $t
  and (f.known_to is null or f.known_to > $t)
  {cve_filter}
order by f.cve_id, f.field, f.source, f.value, f.known_from
"""


def as_time(t: datetime | date | str) -> datetime:
    """A time to ask at. A day means the end of that day in UTC: what was known by then."""
    if isinstance(t, str):
        t = date.fromisoformat(t) if len(t) == 10 else datetime.fromisoformat(t)
    if isinstance(t, datetime):
        if t.tzinfo is None:
            raise ValueError("an as-of time must carry its zone; facts are dated in UTC")
        return t.astimezone(UTC)
    return datetime.combine(t, time(23, 59, 59, 999999), tzinfo=UTC)


class Engine:
    """The as-of engine over one DuckDB connection and one fact relation."""

    def __init__(self, con: duckdb.DuckDBPyConnection, facts: str = FACTS) -> None:
        self.con = con
        self.facts = facts

    def sql(self, with_ids: bool) -> str:
        cve_filter = "and f.cve_id in (select unnest($ids))" if with_ids else ""
        return ASOF_SQL.format(facts=self.facts, cve_filter=cve_filter)

    def asof(self, cve_ids: Sequence[str], t: datetime | date | str) -> pl.DataFrame:
        """The facts current at t for the CVEs asked for."""
        ids = sorted(set(cve_ids))
        return _frame(frame(self.con, self.sql(True), {"t": as_time(t), "ids": ids}))

    def asof_frame(self, t: datetime | date | str) -> pl.DataFrame:
        """The facts current at t for every CVE: the whole lake as it stood at t."""
        return _frame(frame(self.con, self.sql(False), {"t": as_time(t)}))

    def state(self, cve_id: str, t: datetime | date | str) -> dict[str, list[dict[str, object]]]:
        """One CVE at t, field by field, each value with its source and when it became known."""
        frame = self.asof([cve_id], t)
        out: dict[str, list[dict[str, object]]] = {}
        for row in frame.iter_rows(named=True):
            out.setdefault(str(row["field"]), []).append(
                {
                    "source": row["source"],
                    "value": row["value"],
                    "known_from": row["known_from"],
                    "dated_by": row["dated_by"],
                }
            )
        return out


def _frame(found: pl.DataFrame) -> pl.DataFrame:
    return found.select(list(COLUMNS))


def asof(
    con: duckdb.DuckDBPyConnection, cve_ids: Sequence[str], t: datetime | date | str, facts: str = FACTS
) -> pl.DataFrame:
    return Engine(con, facts).asof(cve_ids, t)


def asof_frame(con: duckdb.DuckDBPyConnection, t: datetime | date | str, facts: str = FACTS) -> pl.DataFrame:
    return Engine(con, facts).asof_frame(t)
