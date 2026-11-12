"""A fact table in memory, shaped like silver.cve_fact, for the as-of tests."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime

import duckdb
import pytest

COLUMNS = ("cve_id", "field", "source", "value", "known_from", "known_to", "dated_by", "pre_history")


@dataclass(frozen=True)
class Fact:
    cve_id: str
    field: str
    source: str
    value: str
    known_from: datetime
    known_to: datetime | None
    dated_by: str = "event"
    pre_history: bool = False

    def row(self) -> tuple[object, ...]:
        return (
            self.cve_id,
            self.field,
            self.source,
            self.value,
            self.known_from,
            self.known_to,
            self.dated_by,
            self.pre_history,
        )


def make_table(con: duckdb.DuckDBPyConnection, facts: Sequence[Fact], name: str = "silver.cve_fact") -> None:
    con.execute("create schema if not exists silver")
    con.execute(
        f"create or replace table {name} (cve_id varchar, field varchar, source varchar, value varchar, "
        "known_from timestamptz, known_to timestamptz, dated_by varchar, pre_history boolean)"
    )
    if facts:
        con.executemany(f"insert into {name} values (?, ?, ?, ?, ?, ?, ?, ?)", [f.row() for f in facts])


@pytest.fixture
def con() -> Iterator[duckdb.DuckDBPyConnection]:
    connection = duckdb.connect(":memory:")
    connection.execute("set timezone = 'UTC'")
    try:
        yield connection
    finally:
        connection.close()
