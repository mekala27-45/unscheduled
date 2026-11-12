"""Three ways to talk to DuckDB, written once.

DuckDB 2.0 keeps a statement's result open on the connection until it is fetched to the end, and
refuses other work on that connection meanwhile; it also returns frames only from relations. So a
statement is always run to completion here, and a frame always comes from a relation.
"""

from __future__ import annotations

from typing import Any

import duckdb
import polars as pl


def run(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> None:
    """Run a statement to completion."""
    con.execute(sql, params).fetchall()


def rows(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> list[tuple[Any, ...]]:
    return con.execute(sql, params).fetchall()


def one(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> tuple[Any, ...]:
    found = rows(con, sql, params)
    if len(found) != 1:
        raise ValueError(f"expected one row, got {len(found)}")
    return found[0]


def frame(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> pl.DataFrame:
    out: pl.DataFrame = con.sql(sql, params=params).pl()
    return out


def put(con: duckdb.DuckDBPyConnection, qualified: str, df: pl.DataFrame) -> None:
    """Create or replace a table from a polars frame."""
    con.register("_put_frame", df)
    try:
        run(con, f"create or replace table {qualified} as select * from _put_frame")
    finally:
        con.unregister("_put_frame")
