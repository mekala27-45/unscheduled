"""Bronze as the warehouse sees it: one view per table over the Parquet files present.

Each view reads data/bronze/<table>/ by glob at query time, so a part file the fetcher compacts
between two queries is still found. A table with no files yet becomes an empty table of the
contract shape (packages/sources, unscheduled_sources.contract), and the build reports it as
missing; nothing is invented to fill it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import duckdb
import polars as pl
from unscheduled_sources.contract import TABLES

from unscheduled_lake.db import one, put, run


@dataclass(frozen=True)
class BronzeTable:
    name: str
    files: int
    bytes: int
    rows: int
    present: bool


def files(root: Path, name: str) -> list[Path]:
    base = root / name
    if not base.exists():
        return []
    return sorted(p for p in base.rglob("*.parquet") if p.is_file())


def _sql_path(path: Path) -> str:
    return str(path).replace("'", "''")


def create_views(con: duckdb.DuckDBPyConnection, root: Path) -> list[BronzeTable]:
    run(con, "create schema if not exists bronze")
    out: list[BronzeTable] = []
    for name, spec in TABLES.items():
        found = files(root, name)
        cols = ", ".join(f'"{c}"' for c in spec.columns)
        if found:
            pattern = _sql_path(root / name) + "/**/*.parquet"
            run(
                con,
                f"create or replace view bronze.{name} as select {cols} from "
                f"read_parquet('{pattern}', union_by_name = true, hive_partitioning = false)",
            )
            rows = int(one(con, f"select count(*) from bronze.{name}")[0])
        else:
            put(con, f"bronze.{name}", pl.DataFrame(schema=spec.schema).select(list(spec.columns)))
            rows = 0
        out.append(
            BronzeTable(
                name=name,
                files=len(found),
                bytes=sum(p.stat().st_size for p in found),
                rows=rows,
                present=bool(found),
            )
        )
    frame = pl.DataFrame(
        [vars(t) for t in out],
        schema={
            "name": pl.String,
            "files": pl.Int64,
            "bytes": pl.Int64,
            "rows": pl.Int64,
            "present": pl.Boolean,
        },
    )
    run(con, "create schema if not exists config")
    put(con, "config.bronze_tables", frame)
    return out
