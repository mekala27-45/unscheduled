"""Reading the lake: the marts the questions are computed from, through one read only connection."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import polars as pl
import yaml
from unscheduled_core import paths


def connect(path: Path | None = None) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(path or paths.lake_file()), read_only=True)
    con.execute("set TimeZone = 'UTC'").fetchall()
    return con


def frame(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> pl.DataFrame:
    out: pl.DataFrame = con.sql(sql, params=params).pl()
    return out


def scalar(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> Any:
    found = con.execute(sql, params).fetchall()
    return found[0][0] if found else None


def data_cut(con: duckdb.DuckDBPyConnection) -> datetime:
    """The cut the lake was built at: the newest time any source was seen, as dbt was told."""
    value = scalar(con, "select data_cut from config.lake_build")
    if value is None:
        raise RuntimeError("the lake records no data cut; build it with scripts/build_lake.py")
    cut: datetime = value
    return cut


def plan(root: Path | None = None) -> dict[str, dict[str, Any]]:
    """The registered Phase 1 plan, by question id, exactly as evaluation/phase1_plan.yaml states it."""
    path = (root or paths.root()) / "evaluation" / "phase1_plan.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {str(q["id"]): dict(q) for q in data["questions"]}
    for q in out.values():
        q.setdefault("interval", data["defaults"]["interval"])
        q.setdefault("family_correction", data["defaults"]["family_correction"])
    return out
