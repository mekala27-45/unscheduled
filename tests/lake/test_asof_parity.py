"""The dbt macro and the Python engine are one rule: on the same facts they return the same frames.

dbt/macros/asof.sql is rendered with Jinja exactly as dbt would render it (ref() is not reached,
because the fact relation is passed in), run on DuckDB, and compared with Engine.asof row for row.
The as-of join macro is held to a direct filter in the same way.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random

import duckdb
import jinja2
import polars as pl
from unscheduled_lake.db import frame
from unscheduled_lake.engine import COLUMNS, Engine

from tests.lake.conftest import Fact, make_table

MACROS = Path(__file__).resolve().parents[2] / "dbt" / "macros" / "asof.sql"
START = datetime(2024, 1, 1, tzinfo=UTC)


def render(call: str, **values: object) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.globals["ref"] = lambda name: f"silver.{name}"
    template = env.from_string(MACROS.read_text(encoding="utf-8") + "\n" + call)
    return template.render(**values)


def random_facts(seed: int, n: int = 300) -> list[Fact]:
    rng = Random(seed)
    out: list[Fact] = []
    for i in range(n):
        start = START + timedelta(hours=rng.randrange(0, 24 * 700))
        end = None if rng.random() < 0.4 else start + timedelta(hours=rng.randrange(1, 24 * 200))
        out.append(
            Fact(
                f"CVE-2025-{rng.randrange(1, 30):04d}",
                rng.choice(["nvd_status", "severity", "cwe", "kev"]),
                rng.choice(["nvd", "filer", "cisa_adp", "kev"]),
                f"v{i}",
                start,
                end,
            )
        )
    return out


def sorted_frame(frame: pl.DataFrame) -> pl.DataFrame:
    return frame.select(list(COLUMNS)).sort(list(COLUMNS))


def test_the_macro_and_the_engine_return_the_same_frames(con: duckdb.DuckDBPyConnection) -> None:
    rng = Random(7)
    make_table(con, random_facts(11))
    engine = Engine(con)
    for _ in range(25):
        t = START + timedelta(hours=rng.randrange(0, 24 * 800))
        ids = sorted({f"CVE-2025-{rng.randrange(1, 30):04d}" for _ in range(rng.randrange(1, 8))})
        sql = render("{{ asof('$t', cve_ids, 'silver.cve_fact') }}", cve_ids=ids)
        from_macro = frame(con, sql, {"t": t})
        from_engine = engine.asof(ids, t)
        assert sorted_frame(from_macro).equals(sorted_frame(from_engine))


def test_the_macro_over_every_cve_matches_the_whole_frame(con: duckdb.DuckDBPyConnection) -> None:
    make_table(con, random_facts(12))
    t = START + timedelta(days=300)
    sql = render("{{ asof('$t', none, 'silver.cve_fact') }}")
    from_macro = frame(con, sql, {"t": t})
    assert sorted_frame(from_macro).equals(sorted_frame(Engine(con).asof_frame(t)))


def test_the_join_macro_takes_the_time_from_each_row(con: duckdb.DuckDBPyConnection) -> None:
    rows = random_facts(13)
    make_table(con, rows)
    con.execute("create table asks (cve_id varchar, asked_at timestamptz)")
    rng = Random(3)
    asks = [
        (f"CVE-2025-{rng.randrange(1, 30):04d}", START + timedelta(hours=rng.randrange(0, 24 * 800)))
        for _ in range(40)
    ]
    con.executemany("insert into asks values (?, ?)", asks)
    sql = render("{{ asof_join('asks', 'asked_at', ['nvd_status', 'kev'], 'silver.cve_fact') }}")
    got = sorted(
        (r[0], r[1], r[2], r[3], r[4])
        for r in con.execute(f"select cve_id, asked_at, field, source, value from ({sql})").fetchall()
    )
    expected = sorted(
        (cve, at, f.field, f.source, f.value)
        for cve, at in asks
        for f in rows
        if f.cve_id == cve
        and f.field in {"nvd_status", "kev"}
        and f.known_from <= at
        and (f.known_to is None or f.known_to > at)
    )
    assert got == expected
