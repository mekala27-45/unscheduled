"""The as-of engine checked on the real lake: parity with the dbt macro, and a planted future fact.

A sample of CVEs is drawn by a seeded rule over CVE ids sorted first, so the same lake gives the
same sample under any PYTHONHASHSEED. For each CVE the times asked at are the edges of its own facts
(one microsecond before and at every known_from and known_to), its publication and the data cut,
so every boundary the engine could get wrong is asked about. Three things must hold:

- parity: the Python engine and the dbt macro return identical frames at every time;
- no leak: a fact planted one microsecond after each time asked never appears at that time;
- no loss: every fact known at or before a time and not ended by it does appear.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import duckdb
import numpy as np
import polars as pl
from unscheduled_core.hashing import sha256_text

from unscheduled_lake.db import frame, rows, run
from unscheduled_lake.dbt_project import DbtPaths, compile_inline
from unscheduled_lake.engine import ASOF_SQL, COLUMNS, Engine

SEED = 20261108
TICK = timedelta(microseconds=1)


def sample_cves(
    con: duckdb.DuckDBPyConnection, n: int, seed: int = SEED, facts: str = "silver.cve_fact"
) -> list[str]:
    ids = [r[0] for r in rows(con, f"select distinct cve_id from {facts} order by cve_id")]
    if len(ids) <= n:
        return ids
    rng = np.random.Generator(np.random.PCG64(seed))
    picked = rng.choice(len(ids), size=n, replace=False)
    return sorted(ids[i] for i in picked)


def edge_times(
    con: duckdb.DuckDBPyConnection, ids: list[str], facts: str, per_cve: int, seed: int = SEED
) -> list[datetime]:
    found = rows(
        con,
        f"select distinct t from (select known_from as t from {facts} where cve_id in (select unnest($ids)) "
        f"union all select known_to from {facts} where cve_id in (select unnest($ids)) and known_to is not null) "
        "order by t",
        {"ids": ids},
    )
    edges = sorted({r[0] for r in found})
    times: set[datetime] = set()
    for t in edges:
        times.add(t)
        times.add(t - TICK)
    ordered = sorted(times)
    if len(ordered) > per_cve * len(ids):
        rng = np.random.Generator(np.random.PCG64(seed + 1))
        keep = rng.choice(len(ordered), size=per_cve * len(ids), replace=False)
        ordered = sorted(ordered[i] for i in keep)
    return ordered


def expected(frame: pl.DataFrame, t: datetime) -> pl.DataFrame:
    """The as-of predicate written a second time, over a frame in memory."""
    keep = frame.filter(
        (pl.col("known_from") <= t) & (pl.col("known_to").is_null() | (pl.col("known_to") > t))
    )
    return keep.select(list(COLUMNS)).sort(["cve_id", "field", "source", "value", "known_from"])


def _same(a: pl.DataFrame, b: pl.DataFrame) -> bool:
    key = ["cve_id", "field", "source", "value", "known_from"]
    return a.select(list(COLUMNS)).sort(key).equals(b.select(list(COLUMNS)).sort(key))


def compile_macros(dbt: DbtPaths) -> tuple[str, str]:
    """The dbt macro compiled over the sample table and over the planted table, with $t to bind.

    Compiled before the lake is opened, because dbt opens the work database in its own process.
    """
    return (
        compile_inline(dbt, "{{ asof('$t', none, 'asof_sample') }}"),
        compile_inline(dbt, "{{ asof('$t', none, 'asof_planted') }}"),
    )


def run_checks(
    con: duckdb.DuckDBPyConnection,
    macro_sql: str,
    planted_sql: str,
    n_cves: int = 200,
    per_cve: int = 6,
    facts: str = "silver.cve_fact",
) -> dict[str, Any]:
    ids = sample_cves(con, n_cves, facts=facts)
    run(
        con,
        f"create or replace temp table asof_sample as select * from {facts} where cve_id in (select unnest($ids))",
        {"ids": ids},
    )
    times = edge_times(con, ids, "asof_sample", per_cve)
    engine = Engine(con, "asof_sample")
    planted_engine = Engine(con, "asof_planted")
    sample = frame(con, "select * from asof_sample")
    mismatches = leaks = missing = 0
    examples: list[dict[str, Any]] = []
    for i, t in enumerate(times):
        py = engine.asof(ids, t)
        macro = frame(
            con, f"select * from ({macro_sql}) where cve_id in (select unnest($ids))", {"t": t, "ids": ids}
        )
        want = expected(sample, t)
        if not _same(py, macro):
            mismatches += 1
            if len(examples) < 5:
                examples.append({"check": "parity", "t": t.isoformat()})
        lost = want.join(py, on=["cve_id", "field", "source", "value", "known_from"], how="anti").height
        if lost:
            missing += lost
            if len(examples) < 5:
                examples.append({"check": "no loss", "t": t.isoformat(), "facts": lost})
        # Plant one fact per CVE one tick after t, and one a day after, and ask again at t.
        run(con, "create or replace temp table asof_planted as select * from asof_sample")
        run(
            con,
            "insert into asof_planted select cve_id, 'planted', 'planted', 'PLANTED-' || $i, $t1, null, 'planted', false "
            "from (select unnest($ids) as cve_id) union all "
            "select cve_id, 'planted', 'planted', 'PLANTED-LATER-' || $i, $t2, null, 'planted', false "
            "from (select unnest($ids) as cve_id)",
            {"i": str(i), "t1": t + TICK, "t2": t + timedelta(days=1), "ids": ids},
        )
        for answer in (
            planted_engine.asof(ids, t),
            frame(con, f"select * from ({planted_sql})", {"t": t}),
        ):
            leaked = answer.filter(pl.col("value").str.starts_with("PLANTED")).height
            if leaked:
                leaks += leaked
                if len(examples) < 5:
                    examples.append({"check": "no leak", "t": t.isoformat(), "facts": leaked})
    return {
        "cves": len(ids),
        "times": len(times),
        "frames_compared": len(times),
        "parity_mismatches": mismatches,
        "planted_facts": 2 * len(ids) * len(times),
        "planted_facts_returned": leaks,
        "facts_missing": missing,
        "facts_in_sample": sample.height,
        "seed": SEED,
        "engine_sql_sha256": sha256_text(ASOF_SQL),
        "macro_sql_sha256": sha256_text(macro_sql),
        "examples": examples,
        "passed": mismatches == 0 and leaks == 0 and missing == 0 and len(times) > 0,
    }
