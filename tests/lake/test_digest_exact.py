"""A table digest is exact: the same rows give the same digest in any order and on any thread count."""

from __future__ import annotations

import duckdb
from unscheduled_core.hashing import sha256_json
from unscheduled_lake.digest import table_digest


def _table(con: duckdb.DuckDBPyConnection, order: str) -> None:
    con.execute(
        "create or replace table t as select 'CVE-2026-' || i as cve_id, i * 0.5 as score, "
        f"timestamptz '2026-04-15 00:00:00+00' + to_seconds(i) as known_at from range(300000) r(i) order by {order}"
    )


def test_the_digest_does_not_depend_on_row_order_or_threads() -> None:
    con = duckdb.connect()
    con.execute("set threads = 4")
    _table(con, "i")
    first = table_digest(con, "main.t")["digest"]
    _table(con, "hash(i)")
    con.execute("set threads = 1")
    assert table_digest(con, "main.t")["digest"] == first
    con.execute("set threads = 4")
    assert all(table_digest(con, "main.t")["digest"] == first for _ in range(3))


def test_the_sums_are_exact_integers() -> None:
    # The digest is rebuilt here from the row hashes summed in Python, where integers are exact; a sum
    # taken as a DOUBLE would print in floating point and not match.
    con = duckdb.connect()
    _table(con, "i")
    hashes = [
        int(h)
        for (h,) in con.execute(
            "select md5_number(concat_ws(chr(31), coalesce(cast(cve_id as varchar), chr(0)), "
            "coalesce(cast(score as varchar), chr(0)), coalesce(cast(known_at as varchar), chr(0)))) from t"
        ).fetchall()
    ]
    xor = 0
    for h in hashes:
        xor ^= h
    expected = sha256_json(
        {
            "columns": ["cve_id", "score", "known_at"],
            "rows": len(hashes),
            "xor": str(xor),
            "high": str(sum(h >> 64 for h in hashes)),
            "low": str(sum(h & (2**64 - 1) for h in hashes)),
        }
    )
    assert table_digest(con, "main.t")["digest"] == expected
