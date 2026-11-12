"""Digests of the lake: of the file as published, and of each table's content.

The file digest is what the release and the API check. The content digest is what makes a rebuild
provably idempotent: it is taken over every row of a table, independent of row order and of how
DuckDB laid the file out, so two builds from the same bronze give the same digest even when their
files differ byte for byte.
"""

from __future__ import annotations

import duckdb
from unscheduled_core.hashing import sha256_json

from unscheduled_lake.db import one, rows


def columns(con: duckdb.DuckDBPyConnection, qualified: str) -> list[str]:
    schema, name = qualified.split(".", 1)
    found = rows(
        con,
        "select column_name from information_schema.columns where table_schema = ? and table_name = ? "
        "order by ordinal_position",
        [schema, name],
    )
    return [str(r[0]) for r in found]


def table_digest(con: duckdb.DuckDBPyConnection, qualified: str) -> dict[str, object]:
    """Rows, and an order free digest of every row: count, the xor and the sum of 128 bit row hashes."""
    cols = columns(con, qualified)
    if not cols:
        raise ValueError(f"{qualified} has no columns")
    cells = ", ".join(f"coalesce(cast({_q(c)} as varchar), chr(0))" for c in cols)
    count, xor, high, low = one(
        con,
        f"select count(*), cast(bit_xor(h) as varchar), cast(sum(h >> 64) as varchar), "
        f"cast(sum(h & 18446744073709551615) as varchar) "
        f"from (select md5_number(concat_ws(chr(31), {cells})) as h from {qualified})",
    )
    return {
        "rows": int(count),
        "columns": cols,
        "digest": sha256_json({"columns": cols, "rows": int(count), "xor": xor, "high": high, "low": low}),
    }


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'
