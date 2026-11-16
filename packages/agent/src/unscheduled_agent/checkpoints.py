"""The Postgres checkpointer of the triage graph, for the API: the LangGraph saver over a direct
connection whose search path is the checkpoint schema migration 0005 creates beside the API's own.

The saver's tables are set up once per process and database, under an advisory lock, so two function
instances starting together cannot both run its migrations. It needs a direct connection: the saver
prepares its statements and the search path is a session setting, neither of which a transaction
pooler keeps, which is why the API prefers DATABASE_URL_UNPOOLED.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import sql
from psycopg.rows import dict_row

SETUP_LOCK = 0x756E7363  # the advisory lock key of the setup, the same in every instance
_READY: set[str] = set()


@contextmanager
def saver(url: str, schema: str) -> Iterator[PostgresSaver]:
    key = hashlib.sha256(f"{url}|{schema}".encode()).hexdigest()
    with psycopg.connect(url, autocommit=True, prepare_threshold=0, row_factory=dict_row) as conn:
        conn.execute("set time zone 'UTC'")
        conn.execute(sql.SQL("set search_path to {}").format(sql.Identifier(schema)))
        found = PostgresSaver(conn)
        if key not in _READY:
            conn.execute("select pg_advisory_lock(%s)", (SETUP_LOCK,))
            try:
                found.setup()
            finally:
                conn.execute("select pg_advisory_unlock(%s)", (SETUP_LOCK,))
            _READY.add(key)
        yield found
