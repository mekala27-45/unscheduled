"""What the API can say about its own database, read on the live host and never a connection value.

The probe (results/probe.json) and /health both read these: the server version, whether pgvector is
available for Phase 3 and whether it is installed, the database size against the ceiling in
config/budgets.yaml, the Alembic revision, and the names, only the names, of the connection
variables the container found. An error is reported by its class name alone, because a driver
message can carry a host name. The facts are held for thirty seconds so a status page that polls
/health does not keep a free tier compute awake.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

import sqlalchemy as sa

from unscheduled_api.db import qualified
from unscheduled_api.schemas import DatabaseFacts, LastSync
from unscheduled_api.settings import Settings

TTL_S = 30.0


def read_facts(engine: sa.Engine | None, settings: Settings) -> DatabaseFacts:
    ceiling_mb = settings.budgets.storage_ceiling_mb
    ceiling = settings.budgets.storage_ceiling_bytes
    base: dict[str, object] = {
        "configured": settings.database_configured,
        "variable": settings.database_variable,
        "variables_found": list(settings.variables_found),
        "schema_name": settings.schema,
        "storage_ceiling_mb": ceiling_mb,
        "storage_ceiling_bytes": ceiling,
    }
    empty: dict[str, object] = {
        "reachable": False,
        "migration": None,
        "server_version": None,
        "pgvector_available": None,
        "pgvector_installed": None,
        "database_size_bytes": None,
        "storage_share_used": None,
    }
    if engine is None:
        return DatabaseFacts.model_validate({**base, **empty, "error": None})
    try:
        with engine.connect() as conn:
            version = conn.execute(sa.text("show server_version")).scalar()
            available = conn.execute(
                sa.text("select exists (select 1 from pg_available_extensions where name = 'vector')")
            ).scalar()
            installed = conn.execute(
                sa.text("select exists (select 1 from pg_extension where extname = 'vector')")
            ).scalar()
            size = int(conn.execute(sa.text("select pg_database_size(current_database())")).scalar() or 0)
            migration = conn.execute(
                sa.text(f"select version_num from {qualified(settings.schema, 'alembic_version')} limit 1")
                if _has_version_table(conn, settings.schema)
                else sa.text("select null")
            ).scalar()
    except sa.exc.SQLAlchemyError as err:
        cause = err.orig if isinstance(err, sa.exc.DBAPIError) and err.orig is not None else err
        return DatabaseFacts.model_validate({**base, **empty, "error": type(cause).__name__})
    return DatabaseFacts.model_validate(
        {
            **base,
            "reachable": True,
            "migration": str(migration) if migration is not None else None,
            "server_version": str(version) if version is not None else None,
            "pgvector_available": bool(available),
            "pgvector_installed": bool(installed),
            "database_size_bytes": size,
            "storage_share_used": round(size / ceiling, 4) if ceiling else None,
            "error": None,
        }
    )


def _has_version_table(conn: sa.Connection, schema: str) -> bool:
    found = conn.execute(
        sa.text(
            "select exists (select 1 from information_schema.tables "
            "where table_schema = :s and table_name = 'alembic_version')"
        ),
        {"s": schema},
    ).scalar()
    return bool(found)


def read_last_sync(engine: sa.Engine | None, schema: str) -> LastSync | None:
    """The newest row of the run ledger, or None when there is none or the table cannot be read."""
    if engine is None:
        return None
    try:
        with engine.connect() as conn:
            row = conn.execute(
                sa.text(
                    f"select started_at, status, step, bundle from {qualified(schema, 'ops_run')} "
                    "where kind = 'sync' order by started_at desc, id desc limit 1"
                )
            ).first()
    except sa.exc.SQLAlchemyError:
        return None
    if row is None:
        return None
    return LastSync(at=row.started_at, status=str(row.status), step=row.step, bundle=row.bundle)


class FactsCache:
    def __init__(
        self, engine: sa.Engine | None, settings: Settings, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.clock = clock
        self._lock = threading.Lock()
        self._value: tuple[DatabaseFacts, LastSync | None] | None = None
        self._at = 0.0

    def get(self) -> tuple[DatabaseFacts, LastSync | None]:
        with self._lock:
            if self._value is not None and self.clock() - self._at < TTL_S:
                return self._value
        facts = read_facts(self.engine, self.settings)
        last = read_last_sync(self.engine, self.settings.schema) if facts.reachable else None
        value = (facts, last)
        with self._lock:
            self._value, self._at = value, self.clock()
        return value

    def invalidate(self) -> None:
        with self._lock:
            self._value = None
