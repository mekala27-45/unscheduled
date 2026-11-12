"""The data version every response carries, read from the settings table and held for a few seconds.

The sync writes the descriptor of the bundle it finished loading under the key data_version, and the
cursor of a load in progress under the key sync. Every response names the newest complete bundle;
while a newer one loads, rows may already come from it, and /health says which one is loading. The
value is cached per process for fifteen seconds, and the process that ran the finalize drops its
cache at once.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa

from unscheduled_api.db import qualified
from unscheduled_api.sync import version_label

NONE = "none"
UNAVAILABLE = "unavailable"
TTL_S = 15.0
FAILURE_TTL_S = 5.0  # a database that did not answer is not asked again by every request


@dataclass(frozen=True)
class DataState:
    label: str
    loaded: dict[str, Any] | None
    loading: dict[str, Any] | None
    release_check: dict[str, Any] | None


def read_state(conn: sa.Connection, schema: str) -> DataState:
    rows = conn.execute(
        sa.text(
            f"select key, value from {qualified(schema, 'settings')} "
            "where key in ('data_version', 'sync', 'release_check')"
        )
    ).all()
    values: dict[str, Any] = {str(r.key): r.value for r in rows}
    loaded = values.get("data_version")
    loading = values.get("sync")
    label = version_label(loaded["tag"], loaded["manifest_sha256"]) if loaded else NONE
    return DataState(label=label, loaded=loaded, loading=loading, release_check=values.get("release_check"))


class VersionCache:
    def __init__(
        self, engine: sa.Engine | None, schema: str, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.engine = engine
        self.schema = schema
        self.clock = clock
        self._lock = threading.Lock()
        self._value: DataState | None = None
        self._at: float | None = None

    def state(self) -> DataState | None:
        """The state, or None when there is no database to read it from or it did not answer."""
        if self.engine is None:
            return None
        with self._lock:
            if self._at is not None:
                age = self.clock() - self._at
                if age < (TTL_S if self._value is not None else FAILURE_TTL_S):
                    return self._value
        value: DataState | None
        try:
            with self.engine.connect() as conn:
                value = read_state(conn, self.schema)
        except sa.exc.SQLAlchemyError:
            value = None
        with self._lock:
            self._value, self._at = value, self.clock()
        return value

    def label(self) -> str:
        if self.engine is None:
            return NONE
        state = self.state()
        return state.label if state is not None else UNAVAILABLE

    def invalidate(self) -> None:
        with self._lock:
            self._value = None
            self._at = None
