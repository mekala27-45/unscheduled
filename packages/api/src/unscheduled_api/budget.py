"""The per client daily budget, keyed by a salted hash of the client address, never the address.

The salt is made by the API the first time it starts against a database (32 random bytes, kept in
the settings table under client_salt) and read from there by every instance after, so nobody ever
types it and two instances hash a client the same way. A client is the first 32 hex digits of
sha256(salt:address). The count is taken and checked in one upsert that returns the new count, so
two requests in the same instant cannot both slip under the limit. The day is the UTC day; the
limits are the ones in config/budgets.yaml.

The address is the one Vercel's edge reports (x-vercel-forwarded-for, then x-real-ip), which a
client cannot set through the edge, and the socket peer otherwise.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta

import sqlalchemy as sa
from fastapi import Request

from unscheduled_api.db import qualified
from unscheduled_api.problems import ProblemError

SALT_KEY = "client_salt"
LOOKUPS = "lookups"
MATCHES = "matches"


def client_address(request: Request) -> str:
    for header in ("x-vercel-forwarded-for", "x-real-ip"):
        value = request.headers.get(header, "").split(",")[0].strip()
        if value:
            return value
    return request.client.host if request.client else "unknown"


def client_hash(salt: str, address: str) -> str:
    return hashlib.sha256(f"{salt}:{address}".encode()).hexdigest()[:32]


def ensure_salt(conn: sa.Connection, schema: str) -> str:
    """The salt, made on the first start against this database and read back on every later one."""
    table = qualified(schema, "settings")
    conn.execute(
        sa.text(
            f"insert into {table} (key, value, updated_at) "
            "values (:k, jsonb_build_object('salt', cast(:salt as text)), now()) on conflict (key) do nothing"
        ),
        {"k": SALT_KEY, "salt": secrets.token_hex(32)},
    )
    value = conn.execute(
        sa.text(f"select value ->> 'salt' from {table} where key = :k"), {"k": SALT_KEY}
    ).scalar()
    if not value:
        raise RuntimeError("the client salt could not be read back")
    return str(value)


class Budget:
    def __init__(
        self,
        engine: sa.Engine,
        schema: str,
        limits: dict[str, int],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.engine = engine
        self.schema = schema
        self.limits = dict(limits)
        self.clock = clock or (lambda: datetime.now(UTC))
        self._salt: str | None = None
        self._lock = threading.Lock()

    def salt(self) -> str:
        with self._lock:
            if self._salt is None:
                with self.engine.begin() as conn:
                    self._salt = ensure_salt(conn, self.schema)
            return self._salt

    def client(self, address: str) -> str:
        return client_hash(self.salt(), address)

    def charge(self, address: str, kind: str) -> tuple[str, int, int]:
        """Count one request; (client, used, limit). Past the limit, raise budget-exhausted."""
        limit = self.limits[kind]
        client = self.client(address)
        now = self.clock()
        day: date = now.date()
        table = qualified(self.schema, "client_budget")
        with self.engine.begin() as conn:
            used = int(
                conn.execute(
                    sa.text(
                        f"insert into {table} as b (client, day, kind, used) values (:c, :d, :k, 1) "
                        "on conflict (client, day, kind) do update set used = b.used + 1 returning used"
                    ),
                    {"c": client, "d": day, "k": kind},
                ).scalar_one()
            )
        if used > limit:
            midnight = datetime.combine(day + timedelta(days=1), datetime.min.time(), tzinfo=UTC)
            raise ProblemError(
                "budget-exhausted",
                f"this client has used its {limit} {kind} for today; the budget resets at midnight UTC",
                retry_after_s=int((midnight - now).total_seconds()) + 1,
                context={"kind": kind, "limit": limit, "used": used},
                headers={"X-Budget-Limit": str(limit), "X-Budget-Remaining": "0"},
            )
        return client, used, limit
