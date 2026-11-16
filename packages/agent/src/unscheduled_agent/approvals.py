"""Approvals by hash: the only way a plan becomes approved or a warning becomes ready (C7).

An approval is a record of a person's decision on one draft, named by the sha256 of the verified
draft it was shown. The status of a draft is read, every time, from the draft as it stands: its hash
is taken again from its content, and only a record with that hash, made with the approver's token,
counts. So a draft changed after it was approved has a new hash and no approval, a decision on a
hash nobody was shown counts for nothing, and no state of the graph or of the API can mark a draft
approved or ready on its own.

The approver's token never reaches the build: Vercel holds only its SHA-256 as APPROVER_TOKEN_SHA256,
and the check compares digests in constant time. Nothing applies a plan or files a warning; an
approved plan and a ready warning are records a person acts on.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import psycopg

from unscheduled_agent.schemas import EarlyWarning, PatchPlan
from unscheduled_agent.verify import draft_sha256

TOKEN_ENV = "APPROVER_TOKEN_SHA256"
Kind = Literal["plan", "warning"]
Status = Literal["absent", "blocked", "waiting", "approved", "ready", "rejected"]


def token_ok(token: str | None, expected_sha256: str | None = None) -> bool:
    expected = expected_sha256 if expected_sha256 is not None else os.environ.get(TOKEN_ENV)
    if not token or not expected:
        return False
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, expected.strip().lower())


@dataclass(frozen=True)
class Approval:
    run_id: str
    kind: Kind
    sha256: str
    decision: Literal["approve", "reject"]
    by: str
    at: str
    token_ok: bool

    def row(self) -> dict[str, Any]:
        return asdict(self)


class Store(Protocol):
    def add(self, approval: Approval) -> None: ...

    def records(self, run_id: str) -> list[Approval]: ...


class MemoryStore:
    def __init__(self) -> None:
        self.rows: list[Approval] = []

    def add(self, approval: Approval) -> None:
        self.rows.append(approval)

    def records(self, run_id: str) -> list[Approval]:
        return [r for r in self.rows if r.run_id == run_id]


TABLE = """
create table if not exists {schema}.agent_approval (
    id bigint generated always as identity primary key,
    run_id text not null,
    kind text not null check (kind in ('plan', 'warning')),
    sha256 text not null check (length(sha256) = 64),
    decision text not null check (decision in ('approve', 'reject')),
    decided_by text not null,
    decided_at timestamptz not null,
    token_ok boolean not null
);
create index if not exists agent_approval_run on {schema}.agent_approval (run_id);
"""


class PostgresStore:
    """Approvals as rows that are only ever added: a decision is never edited or deleted."""

    def __init__(self, conn: psycopg.Connection[Any], schema: str) -> None:
        self.conn = conn
        self.schema = schema
        with conn.cursor() as cur:
            cur.execute(TABLE.format(schema=schema))
        conn.commit()

    def add(self, approval: Approval) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                f"insert into {self.schema}.agent_approval (run_id, kind, sha256, decision, decided_by, decided_at, token_ok) "
                "values (%s, %s, %s, %s, %s, %s, %s)",
                (
                    approval.run_id,
                    approval.kind,
                    approval.sha256,
                    approval.decision,
                    approval.by,
                    approval.at,
                    approval.token_ok,
                ),
            )
        self.conn.commit()

    def records(self, run_id: str) -> list[Approval]:
        with self.conn.cursor() as cur:
            cur.execute(
                f"select run_id, kind, sha256, decision, decided_by, decided_at, token_ok from {self.schema}.agent_approval "
                "where run_id = %s order by id",
                (run_id,),
            )
            return [
                Approval(str(r[0]), r[1], str(r[2]), r[3], str(r[4]), r[5].isoformat(), bool(r[6]))
                for r in cur.fetchall()
            ]


def record(
    store: Store,
    run_id: str,
    kind: Kind,
    sha256: str,
    decision: Literal["approve", "reject"],
    by: str,
    token: str | None,
    expected_sha256: str | None = None,
) -> Approval:
    """Keep a person's decision on the draft of that hash; without the token it is kept and counts for nothing."""
    approval = Approval(
        run_id=run_id,
        kind=kind,
        sha256=sha256,
        decision=decision,
        by=by,
        at=datetime.now(UTC).isoformat(timespec="seconds"),
        token_ok=token_ok(token, expected_sha256),
    )
    store.add(approval)
    return approval


def status(store: Store, run_id: str, kind: Kind, check: dict[str, Any] | None) -> Status:
    """The status of a run's draft, from the draft as it stands now and the approvals with its hash."""
    if not check:
        return "absent"
    if check.get("blocked"):
        return "blocked"
    schema = PatchPlan if kind == "plan" else EarlyWarning
    current = draft_sha256(schema.model_validate(check["draft"]))
    counted = [r for r in store.records(run_id) if r.kind == kind and r.sha256 == current and r.token_ok]
    if not counted:
        return "waiting"
    if counted[-1].decision == "approve":
        return "approved" if kind == "plan" else "ready"
    return "rejected"
