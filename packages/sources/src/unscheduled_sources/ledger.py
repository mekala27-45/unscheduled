"""The run ledger: one JSON line per unit of work a fetcher finished, failed or was refused.

data/locks/ledger.jsonl is append only. A row says which source, which window (a day, a page of a
window, a release asset), how many rows went in, how many of them were new to bronze, the digest of
the raw input, how long it took and how it ended. A resumed run reads the ledger to skip the units
already done, so a fetch that stops halfway (a time budget, a dropped connection, a reboot) picks up
at the next unit and never refetches a finished one.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from pydantic import Field
from unscheduled_core.model import StrictModel

from unscheduled_sources.timeutil import iso, utcnow

Status = Literal["ok", "failed", "refused", "empty"]


class LedgerRow(StrictModel):
    source: str
    window: str
    rows_in: int = Field(ge=0)
    rows_changed: int = Field(ge=0)
    digest: str
    duration_s: float = Field(ge=0)
    status: Status
    finished_at: str = Field(default_factory=lambda: iso(utcnow()))
    note: str | None = None


def ledger_path(locks_dir: Path) -> Path:
    return locks_dir / "ledger.jsonl"


def append(locks_dir: Path, row: LedgerRow) -> None:
    path = ledger_path(locks_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(json.loads(row.model_dump_json(exclude_none=True)), sort_keys=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()


def rows(locks_dir: Path, source: str | None = None) -> Iterator[LedgerRow]:
    path = ledger_path(locks_dir)
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = LedgerRow.model_validate_json(line)
            if source is None or row.source == source:
                yield row


def done(locks_dir: Path, source: str) -> set[str]:
    """The windows of a source that finished ok or empty, which a resumed run skips."""
    return {r.window for r in rows(locks_dir, source) if r.status in ("ok", "empty")}
