"""The one interface every source implements, and the driver that runs it.

A fetcher names its units of work (a release asset, a page of a window, a day, a repository at a
commit), fetches each unit into raw files hashed on arrival, and parses raw files into bronze
frames. The driver does the rest the same way for every source: it skips units the ledger already
holds when resuming, checks a pinned file against its lock before parsing, writes the frames to
bronze, records the lock entries with the rows parsed, appends the ledger row, and deletes the raw
files unless they are kept for upload. A refusal is recorded and, where the fetcher allows it, the
run goes on; any other failure is recorded and stops the run.

Lock entry names are "<unit>::<file>", so the files of one unit can be found again in a lock and
parsed again from a release without the network.
"""

from __future__ import annotations

import contextlib
import hashlib
import shutil
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, ClassVar

import polars as pl

from unscheduled_sources import ledger, locks
from unscheduled_sources.bronze import Bronze
from unscheduled_sources.http import Http, Refused
from unscheduled_sources.timeutil import iso, parse_ts, utcnow

SEPARATOR = "::"

Output = tuple[str, pl.DataFrame] | tuple[str, pl.DataFrame, str]


@dataclass
class RawFile:
    """A file as a source gave it, hashed on arrival. `rows` is set by the parser."""

    unit: str
    file: str
    url: str
    path: Path
    sha256: str
    size: int
    fetched_at: datetime
    pinned: bool = False
    rows: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return f"{self.unit}{SEPARATOR}{self.file}"

    def entry(self) -> locks.LockEntry:
        return locks.LockEntry(
            name=self.name,
            url=self.url,
            sha256=self.sha256,
            size=self.size,
            fetched_at=iso(self.fetched_at),
            rows=self.rows,
        )


@dataclass(frozen=True)
class Unit:
    name: str
    window: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Context:
    root: Path
    raw_dir: Path
    bronze: Bronze
    locks_dir: Path
    cache_dir: Path
    config: dict[str, Any]
    keep_raw: bool = False
    resume: bool = True
    budget_s: float | None = None
    today: date = field(default_factory=lambda: utcnow().date())
    log: Callable[[str], None] = print
    http_factory: Callable[..., Http] = Http
    env: dict[str, str] = field(default_factory=dict)

    def source_config(self, source: str) -> dict[str, Any]:
        sources: dict[str, Any] = self.config.get("sources", {})
        if source not in sources:
            raise KeyError(f"config/sources.yaml has no source {source!r}")
        section: dict[str, Any] = sources[source]
        return section


@dataclass
class RunSummary:
    source: str
    units: int = 0
    skipped: int = 0
    rows_in: int = 0
    rows_changed: int = 0
    refused: list[str] = field(default_factory=list)
    stopped_early: bool = False


class Fetcher(ABC):
    source: ClassVar[str]
    tables: ClassVar[tuple[str, ...]]
    # A refusal of one unit (a registry that declines an anonymous client) is a result, not a crash.
    refusal_is_result: ClassVar[bool] = False

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.cfg = ctx.source_config(self.source)

    @property
    def raw_root(self) -> Path:
        return self.ctx.raw_dir / self.source

    @abstractmethod
    def units(self) -> Iterator[Unit]:
        """The units of work, in order. May read what earlier units fetched."""

    @abstractmethod
    def fetch(self, unit: Unit) -> list[RawFile]:
        """Fetch one unit into raw files under raw_root, each hashed on arrival."""

    @abstractmethod
    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        """Parse the raw files of one unit into (table, frame) pairs; set rows on each raw file.

        A snapshot table (mode replace) is yielded as (table, frame, slot): the slot names the file
        the snapshot replaces, so each run rewrites the same file instead of adding one.
        """

    def finish(self) -> None:
        for name in self.tables:
            self.ctx.bronze.compact(name)

    def close(self) -> None:
        return None

    def raw_from_entry(self, entry: locks.LockEntry, path: Path) -> RawFile:
        unit, _, file = entry.name.partition(SEPARATOR)
        fetched = parse_ts(entry.fetched_at)
        assert fetched is not None
        return RawFile(unit, file, entry.url, path, entry.sha256, entry.size, fetched, pinned=True)


def combined_digest(raws: list[RawFile]) -> str:
    digest = hashlib.sha256()
    for raw in sorted(raws, key=lambda r: r.name):
        digest.update(f"{raw.name}\0{raw.sha256}\n".encode())
    return digest.hexdigest()


def batch_id(source: str, raws: list[RawFile]) -> str:
    unit = raws[0].unit if raws else "empty"
    return f"{source}-{unit}-{combined_digest(raws)[:12]}"


def _check_pins(source: str, current: locks.SourceLock, raws: list[RawFile]) -> None:
    names = current.names()
    for raw in raws:
        locks.verify(raw.path, raw.entry())
        if raw.pinned and raw.name in names:
            expected = current.entry(raw.name)
            if expected.sha256 != raw.sha256 or expected.size != raw.size:
                raise locks.LockMismatch(
                    f"{source} {raw.name}: the pinned file changed, sha256 {raw.sha256[:12]} "
                    f"where the lock says {expected.sha256[:12]}"
                )


def _discard(raws: list[RawFile]) -> None:
    folders = set()
    for raw in raws:
        folders.add(raw.path.parent)
        if raw.path.is_dir():
            shutil.rmtree(raw.path, ignore_errors=True)
        else:
            raw.path.unlink(missing_ok=True)
    for folder in folders:
        with contextlib.suppress(OSError):
            folder.rmdir()


def parse_unit(fetcher: Fetcher, raws: list[RawFile]) -> tuple[int, int]:
    """Parse raw files already on disk into bronze; returns rows in and rows changed."""
    rows_in = 0
    changed = 0
    bid = batch_id(fetcher.source, raws)
    for output in fetcher.parse(raws):
        name, frame = output[0], output[1]
        slot = output[2] if len(output) == 3 else bid
        result = fetcher.ctx.bronze.write(name, frame, slot)
        rows_in += result.rows_in
        changed += result.rows_changed
    return rows_in, changed


def run(fetcher: Fetcher) -> RunSummary:
    ctx = fetcher.ctx
    source = fetcher.source
    summary = RunSummary(source)
    finished = ledger.done(ctx.locks_dir, source) if ctx.resume else set()
    started = time.monotonic()
    try:
        for unit in fetcher.units():
            if ctx.budget_s is not None and time.monotonic() - started > ctx.budget_s:
                summary.stopped_early = True
                ctx.log(f"{source}: time budget spent, stopping before {unit.window}")
                break
            if unit.window in finished:
                summary.skipped += 1
                continue
            _run_unit(fetcher, unit, summary)
        fetcher.finish()
    finally:
        fetcher.close()
    return summary


def _run_unit(fetcher: Fetcher, unit: Unit, summary: RunSummary) -> None:
    ctx = fetcher.ctx
    source = fetcher.source
    t0 = time.monotonic()
    raws: list[RawFile] = []
    try:
        raws = fetcher.fetch(unit)
        if not raws:
            ledger.append(
                ctx.locks_dir,
                ledger.LedgerRow(
                    source=source,
                    window=unit.window,
                    rows_in=0,
                    rows_changed=0,
                    digest="",
                    duration_s=round(time.monotonic() - t0, 3),
                    status="empty",
                ),
            )
            return
        _check_pins(source, locks.load(ctx.locks_dir, source), raws)
        rows_in, changed = parse_unit(fetcher, raws)
        locks.record(ctx.locks_dir, source, [r.entry() for r in raws])
        notes = [str(r.meta["note"]) for r in raws if r.meta.get("note")]
        ledger.append(
            ctx.locks_dir,
            ledger.LedgerRow(
                source=source,
                window=unit.window,
                rows_in=rows_in,
                rows_changed=changed,
                digest=combined_digest(raws),
                duration_s=round(time.monotonic() - t0, 3),
                status="ok",
                note="; ".join(notes) if notes else None,
            ),
        )
        summary.units += 1
        summary.rows_in += rows_in
        summary.rows_changed += changed
        ctx.log(f"{source}: {unit.window}: {rows_in} rows in, {changed} new")
    except Refused as refusal:
        ledger.append(
            ctx.locks_dir,
            ledger.LedgerRow(
                source=source,
                window=unit.window,
                rows_in=0,
                rows_changed=0,
                digest="",
                duration_s=round(time.monotonic() - t0, 3),
                status="refused",
                note=f"HTTP {refusal.status} from {refusal.url}",
            ),
        )
        summary.refused.append(unit.window)
        ctx.log(f"{source}: {unit.window}: refused with HTTP {refusal.status}")
        if not fetcher.refusal_is_result:
            raise
    except Exception as error:
        ledger.append(
            ctx.locks_dir,
            ledger.LedgerRow(
                source=source,
                window=unit.window,
                rows_in=0,
                rows_changed=0,
                digest=combined_digest(raws) if raws else "",
                duration_s=round(time.monotonic() - t0, 3),
                status="failed",
                note=f"{type(error).__name__}: {str(error)[:300]}",
            ),
        )
        raise
    finally:
        if not ctx.keep_raw:
            _discard(raws)


def reparse(fetcher: Fetcher, raw_dir: Path) -> RunSummary:
    """Parse every unit of a source again from raw files on disk, each checked against its lock.

    The files are found under raw_dir by their lock entry name; a file that is missing or differs
    from its lock raises LockMismatch before anything is parsed.
    """
    current = locks.load(fetcher.ctx.locks_dir, fetcher.source)
    groups: dict[str, list[RawFile]] = {}
    for entry in current.entries:
        unit, _, file = entry.name.partition(SEPARATOR)
        path = raw_dir / unit / file
        locks.verify(path, entry)
        groups.setdefault(unit, []).append(fetcher.raw_from_entry(entry, path))
    summary = RunSummary(fetcher.source)
    for unit in sorted(groups):
        rows_in, changed = parse_unit(fetcher, groups[unit])
        summary.units += 1
        summary.rows_in += rows_in
        summary.rows_changed += changed
    fetcher.finish()
    return summary
