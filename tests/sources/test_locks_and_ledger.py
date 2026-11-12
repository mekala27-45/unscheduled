"""Locks fail on any mismatch; the ledger resumes a run at the next unit."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import polars as pl
import pytest
from unscheduled_sources import base, ledger, locks
from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.locks import LockEntry, LockMismatch

from tests.sources.conftest import make_context

WHEN = datetime(2026, 11, 8, 3, 0, tzinfo=UTC)


def _entry(path: Path, name: str = "unit::file.json") -> LockEntry:
    sha, size = locks.content_digest(path)
    return LockEntry(
        name=name,
        url="https://example.invalid/file.json",
        sha256=sha,
        size=size,
        fetched_at="2026-11-08T03:00:00Z",
        rows=1,
    )


def test_a_file_that_matches_its_lock_passes(tmp_path: Path) -> None:
    f = tmp_path / "file.json"
    f.write_bytes(b'{"a": 1}')
    locks.verify(f, _entry(f))


def test_a_changed_file_fails_its_lock(tmp_path: Path) -> None:
    f = tmp_path / "file.json"
    f.write_bytes(b'{"a": 1}')
    entry = _entry(f)
    f.write_bytes(b'{"a": 2}')
    with pytest.raises(LockMismatch, match="does not match its lock"):
        locks.verify(f, entry)


def test_a_missing_file_fails_its_lock(tmp_path: Path) -> None:
    f = tmp_path / "file.json"
    f.write_bytes(b"x")
    entry = _entry(f)
    f.unlink()
    with pytest.raises(LockMismatch, match="missing"):
        locks.verify(f, entry)


def test_a_stored_answer_is_hashed_as_received(tmp_path: Path) -> None:
    body = b'{"totalResults": 0}'
    f = tmp_path / "page.json.gz"
    with gzip.GzipFile(f, "wb", mtime=0) as h:
        h.write(body)
    sha, size = locks.content_digest(f)
    import hashlib

    assert sha == hashlib.sha256(body).hexdigest() and size == len(body)


def test_locks_merge_by_name_and_keep_order(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"1")
    e1 = _entry(f, "b::f")
    e2 = _entry(f, "a::f")
    locks.record(tmp_path, "src", [e1])
    lock = locks.record(tmp_path, "src", [e2])
    assert [e.name for e in lock.entries] == ["a::f", "b::f"]
    assert locks.load(tmp_path, "src").entry("a::f").sha256 == e2.sha256


class Counting(Fetcher):
    """A fetcher of three units that writes one KEV row each, for the driver tests."""

    source = "kev"
    tables: ClassVar[tuple[str, ...]] = ("kev",)
    content: ClassVar[dict[str, bytes]] = {}

    def __init__(self, ctx: base.Context) -> None:
        super().__init__(ctx)
        self.fetched: list[str] = []

    def units(self) -> Iterator[Unit]:
        for i in range(3):
            yield Unit(f"u{i}", f"window {i}")

    def fetch(self, unit: Unit) -> list[RawFile]:
        self.fetched.append(unit.name)
        path = self.raw_root / unit.name / "f.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.content.get(unit.name, unit.name.encode()))
        sha, size = locks.content_digest(path)
        return [
            RawFile(
                unit.name, "f.txt", f"https://example.invalid/{unit.name}", path, sha, size, WHEN, pinned=True
            )
        ]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            raw.rows = 1
            yield (
                "kev",
                frame(
                    "kev",
                    [
                        {
                            "cve_id": f"CVE-2026-000{raw.unit[-1]}",
                            "catalog_version": "2026.11.06",
                            "cwes": [],
                        }
                    ],
                ),
            )


def test_a_resumed_run_skips_the_units_the_ledger_holds(tmp_root: Path) -> None:
    ctx = make_context(tmp_root)
    first = Counting(ctx)
    ledger.append(
        ctx.locks_dir,
        ledger.LedgerRow(
            source="kev",
            window="window 0",
            rows_in=1,
            rows_changed=1,
            digest="d",
            duration_s=0.1,
            status="ok",
        ),
    )
    summary = base.run(first)
    assert first.fetched == ["u1", "u2"]
    assert summary.skipped == 1 and summary.units == 2
    again = Counting(ctx)
    summary = base.run(again)
    assert again.fetched == [] and summary.skipped == 3


def test_a_pinned_file_that_changed_upstream_stops_the_run(tmp_root: Path) -> None:
    ctx = make_context(tmp_root, resume=False)
    base.run(Counting(ctx))
    Counting.content = {"u1": b"something else"}
    try:
        with pytest.raises(LockMismatch, match="pinned file changed"):
            base.run(Counting(ctx))
    finally:
        Counting.content = {}
    failed = [r for r in ledger.rows(ctx.locks_dir, "kev") if r.status == "failed"]
    assert failed and "LockMismatch" in (failed[-1].note or "")


def test_the_ledger_records_every_unit_with_its_digest(tmp_root: Path) -> None:
    ctx = make_context(tmp_root)
    base.run(Counting(ctx))
    rows = list(ledger.rows(ctx.locks_dir, "kev"))
    assert [r.window for r in rows] == ["window 0", "window 1", "window 2"]
    assert all(r.status == "ok" and len(r.digest) == 64 and r.rows_in == 1 for r in rows)
    assert pl.read_parquet(next((ctx.bronze.root / "kev").glob("*.parquet"))).height == 3
    # Raw files are gone after parsing; their digests stay in the lock.
    assert not any(ctx.raw_dir.rglob("*.txt"))
    assert len(locks.load(ctx.locks_dir, "kev").entries) == 3
