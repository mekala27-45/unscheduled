"""Locks: every raw file a source gave us, by URL, SHA-256, size, fetch time and rows parsed.

data/locks/<source>.lock.json is written by the fetchers and never by hand. A raw file is hashed as
it arrives; before it is parsed, and whenever it is read back from a release to rederive the lake,
its digest and size are checked against the lock, and a mismatch stops the run with LockMismatch.
Raw files are deleted after parsing to keep the disk small; their digests stay here.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from pydantic import Field
from unscheduled_core.model import StrictModel

from unscheduled_sources.timeutil import iso, utcnow

LOCK_VERSION = 1


class LockMismatch(RuntimeError):
    """A raw file does not match the digest or the size its lock recorded."""


class LockEntry(StrictModel):
    name: str
    url: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    fetched_at: str
    rows: int = Field(ge=0)


class SourceLock(StrictModel):
    source: str
    lock_version: int = LOCK_VERSION
    updated_at: str
    entries: list[LockEntry]

    def entry(self, name: str) -> LockEntry:
        for candidate in self.entries:
            if candidate.name == name:
                return candidate
        raise KeyError(f"the {self.source} lock has no entry {name!r}")

    def names(self) -> set[str]:
        return {e.name for e in self.entries}


def lock_path(locks_dir: Path, source: str) -> Path:
    return locks_dir / f"{source}.lock.json"


def load(locks_dir: Path, source: str) -> SourceLock:
    path = lock_path(locks_dir, source)
    if not path.exists():
        return SourceLock(source=source, updated_at=iso(utcnow()), entries=[])
    return SourceLock.model_validate_json(path.read_text(encoding="utf-8"))


def save(locks_dir: Path, lock: SourceLock) -> Path:
    path = lock_path(locks_dir, lock.source)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(lock.model_dump_json())
    data["entries"] = sorted(data["entries"], key=lambda e: e["name"])
    text = json.dumps(data, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    return path


def record(locks_dir: Path, source: str, entries: list[LockEntry]) -> SourceLock:
    """Merge entries into the source lock by name; an entry with the same name is replaced."""
    if not entries:
        return load(locks_dir, source)
    current = load(locks_dir, source)
    merged = {e.name: e for e in current.entries}
    for e in entries:
        merged[e.name] = e
    lock = SourceLock(
        source=source,
        updated_at=iso(utcnow()),
        entries=[merged[k] for k in sorted(merged)],
    )
    save(locks_dir, lock)
    return lock


def content_digest(path: Path) -> tuple[str, int]:
    """SHA-256 and size of a raw file as it was received.

    A JSON answer is stored gzip compressed under a .gz name it did not arrive with; the digest is
    of the bytes received, so a stored .json.gz is read through gzip first.
    """
    digest = hashlib.sha256()
    size = 0
    opener = gzip.open if path.name.endswith(".json.gz") or path.name.endswith(".txt.gz") else open
    with opener(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def verify(path: Path, entry: LockEntry) -> None:
    """Raise LockMismatch unless the file is exactly the one the lock recorded."""
    if not path.exists():
        raise LockMismatch(f"{path} is missing; the lock expects {entry.sha256[:12]}")
    sha, size = content_digest(path)
    if sha != entry.sha256 or size != entry.size:
        raise LockMismatch(
            f"{path.name} does not match its lock: sha256 {sha[:12]} size {size}, "
            f"the lock says sha256 {entry.sha256[:12]} size {entry.size}"
        )
