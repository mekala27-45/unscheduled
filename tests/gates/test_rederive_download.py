"""The release download reads the sums again each time, keeps what matches and fetches what changed."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from scripts import reset_and_rederive as rd


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_sums_read_names_written_with_a_dot_slash_or_a_star() -> None:
    assert rd.sums_of("aa  ./bronze-kev.tar\nbb *locks.tar.gz\n\n") == {
        "bronze-kev.tar": "aa",
        "locks.tar.gz": "bb",
    }


def test_download_keeps_matches_refetches_changes_and_drops_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {
        "bronze-kev.tar": b"kev, as published again",
        "bronze-cwe.tar": b"cwe, unchanged",
        "locks.tar.gz": b"locks",
        "config.tar.gz": b"config",
        "raw-nvd-0123.tar": b"raw, not wanted here",
    }
    files["SHA256SUMS"] = "".join(f"{_digest(v)}  ./{k}\n" for k, v in files.items()).encode()
    ids = {name: i for i, name in enumerate(files, start=1)}
    release: dict[str, Any] = {"assets": [{"name": n, "id": i} for n, i in ids.items()]}
    monkeypatch.setattr(rd, "CACHE", tmp_path)
    monkeypatch.setattr(rd, "gh_json", lambda path: release)
    fetched: list[str] = []

    def fetch(asset_id: int, target: Path) -> None:
        name = next(n for n, i in ids.items() if i == asset_id)
        fetched.append(name)
        target.write_bytes(files[name])

    monkeypatch.setattr(rd, "fetch_asset", fetch)
    folder = tmp_path / "lake-20261112"
    folder.mkdir()
    (folder / "bronze-cwe.tar").write_bytes(b"cwe, unchanged")
    (folder / "bronze-kev.tar").write_bytes(b"kev, as first published")
    (folder / "bronze-gone.tar").write_bytes(b"a table the release no longer has")

    assert rd.download("lake-20261112") == folder
    assert fetched == ["SHA256SUMS", "bronze-kev.tar", "config.tar.gz", "locks.tar.gz"]
    assert (folder / "bronze-kev.tar").read_bytes() == b"kev, as published again"
    assert not (folder / "bronze-gone.tar").exists()
    assert not (folder / "raw-nvd-0123.tar").exists()
