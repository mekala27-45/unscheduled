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


def test_every_step_reads_and_writes_the_worktree_not_this_checkout(tmp_path: Path) -> None:
    env = rd.step_env(tmp_path / "tree")
    assert env["UNSCHED_ROOT"] == str(tmp_path / "tree")
    assert env["PYTHONHASHSEED"] == "0"


def _releases(monkeypatch: pytest.MonkeyPatch, tags: list[str]) -> None:
    monkeypatch.setattr(rd, "gh_json", lambda path: [{"tag_name": t} for t in tags])


def test_the_settled_release_is_the_one_before_the_newest_by_its_day(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # GitHub lists releases on the same commit in no promised order; the day in the tag decides.
    _releases(monkeypatch, ["lake-20261113", "serving-202611131326", "lake-20261114", "lake-20261112"])
    assert rd.newest_lake_release() == "lake-20261114"
    assert rd.settled_lake_release() == "lake-20261113"


def test_no_settled_release_while_the_only_one_is_still_refreshed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _releases(monkeypatch, ["serving-202611121400", "lake-20261112"])
    with pytest.raises(SystemExit, match="no lake release has settled"):
        rd.settled_lake_release()


def test_a_release_that_changed_since_it_was_recorded_is_named(tmp_path: Path) -> None:
    (tmp_path / "SHA256SUMS").write_bytes(b"sums are not an archive\n")
    (tmp_path / "bronze-kev.tar").write_bytes(b"kev")
    (tmp_path / "locks.tar.gz").write_bytes(b"locks")
    (tmp_path / "bronze-kev.tar.part").write_bytes(b"an interrupted download")
    archives = {"bronze-kev.tar": _digest(b"kev"), "locks.tar.gz": _digest(b"locks")}
    assert rd.archive_digests(tmp_path) == archives
    recorded = {"tag": "lake-20261112", "archives": archives}
    assert rd.unchanged_since_recorded(tmp_path, recorded, "lake-20261112") is None
    assert rd.unchanged_since_recorded(tmp_path, recorded, "lake-20261113") is None
    assert rd.unchanged_since_recorded(tmp_path, None, "lake-20261112") is None
    (tmp_path / "bronze-kev.tar").write_bytes(b"kev, refreshed by an hourly run")
    moved = rd.unchanged_since_recorded(tmp_path, recorded, "lake-20261112")
    assert moved is not None and "bronze-kev.tar differ" in moved


def test_an_archive_the_sums_leave_out_is_checked_by_the_digest_github_recorded() -> None:
    assets: dict[str, Any] = {
        "bronze-kev.tar": {"digest": "sha256:" + "a" * 64},
        "bronze-cwe.tar": {"digest": "sha256:" + "b" * 64},
        "locks.tar.gz": {},
    }
    sums = {"bronze-kev.tar": "a" * 64, "locks.tar.gz": "c" * 64}
    wanted = sorted(assets)
    assert rd.expected_digests(assets, sums, wanted, "lake-20261112") == {
        "bronze-cwe.tar": "b" * 64,
        "bronze-kev.tar": "a" * 64,
        "locks.tar.gz": "c" * 64,
    }
    with pytest.raises(SystemExit, match="in SHA256SUMS and"):
        rd.expected_digests(assets, {**sums, "bronze-cwe.tar": "d" * 64}, wanted, "lake-20261112")
    with pytest.raises(SystemExit, match="no digest"):
        rd.expected_digests({**assets, "config.tar.gz": {}}, sums, [*wanted, "config.tar.gz"], "x")
