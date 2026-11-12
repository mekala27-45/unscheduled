"""Parsing the same raw files again changes nothing, and a raw file that differs from its lock fails."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from unscheduled_sources import base, cvelist
from unscheduled_sources.bronze import file_digest
from unscheduled_sources.cvelist import CveList
from unscheduled_sources.locks import LockMismatch
from unscheduled_sources.osv import Osv

from tests.sources.conftest import fixture_bytes, make_context


def _bronze_digests(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): file_digest(p) for p in sorted(root.rglob("*.parquet"))}


def _osv_handler(request: httpx.Request) -> httpx.Response:
    if "/crates.io/" in request.url.path:
        return httpx.Response(200, content=fixture_bytes("osv_crates.zip"))
    return httpx.Response(200, content=b"PK\x05\x06" + b"\x00" * 18)


def test_a_reparse_of_kept_raw_files_writes_nothing(tmp_root: Path) -> None:
    ctx = make_context(tmp_root, _osv_handler, keep_raw=True)
    base.run(Osv(ctx))
    before = _bronze_digests(ctx.bronze.root)
    again = base.reparse(Osv(make_context(tmp_root, _osv_handler)), ctx.raw_dir / "osv")
    assert again.units == 9 and again.rows_in == 3 and again.rows_changed == 0
    assert _bronze_digests(ctx.bronze.root) == before


def test_a_reparse_into_empty_bronze_rebuilds_the_same_files(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        name = "cvelist_baseline.zip.zip" if request.url.path.endswith(".zip.zip") else "cvelist_delta.zip"
        return httpx.Response(200, content=fixture_bytes(name))

    monkeypatch.setattr(
        cvelist, "release_tags", lambda _url: [("2026-11-08", "0000"), ("2026-11-08", "0200")]
    )
    ctx = make_context(tmp_root, handler, keep_raw=True)
    base.run(CveList(ctx))
    before = _bronze_digests(ctx.bronze.root)
    for table in CveList.tables:
        ctx.bronze.drop(table)
    rebuilt = base.reparse(CveList(make_context(tmp_root, handler)), ctx.raw_dir / "cvelist")
    # The delta repeats the baseline's records, so only the baseline's rows are new.
    in_bronze = sum(ctx.bronze.read(t).height for t in CveList.tables)
    assert rebuilt.rows_changed == in_bronze and rebuilt.rows_in == 2 * in_bronze
    assert _bronze_digests(ctx.bronze.root) == before
    # The raw files a reparse reads are left where they were.
    assert any((ctx.raw_dir / "cvelist").rglob("*.zip.zip"))


def test_a_raw_file_that_differs_from_its_lock_stops_the_reparse(tmp_root: Path) -> None:
    ctx = make_context(tmp_root, _osv_handler, keep_raw=True)
    base.run(Osv(ctx))
    kept = next((ctx.raw_dir / "osv").rglob("crates-io-*/all.zip"))
    kept.write_bytes(kept.read_bytes() + b"tampered")
    with pytest.raises(LockMismatch, match="does not match its lock"):
        base.reparse(Osv(make_context(tmp_root, _osv_handler)), ctx.raw_dir / "osv")
