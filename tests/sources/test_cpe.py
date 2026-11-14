"""The CPE dictionary: one row per name from a recorded page, a resumed run, and the refusals."""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from unscheduled_sources import base, ledger, locks
from unscheduled_sources.cpe import Cpe, UnparsableCpe, parse_cpes, split_cpe
from unscheduled_sources.locks import LockMismatch
from unscheduled_sources.timeutil import utcnow

from tests.sources.conftest import fixture_bytes, make_context


def _handler(calls: list[str]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=fixture_bytes("nvd_cpes_page.json.gz", unzip=True))

    return handler


def test_the_dictionary_page_lands_one_row_per_name(tmp_root: Path) -> None:
    calls: list[str] = []
    ctx = make_context(tmp_root, _handler(calls))
    summary = base.run(Cpe(ctx))
    assert summary.units == 1 and summary.rows_in == 8
    names = ctx.bronze.read("cpe_names")
    assert names.height == 8 and names.get_column("cpe_name_id").n_unique() == 8
    assert set(names.get_column("part").to_list()) == {"a", "h", "o"}
    hp = names.filter(names.get_column("product") == "smart_tank_7000_28b72a_firmware")
    assert hp.height == 1 and hp.get_column("vendor").item() == "hp" and hp.get_column("part").item() == "o"
    assert str(hp.get_column("created").item())[:10] == "2022-12-29"
    windows = [r.window for r in ledger.rows(ctx.locks_dir, "cpe")]
    assert windows and windows[0].startswith("cpes full ")
    assert "resultsPerPage=10000" in calls[0]
    assert all("apiKey" not in e.url for e in locks.load(ctx.locks_dir, "cpe").entries)


def test_a_second_run_resumes_from_the_ledger(tmp_root: Path) -> None:
    calls: list[str] = []
    ctx = make_context(tmp_root, _handler(calls))
    base.run(Cpe(ctx))
    first = len(calls)
    base.run(Cpe(ctx))
    assert len(calls) == first


def test_the_key_moves_the_limit_and_travels_in_a_header(tmp_root: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=fixture_bytes("nvd_cpes_page.json.gz", unzip=True))

    ctx = make_context(tmp_root, handler, env={"NVD_API_KEY": "k" * 36})
    fetcher = Cpe(ctx)
    assert fetcher.limit.requests == 50
    base.run(fetcher)
    assert seen and all(r.headers.get("apiKey") == "k" * 36 and "k" * 36 not in str(r.url) for r in seen)


def test_a_quoted_colon_stays_in_its_component() -> None:
    parts = split_cpe(r"cpe:2.3:a:acme:c\:\\program:1\.0:*:*:*:*:*:*:*")
    assert parts[3] == "acme" and parts[4] == r"c\:\\program" and parts[5] == r"1\.0"


@pytest.mark.parametrize(
    "name",
    [
        "cpe:2.3:x:acme:widget:-:*:*:*:*:*:*:*",  # no such part
        "cpe:2.2:a:acme:widget:-:*:*:*:*:*:*:*",  # another version of the format
        "cpe:2.3:a:acme:widget",  # too few components
    ],
)
def test_a_name_that_is_not_a_cpe_23_name_is_refused(name: str) -> None:
    body = {"products": [{"cpe": {"cpeName": name, "cpeNameId": "X", "created": "2026-01-01T00:00:00.000"}}]}
    with pytest.raises(UnparsableCpe):
        parse_cpes(body, utcnow())


def test_a_kept_page_that_differs_from_its_lock_is_refused(tmp_root: Path) -> None:
    ctx = make_context(tmp_root, _handler([]), keep_raw=True)
    base.run(Cpe(ctx))
    page = next((ctx.raw_dir / "cpe").rglob("page.json.gz"))
    body = json.loads(gzip.decompress(page.read_bytes()))
    body["products"] = body["products"][:1]
    with gzip.GzipFile(page, "wb", mtime=0) as handle:
        handle.write(json.dumps(body).encode())
    with pytest.raises(LockMismatch):
        base.reparse(Cpe(make_context(tmp_root, _handler([]))), ctx.raw_dir / "cpe")
