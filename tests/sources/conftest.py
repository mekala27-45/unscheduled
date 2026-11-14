"""A sources context in a temporary root, with HTTP answered from recorded fixtures.

The fixtures are answers the publishers gave on 8 November 2026, trimmed to a few records and kept
compressed so they stay byte for byte as received; the CPE page joins the records of two answers the
Products API gave on 14 November. A test serves them through httpx.MockTransport, so no fetcher test
touches the network, and the limits in the copied config are raised so no test waits on a rolling
window.
"""

from __future__ import annotations

import gzip
import shutil
from collections.abc import Callable
from datetime import date
from functools import partial
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from unscheduled_sources.base import Context
from unscheduled_sources.bronze import Bronze
from unscheduled_sources.http import Http

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

Handler = Callable[[httpx.Request], httpx.Response]


def fixture_bytes(name: str, *, unzip: bool = False) -> bytes:
    data = (FIXTURES / name).read_bytes()
    return gzip.decompress(data) if unzip else data


def make_context(root: Path, handler: Handler | None = None, **overrides: Any) -> Context:
    (root / "config").mkdir(parents=True, exist_ok=True)
    config = yaml.safe_load((ROOT / "config" / "sources.yaml").read_text(encoding="utf-8"))
    for name in ("nvd", "cpe"):
        config["sources"][name]["limit"]["keyless"] = {"requests": 1000, "window_s": 1}
        config["sources"][name]["limit"]["min_interval_s"] = 0
    (root / "config" / "sources.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    shutil.copy(ROOT / "config" / "labels.yaml", root / "config" / "labels.yaml")
    transport = httpx.MockTransport(handler) if handler is not None else None
    factory = partial(Http, transport=transport, sleep=lambda _s: None)
    ctx = Context(
        root=root,
        raw_dir=root / "data" / "raw",
        bronze=Bronze(root / "data" / "bronze"),
        locks_dir=root / "data" / "locks",
        cache_dir=root / "data" / "cache",
        config=config,
        today=date(2026, 11, 8),
        log=lambda _m: None,
        http_factory=factory,
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    return tmp_path / "repo"
