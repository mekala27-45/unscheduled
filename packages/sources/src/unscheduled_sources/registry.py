"""Every source by name, and the context a run needs, built from the repository layout."""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from unscheduled_core import paths

from unscheduled_sources.base import Context, Fetcher
from unscheduled_sources.bronze import Bronze

# Source name to the module and class that fetch it, in the order a full run takes them: the CVE
# List and KEV first, because EPSS keeps its offsets from their publication dates and KEV list.
# The order a run of every source takes. The CNA list counts each filer's records in the CVE List
# bronze, so it comes after the CVE List: a first fetch from nothing has no bronze before it.
SOURCES: dict[str, tuple[str, str]] = {
    "cvelist": ("unscheduled_sources.cvelist", "CveList"),
    "kev": ("unscheduled_sources.kev", "Kev"),
    "cna_list": ("unscheduled_sources.cna_list", "CnaList"),
    "cwe": ("unscheduled_sources.cwe", "Cwe"),
    "osv": ("unscheduled_sources.osv", "Osv"),
    "ghsa": ("unscheduled_sources.ghsa", "Ghsa"),
    "vulnrichment": ("unscheduled_sources.vulnrichment", "Vulnrichment"),
    "exploits": ("unscheduled_sources.exploits", "Exploits"),
    "registries": ("unscheduled_sources.registries", "Registries"),
    "epss": ("unscheduled_sources.epss", "Epss"),
    "nvd": ("unscheduled_sources.nvd", "Nvd"),
    "cpe": ("unscheduled_sources.cpe", "Cpe"),
}


def fetcher_class(name: str) -> type[Fetcher]:
    if name not in SOURCES:
        raise KeyError(f"no source {name!r}; the sources are {', '.join(SOURCES)}")
    module, attr = SOURCES[name]
    cls: type[Fetcher] = getattr(importlib.import_module(module), attr)
    return cls


def load_config(root: Path) -> dict[str, Any]:
    data = yaml.safe_load((root / "config" / "sources.yaml").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config/sources.yaml is not a mapping")
    return data


def context(
    *,
    keep_raw: bool = False,
    resume: bool = True,
    budget_s: float | None = None,
    log: Callable[[str], None] = print,
) -> Context:
    root = paths.root()
    # Clones live under data/cache/sources, apart from what other packages cache under data/cache.
    default_cache = paths.data_dir() / "cache" / "sources"
    cache = Path(os.environ["UNSCHED_CACHE"]) if os.environ.get("UNSCHED_CACHE") else default_cache
    env = {k: v for k, v in os.environ.items() if k == "NVD_API_KEY" and v}
    return Context(
        root=root,
        raw_dir=paths.raw_dir(),
        bronze=Bronze(paths.bronze_dir()),
        locks_dir=paths.locks_dir(),
        cache_dir=cache,
        config=load_config(root),
        keep_raw=keep_raw,
        resume=resume,
        budget_s=budget_s,
        log=log,
        env=env,
    )
