"""Where things live. Every path is relative to the repository root, found once."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def root() -> Path:
    env = os.environ.get("UNSCHED_ROOT")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "AGENTS.md").exists() and (parent / "pyproject.toml").exists():
            return parent
    return Path.cwd().resolve()


def data_dir() -> Path:
    return root() / "data"


def raw_dir() -> Path:
    env = os.environ.get("UNSCHED_RAW")
    return Path(env).resolve() if env else data_dir() / "raw"


def bronze_dir() -> Path:
    env = os.environ.get("UNSCHED_BRONZE")
    return Path(env).resolve() if env else data_dir() / "bronze"


def lake_file() -> Path:
    env = os.environ.get("UNSCHED_LAKE")
    return Path(env).resolve() if env else data_dir() / "lake" / "unscheduled.duckdb"


def locks_dir() -> Path:
    return data_dir() / "locks"


def results_dir() -> Path:
    return root() / "results"


def config_dir() -> Path:
    return root() / "config"
