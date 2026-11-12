"""Configuration, read from the environment once and never logged.

The database connection arrives as variables that the Neon integration for Vercel writes into the
API project. Nobody types them. They are read in a fixed order: DATABASE_URL_UNPOOLED first, because
the sync holds one transaction across a download and an advisory lock and the pooler in front of
Neon runs in transaction mode; then DATABASE_URL; then POSTGRES_URL. Only the name of the variable
that was used, and the names of the ones present, ever leave this module. The value sits in a field
with repr turned off, so printing a Settings object cannot leak it.

The ceilings come from config/budgets.yaml, the file registered with the criteria, so the API and the
registration hash read the same numbers.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from unscheduled_core import paths

DATABASE_VARIABLES = ("DATABASE_URL_UNPOOLED", "DATABASE_URL", "POSTGRES_URL")
DEFAULT_SCHEMA = "unscheduled"
MEGABYTE = 1_000_000  # the ceiling is read in decimal megabytes, the unit the Neon plan states


class ConfigError(RuntimeError):
    """A required setting is missing or malformed."""


@dataclass(frozen=True)
class Budgets:
    storage_ceiling_mb: int
    lookups_per_day: int
    matches_per_day: int
    sbom_upload_max_bytes: int

    @property
    def storage_ceiling_bytes(self) -> int:
        return self.storage_ceiling_mb * MEGABYTE


def load_budgets(path: Path) -> Budgets:
    if not path.exists():
        raise ConfigError(f"{path} is missing; the API will not run without its ceilings")
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        return Budgets(
            storage_ceiling_mb=int(raw["neon"]["storage_ceiling_mb"]),
            lookups_per_day=int(raw["client_budget_per_day"]["lookups"]),
            matches_per_day=int(raw["client_budget_per_day"]["sbom_matches"]),
            sbom_upload_max_bytes=int(raw["sbom_upload_max_bytes"]),
        )
    except (KeyError, TypeError, ValueError) as err:
        raise ConfigError(f"{path} does not have the expected shape: {type(err).__name__} {err}") from err


def normalize_url(url: str) -> str:
    """The SQLAlchemy form of a libpq URL, with the psycopg 3 driver named."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def parse_origins(text: str | None) -> tuple[str, ...]:
    """UNSCHED_CORS_ORIGINS is a comma separated list; spaces, empties and trailing slashes are dropped."""
    if not text:
        return ()
    seen: dict[str, None] = {}
    for part in text.split(","):
        origin = part.strip().rstrip("/")
        if origin:
            seen.setdefault(origin, None)
    return tuple(seen)


def _flag(value: str | None, default: bool) -> bool:
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str | None = field(repr=False)
    database_variable: str | None
    variables_found: tuple[str, ...]
    schema: str
    cors_origins: tuple[str, ...]
    budgets: Budgets
    migrate_on_start: bool
    cache_dir: Path
    root: Path

    @property
    def database_configured(self) -> bool:
        return self.database_url is not None

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        database_url: str | None = None,
        budgets: Budgets | None = None,
    ) -> Settings:
        source = os.environ if env is None else env
        found = tuple(name for name in DATABASE_VARIABLES if (source.get(name) or "").strip())
        variable: str | None = None
        url: str | None = None
        if database_url is not None:
            variable, url = "explicit", database_url
        elif found:
            variable = found[0]
            url = source[variable].strip()
        schema = (source.get("UNSCHED_DB_SCHEMA") or DEFAULT_SCHEMA).strip()
        if not schema.replace("_", "").isalnum() or not schema[0].isalpha():
            raise ConfigError("UNSCHED_DB_SCHEMA must be letters, digits and underscores")
        root = paths.root()
        cache = source.get("UNSCHED_CACHE_DIR") or str(Path(tempfile.gettempdir()) / "unscheduled-bundle")
        return cls(
            database_url=normalize_url(url) if url else None,
            database_variable=variable,
            variables_found=found,
            schema=schema,
            cors_origins=parse_origins(source.get("UNSCHED_CORS_ORIGINS")),
            budgets=budgets or load_budgets(root / "config" / "budgets.yaml"),
            migrate_on_start=_flag(source.get("UNSCHED_MIGRATE_ON_START"), True),
            cache_dir=Path(cache),
            root=root,
        )
