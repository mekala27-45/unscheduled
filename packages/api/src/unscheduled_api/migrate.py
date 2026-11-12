"""Alembic, run at container start, in process, before the first request is served.

alembic/env.py takes a transaction level advisory lock before it reads the version table, so two
instances that start together run the migrations once between them. A failure is logged by its
class name and the server still starts: /health then reports the database as degraded and the data
routes answer database-unavailable, which is easier to see than a container that never comes up.
"""

from __future__ import annotations

import structlog
from alembic.config import Config

from alembic import command
from unscheduled_api.settings import Settings

log = structlog.get_logger("unscheduled.migrate")


def alembic_config(settings: Settings) -> Config:
    ini = settings.root / "alembic.ini"
    config = Config(str(ini)) if ini.exists() else Config()
    config.set_main_option("script_location", str(settings.root / "alembic"))
    config.attributes["database_url"] = settings.database_url
    config.attributes["schema"] = settings.schema
    return config


def upgrade(settings: Settings, revision: str = "head") -> str | None:
    """Upgrade the schema; None on success, the error class name otherwise."""
    if settings.database_url is None:
        return None
    try:
        command.upgrade(alembic_config(settings), revision)
    except Exception as err:  # reported by class name, never by message, which can carry a host
        log.error("migration failed", error=type(err).__name__)
        return type(err).__name__
    log.info("migrated", revision=revision, schema=settings.schema)
    return None
