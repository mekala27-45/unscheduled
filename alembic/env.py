"""Alembic for the unscheduled schema, with the version table inside the schema (the Day 13 pattern).

Two instances of the container can start in the same second. The migration transaction opens with a
transaction level advisory lock, so the second waits, then reads the version table the first wrote
and finds nothing to do. Every table is created through a schema translate map, so the tables land
in the schema whatever search path the connection has.
"""

from __future__ import annotations

import sqlalchemy as sa
from unscheduled_api.db import metadata
from unscheduled_api.settings import Settings

from alembic import context

MIGRATION_LOCK = 0x756E7363686564  # "unsched" as an integer: the key no other lock in this database uses

config = context.config


def _target() -> tuple[str | None, str]:
    url = config.attributes.get("database_url")
    schema = config.attributes.get("schema")
    if url is None or schema is None:
        settings = Settings.from_env()
        url = url or settings.database_url
        schema = schema or settings.schema
    return url, str(schema)


def run_offline(url: str | None, schema: str) -> None:
    context.configure(
        url=url or "postgresql+psycopg://",
        target_metadata=metadata,
        literal_binds=True,
        version_table_schema=schema,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.execute(f'create schema if not exists "{schema}"')
        context.run_migrations()


def run_online(url: str, schema: str) -> None:
    engine = sa.create_engine(url, poolclass=sa.pool.NullPool, connect_args={"connect_timeout": 10})
    with engine.connect() as connection:
        connection.execution_options(schema_translate_map={None: schema})
        context.configure(
            connection=connection,
            target_metadata=metadata,
            version_table_schema=schema,
            transactional_ddl=True,
        )
        with context.begin_transaction():
            connection.execute(sa.text("select pg_advisory_xact_lock(:k)"), {"k": MIGRATION_LOCK})
            connection.execute(sa.text(f'create schema if not exists "{schema}"'))
            context.run_migrations()
    engine.dispose()


url, schema = _target()
if context.is_offline_mode():
    run_offline(url, schema)
else:
    if url is None:
        raise SystemExit("no database: set DATABASE_URL_UNPOOLED, DATABASE_URL or POSTGRES_URL")
    run_online(url, schema)
