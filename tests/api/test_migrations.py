"""The migrations make exactly the tables db.py declares, in their own schema, once, under a lock."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import psycopg
import sqlalchemy as sa
from unscheduled_api import db, migrate

from tests.api.conftest import settings_for
from tests.api.postgres import plain

ROOT = Path(__file__).resolve().parents[2]


def test_the_migrated_tables_match_the_declared_ones(migrated: sa.Engine) -> None:
    inspector = sa.inspect(migrated)
    tables = set(inspector.get_table_names(schema="unscheduled"))
    assert tables == {t.name for t in db.metadata.sorted_tables} | {"alembic_version"}
    for table in db.metadata.sorted_tables:
        found = {c["name"]: c for c in inspector.get_columns(table.name, schema="unscheduled")}
        assert set(found) == set(table.columns.keys()), table.name
        for column in table.columns:
            assert found[column.name]["nullable"] == column.nullable, (table.name, column.name)
        primary = inspector.get_pk_constraint(table.name, schema="unscheduled")["constrained_columns"]
        assert primary == [c.name for c in table.primary_key.columns], table.name
        indexes = {i["name"] for i in inspector.get_indexes(table.name, schema="unscheduled")}
        assert indexes == {i.name for i in table.indexes}, table.name


def test_the_version_table_lives_in_the_schema_and_nowhere_else(
    migrated: sa.Engine, postgres_url: str
) -> None:
    with psycopg.connect(plain(postgres_url)) as conn:
        found = conn.execute(
            "select table_schema from information_schema.tables where table_name = 'alembic_version'"
        ).fetchall()
        revision = conn.execute('select version_num from "unscheduled"."alembic_version"').fetchone()
    assert ("unscheduled",) in found and ("public",) not in found
    assert revision == ("0001",)


def test_two_instances_starting_together_migrate_once(postgres_url: str, tmp_path: Path) -> None:
    """Three processes, as three containers would be, each running the migration at start."""
    schema = "unscheduled_twice"
    with psycopg.connect(plain(postgres_url), autocommit=True) as conn:
        conn.execute(f'drop schema if exists "{schema}" cascade')
    code = (
        "import sys\n"
        "from unscheduled_api import migrate\n"
        "from unscheduled_api.settings import Settings\n"
        f"settings = Settings.from_env({{'UNSCHED_DB_SCHEMA': '{schema}'}}, database_url=sys.argv[1])\n"
        "print(migrate.upgrade(settings))\n"
    )
    env = {**os.environ, "UNSCHED_ROOT": str(ROOT)}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, postgres_url],
            cwd=tmp_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(3)
    ]
    outputs = [p.communicate(timeout=120) for p in procs]
    assert [p.returncode for p in procs] == [0, 0, 0], outputs
    assert [out.strip().splitlines()[-1] for out, _ in outputs] == ["None", "None", "None"]
    with psycopg.connect(plain(postgres_url), autocommit=True) as conn:
        assert conn.execute(f'select count(*) from "{schema}"."alembic_version"').fetchone() == (1,)
        conn.execute(f'drop schema "{schema}" cascade')


def test_a_migration_that_cannot_reach_the_database_reports_the_class_only(tmp_path: Path) -> None:
    settings = settings_for("postgresql+psycopg://nobody@127.0.0.1:9/none", tmp_path)
    assert migrate.upgrade(settings) == "OperationalError"
