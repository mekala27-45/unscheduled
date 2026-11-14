"""Fixtures for the API tests: a migrated schema in a real Postgres, a fake GitHub, and the app.

The schema is made by the Alembic migrations, never by create_all, so every test runs against the
tables the container makes at start. Every table is emptied before each test that touches the
database, so order cannot hide a missing commit.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from unscheduled_api import migrate
from unscheduled_api.app import create_app
from unscheduled_api.db import make_engine
from unscheduled_api.matching import PackageMatcher, StaticAdvisories
from unscheduled_api.releases import GitHubReleases
from unscheduled_api.services import Services
from unscheduled_api.settings import Budgets, Settings

from tests.api import postgres as _postgres
from tests.api.fixtures.bundle import osv_records, write_bundle
from tests.api.fixtures.github import FakeGitHub

postgres_url = _postgres.postgres_url  # the session fixture, shared with tests/cli

SCHEMA = "unscheduled"
TABLES = (
    "cve",
    "cve_event",
    "product",
    "finding",
    "prediction",
    "match_log",
    "client_budget",
    "ops_run",
    "settings",
)
ORIGIN = "https://unscheduled-triage.vercel.app"
ORIGINS = f"{ORIGIN}, https://unscheduled-sigma.vercel.app/"
TAG = "serving-202611070500"
PUBLISHED_AT = "2026-11-07T05:10:00Z"


class Clock:
    """A clock a test moves by hand, so the minute between release checks passes on demand."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def settings_for(url: str, cache: Path, *, schema: str = SCHEMA, budgets: Budgets | None = None) -> Settings:
    env = {
        "UNSCHED_CORS_ORIGINS": ORIGINS,
        "UNSCHED_CACHE_DIR": str(cache),
        "UNSCHED_MIGRATE_ON_START": "0",
        "UNSCHED_DB_SCHEMA": schema,
    }
    return Settings.from_env(env, database_url=url, budgets=budgets)


def fresh_schema(url: str, schema: str, cache: Path) -> sa.Engine:
    plain = sa.create_engine(url)
    with plain.begin() as conn:
        conn.execute(sa.text(f'drop schema if exists "{schema}" cascade'))
    plain.dispose()
    failed = migrate.upgrade(settings_for(url, cache, schema=schema))
    assert failed is None, f"the migration failed: {failed}"
    return make_engine(url, schema)


def empty(engine: sa.Engine, schema: str) -> None:
    names = ", ".join(f'"{schema}"."{t}"' for t in TABLES)
    with engine.begin() as conn:
        conn.execute(sa.text(f"truncate {names} restart identity"))


@pytest.fixture(scope="session")
def migrated(postgres_url: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[sa.Engine]:
    engine = fresh_schema(postgres_url, SCHEMA, tmp_path_factory.mktemp("migrate-cache"))
    yield engine
    engine.dispose()


@pytest.fixture
def engine(migrated: sa.Engine) -> sa.Engine:
    empty(migrated, SCHEMA)
    return migrated


@pytest.fixture
def github() -> FakeGitHub:
    return FakeGitHub()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    path = tmp_path / "bundle"
    write_bundle(path)
    return path


@pytest.fixture
def make_services(
    postgres_url: str, engine: sa.Engine, github: FakeGitHub, clock: Clock, tmp_path: Path
) -> Callable[..., Services]:
    def build(**options: Any) -> Services:
        settings = settings_for(postgres_url, tmp_path / "cache", budgets=options.get("budgets"))
        return Services.build(
            settings,
            engine=engine,
            releases=GitHubReleases(github.client()),
            matcher=options.get("matcher") or PackageMatcher(StaticAdvisories(osv_records())),
            legacy=options.get("legacy"),
            clock=options.get("clock") or clock,
        )

    return build


@pytest.fixture
def services(make_services: Callable[..., Services]) -> Services:
    return make_services()


@pytest.fixture
def client(services: Services) -> TestClient:
    return TestClient(create_app(services))


def sync_until_done(client: TestClient, limit: int = 60) -> list[dict[str, Any]]:
    answers: list[dict[str, Any]] = []
    for _ in range(limit):
        response = client.post("/internal/sync")
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        answers.append(body)
        if body["status"] in {"done", "current"}:
            return answers
    raise AssertionError(f"the sync did not finish in {limit} calls")


@pytest.fixture
def loaded(client: TestClient, github: FakeGitHub, bundle_dir: Path) -> TestClient:
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    answers = sync_until_done(client)
    assert answers[-1]["status"] == "done"
    return client
