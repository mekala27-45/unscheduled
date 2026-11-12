"""Fixtures for the CLI tests: the fixture bundle loaded once into a schema of its own.

The command line and the API are run against the same Services object, so a difference in their
answers can only come from the code paths, which is what tests/cli exists to catch.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.matching import PackageMatcher, StaticAdvisories
from unscheduled_api.releases import GitHubReleases
from unscheduled_api.services import Services

from tests.api import postgres as _postgres
from tests.api.conftest import PUBLISHED_AT, TAG, fresh_schema, settings_for, sync_until_done
from tests.api.fixtures.bundle import osv_records, write_bundle
from tests.api.fixtures.github import FakeGitHub

postgres_url = _postgres.postgres_url  # the session fixture, shared with tests/api

SCHEMA = "unscheduled_cli"


@pytest.fixture(scope="module")
def cli_engine(postgres_url: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[sa.Engine]:
    engine = fresh_schema(postgres_url, SCHEMA, tmp_path_factory.mktemp("cli-cache"))
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def shared(postgres_url: str, cli_engine: sa.Engine, tmp_path_factory: pytest.TempPathFactory) -> Services:
    """One Services for both surfaces, with the fixture bundle loaded through the sync."""
    root = tmp_path_factory.mktemp("cli")
    github = FakeGitHub()
    bundle = root / "bundle"
    write_bundle(bundle)
    github.publish(bundle, TAG, PUBLISHED_AT)
    services = Services.build(
        settings_for(postgres_url, root / "cache", schema=SCHEMA),
        engine=cli_engine,
        releases=GitHubReleases(github.client()),
        matcher=PackageMatcher(StaticAdvisories(osv_records())),
    )
    sync_until_done(TestClient(create_app(services)))
    return services


@pytest.fixture(scope="module")
def api(shared: Services) -> TestClient:
    return TestClient(create_app(shared))


@pytest.fixture
def advisories_file(tmp_path: Path) -> Path:
    import json

    path = tmp_path / "osv_records.json"
    path.write_text(json.dumps(osv_records()), encoding="utf-8")
    return path
