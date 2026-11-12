"""/health and /v1/meta: the statement, the NVD notice, the attribution and the database facts.

The first two tests run with no database at all, the way the CI container check and the first
Vercel deploy run, and must still answer ok. The rest read a real database and check that the facts
the probe needs are there and that no connection value ever is.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.main import app
from unscheduled_api.services import Services
from unscheduled_api.settings import Settings
from unscheduled_core.statements import GHSA_ATTRIBUTION, NVD_NOTICE, STATEMENT

from tests.api.conftest import TAG


def test_health_answers_with_the_statement() -> None:
    client = TestClient(app)
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["statement"] == STATEMENT


def test_meta_carries_the_nvd_notice() -> None:
    client = TestClient(app)
    body = client.get("/v1/meta").json()
    assert body["nvd_notice"] == NVD_NOTICE
    assert STATEMENT in body["statement"]
    assert body["attribution"] == [GHSA_ATTRIBUTION]


def test_health_without_a_database_is_ok_and_says_none_is_configured() -> None:
    services = Services.build(Settings.from_env({}))
    response = TestClient(create_app(services)).get("/health")
    assert response.status_code == 200
    assert response.content.startswith(b'{"statement":') and b'"status":"ok"' in response.content
    body = response.json()
    assert body["database"]["configured"] is False and body["database"]["variables_found"] == []
    assert body["ready"] is False and body["data_version"] == "none"
    assert response.headers["x-data-version"] == "none"
    assert body["release"] == {
        "repository": "mekala27-45/unscheduled",
        "tag_prefix": "serving-",
        "checked_at": None,
        "newest": None,
    }


def test_meta_states_the_limits_the_service_enforces() -> None:
    services = Services.build(Settings.from_env({}))
    limits = TestClient(create_app(services)).get("/v1/meta").json()["limits"]
    assert limits["page_size_max"] == 100
    assert limits["sbom_upload_max_bytes"] == 2_097_152
    assert limits["storage_ceiling_mb"] == services.settings.budgets.storage_ceiling_mb


@pytest.mark.usefixtures("engine")
def test_health_reports_the_database_facts_the_probe_reads(client: TestClient) -> None:
    body = client.get("/health").json()
    database = body["database"]
    assert database["reachable"] is True and database["migration"] == "0001"
    assert database["server_version"] and database["server_version"][0].isdigit()
    assert isinstance(database["pgvector_available"], bool)
    assert isinstance(database["pgvector_installed"], bool)
    assert database["database_size_bytes"] > 0
    assert database["storage_ceiling_bytes"] == database["storage_ceiling_mb"] * 1_000_000
    assert 0 < database["storage_share_used"] < 1
    assert database["schema_name"] == "unscheduled" and database["error"] is None
    assert body["status"] == "ok" and body["ready"] is False


@pytest.mark.usefixtures("engine")
def test_health_names_the_connection_variables_and_never_their_values(postgres_url: str) -> None:
    secret_looking = postgres_url
    env = {
        "DATABASE_URL_UNPOOLED": secret_looking,
        "POSTGRES_URL": secret_looking,
        "UNSCHED_MIGRATE_ON_START": "0",
    }
    services = Services.build(Settings.from_env(env))
    client = TestClient(create_app(services))
    response = client.get("/health")
    body: dict[str, Any] = response.json()
    assert body["database"]["variable"] == "DATABASE_URL_UNPOOLED"
    assert body["database"]["variables_found"] == ["DATABASE_URL_UNPOOLED", "POSTGRES_URL"]
    host = secret_looking.split("@", 1)[1]
    assert host not in response.text and "postgres" + "ql" not in response.text
    assert host not in repr(services.settings)
    services.dispose()


def test_health_says_degraded_when_the_configured_database_does_not_answer() -> None:
    env = {"DATABASE_URL": "postgresql://nobody@127.0.0.1:9/none", "UNSCHED_MIGRATE_ON_START": "0"}
    services = Services.build(Settings.from_env(env))
    response = TestClient(create_app(services)).get("/health")
    body = response.json()
    assert response.status_code == 200 and body["status"] == "degraded"
    assert body["database"]["reachable"] is False and body["database"]["error"] == "OperationalError"
    assert "127.0.0.1" not in response.text
    data = TestClient(create_app(services)).get("/v1/backlog")
    assert data.status_code == 503 and data.json()["type"].endswith("#problem-database-unavailable")


def test_health_after_a_load_names_the_bundle_and_its_freshness(loaded: TestClient) -> None:
    body = loaded.get("/health").json()
    assert body["ready"] is True
    data = body["data"]
    assert data["tag"] == TAG and data["data_version"].startswith(TAG + "+")
    assert data["counts"]["cve"] == 6 and data["counts"]["finding"] == 6
    assert data["freshness"]["kev_added_latest"] == "2026-06-01"
    assert data["last_sync"]["status"] == "done"
    assert body["release"]["newest"] == TAG


def test_meta_after_a_load_names_every_file_with_its_digest(loaded: TestClient) -> None:
    meta = loaded.get("/v1/meta").json()
    files = {f["file"]: f for f in meta["bundle"]["files"]}
    assert set(files) == {
        "cve.parquet",
        "cve_event.parquet",
        "product.parquet",
        "finding.parquet",
        "backlog.json",
    }
    assert all(len(f["sha256"]) == 64 for f in files.values())
    assert meta["bundle"]["tag"] == TAG
    assert meta["data_version"] == loaded.get("/health").json()["data_version"]


def test_meta_after_a_load_carries_the_quarantine_counts_and_the_ledger(loaded: TestClient) -> None:
    meta = loaded.get("/v1/meta").json()
    assert [r["rule_id"] for r in meta["quarantine"]] == ["Q01", "Q02"]
    assert [r["source"] for r in meta["run_ledger"]] == ["kev", "nvd"]


def test_meta_before_a_load_has_no_quarantine_or_ledger(client: TestClient) -> None:
    meta = client.get("/v1/meta").json()
    assert meta["quarantine"] == [] and meta["run_ledger"] == []
