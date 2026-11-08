from __future__ import annotations

from fastapi.testclient import TestClient
from unscheduled_api.main import app
from unscheduled_core.statements import NVD_NOTICE, STATEMENT


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
