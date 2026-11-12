"""Every error is a typed problem document, and every problem type is explained in docs/SPEC.md."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.problems import KINDS, MEDIA_TYPE, PROBLEM_BASE, ProblemError
from unscheduled_api.services import Services
from unscheduled_api.settings import Settings
from unscheduled_core.statements import STATEMENT

ROOT = Path(__file__).resolve().parents[2]


def app_without_database() -> TestClient:
    return TestClient(create_app(Services.build(Settings.from_env({}))))


def test_an_unknown_route_is_a_not_found_problem() -> None:
    response = app_without_database().get("/v1/nothing-here")
    assert response.status_code == 404
    assert response.headers["content-type"] == MEDIA_TYPE
    body = response.json()
    assert body == {
        "type": PROBLEM_BASE + "not-found",
        "title": KINDS["not-found"].title,
        "status": 404,
        "detail": "no route answers /v1/nothing-here",
        "instance": "/v1/nothing-here",
        "statement": STATEMENT,
        "data_version": "none",
    }


def test_a_wrong_method_is_a_method_not_allowed_problem() -> None:
    response = app_without_database().delete("/v1/meta")
    assert response.status_code == 405 and response.json()["type"].endswith("#problem-method-not-allowed")
    assert "GET" in response.headers["allow"]


def test_a_data_route_without_a_database_is_a_database_problem() -> None:
    response = app_without_database().get("/v1/cves")
    assert response.status_code == 503
    assert "none of DATABASE_URL_UNPOOLED, DATABASE_URL, POSTGRES_URL is set" in response.json()["detail"]


def test_every_problem_type_has_its_section_in_the_spec() -> None:
    spec = (ROOT / "docs" / "SPEC.md").read_text(encoding="utf-8")
    anchors = set(re.findall(r"^### problem-([a-z-]+)$", spec, flags=re.M))
    assert anchors == set(KINDS), sorted(anchors ^ set(KINDS))


def test_a_problem_names_only_known_types() -> None:
    try:
        ProblemError("no-such-problem", "x")
    except KeyError as err:
        assert "no-such-problem" in str(err)
    else:
        raise AssertionError("an unknown problem type was accepted")


def test_retry_after_is_sent_as_a_header_and_in_the_body() -> None:
    err = ProblemError("sync-busy", "busy", retry_after_s=5)
    assert err.headers["Retry-After"] == "5"
    doc = err.document(instance="/internal/sync", statement=STATEMENT, data_version="none")
    assert doc.retry_after_s == 5 and doc.status == 409
