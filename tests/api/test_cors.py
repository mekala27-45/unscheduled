"""CORS for the web origins in UNSCHED_CORS_ORIGINS, a comma separated list, and nobody else."""

from __future__ import annotations

from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.services import Services
from unscheduled_api.settings import Settings, parse_origins

ORIGINS = "https://unscheduled-triage.vercel.app,https://unscheduled-sigma.vercel.app"


def client() -> TestClient:
    return TestClient(create_app(Services.build(Settings.from_env({"UNSCHED_CORS_ORIGINS": ORIGINS}))))


def test_origins_are_parsed_as_a_comma_separated_list() -> None:
    assert parse_origins(" https://a.example/ ,https://b.example,,https://a.example") == (
        "https://a.example",
        "https://b.example",
    )
    assert parse_origins(None) == () and parse_origins("") == ()


def test_the_web_origin_is_allowed_and_sees_the_data_version() -> None:
    response = client().get("/health", headers={"origin": "https://unscheduled-triage.vercel.app"})
    assert response.headers["access-control-allow-origin"] == "https://unscheduled-triage.vercel.app"
    exposed = response.headers["access-control-expose-headers"].lower()
    assert "x-data-version" in exposed and "x-budget-remaining" in exposed


def test_the_preflight_for_an_upload_from_the_web_passes() -> None:
    response = client().options(
        "/v1/match",
        headers={
            "origin": "https://unscheduled-sigma.vercel.app",
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://unscheduled-sigma.vercel.app"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_another_origin_gets_no_cors_headers() -> None:
    response = client().get("/health", headers={"origin": "https://elsewhere.example"})
    assert "access-control-allow-origin" not in response.headers
