"""The committed openapi.json is the app's schema, with every route of section 12, POST /v1/predict of
Phase 2, and honest errors."""

from __future__ import annotations

import json
from pathlib import Path

from unscheduled_core.statements import STATEMENT

from scripts import export_openapi

ROOT = Path(__file__).resolve().parents[2]
ROUTES = {
    ("get", "/health"),
    ("get", "/v1/meta"),
    ("get", "/v1/cves/{cve_id}"),
    ("get", "/v1/cves"),
    ("get", "/v1/cves/{cve_id}/timeline"),
    ("get", "/v1/backlog"),
    ("get", "/v1/products"),
    ("get", "/v1/products/{product_id}/exposure"),
    ("post", "/v1/match"),
    ("post", "/v1/predict"),
    ("get", "/v1/legacy/report.csv"),
    ("post", "/internal/sync"),
    ("get", "/internal/sync"),
}


def committed() -> dict[str, object]:
    data: dict[str, object] = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    return data


def test_the_committed_schema_is_the_one_the_app_makes() -> None:
    assert (ROOT / "openapi.json").read_text(encoding="utf-8") == export_openapi.render()


def test_every_route_of_section_12_is_in_the_schema() -> None:
    paths = committed()["paths"]
    assert isinstance(paths, dict)
    found = {(method, path) for path, item in paths.items() for method in item}
    assert found == ROUTES


def test_every_error_is_documented_as_a_problem_document() -> None:
    paths = committed()["paths"]
    assert isinstance(paths, dict)
    for path, item in paths.items():
        for method, operation in item.items():
            for status, response in operation["responses"].items():
                if int(status) >= 400:
                    assert list(response["content"]) == ["application/problem+json"], (method, path, status)
    schemas = committed()["components"]
    assert isinstance(schemas, dict)
    assert "HTTPValidationError" not in schemas["schemas"]


def test_every_success_body_requires_the_statement_and_the_data_version() -> None:
    schema = committed()
    components = schema["components"]
    assert isinstance(components, dict)
    paths = schema["paths"]
    assert isinstance(paths, dict)
    for path, item in paths.items():
        for method, operation in item.items():
            content = operation["responses"]["200"]["content"]
            if "application/json" not in content:
                continue
            name = content["application/json"]["schema"]["$ref"].rsplit("/", 1)[1]
            required = components["schemas"][name]["required"]
            assert {"statement", "data_version"} <= set(required), (method, path)


def test_the_description_opens_with_the_statement() -> None:
    info = committed()["info"]
    assert isinstance(info, dict)
    assert str(info["description"]).startswith(STATEMENT)
