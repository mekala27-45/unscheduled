"""The OpenAPI 3.1 schema as committed in openapi.json, generated from the app and then made honest.

FastAPI documents its own validation error shape and puts every response under application/json.
This API answers every error with a problem document under application/problem+json, so the schema
is rewritten to say exactly that: each documented error status points at the one Problem schema,
FastAPI's validation models are removed, and the statement opens the description. schemathesis
tests the running app against this file, and CI fails when the file and the app disagree.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from unscheduled_core.statements import GHSA_ATTRIBUTION, NVD_NOTICE, STATEMENT

from unscheduled_api import VERSION
from unscheduled_api.problems import KINDS, MEDIA_TYPE, Problem

PROBLEM_REF = {"$ref": "#/components/schemas/Problem"}

DESCRIPTION = f"""{STATEMENT}

Every CVE the serving slice holds, with the source and the time each value became known; the state
of a CVE on any past day; its ruler events; the NVD backlog values; the stand in products and their
exposure; live matching of a CycloneDX or SPDX JSON SBOM; and the customer's legacy CSV. Every
response carries the statement and the data version. Every error is a problem document
(application/problem+json) whose type links to its explanation in docs/SPEC.md.

{NVD_NOTICE} {GHSA_ATTRIBUTION}"""


def problem_responses(*statuses: int) -> dict[int | str, dict[str, Any]]:
    """The responses argument of a route: one entry per error status it can answer."""
    out: dict[int | str, dict[str, Any]] = {}
    for status in sorted(set(statuses)):
        titles = sorted({k.title for k in KINDS.values() if k.status == status})
        out[status] = {"description": "; ".join(titles) or "a problem document"}
    return out


def build(app: FastAPI) -> dict[str, Any]:
    schema = get_openapi(
        title="unscheduled",
        version=VERSION,
        summary="Triage for the CVEs the NVD no longer analyzes",
        description=DESCRIPTION,
        routes=app.routes,
        license_info={"name": "Apache-2.0", "identifier": "Apache-2.0"},
    )
    components = schema.setdefault("components", {}).setdefault("schemas", {})
    for name in ("HTTPValidationError", "ValidationError"):
        components.pop(name, None)
    defs = Problem.model_json_schema(ref_template="#/components/schemas/{model}")
    for name, sub in (defs.pop("$defs", None) or {}).items():
        components.setdefault(name, sub)
    components["Problem"] = defs
    for path_item in schema.get("paths", {}).values():
        for operation in path_item.values():
            responses = operation.get("responses", {})
            for status, response in responses.items():
                if str(status).isdigit() and int(status) >= 400:
                    response["content"] = {MEDIA_TYPE: {"schema": PROBLEM_REF}}
                    if status == "422" and response.get("description") == "Validation Error":
                        response["description"] = KINDS["invalid-request"].title
    schema["components"]["schemas"] = dict(sorted(components.items()))
    return schema


def install(app: FastAPI) -> None:
    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            app.openapi_schema = build(app)
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
