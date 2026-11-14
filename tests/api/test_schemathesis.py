"""schemathesis against the committed openapi.json, calling the app in process with data loaded.

Every operation in the file is driven with generated requests, valid and invalid, and every answer
must be one the file documents: its status, its media type, its body schema. No answer may be a
server error. The budgets are raised for the run so the generator, not the daily limit, decides
what is exercised.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import schemathesis
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, settings
from schemathesis.specs.openapi.checks import positive_data_acceptance
from unscheduled_api import scoring
from unscheduled_api.app import create_app
from unscheduled_api.settings import Budgets

from tests.api.conftest import PUBLISHED_AT, TAG, sync_until_done
from tests.api.fixtures.github import FakeGitHub
from tests.api.test_predictions import serving_folder

ROOT = Path(__file__).resolve().parents[2]
WIDE = Budgets(
    storage_ceiling_mb=800,
    lookups_per_day=1_000_000,
    matches_per_day=1_000_000,
    sbom_upload_max_bytes=2_097_152,
)


@pytest.fixture
def api_schema(make_services: Any, github: FakeGitHub, bundle_dir: Path, tmp_path: Path) -> Any:
    services = make_services(budgets=WIDE)
    # Small real ONNX models, so POST /v1/predict is driven as the deployment serves it.
    serving_folder(tmp_path / "root")
    services.scorer = scoring.Scorer(tmp_path / "root")
    app = create_app(services)
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    sync_until_done(TestClient(app))
    schema = schemathesis.openapi.from_path(ROOT / "openapi.json")
    schema.app = app
    return schema


lazy = schemathesis.pytest.from_fixture("api_schema")


@lazy.parametrize()
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[
        HealthCheck.function_scoped_fixture,
        HealthCheck.too_slow,
        HealthCheck.filter_too_much,
    ],
)
def test_every_answer_is_one_the_schema_documents(case: Any) -> None:
    # A request can match the schema and still be refused with a documented problem: a cursor this
    # API never issued, a date that does not exist, an id the slice does not hold. So the check that
    # every schema-valid request succeeds is left out; every other check runs, including that every
    # refusal is documented and that schema-violating requests are refused.
    case.call_and_validate(excluded_checks=[positive_data_acceptance])
