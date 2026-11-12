"""GET /v1/legacy/report.csv: the customer's CSV through packages/legacy_adapter, byte exact in its header."""

from __future__ import annotations

import csv
import io
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.legacy import AdapterWriter

adapter_missing = AdapterWriter().available()
needs_adapter = pytest.mark.skipif(adapter_missing is not None, reason=str(adapter_missing))


@needs_adapter
def test_the_report_has_the_legacy_header_and_typed_rows(loaded: TestClient) -> None:
    from unscheduled_legacy_adapter.contract import HEADER, row_problems

    response = loaded.get("/v1/legacy/report.csv")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["x-unscheduled-statement"].startswith("unscheduled is a portfolio demonstration")
    assert response.content.startswith(HEADER)
    lines = list(csv.reader(io.StringIO(response.content.decode("utf-8"), newline="")))
    body = lines[1:]
    assert [row[0] for row in body] == [
        "CVE-2021-90001",
        "CVE-2025-90004",
        "CVE-2026-90003",
        "CVE-2026-90005",
    ]
    assert all(row_problems(row) == [] for row in body)
    first = body[0]
    assert first[1] == "01/03/2021" and first[5] == "10.0" and first[6] == "CRITICAL"
    unscored_by_nvd = next(row for row in body if row[0] == "CVE-2026-90003")
    assert unscored_by_nvd[5] == "" and unscored_by_nvd[6] == ""


class Missing:
    def available(self) -> str | None:
        return "packages/legacy_adapter does not expose adapter.report"

    def write(self, findings: Sequence[Mapping[str, Any]], cves: Mapping[str, Mapping[str, Any]]) -> bytes:
        raise AssertionError("never called")


def test_without_the_adapter_the_route_says_so(make_services: Any, loaded: TestClient) -> None:
    client = TestClient(create_app(make_services(legacy=Missing())))
    response = client.get("/v1/legacy/report.csv")
    assert response.status_code == 503 and response.json()["type"].endswith("#problem-legacy-unavailable")
