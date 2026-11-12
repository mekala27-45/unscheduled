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


@needs_adapter
def test_the_rows_the_serving_bundle_writes_give_the_report_the_matcher_findings_give() -> None:
    """The flat finding rows of the real bundle builder rebuild the same CSV as the matcher's findings.

    The fixture bundle above carries whole Finding records; the bundle the build publishes carries
    flat rows. With no CVE facts the report is made from the finding fields alone, so the two must
    be byte for byte the same.
    """
    import json
    import sys
    from pathlib import Path

    from unscheduled_legacy_adapter import adapter
    from unscheduled_match.matcher import Finding

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "scripts"))
    try:
        import build_serving_bundle as serving
    finally:
        sys.path.pop(0)

    flat = serving.finding_frame(root).filter(today_only()).to_dicts()
    served = AdapterWriter().write(flat, {})

    today = json.loads((root / "results" / "exposure" / "findings_today.json").read_text(encoding="utf-8"))
    findings = [
        Finding.model_validate({**f, "product": f.get("product") or product})
        for product, block in sorted(today["products"].items())
        for f in block["findings"]
    ]
    direct = adapter.report(findings, {})
    assert served.splitlines()[0] == direct.splitlines()[0]
    assert served == direct


def today_only() -> Any:
    import polars as pl

    return pl.col("snapshot") == "today"
