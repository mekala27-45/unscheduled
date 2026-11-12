"""POST /v1/match: CycloneDX and SPDX JSON, the upload limit, typed refusals, and a log of digests only.

The matcher is packages/match itself, fed fixed OSV records instead of the live OSV API, so these
tests exercise the real range evaluation offline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.matching import EngineResult, ParsedSbom, parse_sbom
from unscheduled_api.problems import ProblemError

from tests.api.fixtures.bundle import SBOMS
from tests.api.postgres import plain

pytestmark = pytest.mark.usefixtures("engine")

CDX = (SBOMS / "fixture.cdx.json").read_bytes()
SPDX = (SBOMS / "fixture.spdx.json").read_bytes()
LIMIT = 2_097_152


def log_rows(url: str) -> list[dict[str, Any]]:
    with psycopg.connect(plain(url)) as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute('select * from "unscheduled"."match_log" order by id')
        return list(cur.fetchall())


def test_a_cyclonedx_sbom_is_matched_by_the_real_matcher(client: TestClient, postgres_url: str) -> None:
    response = client.post(
        "/v1/match", content=CDX, headers={"content-type": "application/vnd.cyclonedx+json"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sbom"] == {
        "sha256": hashlib.sha256(CDX).hexdigest(),
        "bytes": len(CDX),
        "format": "cyclonedx",
        "spec_version": "1.6",
        "components": 5,
        "with_purl": 3,
        "without_purl": 2,
    }
    packages = sorted(f["package"] for f in body["findings"])
    assert packages == ["example.org/fixture/logkit", "fixture-etl"]
    assert body["counts"] == {
        "findings": 2,
        "distinct_cves": 2,
        "components_matched": 3,
        "advisories_read": 3,
    }
    logkit = next(f for f in body["findings"] if f["package"] == "example.org/fixture/logkit")
    assert logkit["fixed_versions"] == ["1.2.1"] and logkit["cve_aliases"] == ["CVE-2021-90001"]
    assert body["engine"] == "unscheduled-match over static" and "was not" in body["stored"]
    assert response.headers["x-budget-remaining"] == str(
        client.app.state.services.settings.budgets.matches_per_day - 1
    )


def test_an_spdx_sbom_with_the_same_packages_gives_the_same_findings(client: TestClient) -> None:
    cdx = client.post("/v1/match", content=CDX, headers={"content-type": "application/json"}).json()
    spdx = client.post("/v1/match", content=SPDX, headers={"content-type": "application/spdx+json"}).json()
    assert spdx["sbom"]["format"] == "spdx" and spdx["sbom"]["spec_version"] == "SPDX-2.3"
    assert spdx["sbom"]["components"] == 4 and spdx["sbom"]["without_purl"] == 1

    def key(f: dict[str, Any]) -> tuple[str, str, str]:
        return f["purl"], f["primary_id"], ",".join(f["fixed_versions"])

    assert sorted(map(key, spdx["findings"])) == sorted(map(key, cdx["findings"]))


def test_only_the_digest_counts_timing_and_hashed_client_are_stored(
    client: TestClient, postgres_url: str
) -> None:
    client.post(
        "/v1/match", content=CDX, headers={"content-type": "application/json", "x-real-ip": "203.0.113.9"}
    )
    (row,) = log_rows(postgres_url)
    assert row["sbom_sha256"] == hashlib.sha256(CDX).hexdigest() and row["sbom_bytes"] == len(CDX)
    assert row["components"] == 5 and row["components_without_purl"] == 2
    assert row["findings"] == 2 and row["distinct_cves"] == 2 and row["status"] == "ok"
    assert row["duration_ms"] >= 0 and len(row["client"]) == 32
    stored = json.dumps(row, default=str)
    for fragment in ("logkit", "fixture-etl", "203.0.113.9", "vendored.tar", "bomFormat"):
        assert fragment not in stored


def test_an_upload_over_the_limit_is_refused_from_its_declared_length(
    client: TestClient, postgres_url: str
) -> None:
    big = (
        b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "pad": "' + b"x" * LIMIT + b'"}'
    )
    response = client.post("/v1/match", content=big, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert response.json()["type"].endswith("#problem-payload-too-large")
    assert log_rows(postgres_url) == []


def test_an_upload_over_the_limit_without_a_length_is_cut_off_while_it_streams(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "pad": "'
        for _ in range(40):
            yield b"y" * 65_536
        yield b'"}'

    response = client.post("/v1/match", content=chunks(), headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_an_upload_at_the_limit_is_accepted(client: TestClient) -> None:
    head = b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "pad": "'
    tail = b'"}'
    exact = head + b"z" * (LIMIT - len(head) - len(tail)) + tail
    assert len(exact) == LIMIT
    response = client.post("/v1/match", content=exact, headers={"content-type": "application/json"})
    assert response.status_code == 200 and response.json()["sbom"]["components"] == 0


@pytest.mark.parametrize(
    ("body", "media", "status", "slug"),
    [
        (b"{not json", "application/json", 400, "malformed-body"),
        (b"[1, 2]", "application/json", 422, "unsupported-sbom"),
        (b'{"spdxVersion": "SPDX-3.0"}', "application/json", 422, "unsupported-sbom"),
        (b'{"bomFormat": "CycloneDX", "components": {}}', "application/json", 422, "unsupported-sbom"),
        (CDX, "application/xml", 415, "unsupported-media-type"),
        (CDX, "multipart/form-data; boundary=x", 415, "unsupported-media-type"),
    ],
)
def test_what_is_not_a_json_sbom_is_refused_by_type(
    client: TestClient, body: bytes, media: str, status: int, slug: str
) -> None:
    response = client.post("/v1/match", content=body, headers={"content-type": media})
    assert response.status_code == status
    assert response.json()["type"].endswith(f"#problem-{slug}")


class Unavailable:
    def available(self) -> str | None:
        return "packages/match does not expose matcher.match"

    def run(self, sbom: ParsedSbom, as_of: datetime) -> EngineResult:
        raise AssertionError("an unavailable matcher is never run")


class Upstream:
    def available(self) -> str | None:
        return None

    def run(self, sbom: ParsedSbom, as_of: datetime) -> EngineResult:
        raise ProblemError("upstream-unavailable", "the OSV API did not answer (ConnectError)")


def test_a_matcher_that_is_not_there_answers_so_and_the_attempt_is_logged(
    make_services: Any, postgres_url: str
) -> None:
    client = TestClient(create_app(make_services(matcher=Unavailable())))
    response = client.post("/v1/match", content=CDX, headers={"content-type": "application/json"})
    assert response.status_code == 503 and response.json()["type"].endswith("#problem-matcher-unavailable")
    (row,) = log_rows(postgres_url)
    assert row["status"] == "matcher-unavailable" and row["findings"] is None


def test_an_advisory_source_that_does_not_answer_is_an_upstream_problem(
    make_services: Any, postgres_url: str
) -> None:
    client = TestClient(create_app(make_services(matcher=Upstream())))
    response = client.post("/v1/match", content=SPDX, headers={"content-type": "application/json"})
    assert response.status_code == 503 and response.json()["type"].endswith("#problem-upstream-unavailable")
    assert log_rows(postgres_url)[0]["status"] == "upstream-unavailable"


def test_parse_reads_nested_cyclonedx_components() -> None:
    sbom = parse_sbom(CDX)
    names = [c.name for c in sbom.components]
    assert names == ["logkit", "etl-app", "fixture-etl", "fixture-left-pad", "vendored.tar"]
