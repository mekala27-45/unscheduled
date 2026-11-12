"""GET /v1/cves/{id}, its as-of view, the filtered list with its cursor, and the timeline."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.fixtures.bundle import rows


def fields(body: dict[str, Any]) -> dict[str, Any]:
    return {name: f["value"] for name, f in body["fields"].items()}


def test_a_cve_carries_every_field_with_its_source_and_known_from(loaded: TestClient) -> None:
    response = loaded.get("/v1/cves/CVE-2021-90001")
    assert response.status_code == 200
    body = response.json()
    assert body["known"] is True and body["as_of"] is None
    status = body["fields"]["nvd_status"]
    assert status == {
        "value": "Analyzed",
        "source": "nvd@nist.gov",
        "known_from": "2021-03-12T09:00:00Z",
        "rule": "event nvd_status, nvd_history",
    }
    assert body["fields"]["filer_cvss31_score"]["value"] == 10.0
    assert body["fields"]["published"]["known_from"] == "2021-03-01T12:00:00Z"
    assert body["links"]["cve_org"] == "https://www.cve.org/CVERecord?id=CVE-2021-90001"
    assert body["statement"] and body["data_version"].startswith("serving-")
    assert response.headers["x-data-version"] == body["data_version"]


def test_an_id_in_lower_case_is_the_same_cve(loaded: TestClient) -> None:
    assert loaded.get("/v1/cves/cve-2021-90001").json()["cve_id"] == "CVE-2021-90001"


def test_as_of_a_day_before_publication_knows_nothing(loaded: TestClient) -> None:
    body = loaded.get("/v1/cves/CVE-2021-90001?as_of=2021-02-28").json()
    assert body["known"] is False and body["fields"] == {}
    assert "not yet published on 2021-02-28" in body["note"]


def test_as_of_redraws_the_record_from_what_was_known_that_day(loaded: TestClient) -> None:
    before_analysis = fields(loaded.get("/v1/cves/CVE-2021-90001?as_of=2021-03-05").json())
    assert before_analysis["nvd_status"] == "Awaiting Analysis"
    assert before_analysis["nvd_cvss31_score"] is None
    assert before_analysis["kev_date_added"] is None and before_analysis["exploit_first_seen"] is None
    assert before_analysis["filer_cvss31_score"] == 10.0
    assert before_analysis["epss_score"] is None
    exploit_day = fields(loaded.get("/v1/cves/CVE-2021-90001?as_of=2021-12-09").json())
    assert exploit_day["exploit_first_seen"] == "2021-12-09" and exploit_day["kev_date_added"] is None
    listed = loaded.get("/v1/cves/CVE-2021-90001?as_of=2021-12-10").json()
    assert listed["fields"]["kev_date_added"]["value"] == "2021-12-10"
    assert listed["fields"]["kev_date_added"]["rule"] == "event kev_listed"
    assert listed["fields"]["nvd_status"]["known_from"] == "2021-03-12T09:00:00Z"


def test_as_of_never_returns_a_value_known_later_than_the_day(loaded: TestClient) -> None:
    for day in ("2021-03-01", "2021-03-04", "2021-12-08", "2022-01-04", "2026-11-05"):
        body = loaded.get(f"/v1/cves/CVE-2021-90001?as_of={day}").json()
        for name, value in body["fields"].items():
            known_from = value["known_from"]
            if known_from is not None:
                assert known_from[:10] <= day, (name, known_from, day)


def test_a_field_with_no_date_is_left_out_of_every_as_of_view(loaded: TestClient) -> None:
    current = loaded.get("/v1/cves/CVE-2026-90005").json()
    assert current["fields"]["has_cpe"] == {
        "value": True,
        "source": None,
        "known_from": None,
        "rule": "undated",
    }
    past = loaded.get("/v1/cves/CVE-2026-90005?as_of=2026-11-01").json()
    assert past["fields"]["has_cpe"] == {"value": None, "source": None, "known_from": None, "rule": "undated"}


def test_a_cve_before_2021_points_at_cve_org_for_its_description(loaded: TestClient) -> None:
    body = loaded.get("/v1/cves/CVE-2019-90002").json()
    assert body["fields"]["description"]["value"] is None
    assert "cve.org" in body["note"]


def test_an_unknown_cve_is_a_not_found_problem(loaded: TestClient) -> None:
    response = loaded.get("/v1/cves/CVE-1999-0001")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["type"].endswith("#problem-not-found") and body["context"] == {"cve_id": "CVE-1999-0001"}
    assert body["statement"] and body["data_version"].startswith("serving-")


@pytest.mark.parametrize("bad", ["CVE-21-1", "GHSA-xxxx", "CVE-2021-12", "nothing"])
def test_a_malformed_id_is_an_invalid_request(loaded: TestClient, bad: str) -> None:
    response = loaded.get(f"/v1/cves/{bad}")
    assert response.status_code == 422
    assert response.json()["errors"][0]["location"] == "path.cve_id"


def test_a_malformed_as_of_is_an_invalid_request(loaded: TestClient) -> None:
    response = loaded.get("/v1/cves/CVE-2021-90001?as_of=yesterday")
    assert response.status_code == 422 and response.json()["type"].endswith("#problem-invalid-request")


def test_before_the_first_load_data_routes_say_so(client: TestClient, engine: object) -> None:
    for path in ("/v1/cves/CVE-2021-90001", "/v1/cves", "/v1/backlog", "/v1/products"):
        response = client.get(path)
        assert response.status_code == 503, path
        assert response.json()["type"].endswith("#problem-data-not-loaded")


def test_the_list_is_newest_published_first(loaded: TestClient) -> None:
    body = loaded.get("/v1/cves").json()
    ids = [item["cve_id"] for item in body["items"]]
    expected = [r["cve_id"] for r in sorted(rows("cve"), key=lambda r: r["published"], reverse=True)]
    assert ids == expected
    assert body["next_cursor"] is None and body["limit"] == 50


def test_pages_cover_every_row_once(loaded: TestClient) -> None:
    seen: list[str] = []
    cursor = None
    for _ in range(10):
        query = "/v1/cves?limit=2" + (f"&cursor={cursor}" if cursor else "")
        body = loaded.get(query).json()
        assert len(body["items"]) <= 2
        seen.extend(item["cve_id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert sorted(seen) == sorted(r["cve_id"] for r in rows("cve")) and len(seen) == len(set(seen))


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("nvd_status=Analyzed", {"CVE-2021-90001", "CVE-2019-90002", "CVE-2025-90004", "CVE-2026-90005"}),
        ("kev=true", {"CVE-2021-90001", "CVE-2026-90005"}),
        ("kev=false&nvd_status=Deferred", {"CVE-2026-90003"}),
        ("filer=fixture-vendor", {"CVE-2019-90002", "CVE-2026-90003", "CVE-2024-90006"}),
        ("filer_type=open%20source%20project", {"CVE-2021-90001", "CVE-2025-90004", "CVE-2026-90005"}),
        ("cwe=cwe-79", {"CVE-2026-90003"}),
        ("has_filer_score=true", {"CVE-2021-90001", "CVE-2026-90003", "CVE-2025-90004", "CVE-2026-90005"}),
        ("has_filer_score=false", {"CVE-2019-90002", "CVE-2024-90006"}),
        ("kev_added_from=2026-01-01", {"CVE-2026-90005"}),
        ("kev_added_from=2021-01-01", {"CVE-2021-90001", "CVE-2026-90005"}),
        ("analyzed_from=2025-06-01", {"CVE-2025-90004", "CVE-2026-90005"}),
        ("analyzed_from=2026-06-03", set()),
        ("published_from=2026-04-15", {"CVE-2026-90003", "CVE-2026-90005"}),
        ("published_from=2025-06-01&published_to=2025-06-01", {"CVE-2025-90004"}),
        ("published_to=2019-12-31", {"CVE-2019-90002"}),
    ],
)
def test_each_filter_narrows_the_list(loaded: TestClient, query: str, expected: set[str]) -> None:
    body = loaded.get(f"/v1/cves?{query}").json()
    assert {item["cve_id"] for item in body["items"]} == expected


def test_a_page_never_holds_more_than_a_hundred(loaded: TestClient) -> None:
    response = loaded.get("/v1/cves?limit=101")
    assert response.status_code == 422 and response.json()["errors"][0]["location"] == "query.limit"


def test_a_cursor_for_other_filters_is_refused(loaded: TestClient) -> None:
    cursor = loaded.get("/v1/cves?limit=1").json()["next_cursor"]
    response = loaded.get(f"/v1/cves?limit=1&kev=true&cursor={cursor}")
    assert response.status_code == 400 and "different filters" in response.json()["detail"]


def test_a_forged_cursor_is_refused(loaded: TestClient) -> None:
    response = loaded.get("/v1/cves?cursor=bm90LWEtY3Vyc29y")
    assert response.status_code == 400 and response.json()["type"].endswith("#problem-invalid-cursor")


def test_the_timeline_is_in_time_order(loaded: TestClient) -> None:
    body = loaded.get("/v1/cves/CVE-2021-90001/timeline").json()
    times = [e["at"] for e in body["events"]]
    assert times == sorted(times) and len(times) == 11
    first = [e["kind"] for e in body["events"] if e["at"] == times[0]]
    assert first == sorted(first) and "published" in first  # ties in time fall back to the kind, then the id
    assert body["events"][-1]["kind"] == "adp"
    kev = next(e for e in body["events"] if e["kind"] == "kev_listed")
    assert kev["detail"] == {"field": "kev_date_added", "value": "2021-12-10"} and kev["source"] == "kev"


def test_the_timeline_of_an_unknown_cve_is_not_found(loaded: TestClient) -> None:
    assert loaded.get("/v1/cves/CVE-1999-0001/timeline").status_code == 404
