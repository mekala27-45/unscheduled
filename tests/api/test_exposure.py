"""The stand in products, their exposure on the pin date and today, and the backlog values."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.api.fixtures.bundle import backlog


def test_products_list_the_stand_ins_with_their_pins(loaded: TestClient) -> None:
    body = loaded.get("/v1/products").json()
    ids = [p["product_id"] for p in body["products"]]
    assert ids == ["go-edge-service", "python-data-jobs"]
    edge = body["products"][0]
    assert edge["name"] == "go-edge-service"
    assert edge["attributes"]["commit"] == "0123456789abcdef0123456789abcdef01234567"
    assert edge["attributes"]["commit_date"] == "2024-12-30T18:00:00Z"
    assert edge["attributes"]["scope"].startswith("fixture stand in")


def test_exposure_today_is_the_newest_snapshot(loaded: TestClient) -> None:
    body = loaded.get("/v1/products/go-edge-service/exposure").json()
    assert body["as_of_requested"] == "today" and body["snapshot"] == "2026-11-07"
    assert body["snapshots"] == ["2024-12-31", "2026-11-07"]
    assert body["summary"] == {
        "findings": 2,
        "findings_without_cve": 0,
        "findings_fix_available": 2,
        "distinct_cves": 2,
        "cves_by_nvd_status": {"Analyzed": 1, "Deferred": 1},
        "cves_kev_listed": 1,
        "cves_with_exploit_code": 1,
    }
    by_id = {c["cve_id"]: c for c in body["cves"]}
    assert (
        by_id["CVE-2026-90003"]["nvd_status"] == "Deferred" and by_id["CVE-2026-90003"]["kev_listed"] is False
    )
    assert by_id["CVE-2021-90001"]["kev_listed"] is True


def test_exposure_on_the_pin_date_uses_what_was_known_that_day(loaded: TestClient) -> None:
    body = loaded.get("/v1/products/go-edge-service/exposure?as_of=pin").json()
    assert body["snapshot"] == "2024-12-31" and body["summary"]["findings"] == 1
    (cve,) = body["cves"]
    assert cve["cve_id"] == "CVE-2021-90001" and cve["known"] is True
    assert cve["nvd_status"] == "Analyzed" and cve["kev_listed"] is True and cve["exploit_code_seen"] is True


def test_a_date_picks_the_newest_snapshot_on_or_before_it(loaded: TestClient) -> None:
    body = loaded.get("/v1/products/go-edge-service/exposure?as_of=2025-06-30").json()
    assert body["snapshot"] == "2024-12-31"
    early = loaded.get("/v1/products/go-edge-service/exposure?as_of=2024-01-01")
    assert early.status_code == 404 and "the first is 2024-12-31" in early.json()["detail"]


def test_an_impossible_date_is_an_invalid_request(loaded: TestClient) -> None:
    response = loaded.get("/v1/products/go-edge-service/exposure?as_of=2026-13-45")
    assert response.status_code == 422


def test_a_finding_without_a_cve_is_counted_as_such(loaded: TestClient) -> None:
    body = loaded.get("/v1/products/python-data-jobs/exposure").json()
    assert body["summary"]["findings"] == 3 and body["summary"]["findings_without_cve"] == 1
    assert body["summary"]["findings_fix_available"] == 2
    assert body["summary"]["cves_by_nvd_status"] == {"Analyzed": 2}


def test_an_unknown_product_is_not_found(loaded: TestClient) -> None:
    response = loaded.get("/v1/products/no-such-product/exposure")
    assert response.status_code == 404 and response.json()["context"] == {"product_id": "no-such-product"}


def test_the_backlog_is_served_as_the_bundle_carries_it(loaded: TestClient) -> None:
    body = loaded.get("/v1/backlog").json()
    assert body["backlog"] == backlog()
    assert body["statement"] and body["data_version"].startswith("serving-")
