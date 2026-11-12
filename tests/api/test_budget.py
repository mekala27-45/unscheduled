"""The per client daily budget: counted per hashed client, refused past the limit, salt made once.

Every count is read back through a connection the test opens itself, so a missing commit in the app
cannot pass for a stored count.
"""

from __future__ import annotations

import hashlib
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.settings import Budgets

from tests.api.postgres import plain

pytestmark = pytest.mark.usefixtures("engine")

SMALL = Budgets(storage_ceiling_mb=800, lookups_per_day=3, matches_per_day=1, sbom_upload_max_bytes=2_097_152)


def salt(url: str) -> str:
    with psycopg.connect(plain(url)) as conn:
        row = conn.execute(
            "select value ->> 'salt' from \"unscheduled\".\"settings\" where key = 'client_salt'"
        ).fetchone()
    assert row is not None
    return str(row[0])


def used(url: str) -> dict[tuple[str, str], int]:
    with psycopg.connect(plain(url)) as conn:
        rows = conn.execute('select client, kind, used from "unscheduled"."client_budget"').fetchall()
    return {(r[0], r[1]): int(r[2]) for r in rows}


def test_past_the_daily_limit_a_client_is_refused_until_midnight(
    make_services: Any, postgres_url: str, loaded: TestClient
) -> None:
    client = TestClient(create_app(make_services(budgets=SMALL)))
    headers = {"x-real-ip": "198.51.100.7"}
    remaining = [client.get("/v1/products", headers=headers).headers["x-budget-remaining"] for _ in range(3)]
    assert remaining == ["2", "1", "0"]
    refused = client.get("/v1/products", headers=headers)
    assert refused.status_code == 429
    body = refused.json()
    assert body["type"].endswith("#problem-budget-exhausted") and body["context"]["limit"] == 3
    assert 0 < int(refused.headers["retry-after"]) <= 86_400
    other = client.get("/v1/products", headers={"x-real-ip": "198.51.100.8"})
    assert other.status_code == 200


def test_the_count_is_kept_under_a_salted_hash_never_the_address(
    make_services: Any, postgres_url: str
) -> None:
    client = TestClient(create_app(make_services(budgets=SMALL)))
    client.get("/v1/backlog", headers={"x-vercel-forwarded-for": "192.0.2.44"})
    client.get("/v1/backlog", headers={"x-vercel-forwarded-for": "192.0.2.44"})
    expected = hashlib.sha256(f"{salt(postgres_url)}:192.0.2.44".encode()).hexdigest()[:32]
    assert used(postgres_url) == {(expected, "lookups"): 2}
    with psycopg.connect(plain(postgres_url)) as conn:
        dump = str(conn.execute('select * from "unscheduled"."client_budget"').fetchall())
    assert "192.0.2.44" not in dump


def test_the_salt_is_made_once_and_every_instance_hashes_alike(make_services: Any, postgres_url: str) -> None:
    first = TestClient(create_app(make_services(budgets=SMALL)))
    first.get("/v1/backlog", headers={"x-real-ip": "192.0.2.10"})
    made = salt(postgres_url)
    assert len(made) == 64
    second = TestClient(create_app(make_services(budgets=SMALL)))
    second.get("/v1/backlog", headers={"x-real-ip": "192.0.2.10"})
    assert salt(postgres_url) == made
    assert list(used(postgres_url).values()) == [2]


def test_matches_have_their_own_budget(make_services: Any) -> None:
    client = TestClient(create_app(make_services(budgets=SMALL)))
    sbom = b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}'
    headers = {"x-real-ip": "192.0.2.20", "content-type": "application/json"}
    assert client.post("/v1/match", content=sbom, headers=headers).status_code == 200
    refused = client.post("/v1/match", content=sbom, headers=headers)
    assert refused.status_code == 429 and refused.json()["context"]["kind"] == "matches"
    assert client.get("/v1/cves/CVE-2021-90001", headers=headers).status_code in {200, 503}


def test_health_meta_and_the_sync_are_not_counted(make_services: Any, postgres_url: str) -> None:
    client = TestClient(create_app(make_services(budgets=SMALL)))
    for _ in range(5):
        assert client.get("/health").status_code == 200
        assert client.get("/v1/meta").status_code == 200
    assert used(postgres_url) == {}
