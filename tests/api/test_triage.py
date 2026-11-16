"""POST /v1/triage, the runs, the approvals by hash and the search, against a real Postgres.

The slice is the fixture bundle the other API tests load; the scoped corpus is a GitHub advisory and
a KEV entry for CVE-2021-90001 (tests/api/fixtures/bundle.py), written into corpus_document and
corpus_chunk by the sync's own row builders; test_sync loads the same files through the sync. No provider is configured (config/agent_points.yaml does not exist yet), so the no model floor
drafts, and the run says so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from unscheduled_api import bundle as bnd
from unscheduled_api import triage
from unscheduled_api.db import checkpoint_schema

from tests.api.fixtures.bundle import ADVISORY_DOC, CORPUS_CVE, KEV_DOC, corpus_frames
from tests.api.postgres import plain

CVE = CORPUS_CVE
AS_OF = "2022-01-15"
ADVISORY = ADVISORY_DOC
# Made from words, never a literal a secret scanner would read as a credential.
TOKEN = "-".join(["approver", "token", "for", "the", "triage", "tests", "only"])


def load_corpus(url: str, schema: str = "unscheduled") -> None:
    """The fixture corpus into a schema's corpus tables, row by row as the sync's builders make them."""
    documents, chunks = corpus_frames()
    with psycopg.connect(plain(url), autocommit=True) as conn:
        for raw in documents.to_dicts():
            row = bnd.corpus_document_row(raw)
            row["sections"] = json.dumps(row["sections"])
            conn.execute(
                f'insert into "{schema}".corpus_document ({", ".join(row)}) values ({", ".join(["%s"] * len(row))})',
                tuple(row.values()),
            )
        for raw in chunks.to_dicts():
            row = bnd.corpus_chunk_row(raw)
            conn.execute(
                f'insert into "{schema}".corpus_chunk ({", ".join(row)}) values ({", ".join(["%s"] * len(row))})',
                tuple(row.values()),
            )


@pytest.fixture
def approver(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("APPROVER_TOKEN_SHA256", hashlib.sha256(TOKEN.encode()).hexdigest())
    return TOKEN


@pytest.fixture
def served(loaded: TestClient, postgres_url: str) -> TestClient:
    load_corpus(postgres_url)
    return loaded


def start(client: TestClient, cve: str = CVE, as_of: str | None = AS_OF) -> dict[str, Any]:
    response = client.post("/v1/triage", json={"cve_id": cve, **({"as_of": as_of} if as_of else {})})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def decide(
    client: TestClient,
    run: dict[str, Any],
    decision: str = "approve",
    token: str | None = TOKEN,
    **changes: Any,
) -> Any:
    waiting = run["waiting_for"][0]
    body = {
        "run_id": run["run_id"],
        "kind": "plan" if waiting["kind"] == "patch_plan" else "warning",
        "sha256": waiting["sha256"],
        "decision": decision,
        **changes,
    }
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/v1/approvals", json=body, headers=headers)


def checkpoint_rows(url: str, run_id: str) -> int:
    with psycopg.connect(plain(url)) as conn:
        row = conn.execute(
            f'select count(*) from "{checkpoint_schema("unscheduled")}".checkpoints where thread_id = %s',
            (run_id,),
        ).fetchone()
    return int(row[0]) if row else 0


def test_a_run_reaches_its_first_interrupt_with_a_checked_plan(served: TestClient) -> None:
    run = start(served)
    assert run["status"] == "waiting" and run["cve_id"] == CVE
    assert run["as_of"].startswith(AS_OF)
    assert [w["kind"] for w in run["waiting_for"]] == ["patch_plan"]
    plan = run["drafts"]["plan"]
    assert plan["status"] == "waiting" and plan["by"] == "floor"
    assert plan["sha256"] == run["waiting_for"][0]["sha256"]
    check = plan["check"]
    assert check["blocked"] is False and check["citations_failed"] == 0
    claims = {c["field"]: c for c in check["draft"]["claims"]}
    assert claims["fixed_version"]["value"] == "1.2.1"
    assert claims["fixed_version"]["citations"][0]["source"] == ADVISORY
    assert claims["component"]["value"] == "example.org/fixture/logkit"
    facts = run["facts"]
    assert facts["match"]["product"] == "go-edge-service" and facts["match"]["installed_version"] == "1.2.0"
    assert facts["kev"]["date_added"] == "2021-12-10"
    assert [e["source"] for e in facts["exploits"]] == ["metasploit"]
    assert {e["doc_id"] for e in facts["evidence"]} <= {ADVISORY, KEV_DOC}
    assert list(run["nodes"])[:6] == ["intake", "match", "fill", "rank", "retrieve", "plan"]
    assert run["nodes"]["plan"]["calls"] == 1 and run["nodes"]["plan"]["shadow_usd"] == 0.0
    assert run["note"] == triage.NO_PROVIDER
    assert "not an instruction" in run["untrusted"]
    assert run["statement"] and run["data_version"]


def test_the_run_reads_only_what_was_known_at_its_time(served: TestClient) -> None:
    """Before the KEV listing and before the advisory, the run has neither: no warning follows."""
    run = start(served, as_of="2021-03-01")
    facts = run["facts"]
    assert facts["kev"] is None and facts["exploits"] == [] and facts["fixed_versions"] == []
    claims = {c["field"] for c in run["drafts"]["plan"]["check"]["draft"]["claims"]}
    assert "no_fixed_version" in claims and "fixed_version" not in claims


def test_runs_list_newest_first_and_read_back_whole(served: TestClient) -> None:
    first = start(served)
    second = start(served, as_of="2021-06-01")
    listed = served.get("/v1/runs", params={"limit": 5}).json()
    assert [r["run_id"] for r in listed["runs"]] == [second["run_id"], first["run_id"]]
    assert listed["runs"][0]["status"] == "waiting"
    again = served.get(f"/v1/runs/{first['run_id']}").json()
    assert again["drafts"]["plan"]["sha256"] == first["drafts"]["plan"]["sha256"]
    assert again["waiting_for"] == first["waiting_for"]
    assert served.get("/v1/runs/" + "0" * 32).status_code == 404
    assert served.get("/v1/runs/not-a-run").status_code == 422


def test_a_decision_without_the_token_records_nothing(
    served: TestClient, approver: str, postgres_url: str
) -> None:
    run = start(served)
    for token in (None, "wrong-token"):
        response = decide(served, run, token=token)
        assert response.status_code == 403, response.text
        assert response.json()["type"].endswith("approval-refused")
    after = served.get(f"/v1/runs/{run['run_id']}").json()
    assert after["approvals"] == [] and after["drafts"]["plan"]["status"] == "waiting"
    assert after["waiting_for"] == run["waiting_for"]


def test_a_decision_on_another_hash_records_nothing(served: TestClient, approver: str) -> None:
    run = start(served)
    response = decide(served, run, sha256="f" * 64)
    assert response.status_code == 403 and "nothing was recorded" in response.json()["detail"]
    other_kind = decide(served, run, kind="warning")
    assert other_kind.status_code == 403
    assert served.get(f"/v1/runs/{run['run_id']}").json()["approvals"] == []


def test_approving_the_plan_then_the_warning_by_hash(
    served: TestClient, approver: str, postgres_url: str
) -> None:
    run = start(served)
    plan_sha = run["waiting_for"][0]["sha256"]
    response = decide(served, run)
    assert response.status_code == 200, response.text
    after_plan = response.json()
    assert after_plan["drafts"]["plan"]["status"] == "approved"
    # The CVE was listed by then, so the run drafts a warning and waits again.
    assert [w["kind"] for w in after_plan["waiting_for"]] == ["early_warning"]
    warning = after_plan["drafts"]["warning"]
    assert warning["status"] == "waiting" and warning["check"]["blocked"] is False
    response = decide(served, after_plan)
    assert response.status_code == 200, response.text
    done = response.json()
    assert done["status"] == "decided" and done["waiting_for"] == []
    assert done["drafts"]["plan"]["status"] == "approved" and done["drafts"]["warning"]["status"] == "ready"
    recorded = [(a["kind"], a["decision"], a["sha256"], a["token_ok"]) for a in done["approvals"]]
    assert recorded[0] == ("plan", "approve", plan_sha, True) and recorded[1][:2] == ("warning", "approve")
    # A decided run keeps only its latest checkpoint.
    assert checkpoint_rows(postgres_url, run["run_id"]) == 1
    assert served.get(f"/v1/runs/{run['run_id']}").json()["drafts"]["warning"]["status"] == "ready"


def test_a_rejected_plan_is_rejected(served: TestClient, approver: str) -> None:
    run = start(served, as_of="2021-06-01")
    response = decide(served, run, decision="reject")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["drafts"]["plan"]["status"] == "rejected"
    # Not listed by June 2021, so no warning follows and the run is decided.
    assert body["status"] == "decided" and "warning" not in body["drafts"]


def test_the_token_is_never_logged(
    served: TestClient, approver: str, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    run = start(served)
    decide(served, run, token="not-the-token")
    decide(served, run)
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err + caplog.text
    assert "not-the-token" not in captured.out + captured.err + caplog.text


def test_past_the_serving_budget_the_floor_drafts_and_says_so(
    served: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(triage, "serving", lambda root=None: triage.Serving(per_client=1, per_day=100))
    assert start(served)["note"] == triage.NO_PROVIDER
    second = start(served)
    assert second["note"].startswith("this client has started its 1 triage runs for today")
    assert second["status"] == "waiting"


def test_the_serving_budgets_are_in_the_providers_file() -> None:
    limits = triage.serving()
    assert 0 < limits.per_client <= limits.per_day
    assert triage.floor_reason(limits.per_client, limits.per_day, limits) is None
    assert triage.floor_reason(1, limits.per_day + 1, limits) is not None


def test_the_run_store_cap_refuses_a_new_run(served: TestClient, postgres_url: str) -> None:
    now = datetime.now(UTC)
    with psycopg.connect(plain(postgres_url), autocommit=True) as conn:
        for i in range(triage.WAITING_CAP):
            conn.execute(
                'insert into "unscheduled".agent_run (run_id, cve_id, as_of, created_at, updated_at, status) '
                "values (%s, %s, %s, %s, %s, 'waiting')",
                (f"{i:032x}", CVE, now, now, now),
            )
    response = served.post("/v1/triage", json={"cve_id": CVE, "as_of": AS_OF})
    assert response.status_code == 503 and response.json()["type"].endswith("run-store-full")


def test_a_cve_outside_the_slice_or_before_publication_is_not_found(served: TestClient) -> None:
    assert served.post("/v1/triage", json={"cve_id": "CVE-2020-99999"}).status_code == 404
    early = served.post("/v1/triage", json={"cve_id": CVE, "as_of": "2020-01-01"})
    assert early.status_code == 404 and "not yet published" in early.json()["detail"]
    today = served.post("/v1/triage", json={"cve_id": CVE, "as_of": date.today().isoformat()})
    assert today.status_code == 422
    assert served.post("/v1/triage", json={"cve_id": "CVE-21-1"}).status_code == 422
    assert served.post("/v1/triage", json={"cve_id": CVE, "extra": 1}).status_code == 422


def test_search_answers_as_of_a_past_day_and_marks_the_text_untrusted(served: TestClient) -> None:
    found = served.get("/v1/search", params={"q": "deserialization logkit", "as_of": "2022-01-01"}).json()
    assert found["configuration"] == "floor" and found["results"]
    assert {r["doc_id"] for r in found["results"]} <= {ADVISORY, KEV_DOC}
    assert all(r["untrusted"] for r in found["results"])
    scores = [r["score"] for r in found["results"]]
    assert scores == sorted(scores, reverse=True)
    before = served.get("/v1/search", params={"q": "deserialization logkit", "as_of": "2021-03-01"}).json()
    assert before["results"] == []
    assert served.get("/v1/search", params={"q": "x", "as_of": date.today().isoformat()}).status_code == 422
    assert served.get("/v1/search", params={"q": "", "as_of": "2022-01-01"}).status_code == 422
    sql_like = served.get("/v1/search", params={"q": "'; drop table cve; --", "as_of": "2022-01-01"})
    assert sql_like.status_code == 200


def test_the_agent_routes_count_against_the_client_budget(served: TestClient) -> None:
    response = served.get("/v1/runs")
    assert response.status_code == 200 and "X-Budget-Remaining" in response.headers
