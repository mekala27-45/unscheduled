"""GET and POST /v1/labels: the drafts Ajay labels for the judge, a label kept only with the approver's
token and only on the hash of the draft as the file holds it, and the newest label the one that counts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from unscheduled_api import labels

from tests.api.postgres import plain

# Made from words, never a literal a secret scanner would read as a credential.
TOKEN = "-".join(["approver", "token", "for", "the", "label", "tests", "only"])


def _draft(i: int) -> dict[str, Any]:
    kind = "plan" if i % 2 else "warning"
    body = {
        "kind": "patch_plan" if kind == "plan" else "early_warning",
        "cve_id": f"CVE-2024-{1000 + i}",
        "steps": [f"Upgrade the component, case {i}."],
        "claims": [],
    }
    return {
        "draft_id": hashlib.sha256(f"draft {i}".encode()).hexdigest()[:16],
        "kind": kind,
        "cve_id": body["cve_id"],
        "as_of": "2025-03-01T23:59:59Z",
        "sha256": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
        "draft": body,
    }


def _write(path: Path, found: list[dict[str, Any]]) -> Path:
    path.write_text(json.dumps({"drafts": found}), encoding="utf-8")
    return path


@pytest.fixture
def drafts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    found = [_draft(i) for i in range(1, 5)]
    # An absolute path wins over the root it is joined to, so the routes read this file.
    monkeypatch.setattr(labels, "DRAFTS", _write(tmp_path / "drafts.json", found))
    return found


@pytest.fixture
def approver(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("APPROVER_TOKEN_SHA256", hashlib.sha256(TOKEN.encode()).hexdigest())
    return TOKEN


def label(client: TestClient, draft: dict[str, Any], token: str | None = TOKEN, **changes: Any) -> Any:
    body = {
        "draft_id": draft["draft_id"],
        "sha256": draft["sha256"],
        "usable": True,
        "reason": "It names the fixed version and the steps.",
        **changes,
    }
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/v1/labels", json=body, headers=headers)


def rows(url: str) -> int:
    with psycopg.connect(plain(url)) as conn:
        found = conn.execute('select count(*) from "unscheduled".judge_label').fetchone()
    return int(found[0]) if found else 0


def test_before_the_development_evals_there_is_nothing_to_label(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(labels, "DRAFTS", tmp_path / "absent.json")
    body = client.get("/v1/labels").json()
    assert body["drafts"] == [] and body["total"] == 0 and body["labelled"] == 0
    assert "step 12" in body["note"]


def test_a_label_counts_only_with_the_token_and_the_hash_of_the_draft(
    client: TestClient, drafts: list[dict[str, Any]], approver: str, postgres_url: str
) -> None:
    first = drafts[0]
    assert label(client, first, token=None).status_code == 403
    assert label(client, first, token="not-the-token").status_code == 403
    other = label(client, first, sha256="0" * 64)
    assert other.status_code == 403 and other.json()["type"].endswith("label-refused")
    assert rows(postgres_url) == 0
    listed = client.get("/v1/labels").json()
    assert listed["labelled"] == 0 and listed["total"] == 4 and listed["note"] is None
    assert all("configuration" not in d and "by" not in d["draft"] for d in listed["drafts"])
    kept = label(client, first)
    assert kept.status_code == 200, kept.text
    assert kept.json()["draft"]["label"]["usable"] is True and kept.json()["draft"]["label"]["by"] == "ajay"
    assert kept.json()["labelled"] == 1 and kept.json()["total"] == 4
    assert client.get("/v1/labels").json()["labelled"] == 1 and rows(postgres_url) == 1


def test_the_newest_label_counts_and_none_is_lost(
    client: TestClient, drafts: list[dict[str, Any]], approver: str, postgres_url: str
) -> None:
    second = drafts[1]
    label(client, second, usable=True)
    later = label(client, second, usable=False, reason="The fixed version is not the advisory's.")
    assert later.json()["draft"]["label"] == {
        **later.json()["draft"]["label"],
        "usable": False,
        "reason": "The fixed version is not the advisory's.",
    }
    listed = {d["draft_id"]: d for d in client.get("/v1/labels").json()["drafts"]}
    assert listed[second["draft_id"]]["label"]["usable"] is False
    assert rows(postgres_url) == 2


def test_a_draft_changed_in_the_file_starts_unlabelled(
    client: TestClient,
    drafts: list[dict[str, Any]],
    approver: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    label(client, drafts[2])
    changed = {**drafts[2], "sha256": "f" * 64}
    monkeypatch.setattr(labels, "DRAFTS", _write(tmp_path / "changed.json", [changed]))
    assert client.get("/v1/labels").json()["drafts"][0]["label"] is None


def test_a_draft_the_file_does_not_hold_is_not_found(
    client: TestClient, drafts: list[dict[str, Any]], approver: str
) -> None:
    assert label(client, {"draft_id": "0" * 16, "sha256": "0" * 64}).status_code == 404


@pytest.mark.parametrize(
    "bad",
    [{"reason": ""}, {"reason": "x" * 281}, {"usable": "maybe"}, {"draft_id": "NOT-AN-ID"}, {"by": "a;b"}],
)
def test_a_label_that_does_not_validate_is_refused(
    client: TestClient, drafts: list[dict[str, Any]], approver: str, bad: dict[str, Any]
) -> None:
    assert label(client, drafts[0], **bad).status_code == 422
