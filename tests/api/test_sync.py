"""The pull based sync: digests checked, one bounded step per call, idempotent, rate limited, bounded.

Every assertion about what the sync wrote reads the database through a connection the test opens
itself, never through the app's own session.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import psycopg
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.services import Services
from unscheduled_api.settings import Budgets
from unscheduled_api.sync import CALLS_PER_MINUTE, LOCK_KEY, PLAN

from tests.api.conftest import PUBLISHED_AT, TAG, Clock, sync_until_done
from tests.api.fixtures.bundle import rows, write_bundle
from tests.api.fixtures.github import FakeGitHub
from tests.api.postgres import plain

pytestmark = pytest.mark.usefixtures("engine")


def count(url: str, table: str) -> int:
    with psycopg.connect(plain(url)) as conn:
        row = conn.execute(f'select count(*) from "unscheduled"."{table}"').fetchone()
    assert row is not None
    return int(row[0])


def setting(url: str, key: str) -> Any:
    with psycopg.connect(plain(url)) as conn:
        row = conn.execute('select value from "unscheduled"."settings" where key = %s', (key,)).fetchone()
    return row[0] if row else None


def test_a_full_load_reports_every_step_and_ends_done(
    client: TestClient, github: FakeGitHub, bundle_dir: Path, postgres_url: str
) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    answers = sync_until_done(client)
    assert answers[0]["status"] == "more" and answers[0]["step"] == "start"
    assert answers[-1]["status"] == "done"
    steps = [a["step"] for a in answers[1:]]
    assert steps == [f"{kind} {table}" if table else kind for kind, table in PLAN]
    assert answers[-1]["chunks_done"] == answers[-1]["chunks_total"] == len(PLAN)
    assert all(a["statement"] and a["data_version"] for a in answers)
    assert answers[-1]["data_version"].startswith(TAG + "+")
    assert count(postgres_url, "cve") == len(rows("cve"))
    assert count(postgres_url, "cve_event") == len(rows("cve_event"))
    assert count(postgres_url, "product") == len(rows("product"))
    assert count(postgres_url, "finding") == len(rows("finding"))
    loaded = setting(postgres_url, "data_version")
    assert loaded["tag"] == TAG and loaded["counts"]["cve"] == len(rows("cve"))
    assert setting(postgres_url, "sync") is None
    assert setting(postgres_url, "backlog")["q1"]
    with psycopg.connect(plain(postgres_url)) as conn:
        statuses = [r[0] for r in conn.execute('select status from "unscheduled"."ops_run" order by id')]
    assert statuses[0] == "started" and statuses[-1] == "done"


def test_a_call_when_current_is_a_no_op_that_asks_github_nothing(
    loaded: TestClient, github: FakeGitHub, clock: Clock
) -> None:
    calls = github.api_calls
    body = loaded.post("/internal/sync").json()
    assert body["status"] == "current" and body["checked_release"] is False
    assert github.api_calls == calls
    clock.advance(61)
    body = loaded.post("/internal/sync").json()
    assert body["status"] == "current" and body["checked_release"] is True
    assert github.api_calls == calls + 1 and github.not_modified == 1


def test_get_runs_the_same_handler_for_the_cron(
    client: TestClient, github: FakeGitHub, bundle_dir: Path
) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    first = client.get("/internal/sync", headers={"user-agent": "vercel-cron/1.0"})
    assert first.status_code == 200 and first.json()["status"] == "more"
    for _ in range(len(PLAN)):
        last = client.get("/internal/sync").json()
    assert last["status"] == "done"


def test_a_second_full_load_of_the_same_rows_changes_nothing(
    loaded: TestClient, github: FakeGitHub, clock: Clock, tmp_path: Path, postgres_url: str
) -> None:
    again = tmp_path / "again"
    write_bundle(again, generated_at="2026-11-08T05:00:00Z")
    github.publish(again, "serving-202611080500", "2026-11-08T05:10:00Z")
    clock.advance(61)
    answers = sync_until_done(loaded)
    loads = [a for a in answers if a["step"] and a["step"].startswith(("load", "sweep"))]
    assert loads and all(a["chunk"]["rows_changed"] == 0 for a in loads)
    assert answers[-1]["status"] == "done" and answers[-1]["data_version"].startswith("serving-202611080500+")
    assert count(postgres_url, "cve") == len(rows("cve"))


def test_a_new_bundle_writes_only_what_changed_and_sweeps_what_left(
    loaded: TestClient, github: FakeGitHub, clock: Clock, tmp_path: Path, postgres_url: str
) -> None:
    cves = rows("cve")
    changed = [dict(r) for r in cves if r["cve_id"] != "CVE-2024-90006"]
    for row in changed:
        if row["cve_id"] == "CVE-2026-90003":
            row["nvd_status"] = "Analyzed"
    events = [e for e in rows("cve_event") if e["cve_id"] != "CVE-2024-90006"]
    newer = tmp_path / "newer"
    write_bundle(newer, tables={"cve": changed, "cve_event": events}, generated_at="2026-11-09T05:00:00Z")
    github.publish(newer, "serving-202611090500", "2026-11-09T05:10:00Z")
    clock.advance(61)
    answers = sync_until_done(loaded)
    by_step = {a["step"]: a for a in answers}
    assert by_step["sweep cve"]["chunk"]["rows_changed"] == 1
    assert by_step["load cve"]["chunk"]["rows_changed"] == 1
    assert by_step["sweep cve_event"]["chunk"]["rows_changed"] == 2
    assert count(postgres_url, "cve") == len(cves) - 1
    with psycopg.connect(plain(postgres_url)) as conn:
        status = conn.execute(
            'select nvd_status from "unscheduled"."cve" where cve_id = \'CVE-2026-90003\''
        ).fetchone()
    assert status == ("Analyzed",)


def test_a_file_that_does_not_match_its_digest_is_rejected_and_nothing_is_loaded(
    client: TestClient, github: FakeGitHub, bundle_dir: Path, postgres_url: str
) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT, digests=False)
    github.replace_bytes(TAG, "cve.parquet", b"PAR1 not the file the manifest names")
    assert client.post("/internal/sync").json()["status"] == "more"
    refused = client.post("/internal/sync")
    assert refused.status_code == 502
    body = refused.json()
    assert refused.headers["content-type"].startswith("application/problem+json")
    assert body["type"].endswith("#problem-bundle-rejected") and body["context"]["status"] == "refused"
    assert "differs from the manifest" in body["detail"]
    assert count(postgres_url, "cve") == 0
    assert setting(postgres_url, "sync") is None
    assert setting(postgres_url, "data_version") is None


def test_a_digest_github_reports_that_disagrees_with_the_manifest_is_refused_before_download(
    client: TestClient, github: FakeGitHub, bundle_dir: Path, postgres_url: str
) -> None:
    release = github.publish(bundle_dir, TAG, PUBLISHED_AT)
    for asset in release["assets"]:
        if asset["name"] == "finding.parquet":
            asset["digest"] = "sha256:" + "f" * 64
    refused = client.post("/internal/sync")
    assert refused.status_code == 502
    assert "GitHub reports a digest" in refused.json()["detail"]
    assert github.downloads == 1  # the manifest, nothing else
    assert count(postgres_url, "cve") == 0


def test_a_release_without_a_file_is_refused(
    client: TestClient, github: FakeGitHub, bundle_dir: Path
) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT, omit=("cve_event.parquet",))
    refused = client.post("/internal/sync")
    assert refused.status_code == 502
    assert "no asset named cve_event.parquet" in refused.json()["detail"]


def test_a_missing_required_column_is_refused_by_name(
    client: TestClient, github: FakeGitHub, tmp_path: Path, postgres_url: str
) -> None:
    from tests.api.fixtures.bundle import CVE_TYPES

    types = {k: v for k, v in CVE_TYPES.items() if k != "nvd_status"}
    broken = tmp_path / "broken"
    write_bundle(broken, types={"cve": types})
    github.publish(broken, TAG, PUBLISHED_AT)
    client.post("/internal/sync")
    refused = client.post("/internal/sync")
    assert refused.status_code == 502
    assert "missing required columns: nvd_status" in refused.json()["detail"]
    assert count(postgres_url, "cve") == 0


def test_an_optional_column_that_is_missing_loads_as_null_and_is_named(
    client: TestClient, github: FakeGitHub, tmp_path: Path, postgres_url: str
) -> None:
    from tests.api.fixtures.bundle import CVE_TYPES

    types = {k: v for k, v in CVE_TYPES.items() if k != "epss_percentile"}
    partial = tmp_path / "partial"
    write_bundle(partial, types={"cve": types})
    github.publish(partial, TAG, PUBLISHED_AT)
    sync_until_done(client)
    assert setting(postgres_url, "data_version")["absent_columns"]["cve"] == ["epss_percentile"]
    meta = client.get("/v1/meta").json()
    assert meta["bundle"]["absent_columns"]["cve"] == ["epss_percentile"]


def test_a_chunk_that_would_pass_the_storage_ceiling_is_refused_and_writes_nothing(
    make_services: Any, github: FakeGitHub, bundle_dir: Path, postgres_url: str
) -> None:
    tiny = Budgets(
        storage_ceiling_mb=1, lookups_per_day=100, matches_per_day=10, sbom_upload_max_bytes=2_097_152
    )
    client = TestClient(create_app(make_services(budgets=tiny)))
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    client.post("/internal/sync")
    client.post("/internal/sync")  # sweep cve, which deletes and adds nothing
    refused = client.post("/internal/sync")
    assert refused.status_code == 507
    body = refused.json()
    assert body["context"]["reason"] == "storage" and body["context"]["storage_ceiling_bytes"] == 1_000_000
    assert body["context"]["database_size_bytes"] > 1_000_000
    assert count(postgres_url, "cve") == 0
    with psycopg.connect(plain(postgres_url)) as conn:
        last = conn.execute('select status from "unscheduled"."ops_run" order by id desc limit 1').fetchone()
    assert last == ("refused",)


def test_a_second_caller_gets_busy_while_the_lock_is_held(
    client: TestClient, github: FakeGitHub, bundle_dir: Path, postgres_url: str
) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    held = threading.Event()
    done = threading.Event()

    def hold() -> None:
        with psycopg.connect(plain(postgres_url)) as conn, conn.transaction():
            conn.execute("select pg_advisory_xact_lock(%s)", (LOCK_KEY,))
            held.set()
            done.wait(10)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert held.wait(10)
        busy = client.post("/internal/sync")
        assert busy.status_code == 409
        assert busy.json()["context"]["status"] == "busy" and busy.headers["retry-after"] == "5"
    finally:
        done.set()
        thread.join()
    assert client.post("/internal/sync").json()["status"] == "more"


def test_the_sync_is_rate_limited_per_minute(
    client: TestClient, github: FakeGitHub, clock: Clock, postgres_url: str
) -> None:
    with psycopg.connect(plain(postgres_url)) as conn:
        for _ in range(CALLS_PER_MINUTE):
            conn.execute(
                'insert into "unscheduled"."ops_run" (kind, started_at, finished_at, status) '
                "values ('sync', %s, %s, 'checked')",
                (clock.now, clock.now),
            )
    limited = client.post("/internal/sync")
    assert limited.status_code == 429
    assert limited.json()["context"]["status"] == "rate_limited" and limited.headers["retry-after"] == "60"
    clock.advance(61)
    assert client.post("/internal/sync").status_code == 200


def test_github_refusing_the_listing_is_an_upstream_problem_with_its_reset(
    client: TestClient, github: FakeGitHub, postgres_url: str
) -> None:
    github.refuse_listing = 403
    refused = client.post("/internal/sync")
    assert refused.status_code == 503
    assert refused.json()["type"].endswith("#problem-upstream-unavailable")
    assert int(refused.headers["retry-after"]) > 60
    with psycopg.connect(plain(postgres_url)) as conn:
        last = conn.execute('select status from "unscheduled"."ops_run" order by id desc limit 1').fetchone()
    assert last == ("upstream",)


def test_no_serving_release_is_current_with_nothing_loaded(client: TestClient, github: FakeGitHub) -> None:
    github.releases.append(
        {"id": 1, "tag_name": "v0.1.0", "draft": False, "published_at": "2026-11-07T00:00:00Z", "assets": []}
    )
    body = client.post("/internal/sync").json()
    assert body["status"] == "current" and body["target"] is None
    assert "no release" in body["detail"]


def test_the_sync_takes_no_input(client: TestClient, github: FakeGitHub, bundle_dir: Path) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    other = client.post(
        "/internal/sync?repo=someone/else&tag=serving-x",
        content=json.dumps({"repo": "someone/else", "files": ["x"]}),
        headers={"content-type": "application/json"},
    )
    assert other.status_code == 200 and other.json()["target"].startswith(TAG + "+")


def test_a_new_instance_takes_the_next_step_from_the_cursor_in_the_database(
    make_services: Any, github: FakeGitHub, bundle_dir: Path
) -> None:
    github.publish(bundle_dir, TAG, PUBLISHED_AT)
    first: Services = make_services()
    TestClient(create_app(first)).post("/internal/sync")
    TestClient(create_app(first)).post("/internal/sync")
    second = TestClient(create_app(make_services()))
    body = second.post("/internal/sync").json()
    assert body["step"] == "sweep cve_event" or body["step"] == "load cve"


def test_sync_answers_without_a_database_as_a_problem() -> None:
    from unscheduled_api.settings import Settings

    services = Services.build(Settings.from_env({}))
    response = TestClient(create_app(services)).post("/internal/sync")
    assert response.status_code == 503
    assert response.json()["type"].endswith("#problem-database-unavailable")


def test_the_ledger_rows_are_visible_from_an_independent_connection(
    loaded: TestClient, postgres_url: str
) -> None:
    engine = sa.create_engine(postgres_url)
    with engine.connect() as conn:
        rows_seen = conn.execute(
            sa.text(
                'select step, rows_in, storage_bytes from "unscheduled"."ops_run" where status = \'loaded\''
            )
        ).all()
    engine.dispose()
    assert any(r.step == "load cve" and r.rows_in == len(rows("cve")) for r in rows_seen)
    assert all(r.storage_bytes and r.storage_bytes > 0 for r in rows_seen)
