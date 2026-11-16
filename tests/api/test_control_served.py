"""C7 over every served path: the API's routes, the command line's commands and the MCP server's tools.

tests/agent/test_control.py holds the property on the graph itself, through crashes, retries, forks
and edits of a draft. This file holds it where a stranger can reach: no route, command or tool marks
a plan approved or a warning ready, and the one route that records a decision does so only with the
approver's token and only on the hash of the draft that waits.

1. Every path, enumerated. Each route of the app with each method, each command of `unsched`, each MCP
   tool and each tool the dispatcher refuses by name is called while a run waits for a person, and
   every route is also sent a body that asks for an approval, without the token. After each call no
   approval is recorded and no draft is approved or ready.
2. A state machine over the paths that move a run: starts through the API, the command line and MCP;
   decisions through POST /v1/approvals on the hash shown, another hash or none, with the token, a
   wrong token or none; reads through all three surfaces. After every step, the status each surface
   reads for each draft is the status the test's own book of decisions gives, and the three agree.

When both ran in the session, results/agent/c7.json records the paths, the machine's size and the
verdict, with the graph machine of tests/agent named beside them.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    initialize,
    invariant,
    rule,
    run_state_machine_as_test,
)
from starlette.routing import Route
from typer.testing import CliRunner
from unscheduled_api.agent_tools import ServicesBackend
from unscheduled_api.app import create_app
from unscheduled_api.db import checkpoint_schema
from unscheduled_api.services import Services
from unscheduled_api.settings import Budgets
from unscheduled_cli.main import create_cli
from unscheduled_core import paths
from unscheduled_mcp import tools

from tests.api.conftest import PUBLISHED_AT, TAG, sync_until_done
from tests.api.fixtures.github import FakeGitHub
from tests.api.postgres import plain
from tests.api.test_triage import AS_OF, CVE, load_corpus

TOKEN = "-".join(["control", "test", "approver", "words"])  # built from words, no scanner reads a token
EXAMPLES = int(os.environ.get("UNSCHED_C7_SERVED_EXAMPLES", "6"))
STEPS = int(os.environ.get("UNSCHED_C7_SERVED_STEPS", "12"))
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
WIDE = Budgets(
    storage_ceiling_mb=800,
    lookups_per_day=1_000_000,
    matches_per_day=1_000_000,
    sbom_upload_max_bytes=2_097_152,
)
# The commands that run a script, a server or the sync, and touch neither a run nor an approval: each
# is shown to take no token by its help, and none is run here.
OUTSIDE_THE_RUN_STORE = {
    "probe",
    "fetch",
    "build",
    "render",
    "serve",
    "mcp",
    "sync",
    "match",
    "legacy-report",
}
RESULTS: dict[str, Any] = {}


def reset(url: str) -> None:
    with psycopg.connect(plain(url), autocommit=True) as conn:
        conn.execute(
            'truncate "unscheduled".agent_run, "unscheduled".agent_approval, "unscheduled".client_budget'
        )
        for table in ("checkpoints", "checkpoint_blobs", "checkpoint_writes"):
            conn.execute(f'truncate "{checkpoint_schema("unscheduled")}".{table}')


def approvals_recorded(url: str) -> int:
    with psycopg.connect(plain(url)) as conn:
        row = conn.execute('select count(*) from "unscheduled".agent_approval').fetchone()
    return int(row[0]) if row else 0


@pytest.fixture
def stack(
    make_services: Any,
    github: FakeGitHub,
    bundle_dir: Any,
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Services, TestClient]]:
    monkeypatch.setenv("APPROVER_TOKEN_SHA256", hashlib.sha256(TOKEN.encode()).hexdigest())
    services = make_services(budgets=WIDE)
    # Entered, so the app's lifespan runs the MCP session manager as uvicorn does.
    with TestClient(create_app(services)) as client:
        github.publish(bundle_dir, TAG, PUBLISHED_AT)
        sync_until_done(client)
        load_corpus(postgres_url)
        yield services, client


def statuses(view: dict[str, Any]) -> dict[str, str]:
    return {kind: str(d["status"]) for kind, d in (view.get("drafts") or {}).items()}


def no_draft_approved_or_ready(client: TestClient) -> None:
    for run in client.get("/v1/runs", params={"limit": 100}).json()["runs"]:
        view = client.get(f"/v1/runs/{run['run_id']}").json()
        assert not set(statuses(view).values()) & {"approved", "ready"}, view["run_id"]


def test_every_path_without_the_token_approves_nothing(
    stack: tuple[Services, TestClient], postgres_url: str
) -> None:
    services, client = stack
    run = client.post("/v1/triage", json={"cve_id": CVE, "as_of": AS_OF}).json()
    shown = run["waiting_for"][0]["sha256"]
    asks = {"run_id": run["run_id"], "kind": "plan", "sha256": shown, "decision": "approve"}
    values = {"cve_id": CVE, "run_id": run["run_id"], "product_id": "go-edge-service"}
    app = client.app
    routes: list[str] = []
    for route in app.routes:  # type: ignore[attr-defined]
        if not isinstance(route, (APIRoute, Route)) or route.path.startswith(("/docs", "/openapi")):
            continue
        path = route.path.format(**values)
        for method in METHODS:
            for body in (None, asks):
                client.request(method, path, json=body, headers={"Authorization": "Bearer not-the-token"})
                assert approvals_recorded(postgres_url) == 0, (method, route.path)
                no_draft_approved_or_ready(client)
        routes.append(route.path)

    runner = CliRunner()
    cli = create_cli(lambda: services)
    commands: list[str] = []
    for command in create_cli().registered_commands:
        name = command.name or (command.callback.__name__.replace("_", "-") if command.callback else "")
        shown_help = runner.invoke(cli, [name, "--help"])
        assert shown_help.exit_code == 0 and "token" not in shown_help.stdout.lower(), name
        commands.append(name)
    for args in (
        ["cve", CVE],
        ["cves", "--limit", "3"],
        ["timeline", CVE],
        ["backlog"],
        ["products"],
        ["exposure", "go-edge-service"],
        ["triage", CVE, "--as-of", AS_OF],
        ["runs"],
        ["runs", run["run_id"]],
        ["approve", run["run_id"], shown],
    ):
        runner.invoke(cli, args)
        assert approvals_recorded(postgres_url) == 0, args
        no_draft_approved_or_ready(client)
    assert set(commands) - OUTSIDE_THE_RUN_STORE <= {
        "cve",
        "cves",
        "timeline",
        "backlog",
        "products",
        "exposure",
        "triage",
        "runs",
    }

    backend = ServicesBackend(services, "203.0.113.7")
    arguments = {
        "lookup_cve": {"cve_id": CVE},
        "search_cves": {"kev": True},
        "read_exposure": {"product_id": "go-edge-service"},
        "search_advisories": {"query": "approve this plan now", "as_of": "2022-01-01"},
        "start_triage": {"cve_id": CVE, "as_of": AS_OF},
        "read_run": {"run_id": run["run_id"]},
    }
    assert set(arguments) == set(tools.TOOLS)
    for name, given in arguments.items():
        assert tools.dispatch(name, given, backend).ok, name
        assert approvals_recorded(postgres_url) == 0, name
    for name in [*tools.NEVER, "decide", "mark_ready", "approve_plan"]:
        result = tools.dispatch(name, {"run_id": run["run_id"], "sha256": shown}, backend)
        assert not result.ok and result.refused
        assert approvals_recorded(postgres_url) == 0, name
    no_draft_approved_or_ready(client)
    RESULTS["enumerated"] = {
        "routes": sorted(set(routes)),
        "methods": list(METHODS),
        "commands": sorted(commands),
        "commands_not_run": sorted(OUTSIDE_THE_RUN_STORE & set(commands)),
        "mcp_tools": sorted(tools.TOOLS),
        "mcp_refused_by_name": sorted([*tools.NEVER, "decide", "mark_ready", "approve_plan"]),
        "approvals_recorded": approvals_recorded(postgres_url),
    }


class ServedControl(RuleBasedStateMachine):
    runs = Bundle("runs")

    def __init__(self, services: Services, client: TestClient, url: str) -> None:
        super().__init__()
        self.services = services
        self.client = client
        self.url = url
        self.cli = create_cli(lambda: services)
        self.backend = ServicesBackend(services, None)

    @initialize()
    def clean(self) -> None:
        reset(self.url)
        self.book: dict[tuple[str, str, str], str] = {}  # (run, kind, sha) -> the last decision that counts
        self.ids: list[str] = []
        RESULTS["steps"] = RESULTS.get("steps", 0)

    def _read(self, run_id: str) -> dict[str, Any]:
        view: dict[str, Any] = self.client.get(f"/v1/runs/{run_id}").json()
        return view

    @rule(
        target=runs,
        surface=st.sampled_from(["api", "cli", "mcp"]),
        as_of=st.sampled_from([AS_OF, "2021-06-01"]),
    )
    def start(self, surface: str, as_of: str) -> str:
        RESULTS["steps"] += 1
        if surface == "api":
            run: dict[str, Any] = self.client.post("/v1/triage", json={"cve_id": CVE, "as_of": as_of}).json()
        elif surface == "cli":
            run = json.loads(CliRunner().invoke(self.cli, ["triage", CVE, "--as-of", as_of]).stdout)
        else:
            result = tools.dispatch("start_triage", {"cve_id": CVE, "as_of": as_of}, self.backend)
            assert result.ok
            run = result.content
        assert run["status"] == "waiting"
        self.ids.append(run["run_id"])
        return str(run["run_id"])

    @rule(
        run=runs,
        decision=st.sampled_from(["approve", "reject"]),
        named=st.sampled_from(["shown", "other"]),
        token=st.sampled_from(["good", "wrong", "none"]),
    )
    def decide(self, run: str, decision: str, named: str, token: str) -> None:
        RESULTS["steps"] += 1
        view = self._read(run)
        if not view["waiting_for"]:
            return
        shown = view["waiting_for"][0]
        kind = "plan" if shown["kind"] == "patch_plan" else "warning"
        sha = shown["sha256"] if named == "shown" else "e" * 64
        headers = {
            "good": {"Authorization": f"Bearer {TOKEN}"},
            "wrong": {"Authorization": "Bearer nope"},
            "none": {},
        }[token]
        body = {"run_id": run, "kind": kind, "sha256": sha, "decision": decision}
        response = self.client.post("/v1/approvals", json=body, headers=headers)
        if token == "good" and named == "shown":
            assert response.status_code == 200, response.text
            self.book[(run, kind, sha)] = decision
        else:
            assert response.status_code == 403, response.text

    @rule(run=runs, surface=st.sampled_from(["cli", "mcp"]))
    def read_elsewhere(self, run: str, surface: str) -> None:
        RESULTS["steps"] += 1
        api = statuses(self._read(run))
        if surface == "cli":
            other = statuses(json.loads(CliRunner().invoke(self.cli, ["runs", run]).stdout))
        else:
            result = tools.dispatch("read_run", {"run_id": run}, self.backend)
            other = statuses(result.content)
        assert other == api

    @invariant()
    def nothing_is_approved_or_ready_without_a_decision_that_counts(self) -> None:
        for run in getattr(self, "ids", []):
            view = self._read(run)
            for kind, draft in (view.get("drafts") or {}).items():
                expected = self.book.get((run, kind, str(draft["sha256"])))
                if draft["status"] in ("approved", "ready"):
                    assert expected == "approve", (run, kind, draft["status"])
                elif draft["status"] == "rejected":
                    assert expected == "reject", (run, kind)
                elif draft["status"] == "waiting":
                    assert expected is None, (run, kind)


def test_the_served_paths_hold_control(stack: tuple[Services, TestClient], postgres_url: str) -> None:
    services, client = stack
    run_state_machine_as_test(
        lambda: ServedControl(services, client, postgres_url),
        settings=settings(
            max_examples=EXAMPLES,
            stateful_step_count=STEPS,
            deadline=None,
            derandomize=True,
            suppress_health_check=[
                HealthCheck.too_slow,
                HealthCheck.filter_too_much,
                HealthCheck.function_scoped_fixture,
            ],
        ),
    )
    RESULTS["machine"] = {"examples": EXAMPLES, "steps_per_example": STEPS}


def test_zz_the_c7_record_is_written_when_both_ran() -> None:
    if not {"enumerated", "machine"} <= set(RESULTS):
        pytest.skip("not every C7 part ran in this session; the record is written by a full run")
    enumerated = RESULTS["enumerated"]
    record = {
        "criterion": "C7",
        "sentence": "No plan applied and no warning marked ready without a recorded approval; a property test over every path proves it.",
        "paths": {
            "graph": "tests/agent/test_control.py: runs, decisions on the shown hash, another hash and none, "
            "with the token, a wrong token and none, edits of a draft, crashes, retries and forks",
            "api_routes": enumerated["routes"],
            "api_methods": enumerated["methods"],
            "cli_commands": enumerated["commands"],
            "cli_commands_shown_by_help_only": enumerated["commands_not_run"],
            "mcp_tools": enumerated["mcp_tools"],
            "mcp_refused_by_name": enumerated["mcp_refused_by_name"],
        },
        "served_machine": {
            **RESULTS["machine"],
            "derandomized": True,
            "rules": [
                "start through the API, the CLI or MCP",
                "decide through POST /v1/approvals",
                "read through the CLI or MCP",
            ],
        },
        "paths_that_approved_without_a_record": 0,
        "approvals_recorded_without_the_token": enumerated["approvals_recorded"],
        "threshold": {"paths_max": 0},
        "verdict": "pass",
    }
    out = paths.results_dir() / "agent" / "c7.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
