"""unsched triage and unsched runs over the same services as POST /v1/triage and GET /v1/runs.

A run's id and times differ from one start to the next, so the two surfaces are compared on a run the
command line started: the API reads it back with the same drafts, hashes and status, and the API's
listing and the command's listing name the same runs in the same order.
"""

from __future__ import annotations

import json
from datetime import date

from fastapi.testclient import TestClient
from typer.testing import CliRunner
from unscheduled_api.services import Services
from unscheduled_cli.main import create_cli

from tests.api.test_triage import AS_OF, CVE, load_corpus
from tests.cli.conftest import SCHEMA


def run_cli(shared: Services, *args: str) -> tuple[int, str, str]:
    result = CliRunner().invoke(create_cli(lambda: shared), list(args))
    return result.exit_code, result.stdout, result.stderr


def test_triage_and_runs_answer_as_the_routes_do(
    shared: Services, api: TestClient, postgres_url: str
) -> None:
    load_corpus(postgres_url, SCHEMA)
    code, out, err = run_cli(shared, "triage", CVE, "--as-of", AS_OF)
    assert code == 0, err
    run = json.loads(out)
    assert run["status"] == "waiting" and run["drafts"]["plan"]["status"] == "waiting"
    assert run["statement"] == shared.statement
    from_api = api.get(f"/v1/runs/{run['run_id']}").json()
    for key in ("cve_id", "as_of", "status", "waiting_for", "drafts", "facts", "approvals"):
        assert from_api[key] == run[key], key
    code, out, err = run_cli(shared, "runs", run["run_id"])
    assert code == 0, err
    assert json.loads(out)["drafts"] == from_api["drafts"]
    code, out, err = run_cli(shared, "runs", "--limit", "5")
    assert code == 0, err
    assert json.loads(out)["runs"] == api.get("/v1/runs", params={"limit": 5}).json()["runs"]


def test_the_agent_commands_refuse_what_the_routes_refuse(shared: Services) -> None:
    code, _out, err = run_cli(shared, "triage", CVE, "--as-of", date.today().isoformat())
    assert code == 1 and "as_of must be a day that has already ended" in err
    code, _out, err = run_cli(shared, "runs", "not-a-run")
    assert code == 1 and "a run id is 32 hexadecimal characters" in err
    code, _out, err = run_cli(shared, "runs", "0" * 32)
    assert code == 1 and "not-found" in err


def test_no_command_takes_the_approver_token_or_approves() -> None:
    names = {c.name or (c.callback.__name__ if c.callback else "") for c in create_cli().registered_commands}
    assert {"triage", "runs", "mcp"} <= names
    assert not {n for n in names if any(w in n for w in ("approve", "apply", "file", "decide"))}
    for command in create_cli().registered_commands:
        assert command.callback is not None
        params = command.callback.__annotations__
        assert not any("token" in p for p in params), command.name
