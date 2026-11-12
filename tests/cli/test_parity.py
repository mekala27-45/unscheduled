"""The CLI and the API give the same answers on the same inputs.

Each case runs one `unsched` command and the route it mirrors against the same database, and
compares what came back: JSON as parsed objects, the legacy report byte for byte, a problem as the
same problem document. The few fields that differ by design are set aside, each with its reason:
the time a match ran and how long it took, the sentence about what was stored (the command line
stores nothing), and a problem's instance, which is a URL path on one side and a command on the
other. When every case agrees, results/cli_parity.json records the cases and a digest of each
answer, so the checklist line has its evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner
from unscheduled_api.services import Services
from unscheduled_cli.main import create_cli
from unscheduled_core import paths
from unscheduled_core.hashing import canonical_json

from tests.api.conftest import TAG
from tests.api.fixtures.bundle import SBOMS
from tests.cli.conftest import SCHEMA

ROOT = Path(__file__).resolve().parents[2]
CDX = SBOMS / "fixture.cdx.json"
SPDX = SBOMS / "fixture.spdx.json"
BY_DESIGN = {"duration_ms", "stored", "instance"}
MATCH_TIMES = {"as_of"}

# name, command line, method, path, body
CASES: list[tuple[str, list[str], str, str, Path | None]] = [
    ("a cve", ["cve", "CVE-2021-90001"], "GET", "/v1/cves/CVE-2021-90001", None),
    (
        "a cve as of a day",
        ["cve", "CVE-2021-90001", "--as-of", "2021-03-05"],
        "GET",
        "/v1/cves/CVE-2021-90001?as_of=2021-03-05",
        None,
    ),
    (
        "before publication",
        ["cve", "CVE-2026-90003", "--as-of", "2026-01-01"],
        "GET",
        "/v1/cves/CVE-2026-90003?as_of=2026-01-01",
        None,
    ),
    ("a cve not in the slice", ["cve", "CVE-1999-0001"], "GET", "/v1/cves/CVE-1999-0001", None),
    ("a page", ["cves", "--limit", "2"], "GET", "/v1/cves?limit=2", None),
    (
        "a filtered page",
        ["cves", "--kev", "--filer", "fixture-oss"],
        "GET",
        "/v1/cves?kev=true&filer=fixture-oss",
        None,
    ),
    ("a cwe", ["cves", "--cwe", "cwe-79"], "GET", "/v1/cves?cwe=cwe-79", None),
    ("a timeline", ["timeline", "CVE-2021-90001"], "GET", "/v1/cves/CVE-2021-90001/timeline", None),
    ("the backlog", ["backlog"], "GET", "/v1/backlog", None),
    ("the products", ["products"], "GET", "/v1/products", None),
    ("exposure today", ["exposure", "go-edge-service"], "GET", "/v1/products/go-edge-service/exposure", None),
    (
        "exposure at the pin",
        ["exposure", "go-edge-service", "--as-of", "pin"],
        "GET",
        "/v1/products/go-edge-service/exposure?as_of=pin",
        None,
    ),
    ("an unknown product", ["exposure", "nothing"], "GET", "/v1/products/nothing/exposure", None),
    ("a cyclonedx match", ["match", str(CDX)], "POST", "/v1/match", CDX),
    ("an spdx match", ["match", str(SPDX)], "POST", "/v1/match", SPDX),
]
RESULTS: dict[str, dict[str, Any]] = {}


def without(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: without(v, keys) for k, v in value.items() if k not in keys}
    if isinstance(value, list):
        return [without(v, keys) for v in value]
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(without(value, {"data_version"})).encode()).hexdigest()


def run_cli(shared: Services, args: list[str]) -> tuple[int, Any]:
    result = CliRunner().invoke(create_cli(lambda: shared), args)
    if result.exit_code == 0:
        return 0, json.loads(result.stdout)
    text = result.stderr
    return result.exit_code, json.loads(text[: text.rindex("}") + 1])


@pytest.mark.parametrize(("name", "args", "method", "path", "body"), CASES, ids=[c[0] for c in CASES])
def test_the_command_line_answers_as_the_api_does(
    shared: Services, api: TestClient, name: str, args: list[str], method: str, path: str, body: Path | None
) -> None:
    code, cli_answer = run_cli(shared, args)
    if body is None:
        response = api.request(method, path)
    else:
        response = api.post(path, content=body.read_bytes(), headers={"content-type": "application/json"})
    api_answer = response.json()
    assert (code == 0) == (response.status_code == 200), (code, response.status_code)
    ignore = BY_DESIGN | (MATCH_TIMES if args[0] == "match" else set())
    assert without(cli_answer, ignore) == without(api_answer, ignore)
    RESULTS[name] = {
        "command": "unsched " + " ".join(Path(a).name if a.endswith(".json") else a for a in args),
        "route": f"{method} {path}",
        "http_status": response.status_code,
        "same": True,
        "answer_sha256": digest(without(api_answer, ignore)),
    }


def test_the_legacy_report_is_the_same_bytes(shared: Services, api: TestClient) -> None:
    result = CliRunner().invoke(create_cli(lambda: shared), ["legacy-report"])
    response = api.get("/v1/legacy/report.csv")
    if response.status_code != 200:
        pytest.skip(f"the legacy adapter is not available here: {response.json()['detail']}")
    assert result.exit_code == 0 and result.stdout_bytes == response.content
    RESULTS["the legacy report"] = {
        "command": "unsched legacy-report",
        "route": "GET /v1/legacy/report.csv",
        "http_status": 200,
        "same": True,
        "answer_sha256": hashlib.sha256(response.content).hexdigest(),
    }


def separate_process(args: list[str], postgres_url: str) -> subprocess.CompletedProcess[bytes]:
    env = {
        **os.environ,
        "DATABASE_URL_UNPOOLED": postgres_url,
        "UNSCHED_DB_SCHEMA": SCHEMA,
        "UNSCHED_MIGRATE_ON_START": "0",
        "UNSCHED_ROOT": str(ROOT),
    }
    return subprocess.run(
        [sys.executable, "-m", "unscheduled_cli", *args], cwd=ROOT, env=env, capture_output=True, timeout=120
    )


def test_a_separate_process_reads_the_same_answer(
    shared: Services, api: TestClient, postgres_url: str
) -> None:
    proc = separate_process(["cve", "CVE-2026-90005", "--as-of", "2026-06-01"], postgres_url)
    assert proc.returncode == 0, proc.stderr.decode()[-1000:]
    expected = api.get("/v1/cves/CVE-2026-90005?as_of=2026-06-01").json()
    assert json.loads(proc.stdout) == expected
    RESULTS["a separate process"] = {
        "command": "python -m unscheduled_cli cve CVE-2026-90005 --as-of 2026-06-01",
        "route": "GET /v1/cves/CVE-2026-90005?as_of=2026-06-01",
        "http_status": 200,
        "same": True,
        "answer_sha256": digest(expected),
    }


def test_a_match_against_a_local_advisory_file_agrees_with_the_api(
    shared: Services, api: TestClient, postgres_url: str, advisories_file: Path
) -> None:
    proc = separate_process(["match", str(CDX), "--advisories", str(advisories_file)], postgres_url)
    assert proc.returncode == 0, proc.stderr.decode()[-1000:]
    cli_answer = json.loads(proc.stdout)
    api_answer = api.post(
        "/v1/match", content=CDX.read_bytes(), headers={"content-type": "application/json"}
    ).json()
    ignore = BY_DESIGN | MATCH_TIMES | {"engine"}
    assert without(cli_answer, ignore) == without(api_answer, ignore)
    assert cli_answer["engine"] == "unscheduled-match over osv_records.json"


def test_zz_the_parity_record_is_written_when_every_case_agreed(shared: Services) -> None:
    expected = {c[0] for c in CASES} | {"a separate process"}
    if not expected <= set(RESULTS):
        pytest.skip("not every parity case ran in this session; the record is written by a full run")
    record = {
        "what": "unsched and the API answered the same on the same database, case by case",
        "set_aside_by_design": sorted(BY_DESIGN | MATCH_TIMES),
        "bundle_tag": TAG,
        "cases": [dict(RESULTS[name], name=name) for name in sorted(RESULTS)],
        "passed": all(r["same"] for r in RESULTS.values()),
    }
    out = paths.results_dir() / "cli_parity.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    assert record["passed"] is True
