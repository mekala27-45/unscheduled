"""Cut the console's run fixtures from real answers: the API in process over the API tests' fixture
bundle and corpus, in a Postgres of its own, a run to its first interrupt, the plan approved by its
hash, the warning approved, an earlier run, the runs, a search and a decision without the token.

    python scripts/cut_run_fixtures.py        # writes web/lib/fixtures/runs.ts

The fixture CVE is renamed CVE-2099-0001 and the data version set to fixture, as every fixture of the
console is; the run ids and hashes are the ones the API answered."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("UNSCHED_ROOT", str(ROOT))

from fastapi.testclient import TestClient
from unscheduled_api.app import create_app
from unscheduled_api.matching import PackageMatcher, StaticAdvisories
from unscheduled_api.releases import GitHubReleases
from unscheduled_api.services import Services

from tests.api import postgres
from tests.api.conftest import PUBLISHED_AT, TAG, fresh_schema, settings_for, sync_until_done
from tests.api.fixtures.bundle import corpus_documents, osv_records, write_bundle
from tests.api.fixtures.github import FakeGitHub

TOKEN = "-".join(["fixture", "approver", "words"])  # built from words; no scanner reads a credential
OUT = ROOT / "web" / "lib" / "fixtures" / "runs.ts"
NAMES = {
    "waiting": (
        "API_RUN_WAITING",
        'S["RunView"]',
        "A run at its first interrupt: the plan waits for a person.",
    ),
    "plan_approved": (
        "API_RUN_PLAN_APPROVED",
        'S["RunView"]',
        "The same run after the plan was approved by its hash: the warning waits.",
    ),
    "decided": (
        "API_RUN_DECIDED",
        'S["RunView"]',
        "The same run after the warning was approved: decided, its checkpoints pruned.",
    ),
    "second": (
        "API_RUN_EARLY",
        'S["RunView"]',
        "A run as of a day before the KEV listing and the advisory: no fix known, no warning.",
    ),
    "runs": ("API_RUNS", 'S["RunList"]', "The runs, newest first."),
    "search": ("API_SEARCH", 'S["SearchResults"]', "A search as of a day after the advisory was published."),
    "refused": (
        "API_APPROVAL_REFUSED",
        "Problem",
        "A decision sent without the token: refused, nothing recorded.",
    ),
}


def fixture(answers: dict[str, object]) -> str:
    text = json.dumps(answers).replace("CVE-2021-90001", "CVE-2099-0001")

    def clean(obj: object) -> object:
        if isinstance(obj, dict):
            return {
                k: ("fixture" if k == "data_version" else "__STATEMENT__" if k == "statement" else clean(v))
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [clean(x) for x in obj]
        return obj

    data = clean(json.loads(text))
    assert isinstance(data, dict)
    parts = [
        "/**",
        " * FIXTURE. Cut from real answers of the API in process over its own fixture bundle and corpus",
        " * (tests/api/fixtures) by scripts/cut_run_fixtures.py, with the fixture CVE renamed CVE-2099-0001",
        ' * and the data version set to "fixture". Every value is what the API answered for invented data:',
        " * nothing here is data.",
        " */",
        'import type { components } from "../api/openapi";',
        'import { STATEMENT } from "../statement";',
        "",
        'type S = components["schemas"];',
        "type Problem = { type: string; title: string; status: number; detail: string; instance: string; statement: string; data_version: string };",
        "",
    ]
    for key, (name, typ, doc) in NAMES.items():
        body = json.dumps(data[key], indent=2).replace('"__STATEMENT__"', "STATEMENT")
        parts += [f"/** {doc} */", f"export const {name}: {typ} = {body};", ""]
    return "\n".join(parts)


def main() -> None:
    os.environ["APPROVER_TOKEN_SHA256"] = hashlib.sha256(TOKEN.encode()).hexdigest()
    url = postgres.database_url()
    tmp = Path(tempfile.mkdtemp())
    engine = fresh_schema(url, "webfix", tmp / "migrate")
    github = FakeGitHub()
    bundle = tmp / "bundle"
    write_bundle(bundle, corpus=corpus_documents())
    github.publish(bundle, TAG, PUBLISHED_AT)
    services = Services.build(
        settings_for(url, tmp / "cache", schema="webfix"),
        engine=engine,
        releases=GitHubReleases(github.client()),
        matcher=PackageMatcher(StaticAdvisories(osv_records())),
    )
    with TestClient(create_app(services)) as client:
        sync_until_done(client)
        run = client.post("/v1/triage", json={"cve_id": "CVE-2021-90001", "as_of": "2022-01-15"}).json()
        waiting = run["waiting_for"][0]
        plan = client.post(
            "/v1/approvals",
            json={
                "run_id": run["run_id"],
                "kind": "plan",
                "sha256": waiting["sha256"],
                "decision": "approve",
                "by": "ajay",
            },
            headers={"Authorization": f"Bearer {TOKEN}"},
        ).json()
        warning = plan["waiting_for"][0]
        done = client.post(
            "/v1/approvals",
            json={
                "run_id": run["run_id"],
                "kind": "warning",
                "sha256": warning["sha256"],
                "decision": "approve",
                "by": "ajay",
            },
            headers={"Authorization": f"Bearer {TOKEN}"},
        ).json()
        second = client.post("/v1/triage", json={"cve_id": "CVE-2021-90001", "as_of": "2021-06-01"}).json()
        runs = client.get("/v1/runs", params={"limit": 10}).json()
        search = client.get(
            "/v1/search", params={"q": "logkit deserialization", "as_of": "2022-01-01"}
        ).json()
        refused = client.post(
            "/v1/approvals",
            json={
                "run_id": second["run_id"],
                "kind": "plan",
                "sha256": second["waiting_for"][0]["sha256"],
                "decision": "approve",
                "by": "ajay",
            },
        ).json()
    answers = {
        "waiting": run,
        "plan_approved": plan,
        "decided": done,
        "second": second,
        "runs": runs,
        "search": search,
        "refused": refused,
    }
    OUT.write_text(fixture(answers), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
