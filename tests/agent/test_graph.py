"""The triage graph: two drafts that wait for a person, a decision kept only on the hash it names, a
model draft the verifier blocks replaced by the floor's, a replay from a checkpoint that reaches the
same state, a fork that keeps its parent, and a run resumed from Postgres by a new process."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import psycopg
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.postgres import PostgresSaver
from unscheduled_agent import floor, graph, prices, replay
from unscheduled_agent.router import MemoryBudget, Router, adapters, limits
from unscheduled_agent.schemas import Facts

from tests.agent import evidence
from tests.agent.fixtures import AS_OF, CVE, FixtureSources
from tests.api import postgres as _postgres

postgres_url = _postgres.postgres_url
ROOT = Path(__file__).resolve().parents[2]
CONFIG: dict[str, Any] = {
    "providers": {
        "alpha": {
            "base_url": "https://alpha.test/v1",
            "key_env": "ALPHA_KEY",
            "timeout_s": 5,
            "budget": {"requests_per_day": 50, "tokens_per_day": 100_000},
        }
    },
    "shadow_sku": "gpt-6-luna",
}
KEYS = {"ALPHA_KEY": "made-up-alpha"}


def _run(compiled: Any, run_id: str) -> dict[str, Any]:
    out: dict[str, Any] = compiled.invoke(graph.start(CVE, AS_OF, run_id), graph.config(run_id))
    return out


def _waiting(out: dict[str, Any]) -> dict[str, Any]:
    interrupts = out.get("__interrupt__") or []
    assert interrupts, "the run should wait for a person"
    value: dict[str, Any] = interrupts[0].value
    return value


def test_a_run_waits_twice_and_keeps_only_decisions_on_the_hash_it_showed() -> None:
    compiled = graph.build(FixtureSources(), None).compile(checkpointer=InMemorySaver())
    first = _waiting(_run(compiled, "run-1"))
    assert first["kind"] == "patch_plan" and first["draft"]["fixed_version"] == "2.426.3"
    second = _waiting(graph.decide(compiled, "run-1", "approve", first["sha256"], "ajay"))
    assert second["kind"] == "early_warning" and second["draft"]["actively_exploited"] is True
    out = graph.decide(compiled, "run-1", "approve", "0" * 64, "someone")
    assert out["plan_decision"]["decision"] == "approve" and out["plan_decision"]["by"] == "ajay"
    assert out["warning_decision"]["decision"] == "void" and out["status"] == "decided"
    assert set(out["timings"]) >= {"intake", "match", "fill", "rank", "retrieve", "plan", "verify", "warn"}
    assert [c["provider"] for c in out["calls"]] == ["floor", "floor"]


def test_a_cve_without_exploitation_evidence_gets_no_warning() -> None:
    compiled = graph.build(FixtureSources(), None).compile(checkpointer=InMemorySaver())
    before = datetime(2024, 8, 1, 23, 59, 59, tzinfo=UTC)
    shown = _waiting(compiled.invoke(graph.start(CVE, before, "early"), graph.config("early")))
    out = graph.decide(compiled, "early", "reject", shown["sha256"], "ajay")
    assert (
        out["plan_decision"]["decision"] == "reject" and "warning" not in out and out["status"] == "decided"
    )


def _model(plan: dict[str, Any]) -> httpx.MockTransport:
    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        name = body["response_format"]["json_schema"]["name"]
        if name == "PatchPlan":
            content = json.dumps(plan)
        else:
            facts = Facts.model_validate(
                json.loads(body["messages"][1]["content"])["typed_state"] | {"evidence": []}
            )
            content = floor.warning(facts).model_dump_json()
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 1500, "completion_tokens": 400},
            },
        )

    return httpx.MockTransport(answer)


def _router(transport: httpx.BaseTransport) -> Router:
    return Router(
        adapters(CONFIG, [("alpha", "big-model")], transport, prices.load(ROOT), KEYS),
        MemoryBudget(limits(CONFIG)),
    )


def _facts() -> Facts:
    sources = FixtureSources()
    return Facts(
        cve_id=CVE,
        as_of=AS_OF,
        product="pipeline-runner",
        component="org.jenkins-ci.main:jenkins-core",
        ecosystem="Maven",
        installed_version="2.426.1",
        fixed_versions=sources.fixed_versions(CVE, None, AS_OF),
        kev=sources.kev(CVE, AS_OF),
    )


def test_a_model_draft_the_verifier_blocks_is_replaced_by_the_floor() -> None:
    forged = floor.plan(_facts()).model_dump(mode="json")
    forged["fixed_version"] = "2.426.4"
    for claim in forged["claims"]:
        if claim["field"] in ("fixed_version", "action"):
            claim["value"] = "2.426.4"
    compiled = graph.build(FixtureSources(), _router(_model(forged))).compile(checkpointer=InMemorySaver())
    shown = _waiting(_run(compiled, "forged"))
    state = compiled.get_state(graph.config("forged")).values
    assert state["plan_check"]["by"] == "floor" and state["plan_check"]["replaced"]["blocked"]
    assert shown["draft"]["fixed_version"] == "2.426.3"
    assert state["calls"][0]["provider"] == "alpha" and state["calls"][0]["outcome"] == "ok"


def test_a_run_replays_from_a_checkpoint_to_the_same_state(tmp_path: Path) -> None:
    good = floor.plan(_facts()).model_dump(mode="json")
    cassette = replay.Cassette(tmp_path / "graph.jsonl.gz")
    recorded = graph.build(FixtureSources(), _router(replay.Recording(cassette, _model(good)))).compile(
        checkpointer=InMemorySaver()
    )
    _waiting(_run(recorded, "original"))
    original = recorded.get_state(graph.config("original")).values
    served = graph.build(
        FixtureSources(), _router(replay.Replay(replay.Cassette(tmp_path / "graph.jsonl.gz")))
    )
    saver = InMemorySaver()
    replaying = served.compile(checkpointer=saver)
    _waiting(_run(replaying, "again"))
    before_plan = next(s for s in graph.history(replaying, "again") if s.next == ("plan",))
    out = replaying.invoke(None, before_plan.config)
    _waiting(out)
    replayed = replaying.get_state(graph.config("again")).values
    assert replayed["plan_check"]["sha256"] == original["plan_check"]["sha256"]
    assert replayed["plan"] == original["plan"]


def test_a_fork_with_a_changed_input_is_a_new_run_that_keeps_its_parent() -> None:
    compiled = graph.build(FixtureSources(), None).compile(checkpointer=InMemorySaver())
    _waiting(_run(compiled, "parent"))
    after_match = next(s for s in graph.history(compiled, "parent") if s.next == ("fill",))
    changed = {"match": {**after_match.values["match"], "installed_version": "2.426.2"}}
    child = graph.fork(
        compiled, "parent", after_match.config["configurable"]["checkpoint_id"], changed, as_node="match"
    )
    shown = _waiting(compiled.invoke(None, graph.config(child)))
    values = compiled.get_state(graph.config(child)).values
    assert values["parent_run_id"] == "parent" and values["run_id"] == child
    assert shown["draft"]["installed_version"] == "2.426.2"
    parent = compiled.get_state(graph.config("parent")).values
    assert parent["match"]["installed_version"] == "2.426.1"


def test_a_run_waiting_in_postgres_is_decided_by_a_new_process(postgres_url: str) -> None:
    plain = postgres_url.replace("postgresql+psycopg://", "postgresql://", 1)
    schema = "graph_test"
    with psycopg.connect(plain, autocommit=True) as admin:
        admin.execute(f'drop schema if exists "{schema}" cascade')
        admin.execute(f'create schema "{schema}"')
    scoped = plain + ("&" if "?" in plain else "?") + "options=" + quote(f"-csearch_path={schema}")
    with PostgresSaver.from_conn_string(scoped) as saver:
        saver.setup()
        shown = _waiting(_run(graph.build(FixtureSources(), None).compile(checkpointer=saver), "pg-run"))
    with PostgresSaver.from_conn_string(scoped) as saver:
        later = graph.build(FixtureSources(), None).compile(checkpointer=saver)
        second = _waiting(graph.decide(later, "pg-run", "approve", shown["sha256"], "ajay"))
        out = graph.decide(later, "pg-run", "reject", second["sha256"], "ajay")
        assert (
            out["plan_decision"]["decision"] == "approve" and out["warning_decision"]["decision"] == "reject"
        )
        saver.prune(["pg-run"], strategy="keep_latest")
        assert later.get_state(graph.config("pg-run")).values["status"] == "decided"


@pytest.mark.parametrize("bad", ["approve", "yes"])
def test_a_decision_without_the_hash_is_void(bad: str) -> None:
    compiled = graph.build(FixtureSources(), None).compile(checkpointer=InMemorySaver())
    _waiting(_run(compiled, "nohash"))
    out = compiled.invoke(graph.Command(resume={"decision": bad}), graph.config("nohash"))
    assert compiled.get_state(graph.config("nohash")).values["plan_decision"]["decision"] == "void"
    assert out["__interrupt__"][0].value["kind"] == "early_warning"


def test_the_record_of_the_graph() -> None:
    """results/agent/graph.json, step 8: the nodes and edges as compiled, and the tests behind them."""
    proven = evidence.proven(sys.modules[__name__], "test_the_record_of_the_graph")
    if proven is None:
        pytest.skip("not every graph test passed in this session; the record is written by a full run")
    drawn = graph.build(FixtureSources(), None).compile(checkpointer=InMemorySaver()).get_graph()
    nodes = [n for n in drawn.nodes if not n.startswith("__")]
    edges = [
        {"from": e.source, "to": e.target, "conditional": bool(e.conditional)}
        for e in sorted(drawn.edges, key=lambda e: (e.source, e.target))
    ]
    evidence.write(
        "graph",
        {
            "step": 8,
            "sentence": "The triage graph in LangGraph: code fills the typed state as known at the run time, "
            "the router drafts, the verifier checks every claim, and the run waits for a person at each "
            "approve node, with every checkpoint in Postgres.",
            "nodes": nodes,
            "edges": edges,
            "interrupts": [n for n in nodes if n.startswith("approve")],
            "warning_branch": "after the plan is decided, only for a CVE with exploitation evidence: a KEV "
            "listing, or exploit code seen by the run time",
            "deadline_s": graph.DEADLINE_S,
            "checkpoints": {
                "saver": "langgraph.checkpoint.postgres.PostgresSaver",
                "schema": "the API schema with _checkpoints after it (unscheduled_checkpoints in Neon)",
                "retention": "a decided run keeps its latest checkpoint; past the newest 500 decided runs only "
                "its record stays, and at most 100 runs wait at once (ADR 0011)",
            },
            "control": "tests/agent/test_control.py and tests/api/test_control_served.py, results/agent/c7.json",
            "proven": proven,
            "verdict": "pass",
        },
    )
