"""C7, control: a hypothesis state machine drives the triage graph through random sequences of runs,
decisions on the right hash, on another hash and on none, with the token, a wrong token and none,
edits of a draft after a decision, crashes (a new graph over the same checkpoints), retries from a
checkpoint and forks, and holds after every step that no plan is approved and no warning is ready
without an approval record, made with the token, whose hash is the hash of the draft as it stands.

The status a run shows is never read from the graph: approvals.status takes the draft from the state
as it stands and counts only the records of its hash. The model below keeps its own book of every
record and checks the status against it. Step 14 drives the API, the CLI and the MCP server through
the same machine.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, initialize, invariant, rule
from langgraph.checkpoint.memory import InMemorySaver
from unscheduled_agent import approvals, graph
from unscheduled_agent.schemas import EarlyWarning, PatchPlan
from unscheduled_agent.verify import draft_sha256

from tests.agent.fixtures import AS_OF, CVE, FixtureSources
from tests.api import postgres as _postgres

postgres_url = _postgres.postgres_url

TOKEN = "-".join(["made", "up", "approver", "value"])  # not a token: built so no scanner reads one
TOKEN_SHA256 = hashlib.sha256(TOKEN.encode()).hexdigest()
EXAMPLES = int(os.environ.get("UNSCHED_C7_EXAMPLES", "25"))
STEPS = int(os.environ.get("UNSCHED_C7_STEPS", "20"))
KINDS: tuple[approvals.Kind, ...] = ("plan", "warning")


class Control(RuleBasedStateMachine):
    runs = Bundle("runs")

    @initialize()
    def setup(self) -> None:
        self.saver = InMemorySaver()
        self.builder = graph.build(FixtureSources(), None)
        self.compiled = self.builder.compile(checkpointer=self.saver)
        self.store = approvals.MemoryStore()
        self.book: list[approvals.Approval] = []
        self.count = 0
        self.ids: list[str] = []

    def _waiting(self, run_id: str) -> dict[str, Any] | None:
        snapshot = self.compiled.get_state(graph.config(run_id))
        for task in snapshot.tasks:
            for item in task.interrupts:
                value: dict[str, Any] = item.value
                return value
        return None

    @rule(target=runs)
    def start(self) -> str:
        self.count += 1
        run_id = f"run-{self.count}"
        self.compiled.invoke(graph.start(CVE, AS_OF, run_id), graph.config(run_id))
        self.ids.append(run_id)
        return run_id

    @rule(
        run=runs,
        decision=st.sampled_from(["approve", "reject"]),
        named=st.sampled_from(["shown", "other", "none"]),
        token=st.sampled_from(["good", "wrong", "none"]),
    )
    def decide(self, run: str, decision: str, named: str, token: str) -> None:
        shown = self._waiting(run)
        if shown is None:
            return
        kind: approvals.Kind = "plan" if shown["kind"] == "patch_plan" else "warning"
        sha = {"shown": shown["sha256"], "other": "f" * 64, "none": None}[named]
        secret = {"good": TOKEN, "wrong": "not-the-token", "none": None}[token]
        if sha is not None:
            made = approvals.record(self.store, run, kind, sha, decision, "ajay", secret, TOKEN_SHA256)  # type: ignore[arg-type]
            self.book.append(made)
        resume: dict[str, Any] = {"decision": decision, "by": "ajay"}
        if sha is not None:
            resume["sha256"] = sha
        self.compiled.invoke(graph.Command(resume=resume), graph.config(run))

    @rule(run=runs, kind=st.sampled_from(KINDS))
    def edit(self, run: str, kind: approvals.Kind) -> None:
        """A draft changed after it was shown or decided: its hash changes with its content."""
        values = self.compiled.get_state(graph.config(run)).values
        check = values.get(f"{kind}_check")
        if not check:
            return
        draft = dict(check["draft"])
        if kind == "plan":
            draft["steps"] = [*draft["steps"], "Also restart every service."]
        else:
            draft["member_states"] = "every member state"
        node = "verify" if kind == "plan" else "verify_warning"
        self.compiled.update_state(
            graph.config(run), {f"{kind}_check": {**check, "draft": draft}}, as_node=node
        )

    @rule()
    def crash(self) -> None:
        """The process dies; a new graph reads the same checkpoints."""
        self.compiled = self.builder.compile(checkpointer=self.saver)

    @rule(run=runs)
    def retry(self, run: str) -> None:
        before = [s for s in graph.history(self.compiled, run) if s.next == ("plan",)]
        if before:
            self.compiled.invoke(None, before[0].config)

    @rule(target=runs, run=runs)
    def fork(self, run: str) -> str:
        after = [s for s in graph.history(self.compiled, run) if s.next == ("fill",)]
        if not after:
            return run
        changes = {"match": {**after[0].values["match"], "installed_version": "2.426.2"}}
        child = graph.fork(
            self.compiled, run, after[0].config["configurable"]["checkpoint_id"], changes, as_node="match"
        )
        self.compiled.invoke(None, graph.config(child))
        self.ids.append(child)
        return child

    @invariant()
    def nothing_is_approved_or_ready_without_a_record_of_its_hash(self) -> None:
        for run in getattr(self, "ids", []):
            values = self.compiled.get_state(graph.config(run)).values
            for kind in KINDS:
                check = values.get(f"{kind}_check")
                shown = approvals.status(self.store, run, kind, check)
                if shown not in ("approved", "ready"):
                    continue
                assert check is not None
                schema = PatchPlan if kind == "plan" else EarlyWarning
                current = draft_sha256(schema.model_validate(check["draft"]))
                counted = [
                    r
                    for r in self.book
                    if r.run_id == run and r.kind == kind and r.sha256 == current and r.token_ok
                ]
                assert counted and counted[-1].decision == "approve", (
                    f"{run} {kind} is {shown} without its record"
                )


Control.TestCase.settings = settings(
    max_examples=EXAMPLES,
    stateful_step_count=STEPS,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
TestControl = Control.TestCase


def test_a_record_counts_only_with_the_token_and_the_hash_of_the_draft_as_it_stands() -> None:
    compiled = graph.build(FixtureSources(), None).compile(checkpointer=InMemorySaver())
    out = compiled.invoke(graph.start(CVE, AS_OF, "r"), graph.config("r"))
    shown = out["__interrupt__"][0].value
    store = approvals.MemoryStore()
    check = compiled.get_state(graph.config("r")).values["plan_check"]
    approvals.record(store, "r", "plan", shown["sha256"], "approve", "ajay", "wrong", TOKEN_SHA256)
    assert approvals.status(store, "r", "plan", check) == "waiting"
    approvals.record(store, "r", "plan", shown["sha256"], "approve", "ajay", TOKEN, TOKEN_SHA256)
    assert approvals.status(store, "r", "plan", check) == "approved"
    edited = {**check, "draft": {**check["draft"], "steps": ["Do something else."]}}
    assert approvals.status(store, "r", "plan", edited) == "waiting"
    assert approvals.status(store, "r", "plan", {**check, "blocked": True}) == "blocked"
    assert not approvals.token_ok(TOKEN, None) or os.environ.get(approvals.TOKEN_ENV)


def test_postgres_keeps_every_decision_and_edits_none(postgres_url: str) -> None:
    import psycopg

    plain = postgres_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(plain) as conn:
        conn.execute("drop schema if exists approvals_test cascade")
        conn.execute("create schema approvals_test")
        conn.commit()
        store = approvals.PostgresStore(conn, "approvals_test")
        approvals.record(store, "r", "plan", "a" * 64, "approve", "ajay", TOKEN, TOKEN_SHA256)
        approvals.record(store, "r", "plan", "a" * 64, "reject", "ajay", None, TOKEN_SHA256)
        rows = store.records("r")
        assert [(r.decision, r.token_ok) for r in rows] == [("approve", True), ("reject", False)]
        check = {
            "blocked": False,
            "draft": {
                "kind": "patch_plan",
                "cve_id": CVE,
                "component": None,
                "installed_version": None,
                "fixed_version": None,
                "steps": [],
                "claims": [],
            },
        }
        assert approvals.status(store, "r", "plan", check) == "waiting"
