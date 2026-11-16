"""The triage graph: one CVE at one time, from what code knows to two drafts waiting for a person.

intake, match, fill, rank and retrieve fill the typed state by code from the sources as known at the
run time; plan drafts the patch plan through the router (the floor last); verify checks every claim
(verify.py) and puts the floor's draft in place of a model draft it blocks; approve waits for a
person. When the state holds exploitation evidence (a KEV listing, or exploit code seen), warn,
verify_warning and approve_warning do the same for the early warning.

The approval nodes are interrupts. A run resumes with a decision that names the sha256 of the
verified draft it decides on; a decision on any other hash is recorded as void, so a draft changed
after it was shown can never carry an approval (C7). Nothing in the graph applies a plan or files a
warning: an approved draft is a record a person acts on.

Checkpoints go to the checkpointer the caller gives: the Postgres saver in Neon for the API (with the
retention rule of ADR 0011), memory for tests. A run replays from any checkpoint with recorded
provider answers to the same state, and fork() starts a new run from a checkpoint with a changed
input that keeps the id of its parent.
"""

from __future__ import annotations

import operator
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from itertools import pairwise
from typing import Annotated, Any, Protocol, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from unscheduled_agent import floor, prompts, verify
from unscheduled_agent.router import CallRecord, Prompt, Router
from unscheduled_agent.schemas import (
    EarlyWarning,
    Evidence,
    ExploitSignal,
    Facts,
    FixedVersion,
    KevListing,
    PatchPlan,
)

DEADLINE_S = 25.0  # the router stops trying models before a run passes C8's 30 s
RETRIEVED = 8


class Match(TypedDict, total=False):
    product: str
    component: str
    ecosystem: str
    installed_version: str


class Sources(Protocol):
    """What the graph reads, each answer as known at the run time and never later."""

    def description(self, cve_id: str, at: datetime) -> str | None: ...

    def match(self, cve_id: str, at: datetime) -> Match | None: ...

    def fixed_versions(self, cve_id: str, match: Match | None, at: datetime) -> list[FixedVersion]: ...

    def predictions(self, cve_id: str, at: datetime) -> dict[str, Any]: ...

    def kev(self, cve_id: str, at: datetime) -> KevListing | None: ...

    def exploits(self, cve_id: str, at: datetime) -> list[ExploitSignal]: ...

    def epss(self, cve_id: str, at: datetime) -> float | None: ...

    def retrieve(self, query: str, at: datetime, k: int) -> list[Evidence]: ...

    @property
    def documents(self) -> verify.Documents: ...


def _merge(left: dict[str, float], right: dict[str, float]) -> dict[str, float]:
    return {**left, **right}


class TriageState(TypedDict, total=False):
    run_id: str
    parent_run_id: str | None
    cve_id: str
    as_of: str
    started: float
    description: str | None
    match: Match | None
    fixed_versions: list[dict[str, Any]]
    predictions: dict[str, Any]
    kev: dict[str, Any] | None
    exploits: list[dict[str, Any]]
    epss: float | None
    evidence: list[dict[str, Any]]
    plan: dict[str, Any]
    plan_check: dict[str, Any]
    plan_decision: dict[str, Any]
    warning: dict[str, Any]
    warning_check: dict[str, Any]
    warning_decision: dict[str, Any]
    calls: Annotated[list[dict[str, Any]], operator.add]
    timings: Annotated[dict[str, float], _merge]
    status: str


def facts_of(state: TriageState) -> Facts:
    match = state.get("match") or {}
    return Facts(
        cve_id=state["cve_id"],
        as_of=datetime.fromisoformat(state["as_of"]),
        description=state.get("description"),
        product=match.get("product"),
        component=match.get("component"),
        ecosystem=match.get("ecosystem"),
        installed_version=match.get("installed_version"),
        fixed_versions=[FixedVersion.model_validate(f) for f in state.get("fixed_versions") or []],
        kev=KevListing.model_validate(state["kev"]) if state.get("kev") else None,
        exploits=[ExploitSignal.model_validate(e) for e in state.get("exploits") or []],
        epss=state.get("epss"),
        evidence=[Evidence.model_validate(e) for e in state.get("evidence") or []],
    )


def _timed(
    name: str, step: Callable[[TriageState], dict[str, Any]], sources: object = None
) -> Callable[[TriageState], dict[str, Any]]:
    def node(state: TriageState) -> dict[str, Any]:
        if hasattr(sources, "node"):
            # The guard of defend.py checks each call against the allowlist of the node running.
            sources.node = name
        started = time.perf_counter()
        update = step(state)
        update["timings"] = {name: round((time.perf_counter() - started) * 1000, 2)}
        return update

    return node


def _decide(kind: str, check: dict[str, Any]) -> dict[str, Any]:
    """Wait for a person, then keep the decision only when it names the hash of this draft."""
    answer = interrupt({"kind": kind, "sha256": check["sha256"], "draft": check["draft"]})
    decision = answer if isinstance(answer, dict) else {"decision": str(answer)}
    named = decision.get("sha256")
    valid = named == check["sha256"] and decision.get("decision") in ("approve", "reject")
    return {
        "decision": decision.get("decision") if valid else "void",
        "sha256": check["sha256"],
        "named_sha256": named,
        "by": decision.get("by"),
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "reason": None if valid else "the decision does not name the hash of the draft it was shown",
    }


def build(
    sources: Sources,
    router: Router | None,
    *,
    plan_prompt: Prompt | None = None,
    warning_prompt: Prompt | None = None,
) -> StateGraph[TriageState]:
    plan_prompt = plan_prompt or prompts.load("plan")
    warning_prompt = warning_prompt or prompts.load("warning")

    def intake(state: TriageState) -> dict[str, Any]:
        at = datetime.fromisoformat(state["as_of"])
        return {"description": sources.description(state["cve_id"], at), "status": "running"}

    def match(state: TriageState) -> dict[str, Any]:
        at = datetime.fromisoformat(state["as_of"])
        found = sources.match(state["cve_id"], at)
        fixed = sources.fixed_versions(state["cve_id"], found, at)
        return {"match": found, "fixed_versions": [f.model_dump(mode="json") for f in fixed]}

    def fill(state: TriageState) -> dict[str, Any]:
        return {"predictions": sources.predictions(state["cve_id"], datetime.fromisoformat(state["as_of"]))}

    def rank(state: TriageState) -> dict[str, Any]:
        at = datetime.fromisoformat(state["as_of"])
        kev = sources.kev(state["cve_id"], at)
        return {
            "kev": kev.model_dump(mode="json") if kev else None,
            "exploits": [e.model_dump(mode="json") for e in sources.exploits(state["cve_id"], at)],
            "epss": sources.epss(state["cve_id"], at),
        }

    def retrieve(state: TriageState) -> dict[str, Any]:
        query = state.get("description") or state["cve_id"]
        found = sources.retrieve(query, datetime.fromisoformat(state["as_of"]), RETRIEVED)
        return {"evidence": [e.model_dump(mode="json") for e in found]}

    def draft(
        kind: str,
        prompt: Prompt,
        schema: type[PatchPlan] | type[EarlyWarning],
        template: Callable[[Facts], Any],
    ) -> Callable[[TriageState], dict[str, Any]]:
        def node(state: TriageState) -> dict[str, Any]:
            facts = facts_of(state)
            if router is None:
                written, calls = (
                    template(facts),
                    [CallRecord("floor", "floor", prompt.id, prompt.version, prompt.sha256, "", "floor")],
                )
            else:
                packed = prompts.pack(facts, prompt.context_tokens)
                deadline = state.get("started", time.monotonic()) + DEADLINE_S
                written, calls = router.generate(
                    prompt,
                    packed.inputs,
                    schema,
                    lambda: template(facts),
                    max_tokens=prompt.max_tokens,
                    deadline=deadline,
                )
            return {
                kind: {"draft": written.model_dump(mode="json"), "by": calls[-1].provider},
                "calls": [c.row() for c in calls],
            }

        return node

    def check(
        kind: str, schema: type[PatchPlan] | type[EarlyWarning], template: Callable[[Facts], Any]
    ) -> Callable[[TriageState], dict[str, Any]]:
        def node(state: TriageState) -> dict[str, Any]:
            facts = facts_of(state)
            written = schema.model_validate(state[kind]["draft"])  # type: ignore[literal-required]
            result = verify.check(written, facts, sources.documents)
            first = result.summary()
            replaced = None
            if result.blocked and state[kind]["by"] != "floor":  # type: ignore[literal-required]
                replaced = first
                result = verify.check(template(facts), facts, sources.documents)
            out = result.summary()
            out["replaced"] = replaced
            out["by"] = "floor" if replaced else state[kind]["by"]  # type: ignore[literal-required]
            return {f"{kind}_check": out}

        return node

    def approve(kind: str) -> Callable[[TriageState], dict[str, Any]]:
        def node(state: TriageState) -> dict[str, Any]:
            checked = state[f"{kind}_check"]  # type: ignore[literal-required]
            if checked["blocked"]:
                return {
                    f"{kind}_decision": {
                        "decision": "blocked",
                        "sha256": checked["sha256"],
                        "reasons": checked["reasons"],
                    }
                }
            return {f"{kind}_decision": _decide("patch_plan" if kind == "plan" else "early_warning", checked)}

        return node

    def after_plan(state: TriageState) -> str:
        return "warn" if state.get("kev") or state.get("exploits") else "done"

    def done(state: TriageState) -> dict[str, Any]:
        return {"status": "decided"}

    builder: StateGraph[TriageState] = StateGraph(TriageState)
    steps: dict[str, Callable[[TriageState], dict[str, Any]]] = {
        "intake": intake,
        "match": match,
        "fill": fill,
        "rank": rank,
        "retrieve": retrieve,
        "plan": draft("plan", plan_prompt, PatchPlan, floor.plan),
        "verify": check("plan", PatchPlan, floor.plan),
        "approve": approve("plan"),
        "warn": draft("warning", warning_prompt, EarlyWarning, floor.warning),
        "verify_warning": check("warning", EarlyWarning, floor.warning),
        "approve_warning": approve("warning"),
        "done": done,
    }
    for name, step in steps.items():
        node: Any = _timed(name, step, sources)  # langgraph's node protocols: a state in, an update out
        builder.add_node(name, node)
    order = ["intake", "match", "fill", "rank", "retrieve", "plan", "verify", "approve"]
    builder.add_edge(START, order[0])
    for first, second in pairwise(order):
        builder.add_edge(first, second)
    builder.add_conditional_edges("approve", after_plan, {"warn": "warn", "done": "done"})
    builder.add_edge("warn", "verify_warning")
    builder.add_edge("verify_warning", "approve_warning")
    builder.add_edge("approve_warning", "done")
    builder.add_edge("done", END)
    return builder


def start(cve_id: str, as_of: datetime, run_id: str | None = None, parent: str | None = None) -> TriageState:
    return {
        "run_id": run_id or uuid.uuid4().hex,
        "parent_run_id": parent,
        "cve_id": cve_id,
        "as_of": as_of.astimezone(UTC).isoformat(),
        "started": time.monotonic(),
        "calls": [],
        "timings": {},
    }


def config(run_id: str, checkpoint_id: str | None = None) -> RunnableConfig:
    configurable: dict[str, Any] = {"thread_id": run_id}
    if checkpoint_id:
        configurable["checkpoint_id"] = checkpoint_id
    return RunnableConfig(configurable=configurable)


def decide(graph: Any, run_id: str, decision: str, sha256: str, by: str) -> dict[str, Any]:
    """Resume a run waiting at an approval with a person's decision on the draft of that hash."""
    out: dict[str, Any] = graph.invoke(
        Command(resume={"decision": decision, "sha256": sha256, "by": by}), config(run_id)
    )
    return out


def fork(graph: Any, run_id: str, checkpoint_id: str, changes: dict[str, Any], as_node: str) -> str:
    """A new run from a checkpoint of another, with some of its state changed; it keeps its parent."""
    snapshot = graph.get_state(config(run_id, checkpoint_id))
    child = uuid.uuid4().hex
    values = {
        **snapshot.values,
        **changes,
        "run_id": child,
        "parent_run_id": run_id,
        "started": time.monotonic(),
    }
    values.pop("calls", None)
    values.pop("timings", None)
    graph.update_state(config(child), values, as_node=as_node)
    return child


def history(graph: Any, run_id: str) -> Sequence[Any]:
    return list(graph.get_state_history(config(run_id)))


def run_to_interrupts(
    sources: Sources, router: Router | None, cve_id: str, at: datetime, run_id: str
) -> dict[str, Any]:
    """One run in memory to its approval interrupts with no approval given, as the evals read it: the
    plan's decision names no hash, so it is void, and the run goes on to the warning when there is one."""
    from langgraph.checkpoint.memory import InMemorySaver

    compiled = build(sources, router).compile(checkpointer=InMemorySaver())
    compiled.invoke(start(cve_id, at, run_id), config(run_id))
    snapshot = compiled.get_state(config(run_id))
    if any(t.interrupts for t in snapshot.tasks) and snapshot.values.get("plan_check"):
        compiled.invoke(Command(resume={"decision": "none"}), config(run_id))
    return dict(compiled.get_state(config(run_id)).values)
