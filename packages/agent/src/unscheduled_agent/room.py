"""The room one triage run takes in the checkpoint store, measured before the graph exists.

The room plan (step 2, ADR 0011) has to budget the Postgres checkpointer before step 8 builds the
triage graph, so this module runs a fixture graph with the node names of the triage graph, a state
the size of the planned one, and the approval interrupt, against a Postgres that is not Neon. It
reports the bytes the checkpoint tables gain per run as the run waits for a person, and what is left
after the retention rule keeps only the latest checkpoint of a decided run, or deletes it.

The fixture's state sizes are declared below and recorded with the result; step 8 measures the real
graph the same way and replaces them.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from itertools import pairwise
from typing import Any, TypedDict
from urllib.parse import quote

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

NODES = ("intake", "match", "fill", "rank", "retrieve", "plan", "verify", "approve")
# Bytes of what each node adds to the state in the fixture, from the planned state of section 9.
FIXTURE_BYTES = {
    "finding": 1_000,
    "match": 500,
    "predictions": 2_000,
    "retrieved": 12_000,
    "claims": 6_000,
    "checks": 3_000,
    "costs": 1_200,
}
TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")


class FixtureState(TypedDict, total=False):
    cve_id: str
    finding: str
    match: str
    predictions: str
    retrieved: str
    claims: str
    checks: str
    costs: str
    decision: str


def _text(rng: random.Random, size: int) -> str:
    """Text of about size bytes that compresses like prose, not like a run of one letter."""
    words = ["advisory", "fixed", "version", "component", "exploited", "upgrade", "range", "cites"]
    out: list[str] = []
    length = 0
    while length < size:
        word = rng.choice(words) + str(rng.randint(0, 999))
        out.append(word)
        length += len(word) + 1
    return " ".join(out)[:size]


def fixture_builder(seed: int = 7) -> StateGraph[FixtureState]:
    rng = random.Random(seed)

    def adds(*keys: str) -> Callable[[FixtureState], dict[str, Any]]:
        def node(state: FixtureState) -> dict[str, Any]:
            return {k: _text(rng, FIXTURE_BYTES[k]) for k in keys}

        return node

    def approve(state: FixtureState) -> dict[str, Any]:
        decision = interrupt({"draft": state.get("claims", "")[:64]})
        return {"decision": str(decision)}

    # Any: the node protocols of langgraph take a state and return an update, which these are.
    steps: dict[str, Any] = {
        "intake": adds("finding"),
        "match": adds("match"),
        "fill": adds("predictions"),
        "rank": adds("costs"),
        "retrieve": adds("retrieved"),
        "plan": adds("claims"),
        "verify": adds("checks"),
        "approve": approve,
    }
    builder: StateGraph[FixtureState] = StateGraph(FixtureState)
    for name in NODES:
        builder.add_node(name, steps[name])
    builder.add_edge(START, NODES[0])
    for first, second in pairwise(NODES):
        builder.add_edge(first, second)
    builder.add_edge(NODES[-1], END)
    return builder


def _sizes(conn: psycopg.Connection[Any], schema: str) -> dict[str, int]:
    rows = conn.execute(
        "select c.relname, pg_total_relation_size(c.oid) from pg_class c "
        "join pg_namespace n on n.oid = c.relnamespace where n.nspname = %s and c.relkind = 'r'",
        (schema,),
    ).fetchall()
    found = {str(name): int(size) for name, size in rows}
    return {t: found.get(t, 0) for t in TABLES}


def measure(url: str, runs: int = 20, schema: str = "room_checkpoints") -> dict[str, Any]:
    """Run the fixture graph runs times to its approval interrupt and measure the checkpoint tables:
    while every run waits, after keep_latest on half of them, and after deleting the other half."""
    plain = url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(plain, autocommit=True) as admin:
        admin.execute(f'drop schema if exists "{schema}" cascade')
        admin.execute(f'create schema "{schema}"')
    scoped = plain + ("&" if "?" in plain else "?") + "options=" + quote(f"-csearch_path={schema}")
    with PostgresSaver.from_conn_string(scoped) as saver:
        saver.setup()
        graph = fixture_builder().compile(checkpointer=saver)
        with psycopg.connect(plain, autocommit=True) as conn:
            empty = _sizes(conn, schema)
            final: dict[str, Any] = {}
            for i in range(runs):
                final = graph.invoke(
                    {"cve_id": f"CVE-2026-{i:05d}"}, {"configurable": {"thread_id": f"fixture-{i}"}}
                )
            waiting = _sizes(conn, schema)
            half = [f"fixture-{i}" for i in range(runs // 2)]
            saver.prune(half, strategy="keep_latest")
            conn.execute(
                f'vacuum full "{schema}".checkpoints, "{schema}".checkpoint_blobs, "{schema}".checkpoint_writes'
            )
            kept = _sizes(conn, schema)
            saver.prune([f"fixture-{i}" for i in range(runs // 2, runs)], strategy="delete")
            conn.execute(
                f'vacuum full "{schema}".checkpoints, "{schema}".checkpoint_blobs, "{schema}".checkpoint_writes'
            )
            deleted = _sizes(conn, schema)
            row = conn.execute(f'select count(*) from "{schema}".checkpoints').fetchone()
            checkpoints = int(row[0]) if row else 0
    state = {k: v for k, v in final.items() if k != "__interrupt__"}
    waiting_total = sum(waiting.values()) - sum(empty.values())
    kept_total = sum(kept.values()) - sum(empty.values())
    deleted_total = sum(deleted.values()) - sum(empty.values())
    return {
        "runs": runs,
        "nodes": list(NODES),
        "fixture_bytes": FIXTURE_BYTES,
        "state_bytes": len(json.dumps(state)),
        "empty_tables_bytes": sum(empty.values()),
        "waiting": {"tables": waiting, "bytes_per_run": round(waiting_total / runs)},
        "keep_latest": {
            "runs": runs // 2,
            "bytes_per_run": round((kept_total - (runs - runs // 2) * waiting_total / runs) / (runs // 2)),
        },
        "deleted": {"checkpoints_left": checkpoints, "bytes_left": deleted_total},
        "note": (
            "a fixture graph with the node names of the triage graph and the planned state sizes, "
            "run to its approval interrupt; step 8 measures the real graph the same way"
        ),
    }
