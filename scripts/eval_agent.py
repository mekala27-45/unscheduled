"""The agent evals of step 12 on KEV listings (evaluation/phase3_plan.yaml, agent).

    python scripts/eval_agent.py --window development --database-url postgresql://... [--write]

Every listing of the window runs through the no model floor; a seeded draw of each window runs through
every model configuration of config/agent_points.yaml (each provider and model alone behind the
router, the floor last), with the provider answers served from tests/replays (or recorded there with
--record, which only agent-record.yml passes). Each run is the triage graph behind the guard, as of
the end of the listing day, to its approval interrupts, with no approval given.

Scored by code: C5 (claims drafted, verified and removed; drafts blocked; unverified citations in the
drafts that reached a person), the fixed version share, the component share, the warning fields
share, and the cost per node and per run in tokens, milliseconds and shadow price. Shares carry 2000
paired bootstrap resamples against the floor. The shadow window is read once, after the agent_points
stage is hashed; this script refuses it before.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import UTC, datetime, time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import polars as pl
import yaml
from unscheduled_agent import defend, graph, prices, replay, verify
from unscheduled_agent.router import MemoryBudget, Router, adapters, limits
from unscheduled_agent.schemas import EarlyWarning, PatchPlan
from unscheduled_retrieval import metrics

from scripts.agent_sources import LakeSources, listings

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261116
OUT = ROOT / "results" / "agent"


def draw(ids: list[str], n: int, seed: int = SEED) -> list[str]:
    """The plan's seeded draw: sort by id, then take the first n by the sha256 of the seed and the id."""
    return sorted(sorted(ids), key=lambda i: hashlib.sha256(f"{seed}:{i}".encode()).hexdigest())[:n]


def run_one(
    sources: LakeSources, router: Router | None, cve_id: str, at: datetime, run_id: str
) -> dict[str, Any]:
    guard = defend.Guard(sources)
    state = graph.run_to_interrupts(guard, router, cve_id, at, run_id)
    state["defenses"] = dict(guard.counts)
    return state


def score(state: dict[str, Any], sources: LakeSources) -> dict[str, Any]:
    facts = graph.facts_of(state)  # type: ignore[arg-type]
    plan = state["plan_check"]["draft"]
    reference = facts.fixed_versions[0].version if facts.fixed_versions else None
    out: dict[str, Any] = {
        "fixed_version": float(plan.get("fixed_version") == reference),
        "component": float(plan.get("component") == facts.component),
        "plan_by": state["plan_check"]["by"],
    }
    drafted = [state["plan_check"]]
    if state.get("warning_check"):
        warning = state["warning_check"]["draft"]
        drafted.append(state["warning_check"])
        out["warning_fields"] = float(
            bool(warning.get("product"))
            and bool(warning.get("vulnerability"))
            and bool(warning.get("actively_exploited"))
            and bool(warning.get("evidence"))
            and bool(warning.get("member_states"))
        )
    c5: Counter[str] = Counter()
    for check in drafted:
        first = check.get("replaced") or check
        c5["drafts"] += 1
        c5["claims_drafted"] += first["claims_drafted"]
        c5["claims_verified"] += first["claims_verified"]
        c5["claims_removed"] += first["claims_removed"]
        c5["drafts_blocked"] += int(first["blocked"])
        c5["citations_failed"] += first["citations_failed"]
        if not check["blocked"]:
            schema = PatchPlan if check["draft"]["kind"] == "patch_plan" else EarlyWarning
            again = verify.check(schema.model_validate(check["draft"]), facts, sources.documents)
            c5["unverified_in_approval_drafts"] += again.citations_failed
            c5["reached_approval"] += 1
    out["c5"] = dict(c5)
    calls = state.get("calls") or []
    out["cost"] = {
        "tokens_in": sum(c["tokens_in"] for c in calls),
        "tokens_out": sum(c["tokens_out"] for c in calls),
        "shadow_usd": round(sum(c["shadow_usd"] for c in calls), 6),
        "ms": round(sum((state.get("timings") or {}).values()), 1),
        "nodes_ms": state.get("timings") or {},
        "calls": [
            {k: c[k] for k in ("provider", "model", "outcome", "tokens_in", "tokens_out", "ms")}
            for c in calls
        ],
    }
    out["defenses"] = state.get("defenses") or {}
    return out


def summarize(rows: list[dict[str, Any]], floor: list[dict[str, Any]] | None) -> dict[str, Any]:
    out: dict[str, Any] = {"runs": len(rows)}
    draws = metrics.resamples(len(rows))
    for name in ("fixed_version", "component", "warning_fields"):
        values = np.asarray([r.get(name, np.nan) for r in rows], dtype=float)
        out[name] = metrics.interval(values, draws)
        if floor is not None:
            base = np.asarray([r.get(name, np.nan) for r in floor], dtype=float)
            out[f"{name}_minus_floor"] = metrics.interval(values - base, draws)
    c5: Counter[str] = Counter()
    for r in rows:
        c5.update(r["c5"])
    out["c5"] = dict(c5)
    ms = sorted(r["cost"]["ms"] for r in rows)
    out["cost"] = {
        "tokens_in": sum(r["cost"]["tokens_in"] for r in rows),
        "tokens_out": sum(r["cost"]["tokens_out"] for r in rows),
        "shadow_usd": round(sum(r["cost"]["shadow_usd"] for r in rows), 6),
        "shadow_usd_per_1000_runs": round(
            1000 * sum(r["cost"]["shadow_usd"] for r in rows) / max(1, len(rows)), 4
        ),
        "ms_p50": ms[len(ms) // 2] if ms else None,
        "ms_p95": ms[min(len(ms) - 1, round(0.95 * (len(ms) - 1)))] if ms else None,
    }
    defenses: Counter[str] = Counter()
    for r in rows:
        defenses.update(r["defenses"])
    out["defenses"] = dict(defenses)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--window", choices=["development", "shadow"], default="development")
    parser.add_argument("--work", type=Path, default=ROOT / "data" / "cache" / "lake" / "unscheduled.duckdb")
    parser.add_argument("--corpus", type=Path, default=ROOT / "data" / "corpus")
    parser.add_argument("--findings", type=Path, default=ROOT / "data" / "serving" / "finding.parquet")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--record", action="store_true", help="record provider calls (agent-record.yml only)")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    registration = json.loads((ROOT / "evaluation" / "registration.json").read_text(encoding="utf-8"))
    stages = [s.get("stage") for s in registration.get("stages", [])]
    if args.window == "shadow" and "agent_points" not in stages:
        raise SystemExit("eval: the shadow window is read only after the agent_points stage is hashed")
    from scripts.eval_retrieval_runtime import searcher_from_frozen

    retrieve, close = searcher_from_frozen(ROOT, args.corpus, args.database_url)
    sources = LakeSources(args.work, args.corpus, args.findings, retrieve)
    population = listings(sources.con).filter(pl.col("window") == args.window)
    points_path = ROOT / "config" / "agent_points.yaml"
    points = yaml.safe_load(points_path.read_text(encoding="utf-8")) if points_path.exists() else {}
    order = [tuple(x) for x in points.get("router_order") or []]
    sample_n = int((points.get("samples") or {}).get(args.window, 60))
    config = yaml.safe_load((ROOT / "config" / "providers.yaml").read_text(encoding="utf-8"))
    book = prices.load(ROOT)

    def day_end(at: datetime) -> datetime:
        return datetime.combine(at.astimezone(UTC).date(), time(23, 59, 59, 999999), tzinfo=UTC)

    rows = list(population.iter_rows(named=True))
    results: dict[str, Any] = {
        "floor": [
            score(
                run_one(sources, None, r["cve_id"], day_end(r["listed_at"]), f"floor-{r['cve_id']}"), sources
            )
            for r in rows
        ]
    }
    sampled = set(draw([r["cve_id"] for r in rows], sample_n))
    floor_sampled = [s for s, r in zip(results["floor"], rows, strict=True) if r["cve_id"] in sampled]
    for provider, model in order:
        cassette = replay.Cassette(
            ROOT / "tests" / "replays" / f"agent_{args.window}_{provider}_{model.replace('/', '_')}.jsonl.gz"
        )
        transport = replay.Recording(cassette) if args.record else replay.Replay(cassette)
        router = Router(adapters(config, [(provider, model)], transport, book), MemoryBudget(limits(config)))
        name = f"{provider}/{model}"
        results[name] = [
            score(
                run_one(sources, router, r["cve_id"], day_end(r["listed_at"]), f"{name}-{r['cve_id']}"),
                sources,
            )
            for r in rows
            if r["cve_id"] in sampled
        ]
    close()
    record = {
        "phase": 3,
        "window": args.window,
        "run_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "population": {"listings": len(rows), "sample": len(sampled), "seed": SEED},
        "configurations": {
            name: summarize(rs, None if name == "floor" else floor_sampled) for name, rs in results.items()
        },
        "runs": {name: rs for name, rs in results.items()},
        "result": "pass",
    }
    print(json.dumps({k: v for k, v in record["configurations"].items()}, indent=1, default=str)[:4000])
    if args.write:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / f"evals_{args.window}.json").write_text(
            json.dumps(record, indent=1, default=str) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
