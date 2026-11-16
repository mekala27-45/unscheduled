"""Run the red team of evaluation/redteam/cases.jsonl through the defenses (steps 11 and 12).

    python scripts/run_redteam.py --half development          # tuning: the development half
    python scripts/run_redteam.py --half development --write  # and results/agent/redteam_development.json

Each graph case runs through the floor (and, from step 12, every model configuration of
config/agent_points.yaml with recorded replays); each MCP case is a request to the tool dispatcher of
packages/mcp. The held out half is not run here: scripts/score_redteam.py runs it once, after the
agent_points stage is hashed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unscheduled_agent import redteam
from unscheduled_mcp import tools

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "evaluation" / "redteam" / "cases.jsonl"
OUT = ROOT / "results" / "agent" / "redteam_development.json"


class RecordingBackend:
    """A backend for the MCP cases that answers like the real one and records what it was asked."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def search(self, query: str, as_of: date) -> list[dict[str, Any]]:
        self.calls.append("search")
        return [
            {
                "chunk_id": "c1",
                "doc_id": "ghsa:GHSA-0000-0000-0000",
                "known_from": as_of.isoformat(),
                "score": 0.1,
            }
        ]

    def start_triage(self, cve_id: str, as_of: date | None) -> dict[str, Any]:
        self.calls.append("start_triage")
        return {"run_id": "0" * 32, "status": "waiting"}

    def read_run(self, run_id: str) -> dict[str, Any]:
        self.calls.append("read_run")
        return {"run_id": run_id, "plan": "waiting"}


def run(half: str) -> dict[str, Any]:
    header, cases = redteam.load(CASES)
    chosen = [c for c in cases if c["half"] == half]
    outcomes: list[dict[str, Any]] = []
    for case in chosen:
        if case["category"] == "mcp_request":
            backend = RecordingBackend()
            payload = case["payload"]
            result = tools.dispatch(payload["tool"], dict(payload["arguments"]), backend)
            outcome = redteam.evaluate_mcp(case, result, backend.calls)
            outcome["configuration"] = "mcp"
        else:
            outcome = redteam.run_graph_case(case, header["bases"], router=None)
            outcome["configuration"] = "floor"
        outcomes.append(outcome)
    followed = [o for o in outcomes if o["followed"]]
    defenses: Counter[str] = Counter()
    for o in outcomes:
        defenses.update(o.get("defenses") or {})
        if o.get("refused"):
            defenses["mcp refusal"] += 1
    return {
        "phase": 3,
        "half": half,
        "run_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "cases": len(outcomes),
        "configurations": sorted({o["configuration"] for o in outcomes}),
        "followed": len(followed),
        "followed_cases": [{"id": o["id"], "failed": o["failed"]} for o in followed],
        "by_category": {
            cat: {
                "cases": sum(1 for o in outcomes if o["category"] == cat),
                "followed": sum(1 for o in followed if o["category"] == cat),
            }
            for cat in sorted({o["category"] for o in outcomes})
        },
        "defenses": dict(sorted(defenses.items())),
        "outcomes": outcomes,
        "note": "the development half, for tuning the defenses; the held out half is scored once by scripts/score_redteam.py",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--half", choices=["development"], default="development")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    record = run(args.half)
    print(json.dumps({k: record[k] for k in ("cases", "followed", "by_category", "defenses")}, indent=1))
    for case in record["followed_cases"]:
        print("followed:", case["id"], case["failed"])
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(record, indent=1, default=str) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
