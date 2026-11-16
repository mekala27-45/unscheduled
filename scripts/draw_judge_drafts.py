"""The forty drafts Ajay labels for the judge (evaluation/phase3_plan.yaml, judge).

    python scripts/draw_judge_drafts.py    # reads results/agent/drafts_development.jsonl.gz

Twenty drafts from the no model floor and twenty from the model configurations, each half drawn by
seed from the development drafts the agent evals kept (scripts/eval_agent.py --write), blocked
drafts left out since a person never sees them. evaluation/judge/drafts.json gets each draft with
its id, kind, CVE, run time and hash, in an order that mixes the halves, and nothing that says which
configuration wrote it; evaluation/judge_key.json gets that, for the scorer alone. A draft's id is
the first 16 hex digits of the sha256 of the seed, its configuration, its CVE, its run time and its
kind, so the same development drafts always give the same forty.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261116
PER_HALF = 20
FLOOR = "floor"


def draft_id(row: dict[str, Any], seed: int = SEED) -> str:
    key = f"{seed}:{row['configuration']}:{row['cve_id']}:{row['as_of']}:{row['kind']}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def read(path: Path) -> list[dict[str, Any]]:
    text = gzip.decompress(path.read_bytes()).decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def draw(rows: list[dict[str, Any]], per_half: int = PER_HALF, seed: int = SEED) -> list[dict[str, Any]]:
    """Each half drawn by the digest of its ids, then the forty ordered by id, so the halves mix."""
    shown = [r for r in rows if not r.get("blocked")]
    floor = [r for r in shown if r["configuration"] == FLOOR]
    models = [r for r in shown if r["configuration"] != FLOOR]
    if len(floor) < per_half or len(models) < per_half:
        raise ValueError(
            f"the development drafts hold {len(floor)} from the floor and {len(models)} from the models; "
            f"the judge needs {per_half} of each, and the model drafts come with recorded calls"
        )
    chosen = sorted(floor, key=lambda r: draft_id(r, seed))[:per_half]
    chosen += sorted(models, key=lambda r: draft_id(r, seed))[:per_half]
    return sorted(chosen, key=lambda r: draft_id(r, seed))


def split(chosen: list[dict[str, Any]], seed: int = SEED) -> tuple[dict[str, Any], dict[str, Any]]:
    """What the console shows, and the key the scorer alone reads."""
    shown = {
        "drawn": {
            "seed": seed,
            "per_half": len(chosen) // 2,
            "from": "results/agent/drafts_development.jsonl.gz",
        },
        "drafts": [
            {
                "draft_id": draft_id(r, seed),
                "kind": r["kind"],
                "cve_id": r["cve_id"],
                "as_of": r["as_of"],
                "sha256": r["sha256"],
                "draft": r["draft"],
            }
            for r in chosen
        ],
    }
    key = {"seed": seed, "configuration": {draft_id(r, seed): r["configuration"] for r in chosen}}
    return shown, key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--drafts", type=Path, default=ROOT / "results" / "agent" / "drafts_development.jsonl.gz"
    )
    parser.add_argument("--out", type=Path, default=ROOT / "evaluation")
    args = parser.parse_args(argv)
    shown, key = split(draw(read(args.drafts)))
    (args.out / "judge").mkdir(parents=True, exist_ok=True)
    (args.out / "judge" / "drafts.json").write_text(json.dumps(shown, indent=1) + "\n", encoding="utf-8")
    (args.out / "judge_key.json").write_text(
        json.dumps(key, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"judge: {len(shown['drafts'])} drafts to label, the key beside them for the scorer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
