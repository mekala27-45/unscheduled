"""Record provider calls into tests/replays, for the tests and evals that serve them back.

    python scripts/record_replays.py smoke     # one patch plan from every provider and model with a key

Runs only where a provider key is set (agent-record.yml, started by Ajay, with the keys as Actions
secrets) and never in CI (UNSCHED_REPLAY_ONLY=1 refuses a network transport). Each call goes through
replay.Recording, which writes the request body, the status, the response body and the limit headers
of each call, and never a request header. The smoke job asks every model for the patch plan of one
fixed case, so the adapters are checked against the providers' real answers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml
from unscheduled_agent import floor, prices, replay
from unscheduled_agent.router import MemoryBudget, Prompt, Router, adapters, limits
from unscheduled_agent.schemas import Facts, FixedVersion, PatchPlan

ROOT = Path(__file__).resolve().parents[1]
REPLAYS = ROOT / "tests" / "replays"
SMOKE_PROMPT = Prompt(
    "smoke_plan",
    "1",
    "You write a patch plan for one vulnerable component as JSON that matches the schema. Use only the "
    "facts given. Every claim cites the source that holds its fact, as the facts name it.",
)
SMOKE_FACTS = Facts(
    cve_id="CVE-2024-23897",
    as_of=datetime(2024, 8, 19, 23, 59, 59, tzinfo=UTC),
    product="pipeline-runner",
    component="org.jenkins-ci.main:jenkins-core",
    ecosystem="Maven",
    installed_version="2.426.1",
    fixed_versions=[FixedVersion(version="2.426.3", source="ghsa:GHSA-6f9g-cxwr-q5jr")],
)


def smoke() -> dict[str, object]:
    config = yaml.safe_load((ROOT / "config" / "providers.yaml").read_text(encoding="utf-8"))
    book = prices.load(ROOT)
    cassette = replay.Cassette(REPLAYS / "router_smoke.jsonl.gz")
    out: dict[str, object] = {}
    for name, provider in config["providers"].items():
        if not os.environ.get(provider["key_env"]):
            out[name] = {"recorded": False, "reason": f"{provider['key_env']} is not set"}
            continue
        for model in provider.get("models") or []:
            router = Router(
                adapters(config, [(name, model)], replay.Recording(cassette), book),
                MemoryBudget(limits(config)),
            )
            _draft, calls = router.generate(
                SMOKE_PROMPT,
                {"facts": SMOKE_FACTS.model_dump(mode="json")},
                PatchPlan,
                lambda: floor.plan(SMOKE_FACTS),
                max_tokens=1200,
            )
            out[f"{name}/{model}"] = {
                "outcomes": [c.outcome for c in calls],
                "tokens": [c.tokens_in + c.tokens_out for c in calls],
            }
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("job", choices=["smoke"])
    args = parser.parse_args(argv)
    result = {
        "job": args.job,
        "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "calls": smoke(),
    }
    print(json.dumps(result, indent=1))
    (REPLAYS / f"{args.job}.summary.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
