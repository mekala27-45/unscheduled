"""Count the GPU hours of each month from the requests under requests/gpu/, against the ceiling.

    uv run python scripts/gpu_hours.py

Every GPU run is declared in a committed file under requests/gpu/ before it starts, with the hours
it declares, and the file records the hours used once the run ends (evaluation/phase2_plan.yaml,
gpu). This sums the hours used in the month of the lake cut against kaggle_gpu_hours_month in
config/budgets.yaml, refuses a month whose declared hours pass the ceiling, and writes the manifest
part results/parts/gpu.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import yaml
from unscheduled_core.manifest import ManifestBuilder

ORIGIN = "scripts/gpu_hours.py"
STATUSES = ("not run", "running", "done", "failed")


def read_requests(folder: Path) -> list[dict[str, Any]]:
    requests = []
    for path in sorted(folder.glob("*.yaml")):
        entry = yaml.safe_load(path.read_text(encoding="utf-8"))
        missing = [k for k in ("run", "month", "hours_declared", "hours_used", "status") if k not in entry]
        if missing:
            raise SystemExit(f"gpu: {path.name} lacks {missing}")
        if entry["status"] not in STATUSES:
            raise SystemExit(f"gpu: {path.name} has status {entry['status']!r}, not one of {STATUSES}")
        requests.append({**entry, "file": path.name, "month": str(entry["month"])})
    return requests


def ledger(requests: list[dict[str, Any]], month: str, ceiling: float) -> dict[str, Any]:
    mine = [r for r in requests if r["month"] == month]
    declared = sum(float(r["hours_declared"]) for r in mine if r["status"] != "not run")
    used = sum(float(r["hours_used"]) for r in mine)
    if declared > ceiling or used > ceiling:
        raise SystemExit(
            f"gpu: {month} declares {declared} and used {used} hours, past the ceiling of {ceiling}"
        )
    return {
        "month": month,
        "ceiling": ceiling,
        "requests": len(mine),
        "runs": sum(1 for r in mine if r["status"] in ("running", "done", "failed")),
        "used": used,
        "left": ceiling - used,
    }


def manifest_part(entry: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    population = f"GPU requests under requests/gpu/ for {entry['month']}"
    for key, value, fmt in (
        ("hours_month", entry["ceiling"], "float1"),
        ("hours_used", entry["used"], "float1"),
        ("hours_left", entry["left"], "float1"),
        ("requests", entry["requests"], "int"),
        ("runs", entry["runs"], "int"),
    ):
        m.value(f"models.gpu.{key}", value, fmt, origin=ORIGIN, population=population, source="models")
    return m.dump()


def main(root: Path = ROOT) -> int:
    budgets = yaml.safe_load((root / "config" / "budgets.yaml").read_text(encoding="utf-8"))
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    as_of = str(sets_record["lake_cut"])[:10]
    entry = ledger(
        read_requests(root / "requests" / "gpu"), as_of[:7], float(budgets["kaggle_gpu_hours_month"])
    )
    (root / "results" / "parts" / "gpu.json").write_text(
        json.dumps(manifest_part(entry, as_of), indent=1) + "\n", encoding="utf-8"
    )
    print(f"gpu: {entry['used']} of {entry['ceiling']} hours used in {entry['month']}, {entry['runs']} runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
