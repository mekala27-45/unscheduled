"""The exploitation runs side by side: every committed record of the exploitation step, what each read,
the machine it ran on, the trees its search chose and what LightGBM and the floor scored on development.

    uv run python scripts/rank_runs.py

Reads results/models/rank.json, the exploitation model, and the earlier runs kept beside it (RUNS),
and writes the manifest part results/parts/rank_runs.json: one row per run, and the lowest and
highest development recall in the top five percent over the runs, for LightGBM and for the floor.
The records are the evidence of DECISIONS.md (the exploitation rerun, and the exploitation step pins
its numeric kernels): between runs the search moves and the floor barely does. A record kept twice,
such as the model copied beside itself, is counted once, by its Actions run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.manifest import ManifestBuilder

ORIGIN = "scripts/rank_runs.py"
MODEL = "rank.json"
# The earlier runs, in the order they were made, each with what set it apart.
RUNS = (
    ("rank_refit.json", "the first run, on its own refit of the band floor"),
    ("rank_rerun.json", "the rerun, on the committed band floor"),
    ("rank_unpinned.json", "the rerun again, on another runner"),
    ("rank_pinned.json", "the run with the numeric kernels pinned"),
)
# The processor a run printed in its log, for the one run that printed it before records kept it
# (the models workflow's machine step, added with that run).
LOGGED_PROCESSORS = {"43588159927": "AMD EPYC 9V74 80-Core Processor, from the run log"}
COLUMNS = (
    "Run",
    "Processor",
    "Leaves",
    "Learning rate",
    "Trees",
    "LightGBM, top five percent",
    "LightGBM, average precision",
    "Floor, top five percent",
    "Floor, average precision",
)
FORMATS = ("text", "text", "int", "float3", "int", "pct1", "float3", "pct1", "float3")


def describe(record: dict[str, Any]) -> str:
    """What set a record's run apart, read from the record itself."""
    environment = record.get("environment") or {}
    if environment.get("numerics"):
        return "the run with the numeric kernels pinned"
    if (record.get("band_floor") or {}).get("source"):
        return "a run on the committed band floor"
    return "the first run, on its own refit of the band floor"


def row(label: str, record: dict[str, Any]) -> list[Any]:
    environment = record.get("environment") or {}
    run = str(environment.get("github_run_id"))
    processor = (
        (environment.get("numerics") or {}).get("processor") or LOGGED_PROCESSORS.get(run) or "not recorded"
    )
    params = record["lgbm"]["params"]
    dev = record["dev"]
    return [
        label,
        processor,
        int(params["num_leaves"]),
        float(params["learning_rate"]),
        int(record["lgbm"]["trees"]),
        float(dev["lgbm"]["recall_at_top5"]),
        float(dev["lgbm"]["average_precision"]),
        float(dev["floor"]["recall_at_top5"]),
        float(dev["floor"]["average_precision"]),
    ]


def runs(folder: Path) -> list[list[Any]]:
    """One row per distinct run, the earlier runs first and the model last."""
    model = json.loads((folder / MODEL).read_text(encoding="utf-8"))
    model_run = (model.get("environment") or {}).get("github_run_id")
    rows: list[list[Any]] = []
    seen: set[str] = set()
    for name, label in RUNS:
        path = folder / name
        if not path.exists():
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        run = str((record.get("environment") or {}).get("github_run_id"))
        if run == str(model_run) or run in seen:
            continue
        seen.add(run)
        rows.append(row(label, record))
    rows.append(row(f"{describe(model)}: the exploitation model", model))
    return rows


def manifest_part(rows: list[list[Any]], as_of: str, model_pinned: bool = False) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    population = "development window CVEs published, Q03 left out, KEV within 180 days, in each run"
    m.table(
        "models.rank.runs",
        COLUMNS,
        FORMATS,
        rows,
        origin=ORIGIN,
        population=population,
        source="models",
    )
    m.value("models.rank.runs.count", len(rows), "int", origin=ORIGIN, population=population, source="models")
    m.value(
        "models.rank.runs.model_pinned",
        "yes" if model_pinned else "no",
        "text",
        origin=ORIGIN,
        population="whether the exploitation model is the run with the numeric kernels pinned",
        source="models",
    )
    for column, name in ((5, "lgbm"), (7, "floor")):
        values = [r[column] for r in rows]
        for end, value in (("low", min(values)), ("high", max(values))):
            m.value(
                f"models.rank.runs.{name}_recall_{end}",
                value,
                "pct1",
                origin=ORIGIN,
                population=population,
                source="models",
            )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    folder = root / "results" / "models"
    rows = runs(folder)
    model = json.loads((folder / MODEL).read_text(encoding="utf-8"))
    pinned = bool((model.get("environment") or {}).get("numerics"))
    sets_record = json.loads((folder / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(rows, str(sets_record["lake_cut"])[:10], model_pinned=pinned)
    out = root / "results" / "parts" / "rank_runs.json"
    out.write_text(json.dumps(part, indent=1) + "\n", encoding="utf-8")
    low, high = min(r[5] for r in rows), max(r[5] for r in rows)
    print(
        f"rank runs: {len(rows)} runs, LightGBM recall in the top five percent from {low:.1%} to {high:.1%}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
