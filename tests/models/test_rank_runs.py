"""The exploitation runs table: one row per distinct run, the model last, the processor from the
record or the run log, and the range of development recall over the runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts import rank_runs


def record(run: str, leaves: int, lgbm: float, floor: float, **extra: Any) -> dict[str, Any]:
    return {
        "lgbm": {"params": {"num_leaves": leaves, "learning_rate": 0.02}, "trees": 100},
        "dev": {
            "lgbm": {"recall_at_top5": lgbm, "average_precision": 0.02},
            "floor": {"recall_at_top5": floor, "average_precision": 0.05},
        },
        "environment": {"github_run_id": run, **extra.pop("environment", {})},
        **extra,
    }


def write(folder: Path, name: str, data: dict[str, Any]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(json.dumps(data), encoding="utf-8")


def test_runs_are_listed_once_each_with_the_model_last(tmp_path: Path) -> None:
    folder = tmp_path / "results" / "models"
    write(folder, "rank_refit.json", record("1", 131, 0.47, 0.41))
    write(folder, "rank_unpinned.json", record("43588159927", 222, 0.38, 0.42, band_floor={"source": {}}))
    pinned = record("3", 40, 0.30, 0.41, environment={"numerics": {"processor": "Some CPU"}})
    write(folder, "rank_pinned.json", pinned)
    write(folder, "rank.json", pinned)
    rows = rank_runs.runs(folder)
    assert [r[0] for r in rows] == [
        "the first run, on its own refit of the band floor",
        "the rerun again, on another runner",
        "the run with the numeric kernels pinned: the exploitation model",
    ]
    assert [r[1] for r in rows] == [
        "not recorded",
        "AMD EPYC 9V74 80-Core Processor, from the run log",
        "Some CPU",
    ]
    part = rank_runs.manifest_part(rows, "2026-11-13", model_pinned=True)
    assert part["values"]["models.rank.runs.count"]["value"] == 3
    assert part["values"]["models.rank.runs.model_pinned"]["value"] == "yes"
    assert part["values"]["models.rank.runs.lgbm_recall_low"]["value"] == 0.30
    assert part["values"]["models.rank.runs.lgbm_recall_high"]["value"] == 0.47
    assert part["values"]["models.rank.runs.floor_recall_high"]["value"] == 0.42
    assert len(part["tables"]["models.rank.runs"]["rows"]) == 3
