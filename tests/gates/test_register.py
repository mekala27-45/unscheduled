"""The registration: the plan before the lake, the data files before any test CVE, and no silent edit."""

from __future__ import annotations

import json
from pathlib import Path

from scripts import register


def _tree(root: Path) -> None:
    for rel in (*register.STAGES["plan"], *register.STAGES["data"]):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {rel}\nvalue: 1\n", encoding="utf-8")


def test_plan_then_data_registers_every_file(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert register.register(tmp_path, "plan") == 0
    assert register.register(tmp_path, "data") == 0
    full = json.loads((tmp_path / register.FULL_OUT).read_text(encoding="utf-8"))
    assert len(full["files"]) == 6
    assert [s["stage"] for s in full["stages"]] == ["plan", "data"]
    assert full["stages"][0]["state_at_hash"] == {"bronze_tables": [], "lake_file": False, "result_files": []}
    assert full["stages"][0]["first_committed"]["config/criteria.yaml"] is None
    assert register.check(tmp_path) == 0


def test_a_change_after_the_hash_fails_the_check(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert register.register(tmp_path, "plan") == 0
    (tmp_path / "config" / "criteria.yaml").write_text("value: 2\n", encoding="utf-8")
    assert register.check(tmp_path) == 1
    assert register.register(tmp_path, "data") == 1
    assert register.register(tmp_path, "plan") == 1


def test_the_plan_is_refused_once_the_lake_exists(tmp_path: Path) -> None:
    _tree(tmp_path)
    lake = tmp_path / "data" / "lake" / "unscheduled.duckdb"
    lake.parent.mkdir(parents=True)
    lake.write_bytes(b"x")
    assert register.register(tmp_path, "plan") == 1
    assert not (tmp_path / register.PLAN_OUT).exists()
    assert register.check(tmp_path) == 0


def test_the_fetcher_counters_do_not_move_the_vocabulary_hash(tmp_path: Path) -> None:
    _tree(tmp_path)
    labels = tmp_path / "config" / "labels.yaml"
    labels.write_text(
        "nvd_vuln_status:\n  Deferred:\n    meaning: lowest priority\n    first_seen: '2026-11-08'\n"
        "    cves_at_last_fetch: 10\n",
        encoding="utf-8",
    )
    assert register.register(tmp_path, "plan") == 0
    assert register.register(tmp_path, "data") == 0
    labels.write_text(labels.read_text(encoding="utf-8").replace("10", "12"), encoding="utf-8")
    assert register.check(tmp_path) == 0
    labels.write_text(
        labels.read_text(encoding="utf-8").replace("lowest priority", "not scheduled"), encoding="utf-8"
    )
    assert register.check(tmp_path) == 1


def _later(root: Path, name: str) -> None:
    for rel in register.STAGES[name]:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {rel}\nvalue: 1\n", encoding="utf-8")


def test_a_later_stage_keeps_the_phase_one_hash_and_is_checked(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert register.register(tmp_path, "plan") == 0
    assert register.register(tmp_path, "data") == 0
    before = json.loads((tmp_path / register.FULL_OUT).read_text(encoding="utf-8"))
    _later(tmp_path, "models")
    assert register.register(tmp_path, "models") == 0
    after = json.loads((tmp_path / register.FULL_OUT).read_text(encoding="utf-8"))
    assert after["hash"] == before["hash"] and after["files"] == before["files"]
    assert [s["stage"] for s in after["stages"]] == ["plan", "data", "models"]
    assert after["stages"][2]["model_results_at_hash"] == []
    assert register.register(tmp_path, "models") == 1
    (tmp_path / "evaluation" / "phase2_plan.yaml").write_text("value: 2\n", encoding="utf-8")
    assert register.check(tmp_path) == 1


def test_a_later_stage_is_refused_after_what_it_must_precede(tmp_path: Path) -> None:
    _tree(tmp_path)
    _later(tmp_path, "models")
    assert register.register(tmp_path, "models") == 1
    assert register.register(tmp_path, "plan") == 0
    assert register.register(tmp_path, "data") == 0
    results = tmp_path / "results" / "models"
    results.mkdir(parents=True)
    (results / "floors.json").write_text("{}", encoding="utf-8")
    assert register.register(tmp_path, "models") == 1
    (results / "floors.json").unlink()
    assert register.register(tmp_path, "models") == 0
    _later(tmp_path, "operating_points")
    (results / "test_scoring.json").write_text("{}", encoding="utf-8")
    assert register.register(tmp_path, "operating_points") == 1
