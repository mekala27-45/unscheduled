"""A checklist line is done only when its evidence holds: a stated result must be a pass."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.build_manifest import evidence_holds


def _write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_a_record_of_a_failed_run_does_not_hold(tmp_path: Path) -> None:
    assert evidence_holds(_write(tmp_path / "rederive.json", {"result": "pass", "equal": 693}))
    assert not evidence_holds(_write(tmp_path / "c8.json", {"result": "fail"}))
    assert evidence_holds(_write(tmp_path / "locks.json", {"files": 3}))
    assert not evidence_holds(tmp_path / "missing.json")
    (tmp_path / "empty.md").write_text("", encoding="utf-8")
    assert not evidence_holds(tmp_path / "empty.md")


def test_the_live_check_needs_both_phases(tmp_path: Path) -> None:
    awake = {"awake": {"result": "pass"}}
    assert not evidence_holds(_write(tmp_path / "live_check.json", awake))
    both = {**awake, "asleep": {"result": "pass"}}
    assert evidence_holds(_write(tmp_path / "live_check.json", both))
    assert not evidence_holds(_write(tmp_path / "live_check.json", {**both, "asleep": {"result": "fail"}}))
