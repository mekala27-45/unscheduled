"""A checklist line is done only when its evidence holds: a stated result must be a pass."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.build_manifest import checklist_rows, condition_holds, evidence_holds


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


def test_a_later_phase_asks_for_what_only_it_writes(tmp_path: Path) -> None:
    release = _write(tmp_path / "release.json", {"tag": "v0.1.0", "result": "pass", "steps": [{"n": 1}]})
    assert condition_holds(release, [["steps", "0", "n"]], {"tag": "v0.1.0"})
    assert not condition_holds(release, [], {"tag": "v0.2.0"})
    assert not condition_holds(release, [["parts", "rank.json"]], {})
    (tmp_path / "config").mkdir()
    (tmp_path / "results").mkdir()
    _write(tmp_path / "results" / "release.json", {"tag": "v0.1.0", "result": "pass"})
    spec = {
        "items": [{"n": 1, "text": "the first tag", "evidence": ["results/release.json"]}],
        "phase2": [
            {
                "n": 1,
                "text": "the second tag",
                "evidence": [{"file": "results/release.json", "equals": {"tag": "v0.2.0"}}],
            }
        ],
    }
    (tmp_path / "config" / "checklist.yaml").write_text(yaml.safe_dump(spec), encoding="utf-8")
    assert checklist_rows(tmp_path)[0][1] == "done"
    assert checklist_rows(tmp_path, "phase2")[0][1:] == ["not done", "the second tag", "results/release.json"]
    _write(tmp_path / "results" / "release.json", {"tag": "v0.2.0", "result": "pass"})
    assert checklist_rows(tmp_path, "phase2")[0][1] == "done"
