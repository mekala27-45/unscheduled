"""The release record: a tag names the phase it closes, the record reads that phase's checklist and
leaves out only the last line, and a step's last line is its own, not uv's deprecation notice."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import record_release as rr


def manifest(rows_by_table: dict[str, list[list[Any]]]) -> dict[str, Any]:
    return {"tables": {key: {"rows": rows} for key, rows in rows_by_table.items()}}


def test_a_tag_names_the_phase_it_closes() -> None:
    assert rr.phase_of("v0.1.0") == 1
    assert rr.phase_of("v0.2.0") == 2
    assert rr.phase_of("v0.4.0") == 4
    assert rr.phase_of("v1.0.0") == 5


@pytest.mark.parametrize("tag", ["v0.0.0", "v0.5.0", "v0.2.1", "0.2.0", "v2.0.0", "release"])
def test_anything_else_is_refused(tag: str) -> None:
    with pytest.raises(SystemExit):
        rr.phase_of(tag)


def test_the_record_reads_the_checklist_of_its_own_phase() -> None:
    m = manifest(
        {
            "checklist": [
                [1, "done", "phase one line", "a.json"],
                [18, "not done", "the phase one tag", "b.json"],
            ],
            "checklist.phase2": [
                [1, "done", "the probes", "a.json"],
                [14, "not done", "the predictions live", "b.json"],
                [18, "not done", "the release record", "c.json"],
            ],
        }
    )
    assert rr.checklist_key(1) == "checklist" and rr.checklist_key(2) == "checklist.phase2"
    assert rr.open_lines(m, 1) == []
    assert rr.open_lines(m, 2) == ["14. the predictions live"]


def test_an_open_line_fails_the_record_as_a_failed_step_does() -> None:
    steps = [{"name": "pytest", "exit_code": 0}]
    evidence = {"rederive": {"present": True, "result": "pass"}}
    assert rr.verdict(steps, evidence, 60, []) == ("pass", [])
    result, failed = rr.verdict(steps, evidence, 60, ["14. the predictions live"])
    assert result == "fail" and failed == ["checklist line 14. the predictions live"]
    result, failed = rr.verdict([{"name": "mypy", "exit_code": 1}], evidence, 49, [])
    assert result == "fail"
    assert failed == ["mypy", "commits: 49 conventional, fewer than 50"]


def test_a_step_keeps_its_own_last_line() -> None:
    notice = (
        "warning: The `UV_NATIVE_TLS` environment variable is deprecated and will be removed in a future "
        "release. Use `UV_SYSTEM_CERTS` instead."
    )
    assert rr.last_line("580 passed in 212s\n", notice + "\n") == "580 passed in 212s"
    assert rr.last_line("", notice + "\nerror: no such file\n") == "error: no such file"
    assert rr.last_line("", notice) == ""


def test_the_commit_count_starts_at_the_last_version_tag_not_a_lake_tag(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git(
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "feat: one",
    )
    assert rr.previous_tag(tmp_path) is None
    git("tag", "v0.1.0")
    git(
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "fix: two",
    )
    git("tag", "lake-20261114")
    git("tag", "serving-202611141230")
    assert rr.previous_tag(tmp_path) == "v0.1.0"
