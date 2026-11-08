"""The release notes print only what the manifest holds, and the statement."""

from __future__ import annotations

from unscheduled_core.manifest import ManifestBuilder
from unscheduled_core.statements import NVD_NOTICE

from scripts import release_notes


def _manifest(done: int) -> ManifestBuilder:
    builder = ManifestBuilder("2026-11-07")
    rows = [
        [1, "done" if done else "not done", "The first line", "a.json"],
        [2, "not done", "The second", "b"],
    ]
    builder.table(
        "checklist",
        ["Item", "Status", "Line", "Evidence"],
        ["int", "text", "text", "text"],
        rows,
        origin="test",
        population="test",
        source="build",
    )
    builder.value("build.checklist_done", done, "int", origin="test", population="test", source="build")
    builder.value("build.checklist_total", 2, "int", origin="test", population="test", source="build")
    return builder


def test_notes_count_the_done_lines_and_list_the_rest() -> None:
    text = release_notes.notes(_manifest(1).build())
    assert text.startswith("1 of 2 lines")
    assert "- The second" in text and "- The first line" not in text
    assert NVD_NOTICE in text
