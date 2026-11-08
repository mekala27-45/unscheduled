"""The claim gate: documents rendered from the manifest, a hand edit caught, nothing refused."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_render.render import ClaimGateError, Renderer, hand_typed_numbers, tracked
from unscheduled_render.targets import discover, template_roots


def _root(tmp_path: Path, template: str) -> Renderer:
    folder = tmp_path / "docs" / "templates"
    folder.mkdir(parents=True)
    (folder / "NOTE.md.j2").write_text(template, encoding="utf-8")
    builder = ManifestBuilder("2026-11-07")
    builder.value("lake.rows", 5, "int", origin="test", population="test", source="lake")
    return Renderer(tmp_path, builder.build(), discover(tmp_path), template_roots(tmp_path))


def test_claim_gate_passes_a_document_rendered_from_the_manifest(tmp_path: Path) -> None:
    renderer = _root(tmp_path, "The lake holds {{ v('lake.rows') }} rows.\n")
    renderer.write_all()
    assert (tmp_path / "NOTE.md").read_text(encoding="utf-8") == "The lake holds 5 rows.\n"
    assert renderer.check_all() == []


def test_claim_gate_catches_a_number_edited_by_hand(tmp_path: Path) -> None:
    renderer = _root(tmp_path, "The lake holds {{ v('lake.rows') }} rows.\n")
    renderer.write_all()
    (tmp_path / "NOTE.md").write_text("The lake holds 6 rows.\n", encoding="utf-8")
    drifts = renderer.check_all()
    assert [d.output for d in drifts] == ["NOTE.md"]
    assert hand_typed_numbers("The lake holds 7 rows, {{ v('lake.rows') }} checked.", []) == ["7"]
    assert hand_typed_numbers("Phase 1 of 5 began.", ["Phase 1 of 5"]) == []


def test_claim_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ClaimGateError, match="no documents"):
        Renderer(tmp_path, ManifestBuilder("2026-11-07").build(), [], [])
    folder = tmp_path / "docs" / "templates"
    folder.mkdir(parents=True)
    (folder / "NOTE.md.j2").write_text("text\n", encoding="utf-8")
    with pytest.raises(ClaimGateError, match="empty manifest"):
        Renderer(
            tmp_path, ManifestBuilder("2026-11-07").build(), discover(tmp_path), template_roots(tmp_path)
        )


def test_tracked_counts_a_path_only_once_it_is_in_git(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert not tracked(tmp_path, "pkg")
    subprocess.run(["git", "add", "pkg/a.py"], cwd=tmp_path, check=True)
    assert tracked(tmp_path, "pkg") and tracked(tmp_path, "pkg/a.py")
    assert not tracked(tmp_path, "missing")
