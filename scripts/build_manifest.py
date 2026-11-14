"""Assemble results/manifest.json from the parts each step saved, plus the printed checklist.

    python scripts/build_manifest.py

Every step writes its own part under results/parts/ (a ManifestBuilder dump), so steps can run
apart and the manifest is assembled once. The checklist table marks a line done only when all of
its evidence files exist and are not empty.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import yaml
from unscheduled_core.manifest import ManifestBuilder, write

LIVE_CHECK_PHASES = ("awake", "asleep")


def evidence_holds(path: Path) -> bool:
    """A piece of evidence exists and is not empty. A JSON record that states a result must state a
    pass, and the live check must hold a pass for each of its phases: a record of a failed run is
    evidence of the failure, not of the line."""
    if not path.exists() or path.stat().st_size == 0:
        return False
    if path.suffix != ".json":
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if not isinstance(data, dict):
        return True
    if path.name == "live_check.json":
        return all(
            isinstance(data.get(phase), dict) and data[phase].get("result") == "pass"
            for phase in LIVE_CHECK_PHASES
        )
    return bool(data.get("result", "pass") == "pass")


def _at(data: Any, path: list[str]) -> tuple[bool, Any]:
    """The value at a key path, a digit indexing a list."""
    for key in path:
        if isinstance(data, list) and key.isdigit() and int(key) < len(data):
            data = data[int(key)]
        elif isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return False, None
    return True, data


def condition_holds(path: Path, has: list[list[str]], equals: dict[str, Any]) -> bool:
    """A later phase's evidence can be a file an earlier phase wrote too, so a line may also ask for
    what only this phase writes into it: keys that must be there (has, each a list of keys from the
    top) and values that must match (equals, a key path joined by slashes)."""
    if not has and not equals:
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not all(_at(data, list(keys))[0] for keys in has):
        return False
    return all(_at(data, key.split("/")) == (True, value) for key, value in equals.items())


def checklist_rows(root: Path, section: str = "items") -> list[list[str | int | None]]:
    spec = yaml.safe_load((root / "config" / "checklist.yaml").read_text(encoding="utf-8"))
    rows: list[list[str | int | None]] = []
    for item in spec.get(section, []):
        names: list[str] = []
        ok = True
        for entry in item["evidence"]:
            if isinstance(entry, str):
                names.append(entry)
                ok = ok and evidence_holds(root / entry)
                continue
            names.append(str(entry["file"]))
            path = root / str(entry["file"])
            ok = (
                ok
                and evidence_holds(path)
                and condition_holds(path, entry.get("has", []), entry.get("equals", {}))
            )
        rows.append([int(item["n"]), "done" if ok else "not done", str(item["text"]), ", ".join(names)])
    return rows


def build(root: Path, as_of: str) -> ManifestBuilder:
    builder = ManifestBuilder(as_of)
    parts = sorted((root / "results" / "parts").glob("*.json"))
    for part in parts:
        builder.merge(json.loads(part.read_text(encoding="utf-8")))
    rows = checklist_rows(root)
    builder.table(
        "checklist",
        ["Item", "Status", "Line", "Evidence"],
        ["int", "text", "text", "text"],
        rows,
        origin="scripts/build_manifest.py",
        population="the section 20 checklist",
        source="build",
    )
    builder.value(
        "build.checklist_done",
        sum(1 for r in rows if r[1] == "done"),
        "int",
        origin="scripts/build_manifest.py",
        population="the section 20 checklist",
        source="build",
    )
    builder.value(
        "build.checklist_total",
        len(rows),
        "int",
        origin="scripts/build_manifest.py",
        population="the section 20 checklist",
        source="build",
    )
    phase2 = checklist_rows(root, "phase2")
    if phase2:
        population = "the Phase 2 checklist, section 20 of the Phase 2 prompt"
        builder.table(
            "checklist.phase2",
            ["Item", "Status", "Line", "Evidence"],
            ["int", "text", "text", "text"],
            phase2,
            origin="scripts/build_manifest.py",
            population=population,
            source="build",
        )
        for key, value in (
            ("build.phase2.checklist_done", sum(1 for r in phase2 if r[1] == "done")),
            ("build.phase2.checklist_total", len(phase2)),
        ):
            builder.value(
                key, value, "int", origin="scripts/build_manifest.py", population=population, source="build"
            )
    return builder


def main() -> int:
    as_of = os.environ.get("UNSCHED_AS_OF") or datetime.now(UTC).date().isoformat()
    manifest = build(ROOT, as_of).build()
    write(manifest, ROOT / "results" / "manifest.json")
    print(f"manifest: {len(manifest.values)} values, {len(manifest.tables)} tables, as of {as_of}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
