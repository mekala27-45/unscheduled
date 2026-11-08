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

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import yaml
from unscheduled_core.manifest import ManifestBuilder, write


def checklist_rows(root: Path) -> list[list[str | int | None]]:
    spec = yaml.safe_load((root / "config" / "checklist.yaml").read_text(encoding="utf-8"))
    rows: list[list[str | int | None]] = []
    for item in spec["items"]:
        evidence = [str(e) for e in item["evidence"]]
        ok = all((root / e).exists() and (root / e).stat().st_size > 0 for e in evidence)
        rows.append([int(item["n"]), "done" if ok else "not done", str(item["text"]), ", ".join(evidence)])
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
    return builder


def main() -> int:
    as_of = os.environ.get("UNSCHED_AS_OF") or datetime.now(UTC).date().isoformat()
    manifest = build(ROOT, as_of).build()
    write(manifest, ROOT / "results" / "manifest.json")
    print(f"manifest: {len(manifest.values)} values, {len(manifest.tables)} tables, as of {as_of}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
