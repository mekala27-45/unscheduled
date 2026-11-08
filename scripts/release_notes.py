"""Print the notes for a version release, every figure read from results/manifest.json.

    python scripts/release_notes.py > notes.md

The notes say how much of the phase checklist is done, list what is not, and close with the
statement. Nothing in them is typed by hand: a number comes from the manifest or is not printed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.manifest import Manifest, load
from unscheduled_core.statements import statement_markdown


def notes(manifest: Manifest) -> str:
    rows = manifest.tables["checklist"].rows
    open_rows = [r for r in rows if r[1] != "done"]
    lines = [
        f"{manifest.text('build.checklist_done')} of {manifest.text('build.checklist_total')} lines of the "
        "phase checklist are done, each with its evidence file (RESULTS.md).",
        "",
    ]
    if open_rows:
        lines.append("Not done:")
        lines.append("")
        lines.extend(f"- {r[2]}" for r in open_rows)
        lines.append("")
    lines.append("The manifest and the registration of the plan are attached to this release.")
    lines.append("")
    lines.append(statement_markdown())
    return "\n".join(lines) + "\n"


def main() -> int:
    sys.stdout.write(notes(load(ROOT / "results" / "manifest.json")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
