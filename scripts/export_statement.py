"""Write the statement into the web app so both read one source. The statement gate compares them."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.statements import GHSA_ATTRIBUTION, NVD_NOTICE, STATEMENT

TARGET = ROOT / "web" / "lib" / "statement.ts"


def render() -> str:
    return (
        "// Generated from packages/core/src/unscheduled_core/statements.py by scripts/export_statement.py.\n"
        "// Do not edit by hand; the statement gate compares the two.\n"
        f"export const STATEMENT = {json.dumps(STATEMENT)};\n"
        f"export const NVD_NOTICE = {json.dumps(NVD_NOTICE)};\n"
        f"export const GHSA_ATTRIBUTION = {json.dumps(GHSA_ATTRIBUTION)};\n"
    )


def main(check: bool) -> int:
    text = render()
    if check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != text:
            print("web/lib/statement.ts differs from the Python statement; run scripts/export_statement.py")
            return 1
        print("statement export: web/lib/statement.ts matches")
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print("statement export: wrote web/lib/statement.ts")
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
