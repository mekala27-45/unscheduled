"""Write the API's OpenAPI schema to openapi.json, or check that the committed file still matches.

    python scripts/export_openapi.py          # write openapi.json
    python scripts/export_openapi.py --check  # exit 1 when the app and the committed file differ

The schema is generated from the app with no database and no network: routes and models alone
decide it. CI runs the check, schemathesis tests the running app against the committed file, and the
web's typed client is generated from it, so a route cannot change shape without a reviewed diff.
"""

from __future__ import annotations

import difflib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_api.app import create_app
from unscheduled_api.services import Services
from unscheduled_api.settings import Settings

TARGET = ROOT / "openapi.json"


def render() -> str:
    os.environ.setdefault("UNSCHED_ROOT", str(ROOT))
    services = Services.build(Settings.from_env({}))
    schema = create_app(services).openapi()
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(check: bool) -> int:
    text = render()
    if check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != text:
            diff = difflib.unified_diff(
                current.splitlines(keepends=True),
                text.splitlines(keepends=True),
                fromfile="openapi.json (committed)",
                tofile="openapi.json (from the app)",
                n=2,
            )
            sys.stdout.writelines(list(diff)[:200])
            print("openapi: the committed schema differs from the app; run scripts/export_openapi.py")
            return 1
        print("openapi: openapi.json matches the app")
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"openapi: wrote {TARGET.name}, {len(json.loads(text)['paths'])} paths")
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
