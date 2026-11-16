"""The records of steps 6, 7 and 8 (results/agent/router.json, prompts.json and graph.json).

Each is written by the last test of the module that proves its part, and only when every other test
of that module passed in the same session: a record says which tests stand behind it, by name, and a
skipped or failed test leaves the record as it was. Like results/agent/c7.json, a record holds no
time and no machine, so a run on any machine writes the same bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any

from unscheduled_core import paths

ROOT = Path(__file__).resolve().parents[2]
_WORDS = {"cve": "CVE", "kev": "KEV", "postgres": "Postgres", "mcp": "MCP", "api": "API", "ci": "CI"}
_PASSED: dict[str, set[str]] = {}
_FAILED: dict[str, set[str]] = {}


def note(nodeid: str, *, passed: bool) -> None:
    """One test's outcome; a parametrized test counts as passed only if every case passed."""
    module, _, name = nodeid.partition("::")
    name = name.split("[", 1)[0]
    (_PASSED if passed else _FAILED).setdefault(module, set()).add(name)


def proven(module: ModuleType, record_test: str) -> list[str] | None:
    """The module's tests as sentences, in their order, if each passed in this session; else None."""
    key = Path(str(module.__file__)).resolve().relative_to(ROOT).as_posix()
    names = [n for n, f in vars(module).items() if n.startswith("test_") and callable(f) and n != record_test]
    passed = _PASSED.get(key, set()) - _FAILED.get(key, set())
    if not names or any(n not in passed for n in names):
        return None
    return [" ".join(_WORDS.get(w, w) for w in n.removeprefix("test_").split("_")) for n in names]


def write(part: str, record: dict[str, Any]) -> Path:
    out = paths.results_dir() / "agent" / f"{part}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return out
