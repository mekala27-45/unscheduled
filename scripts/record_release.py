"""Run the phase gate of the cut-a-release skill and write what it found to results/release.json.

    python scripts/record_release.py [--tag v0.1.0]

Runs, in order and on a clean checkout, the commands of .claude/skills/cut-a-release that need no
browser: the gates, ruff, mypy, pytest, and the manifest with the claim gate. It reads the evidence
the other steps wrote (the live API check, the load test, the live check in a browser, the reset and
rederive, the design gates) and counts the conventional commits. The file is written whatever the
outcome, so a failed gate is on the record; the exit code is 1 when any part fails.

The tag goes on the commit that adds results/release.json. Pushing it starts release.yml, which
publishes the release notes; that push is Ajay's to make (BUILD_STATE.md).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "release.json"
CONVENTIONAL = re.compile(
    r"^(feat|fix|docs|chore|test|ci|refactor|perf|build|style)(\([a-z0-9 ,_/-]+\))?!?: "
)
MINIMUM_COMMITS = 50
COMMANDS: tuple[tuple[str, list[str]], ...] = (
    ("gates", ["make", "gates"]),
    ("ruff check", ["uv", "run", "ruff", "check", "."]),
    ("ruff format", ["uv", "run", "ruff", "format", "--check", "."]),
    ("mypy", ["uv", "run", "mypy"]),
    ("pytest", ["uv", "run", "pytest", "-q", "-p", "no:warnings"]),
    ("manifest", ["uv", "run", "python", "scripts/build_manifest.py"]),
    ("claim gate", ["uv", "run", "python", "scripts/check_published_numbers.py"]),
)
EVIDENCE = {
    "api_verify": "results/live/api_verify.json",
    "load": "results/load/c8.json",
    "live_check": "results/live_check.json",
    "rederive": "results/rederive.json",
    "design_gates": "results/design/gates.json",
}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def run(name: str, argv: list[str]) -> dict[str, Any]:
    t0 = time.monotonic()
    done = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
    tail = (done.stdout + done.stderr).strip().splitlines()[-1:] or [""]
    print(f"release: {'pass' if done.returncode == 0 else 'FAIL'} {name}")
    return {
        "name": name,
        "command": " ".join(argv),
        "exit_code": done.returncode,
        "seconds": round(time.monotonic() - t0, 1),
        "last_line": tail[0][:300],
    }


def evidence_summary(path: str) -> dict[str, Any]:
    file = ROOT / path
    if not file.exists():
        return {"file": path, "present": False}
    data = json.loads(file.read_text(encoding="utf-8"))
    summary: dict[str, Any] = {"file": path, "present": True}
    if isinstance(data, dict):
        for key in ("result", "passed", "total", "checked_at", "finished_at", "release"):
            if key in data:
                summary[key] = data[key]
        for phase in ("awake", "asleep"):
            if isinstance(data.get(phase), dict):
                summary[phase] = {k: data[phase].get(k) for k in ("result", "passed", "total", "finished_at")}
        if isinstance(data.get("sloplint"), dict):
            summary["sloplint"] = data["sloplint"].get("result")
    return summary


def evidence_ok(name: str, summary: dict[str, Any]) -> bool:
    if not summary.get("present"):
        return False
    if name == "live_check":
        return all((summary.get(phase) or {}).get("result") == "pass" for phase in ("awake", "asleep"))
    if name == "design_gates":
        return summary.get("sloplint") == "pass"
    return summary.get("result") == "pass"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", default="v0.1.0")
    args = parser.parse_args(argv)
    if git("status", "--porcelain", "--untracked-files=no").strip():
        raise SystemExit("release: commit first; the gate runs on a clean checkout")
    subjects = git("log", "--format=%s").splitlines()
    conventional = sum(bool(CONVENTIONAL.match(s)) for s in subjects)
    steps = [run(name, argv_) for name, argv_ in COMMANDS]
    manifest = json.loads((ROOT / "results" / "manifest.json").read_text(encoding="utf-8"))
    rows = manifest["tables"]["checklist"]["rows"]
    open_lines = [f"{r[0]}. {r[2]}" for r in rows if r[1] != "done" and r[0] != 18]
    evidence = {name: evidence_summary(path) for name, path in EVIDENCE.items()}
    record = {
        "tag": args.tag,
        "on": "the commit that adds this file",
        "built_from": git("rev-parse", "HEAD").strip(),
        "recorded_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commits": {"total": len(subjects), "conventional": conventional, "minimum": MINIMUM_COMMITS},
        "steps": steps,
        "evidence": evidence,
        "checklist_open_before_this_line": open_lines,
        "push": "the tag push starts release.yml, which reruns the gates and publishes the notes",
    }
    failed = [s["name"] for s in steps if s["exit_code"] != 0]
    missing = [n for n, e in evidence.items() if not evidence_ok(n, e)]
    record["result"] = "pass" if not failed and not missing and conventional >= MINIMUM_COMMITS else "fail"
    record["failed"] = failed + [f"evidence {m}" for m in missing]
    OUT.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"release: {record['result']} ({conventional} conventional commits); wrote {OUT.relative_to(ROOT)}")
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
