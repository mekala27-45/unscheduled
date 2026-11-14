"""Run the phase gate of the cut-a-release skill and write what it found to results/release.json.

    python scripts/record_release.py [--tag v0.2.0]

Runs, in order and on a clean checkout, the commands of .claude/skills/cut-a-release that need no
browser: the gates, ruff, mypy, pytest, and the manifest with the claim gate. It reads the evidence
the other steps wrote (the live API check, the load test, the live check in a browser, the reset and
rederive, the design gates), counts the conventional commits since the previous tag, and reads the
checklist of the phase the tag closes (v0.N.0 closes Phase N, v1.0.0 Phase 5): every line but the
last, which this record completes, must be done. The file is written whatever the outcome, so a
failed gate is on the record; the exit code is 1 when any part fails.

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
LAST_PHASE = 5
TAG = re.compile(r"^v(?P<major>\d+)\.(?P<minor>\d+)\.0$")
UV_NOTICE = re.compile(r"^warning: The `\w+` environment variable is deprecated")
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


def last_line(stdout: str, stderr: str) -> str:
    """The command's own last line: stdout's when it wrote one, else stderr's, never uv's notice that
    an environment variable is deprecated."""
    for text in (stdout, stderr):
        lines = [line for line in text.strip().splitlines() if line.strip() and not UV_NOTICE.match(line)]
        if lines:
            return lines[-1][:300]
    return ""


def run(name: str, argv: list[str]) -> dict[str, Any]:
    t0 = time.monotonic()
    done = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
    print(f"release: {'pass' if done.returncode == 0 else 'FAIL'} {name}")
    return {
        "name": name,
        "command": " ".join(argv),
        "exit_code": done.returncode,
        "seconds": round(time.monotonic() - t0, 1),
        "last_line": last_line(done.stdout, done.stderr),
    }


def phase_of(tag: str) -> int:
    """v0.N.0 closes Phase N and v1.0.0 closes Phase 5, the last."""
    match = TAG.match(tag)
    if not match:
        raise SystemExit(f"release: {tag} is not a phase tag (v0.N.0 or v1.0.0)")
    major, minor = int(match["major"]), int(match["minor"])
    if major == 1 and minor == 0:
        return LAST_PHASE
    if major == 0 and 1 <= minor < LAST_PHASE:
        return minor
    raise SystemExit(f"release: {tag} is not a phase tag (v0.N.0 or v1.0.0)")


def checklist_key(phase: int) -> str:
    """The manifest table of a phase's checklist; Phase 1 kept the plain name."""
    return "checklist" if phase == 1 else f"checklist.phase{phase}"


def open_lines(manifest: dict[str, Any], phase: int) -> list[str]:
    """The phase's checklist lines not done, leaving out the last, which the release record and the tag
    complete."""
    rows = manifest["tables"][checklist_key(phase)]["rows"]
    last = max(int(r[0]) for r in rows)
    return [f"{r[0]}. {r[2]}" for r in rows if r[1] != "done" and int(r[0]) != last]


def previous_tag(root: Path = ROOT) -> str | None:
    """The newest phase tag HEAD descends from, so the commit count is this phase's own. The lake and
    serving releases tag the repository too, so only a version tag counts."""
    done = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.stdout.strip() or None


def verdict(
    steps: list[dict[str, Any]], evidence: dict[str, dict[str, Any]], conventional: int, still_open: list[str]
) -> tuple[str, list[str]]:
    failed = [s["name"] for s in steps if s["exit_code"] != 0]
    failed += [f"evidence {n}" for n, e in evidence.items() if not evidence_ok(n, e)]
    if conventional < MINIMUM_COMMITS:
        failed.append(f"commits: {conventional} conventional, fewer than {MINIMUM_COMMITS}")
    failed += [f"checklist line {line}" for line in still_open]
    return ("pass" if not failed else "fail"), failed


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
    parser.add_argument("--tag", default="v0.2.0")
    args = parser.parse_args(argv)
    phase = phase_of(args.tag)
    if git("status", "--porcelain", "--untracked-files=no").strip():
        raise SystemExit("release: commit first; the gate runs on a clean checkout")
    since = previous_tag()
    subjects = git("log", "--format=%s", *([f"{since}..HEAD"] if since else [])).splitlines()
    conventional = sum(bool(CONVENTIONAL.match(s)) for s in subjects)
    steps = [run(name, argv_) for name, argv_ in COMMANDS]
    manifest = json.loads((ROOT / "results" / "manifest.json").read_text(encoding="utf-8"))
    still_open = open_lines(manifest, phase)
    evidence = {name: evidence_summary(path) for name, path in EVIDENCE.items()}
    record = {
        "tag": args.tag,
        "phase": phase,
        "on": "the commit that adds this file",
        "built_from": git("rev-parse", "HEAD").strip(),
        "recorded_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commits": {
            "since": since,
            "total": len(subjects),
            "conventional": conventional,
            "minimum": MINIMUM_COMMITS,
        },
        "steps": steps,
        "evidence": evidence,
        "checklist": checklist_key(phase),
        "checklist_open_before_this_line": still_open,
        "push": "the tag push starts release.yml, which reruns the gates and publishes the notes",
    }
    record["result"], record["failed"] = verdict(steps, evidence, conventional, still_open)
    OUT.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"release: {record['result']} ({conventional} conventional commits); wrote {OUT.relative_to(ROOT)}")
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
