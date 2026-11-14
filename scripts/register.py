"""Hash the registered plan in two stages, each before the evidence it could be bent to fit.

    python scripts/register.py plan     # the criteria, splits, budgets and Phase 1 plan
    python scripts/register.py data     # then the status vocabulary and the seeded samples
    python scripts/register.py models   # Phase 2: its plan and the pinned weights, before any model
    python scripts/register.py operating_points  # the frozen operating points, before test
    python scripts/register.py --check  # fail if any registered file changed since its hash

The plan stage is hashed before the lake exists and before any result is computed, and records
what existed at that moment and the commit that first added each plan file, so the order can be
checked against the public history. The data stage hashes the two files that
are read from the data (config/labels.yaml) or drawn from it with a fixed seed (config/samples.yaml),
before any test CVE is scored, and writes evaluation/registration.json with the hash over all six
files. A later change is a change request, recorded in DECISIONS.md with both verdicts, never a
silent edit.

config/labels.yaml is hashed by its vocabulary: every status value with its meaning and labels.
The three counters the fetcher moves forward on each run (first_seen, last_seen and
cves_at_last_fetch) are observations, not commitments, so they are left out of its hash; a new
value, a changed meaning or a changed label still fails the check.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STAGES: dict[str, tuple[str, ...]] = {
    "plan": (
        "config/criteria.yaml",
        "config/splits.yaml",
        "config/budgets.yaml",
        "evaluation/phase1_plan.yaml",
    ),
    "data": (
        "config/labels.yaml",
        "config/samples.yaml",
    ),
    # Phase 2: added after the Phase 1 registration, each as a stage of its own, without changing
    # the Phase 1 hash or files at the top of evaluation/registration.json.
    "models": (
        "evaluation/phase2_plan.yaml",
        "config/models.yaml",
    ),
    "operating_points": ("config/operating_points.yaml",),
}
LATER = ("models", "operating_points")
NOTES = {
    "plan": "hashed before the lake existed and before any result was computed",
    "data": "read from the data or drawn with a fixed seed, hashed before any test CVE was scored",
    "models": "the Phase 2 plan and the pinned weights, hashed before any model saw a test CVE",
    "operating_points": "the operating points chosen on development, hashed before test was scored",
}
PLAN_OUT = Path("evaluation/registration_plan.json")
FULL_OUT = Path("evaluation/registration.json")


COUNTERS = ("first_seen", "last_seen", "cves_at_last_fetch")


def registered_bytes(rel: str, path: Path) -> bytes:
    """What the hash covers: the file, or for the status vocabulary the file without its counters."""
    if rel != "config/labels.yaml":
        return path.read_bytes()
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for entry in (data.get("nvd_vuln_status") or {}).values():
        if isinstance(entry, dict):
            for key in COUNTERS:
                entry.pop(key, None)
    return json.dumps(data, sort_keys=True, ensure_ascii=False, default=str).encode()


def digests(root: Path, files: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in files:
        path = root / rel
        if not path.exists():
            raise FileNotFoundError(f"cannot register: {rel} does not exist yet")
        out[rel] = hashlib.sha256(registered_bytes(rel, path)).hexdigest()
    return out


def combined(files: dict[str, str]) -> str:
    joined = "\n".join(f"{k} {v}" for k, v in sorted(files.items()))
    return hashlib.sha256(joined.encode()).hexdigest()


def state(root: Path) -> dict[str, object]:
    """What existed when a stage was hashed, so the order can be checked afterwards."""
    bronze = root / "data" / "bronze"
    backlog = root / "results" / "backlog"
    return {
        "bronze_tables": sorted(p.name for p in bronze.iterdir() if p.is_dir()) if bronze.exists() else [],
        "lake_file": (root / "data" / "lake" / "unscheduled.duckdb").exists(),
        "result_files": sorted(p.name for p in backlog.glob("*.json")) if backlog.exists() else [],
    }


def first_commit(root: Path, rel: str) -> dict[str, object] | None:
    """The commit that added a file and whether it changed since; None outside a git checkout."""
    log = subprocess.run(
        ["git", "log", "--diff-filter=A", "--format=%H %cI", "--", rel],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = log.stdout.split()
    if log.returncode != 0 or len(lines) < 2:
        return None
    since = subprocess.run(
        ["git", "log", "--format=%H", f"{lines[-2]}..HEAD", "--", rel],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    dirty = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", rel], cwd=root, check=False)
    return {
        "added_in": lines[-2],
        "added_at": lines[-1],
        "changed_since": bool(since.stdout.strip()) or dirty.returncode != 0,
    }


def stage_record(root: Path, name: str, files: dict[str, str]) -> dict[str, object]:
    return {
        "stage": name,
        "registered_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "hash": combined(files),
        "files": files,
        "first_committed": {rel: first_commit(root, rel) for rel in files},
        "state_at_hash": state(root),
        "note": NOTES[name],
    }


def changed(root: Path, record: dict[str, Any]) -> list[str]:
    files: dict[str, str] = dict(record["files"])
    now = digests(root, tuple(files))
    return sorted(k for k, v in files.items() if now[k] != v)


def write(path: Path, record: dict[str, object]) -> None:
    path.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")


def model_results(root: Path) -> list[str]:
    folder = root / "results" / "models"
    return sorted(p.name for p in folder.glob("*.json")) if folder.exists() else []


def later_refusal(root: Path, name: str) -> str | None:
    """Why a later stage cannot be hashed now: what it must come before already exists."""
    found = model_results(root)
    if name == "models" and found:
        return "a model result already exists: " + ", ".join(found)
    if name == "operating_points" and "test_scoring.json" in found:
        return "test was already scored"
    return None


def register_later(root: Path, name: str) -> int:
    full_path = root / FULL_OUT
    if not full_path.exists():
        print("registration: complete the plan and data stages first")
        return 1
    full: dict[str, Any] = json.loads(full_path.read_text(encoding="utf-8"))
    if any(s.get("stage") == name for s in full["stages"]):
        print(f"registration: the {name} stage is registered; a change is a change request")
        return 1
    moved = changed(root, full) + [f for s in full["stages"] for f in changed(root, s)]
    if moved:
        print("registration: a registered file changed since its hash: " + ", ".join(sorted(set(moved))))
        return 1
    refusal = later_refusal(root, name)
    if refusal:
        print(f"registration: refused, {refusal}")
        return 1
    record = stage_record(root, name, digests(root, STAGES[name]))
    record["model_results_at_hash"] = model_results(root)
    full["stages"].append(record)
    write(full_path, full)
    print(f"registration: the {name} stage hashed as {str(record['hash'])[:12]}")
    return 0


def register(root: Path, name: str) -> int:
    if name in LATER:
        return register_later(root, name)
    plan_path, full_path = root / PLAN_OUT, root / FULL_OUT
    if name == "plan":
        if plan_path.exists():
            print("registration: the plan is already registered; a change is a change request")
            return 1
        record = stage_record(root, "plan", digests(root, STAGES["plan"]))
        at_hash = state(root)
        if at_hash["lake_file"] or at_hash["result_files"]:
            print("registration: refused, the lake or a result already exists")
            return 1
        write(plan_path, record)
        print(f"registration: plan hashed as {str(record['hash'])[:12]}")
        return 0
    if not plan_path.exists():
        print("registration: register the plan first")
        return 1
    if full_path.exists():
        print("registration: already complete; a change is a change request")
        return 1
    plan: dict[str, Any] = json.loads(plan_path.read_text(encoding="utf-8"))
    moved = changed(root, plan)
    if moved:
        print("registration: the plan changed since its hash: " + ", ".join(moved))
        return 1
    data_files = digests(root, STAGES["data"])
    data = stage_record(root, "data", data_files)
    every = {**dict(plan["files"]), **data_files}
    full: dict[str, object] = {
        "hash": combined(every),
        "files": every,
        "stages": [plan, data],
        "note": "registered before any test CVE was scored by anything",
    }
    write(full_path, full)
    print(f"registration: complete, {len(every)} files hashed as {str(full['hash'])[:12]}")
    return 0


def check(root: Path) -> int:
    found = False
    for path in (root / PLAN_OUT, root / FULL_OUT):
        if not path.exists():
            continue
        found = True
        record: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        moved = changed(root, record)
        for stage in record.get("stages") or []:
            moved += [f for f in changed(root, stage) if f not in moved]
        if moved:
            print(f"registration: changed since {path.name}: " + ", ".join(moved))
            return 1
    if not found:
        print("registration: not registered yet")
    else:
        print("registration: every registered file matches its hash")
    return 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return check(ROOT)
    if len(argv) != 1 or argv[0] not in STAGES:
        print("usage: register.py plan | data | models | operating_points | --check")
        return 2
    return register(ROOT, argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
