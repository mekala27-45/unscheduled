"""Reset and rederive: rebuild every number of the lake and the backlog in a fresh worktree, from a release.

    python scripts/reset_and_rederive.py [--release lake-YYYYMMDD] [--keep]

1. The newest lake release (or --release): its bronze archives, locks and config, each archive checked
   against the release's SHA256SUMS before it is opened. The downloads are kept under data/cache; the
   sums are read again on each run, so an archive is fetched again only when the release changed it.
   Releases are read through the REST API (gh api), which answers wherever gh is signed in.
2. A git worktree of HEAD in a temporary folder, holding nothing of data/ but what the release holds.
3. In the worktree, the steps lake.yml runs: scripts/build_lake.py, scripts/run_analysis.py and
   scripts/backlog_charts.py, with this checkout's environment.
4. Every value, table and figure of results/parts/lake.json and results/parts/backlog.json compared
   with the committed parts, and the lake digest with the committed one.

The committed numbers must come from the same release for the comparison to mean anything; the
record names the release, the commit and every difference. Raw files are not parsed again here:
they are several gigabytes and this machine holds a few, so the bronze is checked by digest instead
(DECISIONS.md, 12 November 2026). Writes results/rederive.json; exits 1 on any difference.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mekala27-45/unscheduled"
CACHE = ROOT / "data" / "cache" / "release"
OUT = ROOT / "results" / "rederive.json"
PARTS = ("lake.json", "backlog.json")
# The DuckDB file itself is not byte for byte reproducible (its block layout depends on the run); the
# content digest over every table's rows is, and that is the digest compared.
NOT_COMPARED = {"values:lake.sha256": "the file digest; lake.content_digest is compared instead"}


def steps(memory: str, threads: int) -> tuple[list[str], ...]:
    """The steps lake.yml runs. The DuckDB memory limit and threads are the machine's to set: lake.yml
    gives 10GB and 4 on a 16 GB runner, and a build machine with 8 GB needs about half of that."""
    return (
        ["scripts/build_lake.py", "--memory", memory, "--threads", str(threads)],
        ["scripts/run_analysis.py"],
        ["scripts/backlog_charts.py"],
    )


def sh(args: list[str], cwd: Path = ROOT) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


WANTED = ("bronze-*.tar", "locks.tar.gz", "config.tar.gz")


def gh_json(path: str) -> Any:
    """One GitHub REST call through the gh command line, which reads its own credential. The REST
    API answers in Actions and in a coding agent's session alike, where GraphQL may be closed."""
    return json.loads(sh(["gh", "api", path]))


def newest_lake_release() -> str:
    tags = [str(r["tag_name"]) for r in gh_json(f"repos/{REPOSITORY}/releases?per_page=50")]
    lake = sorted((t for t in tags if t.startswith("lake-")), reverse=True)
    if not lake:
        raise SystemExit("rederive: the repository has no lake release yet")
    return lake[0]


def sums_of(text: str) -> dict[str, str]:
    """SHA256SUMS as written by sha256sum: digest, two spaces, the name (with ./ or * before it)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2:
            out[fields[1].lstrip("*").removeprefix("./")] = fields[0]
    return out


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch_asset(asset_id: int, target: Path) -> None:
    partial = target.with_name(target.name + ".part")
    with partial.open("wb") as out:
        subprocess.run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/octet-stream",
                f"repos/{REPOSITORY}/releases/assets/{asset_id}",
            ],
            cwd=ROOT,
            stdout=out,
            check=True,
        )
    partial.replace(target)


def download(tag: str) -> Path:
    """The release's bronze, locks and config, each checked against its SHA256SUMS. The sums are read
    again on every call, so a release republished under the same tag the same day is fetched again,
    while an archive already here with the digest the sums give is kept."""
    folder = CACHE / tag
    folder.mkdir(parents=True, exist_ok=True)
    assets = {str(a["name"]): a for a in gh_json(f"repos/{REPOSITORY}/releases/tags/{tag}")["assets"]}
    if "SHA256SUMS" not in assets:
        raise SystemExit(f"rederive: {tag} has no SHA256SUMS")
    fetch_asset(int(assets["SHA256SUMS"]["id"]), folder / "SHA256SUMS")
    sums = sums_of((folder / "SHA256SUMS").read_text(encoding="utf-8"))
    wanted = sorted(n for n in assets if any(fnmatch.fnmatch(n, p) for p in WANTED))
    for name in wanted:
        if name not in sums:
            raise SystemExit(f"rederive: {name} in {tag} is not listed in its SHA256SUMS")
        target = folder / name
        if target.exists() and file_sha256(target) == sums[name]:
            continue
        fetch_asset(int(assets[name]["id"]), target)
    for stale in folder.glob("bronze-*.tar"):
        if stale.name not in wanted:
            stale.unlink()
    sh(["sha256sum", "--check", "--ignore-missing", "--quiet", "SHA256SUMS"], cwd=folder)
    return folder


def extract(folder: Path, work: Path) -> dict[str, int]:
    counts = {"bronze_archives": 0}
    (work / "data" / "bronze").mkdir(parents=True, exist_ok=True)
    for archive in sorted(folder.glob("bronze-*.tar")):
        with tarfile.open(archive) as tar:
            tar.extractall(work / "data" / "bronze", filter="data")
        counts["bronze_archives"] += 1
    with tarfile.open(folder / "locks.tar.gz") as tar:
        tar.extractall(work / "data", filter="data")
    with tarfile.open(folder / "config.tar.gz") as tar:
        tar.extractall(work / "config", filter="data")
    return counts


def same(a: Any, b: Any) -> bool:
    if isinstance(a, float) and isinstance(b, float):
        return a == b or (math.isnan(a) and math.isnan(b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b, strict=True))
    return bool(a == b)


def compare(committed: dict[str, Any], rebuilt: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"compared": 0, "equal": 0, "differ": [], "missing": [], "extra": []}
    for kind in ("values", "tables", "figures"):
        mine, theirs = committed.get(kind, {}), rebuilt.get(kind, {})
        for key in sorted(mine):
            if f"{kind}:{key}" in NOT_COMPARED:
                continue
            if key not in theirs:
                out["missing"].append(f"{kind}:{key}")
                continue
            out["compared"] += 1
            a, b = mine[key], theirs[key]
            if kind == "values":
                a, b = a.get("value"), b.get("value")
            elif kind == "tables":
                a, b = a.get("rows"), b.get("rows")
            if same(a, b):
                out["equal"] += 1
            else:
                out["differ"].append({"key": f"{kind}:{key}", "committed": a, "rebuilt": b})
        out["extra"] += [f"{kind}:{k}" for k in sorted(set(theirs) - set(mine))]
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", default=None)
    parser.add_argument("--keep", action="store_true", help="keep the worktree for inspection")
    parser.add_argument("--memory", default="3GB", help="the DuckDB memory limit of the lake build")
    parser.add_argument("--threads", type=int, default=2, help="DuckDB and dbt threads")
    args = parser.parse_args(argv)
    if sh(["git", "status", "--porcelain", "--untracked-files=no"]).strip():
        raise SystemExit(
            "rederive: commit first, so the worktree is the code that made the committed numbers"
        )

    tag = args.release or newest_lake_release()
    commit = sh(["git", "rev-parse", "HEAD"]).strip()
    started = time.monotonic()
    folder = download(tag)
    work = Path(tempfile.mkdtemp(prefix="unscheduled-rederive-"))
    tree = work / "tree"
    sh(["git", "worktree", "add", "--detach", str(tree), commit])
    record: dict[str, Any] = {
        "release": tag,
        "commit": commit,
        "started_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "inputs": "the release's bronze, locks and config, each archive checked against its SHA256SUMS",
    }
    try:
        record["restored"] = extract(folder, tree)
        timings = {}
        record["build_settings"] = {"memory": args.memory, "threads": args.threads}
        for step in steps(args.memory, args.threads):
            t0 = time.monotonic()
            subprocess.run([sys.executable, *step], cwd=tree, check=True)
            timings[step[0]] = round(time.monotonic() - t0, 1)
        record["step_seconds"] = timings
        parts = {}
        for name in PARTS:
            committed = json.loads((ROOT / "results" / "parts" / name).read_text(encoding="utf-8"))
            rebuilt = json.loads((tree / "results" / "parts" / name).read_text(encoding="utf-8"))
            parts[name] = compare(committed, rebuilt)
        record["parts"] = parts
        record["not_compared"] = NOT_COMPARED
    finally:
        if not args.keep:
            subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=ROOT, check=False)
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"rederive: the worktree stays at {tree}")
    compared = sum(p["compared"] for p in record["parts"].values())
    equal = sum(p["equal"] for p in record["parts"].values())
    gaps = sum(len(p["missing"]) + len(p["differ"]) for p in record["parts"].values())
    record["compared"] = compared
    record["equal"] = equal
    record["result"] = "pass" if gaps == 0 and compared > 0 else "fail"
    record["seconds"] = round(time.monotonic() - started, 1)
    OUT.write_text(json.dumps(record, indent=1, default=str) + "\n", encoding="utf-8")
    print(f"rederive: {equal} of {compared} entries equal from {tag}; {record['result']}")
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
