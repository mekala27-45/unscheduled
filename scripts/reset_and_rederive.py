"""Reset and rederive: rebuild every number of the lake and the backlog in a fresh worktree, from a release.

    python scripts/reset_and_rederive.py [--release lake-YYYYMMDD] [--keep]

1. The lake release the committed numbers came from, as results/lake/release.json names it (or
   --release; with neither, the newest settled release): its bronze archives, locks and config, each
   archive checked before it is opened against the release's SHA256SUMS (or, for one the sums leave
   out, the digest GitHub recorded at upload) and against the digest the record kept, so a release
   that changed since stops the run. The downloads are kept
   under data/cache; the sums are read again on each run, so an archive is fetched again only when
   the release changed it. Releases are read through the REST API (gh api), which answers wherever
   gh is signed in.
2. A git worktree of HEAD in a temporary folder, holding nothing of data/ but what the release holds.
3. In the worktree, the steps lake.yml runs: scripts/build_lake.py, scripts/run_analysis.py and
   scripts/backlog_charts.py, with this checkout's environment.
4. Every value, table and figure of results/parts/lake.json and results/parts/backlog.json compared
   with the committed parts, and the lake digest with the committed one.

The committed numbers must come from the same release for the comparison to mean anything; the
record names the release, the commit and every difference. Raw files are not parsed again here:
they are several gigabytes and this machine holds a few, so the bronze is checked by digest instead
(DECISIONS.md, 12 November 2026). Writes results/rederive.json; exits 1 on any difference.

With --models, the Phase 2 models follow in the same worktree: the sets are rebuilt from the rebuilt
lake and must match their content digests; the CPU models a laptop can fit, the survival models and
the exploitation models, are fit again (the exploitation step on the committed band floor, checked by
digest) and their parts compared with the committed ones; and once test has been scored, the
scoring is run again by scripts/score_test.py --recheck from the test prediction files the operating
points froze, copied from this checkout's data/models and checked by digest, and every number of
C1, C2 and the scoring record compared. The floors, the text model and the product models are not
fit again here: the floors take hours on a four CPU runner and the text model's embeddings longer, so
their predictions are checked through the frozen digests instead.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
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


MODEL_PARTS = ("survival.json", "rank.json")
NOT_REFIT = {
    "floors": "about two and a half hours on a four CPU runner; their test predictions are checked by digest",
    "fallback": "hours of embedding on a runner; its test predictions are checked by digest",
    "product": "reads the embeddings too; its test candidates are checked by digest",
}
R_CHECK = "models.survival.r_check."


def model_steps(jobs: int, survival_jobs: int, r_check: bool) -> tuple[list[str], ...]:
    """The CPU models a laptop can fit, after the sets are rebuilt and checked. LightGBM gets the
    threads the models workflow gives it, since its sums depend on them. The survival forest fits the
    same trees with any number of jobs, and each job holds its own copy of the data, so a machine
    with 8 GB runs it with fewer."""
    return (
        ["scripts/build_sets.py", "--check"],
        ["scripts/train_survival.py", "--jobs", str(survival_jobs), *(["--r-check"] if r_check else [])],
        ["scripts/train_rank.py", "--jobs", str(jobs)],
    )


def copy_floor(tree: Path) -> None:
    """The committed band floor the exploitation step projects with; train_rank.py checks its digest."""
    source = ROOT / "data" / "models" / "floors" / "floors.joblib"
    if not source.exists():
        raise SystemExit(
            "rederive: data/models/floors/floors.joblib is missing; restore the floors step's artifact"
        )
    target = tree / "data" / "models" / "floors"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target / "floors.joblib")


def copy_frozen(tree: Path) -> Path:
    """The test prediction files the operating points froze, apart from what the refits wrote."""
    sys.path.insert(0, str(ROOT))
    from scripts.choose_operating_points import TEST_FILES

    frozen = tree / "data" / "frozen"
    for path in TEST_FILES.values():
        source = ROOT / "data" / "models" / path
        if not source.exists():
            raise SystemExit(f"rederive: data/models/{path} is missing; restore the model step's artifact")
        (frozen / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, frozen / path)
    return frozen


def step_env(tree: Path) -> dict[str, str]:
    """The environment of a step in the worktree. The packages are imported from this checkout's
    environment, and they find the repository root from their own location unless UNSCHED_ROOT names
    it, so without it every step would read and write this checkout instead of the worktree. The
    hash seed is fixed as lake.yml fixes it."""
    return {**os.environ, "UNSCHED_ROOT": str(tree), "PYTHONHASHSEED": "0"}


def sh(args: list[str], cwd: Path = ROOT) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


WANTED = ("bronze-*.tar", "locks.tar.gz", "config.tar.gz")


def gh_json(path: str) -> Any:
    """One GitHub REST call through the gh command line, which reads its own credential. The REST
    API answers in Actions and in a coding agent's session alike, where GraphQL may be closed."""
    return json.loads(sh(["gh", "api", path]))


def lake_releases() -> list[str]:
    """Every lake release, oldest first. A tag lake-YYYYMMDD sorts by its day, which the list order
    of GitHub does not promise."""
    tags = [str(r["tag_name"]) for r in gh_json(f"repos/{REPOSITORY}/releases?per_page=100")]
    return sorted(t for t in tags if t.startswith("lake-"))


def newest_lake_release() -> str:
    lake = lake_releases()
    if not lake:
        raise SystemExit("rederive: the repository has no lake release yet")
    return lake[-1]


def settled_lake_release() -> str:
    """The newest lake release that no run changes any more. The hourly fetch refreshes the newest
    release in place until the daily fetch writes the next one, so the newest is still moving and the
    one before it is settled. Committed numbers come from a settled release, so that a rebuild next
    month reads the same bronze (DECISIONS.md, 13 November 2026)."""
    lake = lake_releases()
    if len(lake) < 2:
        raise SystemExit(
            "rederive: no lake release has settled yet; the newest is refreshed every hour until "
            "the next daily fetch"
        )
    return lake[-2]


RECORD = ROOT / "results" / "lake" / "release.json"


def recorded_release() -> dict[str, Any] | None:
    """The release the committed numbers were rebuilt from, as scripts/restore_release.py wrote it."""
    if not RECORD.exists():
        return None
    record: dict[str, Any] = json.loads(RECORD.read_text(encoding="utf-8"))
    return record


def unchanged_since_recorded(folder: Path, recorded: dict[str, Any] | None, tag: str) -> str | None:
    """Why the release cannot stand behind the committed numbers, or None when it can: restored again
    under the recorded tag, every archive must have the digest results/lake/release.json kept."""
    if not recorded or recorded.get("tag") != tag:
        return None
    now = archive_digests(folder)
    kept = dict(recorded.get("archives") or {})
    moved = sorted(n for n in set(now) | set(kept) if now.get(n) != kept.get(n))
    if moved:
        return (
            f"{tag} changed after the committed numbers were rebuilt from it: "
            f"{', '.join(moved)} differ from results/lake/release.json"
        )
    return None


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
    expected = expected_digests(assets, sums, wanted, tag)
    for name in wanted:
        target = folder / name
        if target.exists() and file_sha256(target) == expected[name]:
            continue
        fetch_asset(int(assets[name]["id"]), target)
        if file_sha256(target) != expected[name]:
            target.unlink()
            raise SystemExit(f"rederive: {name} from {tag} does not have the digest {expected[name][:12]}")
    for stale in folder.glob("bronze-*.tar"):
        if stale.name not in wanted:
            stale.unlink()
    return folder


def download_one(tag: str, name: str) -> tuple[Path, str]:
    """One asset of a release, checked against its SHA256SUMS or, when the sums leave it out, the
    digest GitHub recorded at upload; kept in the cache while it still has that digest."""
    folder = CACHE / tag
    folder.mkdir(parents=True, exist_ok=True)
    assets = {str(a["name"]): a for a in gh_json(f"repos/{REPOSITORY}/releases/tags/{tag}")["assets"]}
    if name not in assets:
        raise SystemExit(f"restore: {tag} has no {name}")
    sums: dict[str, str] = {}
    if "SHA256SUMS" in assets:
        fetch_asset(int(assets["SHA256SUMS"]["id"]), folder / "SHA256SUMS")
        sums = sums_of((folder / "SHA256SUMS").read_text(encoding="utf-8"))
    expected = expected_digests(assets, sums, [name], tag)[name]
    target = folder / name
    if not (target.exists() and file_sha256(target) == expected):
        fetch_asset(int(assets[name]["id"]), target)
        if file_sha256(target) != expected:
            target.unlink()
            raise SystemExit(f"restore: {name} from {tag} does not have the digest {expected[:12]}")
    return target, expected


def expected_digests(
    assets: dict[str, Any], sums: dict[str, str], wanted: list[str], tag: str
) -> dict[str, str]:
    """The digest each archive must have: the one the release's SHA256SUMS lists or, for an archive
    the sums leave out (an hourly run wrote sums over only what it uploaded, before 13 November), the
    SHA-256 GitHub recorded when the archive was uploaded. Where both exist they must agree."""
    out: dict[str, str] = {}
    for name in wanted:
        listed = sums.get(name)
        recorded = str(assets[name].get("digest") or "").removeprefix("sha256:") or None
        if listed and recorded and listed != recorded:
            raise SystemExit(
                f"rederive: {name} in {tag} has {listed[:12]} in SHA256SUMS and {recorded[:12]} on GitHub"
            )
        digest = listed or recorded
        if not digest:
            raise SystemExit(f"rederive: {name} in {tag} has no digest in SHA256SUMS or on GitHub")
        out[name] = digest
    return out


def archive_digests(folder: Path) -> dict[str, str]:
    """The SHA-256 of every archive a restore opens, by name."""
    return {
        p.name: file_sha256(p)
        for p in sorted(folder.iterdir())
        if any(fnmatch.fnmatch(p.name, pattern) for pattern in WANTED)
    }


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
    parser.add_argument("--models", action="store_true", help="the Phase 2 models too (see the docstring)")
    parser.add_argument(
        "--jobs", type=int, default=4, help="threads for the model fits, as the models workflow uses"
    )
    parser.add_argument(
        "--survival-jobs",
        type=int,
        default=1,
        help="the survival forest's jobs; each holds a copy of the data",
    )
    args = parser.parse_args(argv)
    if sh(["git", "status", "--porcelain", "--untracked-files=no"]).strip():
        raise SystemExit(
            "rederive: commit first, so the worktree is the code that made the committed numbers"
        )

    recorded = recorded_release()
    tag = args.release or (str(recorded["tag"]) if recorded else settled_lake_release())
    commit = sh(["git", "rev-parse", "HEAD"]).strip()
    started = time.monotonic()
    folder = download(tag)
    moved = unchanged_since_recorded(folder, recorded, tag)
    if moved:
        raise SystemExit(f"rederive: {moved}")
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
            subprocess.run([sys.executable, *step], cwd=tree, env=step_env(tree), check=True)
            timings[step[0]] = round(time.monotonic() - t0, 1)
        record["step_seconds"] = timings
        parts = {}
        for name in PARTS:
            committed = json.loads((ROOT / "results" / "parts" / name).read_text(encoding="utf-8"))
            rebuilt = json.loads((tree / "results" / "parts" / name).read_text(encoding="utf-8"))
            parts[name] = compare(committed, rebuilt)
        not_compared = dict(NOT_COMPARED)
        if args.models:
            r_check = shutil.which("Rscript") is not None
            copy_floor(tree)
            for step in model_steps(args.jobs, args.survival_jobs, r_check):
                t0 = time.monotonic()
                subprocess.run([sys.executable, *step], cwd=tree, env=step_env(tree), check=True)
                timings[step[0]] = round(time.monotonic() - t0, 1)
            for name in MODEL_PARTS:
                committed = json.loads((ROOT / "results" / "parts" / name).read_text(encoding="utf-8"))
                rebuilt = json.loads((tree / "results" / "parts" / name).read_text(encoding="utf-8"))
                if not r_check:
                    for key in [k for k in committed.get("values", {}) if k.startswith(R_CHECK)]:
                        not_compared[f"values:{key}"] = (
                            "R is not on this machine; the models workflow ran the check"
                        )
                        committed["values"].pop(key)
                parts[name] = compare(committed, rebuilt)
            record["not_refit"] = NOT_REFIT
            if (tree / "results" / "models" / "test_scoring.json").exists():
                frozen = copy_frozen(tree)
                t0 = time.monotonic()
                done = subprocess.run(
                    [sys.executable, "scripts/score_test.py", "--recheck", "--models", str(frozen)],
                    cwd=tree,
                    env=step_env(tree),
                    check=False,
                )
                timings["scripts/score_test.py --recheck"] = round(time.monotonic() - t0, 1)
                recheck = json.loads(
                    (tree / "results" / "models" / "test_recheck.json").read_text(encoding="utf-8")
                )
                record["test_recheck"] = {**recheck, "exit": done.returncode}
            record["step_seconds"] = timings
        record["parts"] = parts
        record["not_compared"] = not_compared
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
    recheck_failed = record.get("test_recheck", {}).get("result", "pass") != "pass"
    record["result"] = "pass" if gaps == 0 and compared > 0 and not recheck_failed else "fail"
    record["seconds"] = round(time.monotonic() - started, 1)
    OUT.write_text(json.dumps(record, indent=1, default=str) + "\n", encoding="utf-8")
    print(f"rederive: {equal} of {compared} entries equal from {tag}; {record['result']}")
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
