"""Git for the sources that publish as repositories: a pinned head, a clone, one log pass.

A repository source is pinned by the commit its head pointed to when the run started; every file
read and every log line comes from that commit, so a run is reproducible from its lock. Large
repositories are cloned without blobs (only commits and trees), which is all a log of added paths
needs, and only the paths a parser reads are checked out. Rename detection is off: it would ask for
blob contents, and a moved file is dated at the path it has now.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from unscheduled_sources.timeutil import parse_ts

GIT_TIMEOUT_S = 3600.0
CLOCK_FLOOR = datetime(2000, 1, 1, tzinfo=UTC)


class GitError(RuntimeError):
    pass


class CloneTooLarge(GitError):
    """A clone grew past the size its caller allowed, and was stopped and removed."""


def _size_mb(path: Path) -> float:
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total / 1e6


def guarded_clone(args: Sequence[str], dest: Path, max_mb: float, poll_s: float = 3.0) -> None:
    """git clone that is stopped, and its directory removed, once it passes max_mb on disk."""
    import shutil
    import time

    proc = subprocess.Popen(
        ["git", *QUIET, *args, str(dest)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    while proc.poll() is None:
        if dest.exists() and _size_mb(dest) > max_mb:
            proc.kill()
            proc.wait()
            shutil.rmtree(dest, ignore_errors=True)
            raise CloneTooLarge(f"the clone passed {max_mb:.0f} MB and was stopped")
        time.sleep(poll_s)
    if proc.returncode != 0:
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        raise GitError(f"git clone failed: {err.strip()[:400]}")


# No automatic housekeeping: a partial clone repacks after lazy fetches, which costs disk and time.
QUIET = ("-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "advice.detachedHead=false")


def git(repo: Path | None, *args: str, timeout_s: float = GIT_TIMEOUT_S) -> str:
    cmd = ["git", *QUIET, *(["-C", str(repo)] if repo is not None else []), *args]
    try:
        done = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.CalledProcessError as err:
        raise GitError(f"git {' '.join(args[:3])} failed: {err.stderr.strip()[:400]}") from err
    except subprocess.TimeoutExpired as err:
        raise GitError(f"git {' '.join(args[:3])} timed out after {timeout_s:.0f}s") from err
    return done.stdout


def remote_head(url: str, ref: str = "HEAD") -> str:
    out = git(None, "ls-remote", url, ref, timeout_s=120.0)
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if name == ref or (ref == "HEAD" and name == "HEAD"):
            return sha.strip()
    raise GitError(f"{url} has no {ref}")


def has_commit(repo: Path, commit: str) -> bool:
    probe = subprocess.run(
        ["git", *QUIET, "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True
    )
    return probe.returncode == 0


def ensure_clone(
    url: str,
    dest: Path,
    commit: str,
    *,
    blobless: bool,
    shallow: bool = False,
    sparse: Sequence[str] = (),
    max_mb: float | None = None,
) -> Path:
    """A clone at dest that holds commit; created once, fetched forward after that.

    blobless clones carry commits and trees only; shallow clones carry the one commit. A sparse
    pattern list checks out only those paths, and git fetches their blobs in one batch to do it.
    """
    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        args = ["clone", "--quiet", "--no-checkout"]
        if blobless:
            args.append("--filter=blob:none")
        if shallow:
            args += ["--depth", "1"]
        if max_mb is not None:
            guarded_clone([*args, url], dest, max_mb)
        else:
            git(None, *args, url, str(dest))
    if not has_commit(dest, commit):
        if shallow:
            git(dest, "fetch", "--quiet", "--depth", "1", "origin", commit)
        else:
            git(dest, "fetch", "--quiet", "origin")
    if sparse:
        checkout(dest, commit, sparse)
    return dest


def checkout(repo: Path, commit: str, patterns: Sequence[str]) -> None:
    """Check out only the paths matching patterns (gitignore style) at commit."""
    git(repo, "sparse-checkout", "set", "--no-cone", *patterns)
    git(repo, "checkout", "--quiet", "--force", commit)


def first_added(
    repo: Path, commit: str, pathspecs: Sequence[str]
) -> tuple[str, dict[str, tuple[str, datetime]]]:
    """The raw log text and, for every path added up to commit, its first adding commit and time.

    One pass of git log over the history: --diff-filter=A lists added paths, --no-renames keeps the
    pass free of blob reads, and the oldest addition of a path wins.
    """
    text = git(
        repo,
        "log",
        "--no-renames",
        "--diff-filter=A",
        "--name-only",
        "--format=commit %H %cI",
        commit,
        "--",
        *pathspecs,
    )
    return text, parse_first_added(text)


def parse_first_added(text: str) -> dict[str, tuple[str, datetime]]:
    """Read a first_added log: git lists newest first, so a later line for a path is an older add.

    A commit dated before CLOCK_FLOOR was made on a machine whose clock was unset (git records
    1970-01-01 for it); its time says nothing about when the file appeared, so its additions are
    skipped and the next oldest addition dates the path.
    """
    first: dict[str, tuple[str, datetime]] = {}
    current: tuple[str, datetime] | None = None
    for line in text.splitlines():
        if line.startswith("commit "):
            _, sha, stamp = line.split(" ", 2)
            when = parse_ts(stamp)
            assert when is not None
            current = (sha, when) if when >= CLOCK_FLOOR else None
        elif line and current is not None:
            first[line] = current
    return first


def ls_tree(repo: Path, commit: str, pathspecs: Sequence[str] = ()) -> str:
    return git(repo, "ls-tree", "-r", "--full-tree", commit, "--", *pathspecs)
