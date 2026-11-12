"""The GitHub Advisory Database: the reviewed advisories, and when each first appeared there.

The repository is pinned by its head commit. Its reviewed advisories are read one year directory
at a time through a sparse checkout. The first appearance of an advisory under github-reviewed
needs the whole history, and a clone of that history without blobs is several gigabytes, so the
log pass runs only where the disk allows it (history: auto checks the free space against
history_min_free_gb); elsewhere the clone is shallow, first_seen_commit is left empty, and the
ledger note says why. Advisory data is CC BY 4.0, credited on every page that uses it.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from unscheduled_core.hashing import canonical_json

from unscheduled_sources import gitrepo
from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.kev import read_text, write_text
from unscheduled_sources.timeutil import parse_ts, utcnow
from unscheduled_sources.vulnrichment import tree_paths

PATH = re.compile(r"^advisories/github-reviewed/(\d{4})/\d{2}/(GHSA-[\w-]+)/\2\.json$")


def ghsa_row(record: dict[str, Any], first_seen: Any) -> dict[str, Any]:
    specific = record.get("database_specific") or {}
    affected = record.get("affected")
    return {
        "ghsa_id": str(record["id"]),
        "cve_ids": [str(a) for a in record.get("aliases") or [] if str(a).startswith("CVE-")],
        "published": parse_ts(record.get("published")),
        "modified": parse_ts(record.get("modified")),
        "withdrawn": parse_ts(record.get("withdrawn")),
        "severity": specific.get("severity"),
        "cwe_ids": [str(c) for c in specific.get("cwe_ids") or []],
        "affected_json": canonical_json(affected) if affected is not None else None,
        "first_seen_commit": first_seen,
    }


class Ghsa(Fetcher):
    source = "ghsa"
    tables: ClassVar[tuple[str, ...]] = ("ghsa",)

    @property
    def repo(self) -> Path:
        return self.ctx.cache_dir / "advisory-database"

    def history(self) -> bool:
        mode = str(self.cfg.get("history", "auto"))
        if mode in ("always", "never"):
            return mode == "always"
        free_gb = (
            shutil.disk_usage(
                self.ctx.cache_dir.parent if not self.ctx.cache_dir.exists() else self.ctx.cache_dir
            ).free
            / 1e9
        )
        return free_gb >= float(self.cfg.get("history_min_free_gb", 12))

    def units(self) -> Iterator[Unit]:
        head = gitrepo.remote_head(self.cfg["git"])
        yield Unit(f"head-{head[:12]}", f"head {head[:12]}", {"commit": head})

    def fetch(self, unit: Unit) -> list[RawFile]:
        commit = unit.meta["commit"]
        self.ctx.cache_dir.mkdir(parents=True, exist_ok=True)
        with_history = self.history()
        reason = "the history clone needs more free disk than this host had"
        repo: Path | None = None
        if with_history:
            try:
                repo = gitrepo.ensure_clone(
                    self.cfg["git"],
                    self.repo,
                    commit,
                    blobless=True,
                    max_mb=float(self.cfg.get("history_max_clone_mb", 6000)),
                )
            except gitrepo.CloneTooLarge as err:
                with_history = False
                reason = f"the history clone was stopped: {err}"
        if repo is None:
            repo = gitrepo.ensure_clone(self.cfg["git"], self.repo, commit, blobless=True, shallow=True)
        tree = gitrepo.ls_tree(repo, commit, [self.cfg["path"]])
        kept = "\n".join(line for line in tree.splitlines() if PATH.search(line.partition("\t")[2])) + "\n"
        folder = self.raw_root / unit.name
        url = f"{self.cfg['git']}/tree/{commit}"
        texts = [("tree.txt.gz", kept)]
        if with_history:
            log, _ = gitrepo.first_added(repo, commit, [self.cfg["path"]])
            texts.append(("gitlog.txt.gz", log))
        raws = []
        for name, text in texts:
            sha, size = write_text(folder / name, text)
            raws.append(
                RawFile(
                    unit.name,
                    name,
                    url,
                    folder / name,
                    sha,
                    size,
                    utcnow(),
                    pinned=True,
                    meta={"commit": commit},
                )
            )
        if not with_history:
            raws[0].meta["note"] = f"first_seen_commit not computed: {reason}"
        return raws

    def raw_from_entry(self, entry: Any, path: Path) -> RawFile:
        raw = super().raw_from_entry(entry, path)
        raw.meta["commit"] = str(entry.url).rsplit("/", 1)[-1]
        return raw

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        by_file = {r.file: r for r in raws}
        tree_raw = by_file["tree.txt.gz"]
        commit = str(tree_raw.meta["commit"])
        first: dict[str, Any] = {}
        if "gitlog.txt.gz" in by_file:
            first = gitrepo.parse_first_added(read_text(by_file["gitlog.txt.gz"].path))
            by_file["gitlog.txt.gz"].rows = len(first)
        paths = tree_paths(read_text(tree_raw.path), PATH)
        shallow = "gitlog.txt.gz" not in by_file
        repo = gitrepo.ensure_clone(self.cfg["git"], self.repo, commit, blobless=True, shallow=shallow)
        years: dict[str, list[str]] = defaultdict(list)
        for path in paths:
            years[path.split("/")[2]].append(path)
        total = 0
        unreadable = 0
        for year in sorted(years):
            gitrepo.checkout(repo, commit, [f"/{self.cfg['path']}/{year}/"])
            rows: list[dict[str, Any]] = []
            for path in years[year]:
                try:
                    record = json.loads((repo / path).read_bytes())
                except (ValueError, OSError):
                    unreadable += 1
                    continue
                added = first.get(path)
                rows.append(ghsa_row(record, added[1] if added else None))
            total += len(rows)
            self.ctx.log(f"ghsa {year}: {len(rows)} reviewed advisories")
            yield "ghsa", frame("ghsa", rows)
        gitrepo.checkout(repo, commit, ["/README.md"])
        tree_raw.rows = total
        if unreadable:
            tree_raw.meta["note"] = (
                str(tree_raw.meta.get("note", "")) + f"; unreadable files {unreadable}"
            ).strip("; ")

    def finish(self) -> None:
        super().finish()
        if not self.cfg.get("keep_clone", False):
            shutil.rmtree(self.repo, ignore_errors=True)
