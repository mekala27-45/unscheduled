"""CISA KEV: the kev-data JSON and CSV at the head commit, the git log for when each entry first
appeared, and a cross check against the catalog cisa.gov serves.

kev-data is pinned by its head commit and its files are read at that commit from
raw.githubusercontent.com, so a rerun reads the same bytes. One log pass with -U0 keeps only the
lines that add a cveID, which is all the first appearance needs. The cisa.gov feed is fetched and
compared (catalog version, CVE set); a difference is recorded in the ledger note, and the bronze
table comes from the repository file.

The text of each entry (Phase 3) changes after it is listed: CISA rewrites a description or adds a
link to the notes. A one time unit reads the catalog file at every commit of its history, oldest
first, and keeps each distinct text of each entry with the time of the first commit that held it;
after that each new head adds the texts it is the first to hold. The history starts on 27 January
2025, so the text of an entry listed before then is known from that day on.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from unscheduled_core.hashing import canonical_json

from unscheduled_sources import gitrepo
from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.locks import content_digest
from unscheduled_sources.timeutil import parse_day, parse_ts, utcnow

ADDED = re.compile(r'^\+\s*"cveID":\s*"(CVE-\d{4}-\d+)"')
HISTORY_UNIT = "text-history"
HISTORY_FILE = "text_history.jsonl.gz"


def write_text(path: Path, text: str) -> tuple[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(path, "wb", mtime=0) as handle:
        handle.write(text.encode("utf-8"))
    return content_digest(path)


def read_text(path: Path) -> str:
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rb") as handle:
        data: bytes = handle.read()
    return data.decode("utf-8")


def first_seen_from_log(text: str) -> dict[str, datetime]:
    """CVE to the time of the oldest commit that added its cveID line (the log runs oldest first)."""
    first: dict[str, datetime] = {}
    when: datetime | None = None
    for line in text.splitlines():
        if line.startswith("commit "):
            when = parse_ts(line.split(" ", 2)[2])
        elif when is not None and (m := ADDED.match(line)):
            first.setdefault(m.group(1), when)
    return first


def kev_rows(catalog: dict[str, Any], first_seen: dict[str, datetime]) -> list[dict[str, Any]]:
    version = str(catalog.get("catalogVersion") or "")
    rows: list[dict[str, Any]] = []
    for v in catalog.get("vulnerabilities") or []:
        cve = str(v["cveID"]).strip()
        rows.append(
            {
                "cve_id": cve,
                "vendor_project": v.get("vendorProject"),
                "product": v.get("product"),
                "vulnerability_name": v.get("vulnerabilityName"),
                "date_added": parse_day(v.get("dateAdded")),
                "due_date": parse_day(v.get("dueDate")),
                "known_ransomware": v.get("knownRansomwareCampaignUse"),
                "cwes": [str(c) for c in v.get("cwes") or []],
                "catalog_version": version,
                "first_seen_commit": first_seen.get(cve),
            }
        )
    return rows


TEXT_FIELDS = ("vulnerabilityName", "shortDescription", "requiredAction", "notes")


def text_digest(entry: dict[str, Any]) -> str:
    """The first 16 hex characters of the SHA-256 of an entry's four text fields."""
    return hashlib.sha256(canonical_json({k: entry.get(k) for k in TEXT_FIELDS}).encode()).hexdigest()[:16]


def kev_text_rows(catalog: dict[str, Any], captured_at: datetime) -> list[dict[str, Any]]:
    """The text of every entry, for the advisory corpus, keyed by a digest of the text: an entry gets
    a new row only when CISA edits its name, description, required action or notes."""
    version = str(catalog.get("catalogVersion") or "")
    rows: list[dict[str, Any]] = []
    for v in catalog.get("vulnerabilities") or []:
        rows.append(
            {
                "cve_id": str(v["cveID"]).strip(),
                "text_digest": text_digest(v),
                "catalog_version": version,
                "date_added": parse_day(v.get("dateAdded")),
                "vulnerability_name": v.get("vulnerabilityName"),
                "short_description": v.get("shortDescription"),
                "required_action": v.get("requiredAction"),
                "notes": v.get("notes"),
                "captured_at": captured_at,
            }
        )
    return rows


def text_history(repo: Path, head: str, json_file: str) -> str:
    """Every distinct text of every entry in the history of the catalog file, as JSON lines: the
    entry as the first commit that held its text gave it, with that commit and its time. A commit
    whose file does not parse is a line of its own and is left out."""
    log = gitrepo.git(repo, "log", "--reverse", "--no-renames", "--format=%H %cI", head, "--", json_file)
    seen: set[tuple[str, str]] = set()
    lines: list[str] = []
    for line in log.splitlines():
        sha, _, when = line.strip().partition(" ")
        if not sha:
            continue
        try:
            catalog = json.loads(gitrepo.git(repo, "show", f"{sha}:{json_file}"))
        except ValueError:
            lines.append(canonical_json({"commit": sha, "time": when, "unreadable": True}))
            continue
        version = catalog.get("catalogVersion")
        for entry in catalog.get("vulnerabilities") or []:
            key = (str(entry["cveID"]).strip(), text_digest(entry))
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                canonical_json({"commit": sha, "time": when, "catalogVersion": version, "entry": entry})
            )
    return "\n".join(lines) + "\n"


def history_rows(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """The kev_text rows of a text history, and the commits whose catalog did not parse."""
    rows: list[dict[str, Any]] = []
    unreadable: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("unreadable"):
            unreadable.append(f"{item['commit'][:12]} ({item['time']})")
            continue
        captured = parse_ts(item["time"])
        assert captured is not None
        catalog = {"catalogVersion": item.get("catalogVersion"), "vulnerabilities": [item["entry"]]}
        rows.extend(kev_text_rows(catalog, captured))
    return rows, unreadable


def cross_check(repo: dict[str, Any], feed: dict[str, Any], csv_text: str | None) -> str:
    ours = {v["cveID"] for v in repo.get("vulnerabilities") or []}
    theirs = {v["cveID"] for v in feed.get("vulnerabilities") or []}
    parts = [
        f"repo catalog {repo.get('catalogVersion')} with {len(ours)}",
        f"cisa.gov catalog {feed.get('catalogVersion')} with {len(theirs)}",
        f"only in repo {len(ours - theirs)}",
        f"only on cisa.gov {len(theirs - ours)}",
    ]
    if csv_text is not None:
        csv_ids = {r["cveID"] for r in csv.DictReader(io.StringIO(csv_text))}
        parts.append(f"csv rows {len(csv_ids)}, csv and json differ by {len(csv_ids ^ ours)}")
    return "; ".join(parts)


class Kev(Fetcher):
    source = "kev"
    tables: ClassVar[tuple[str, ...]] = ("kev", "kev_text")

    def units(self) -> Iterator[Unit]:
        head = gitrepo.remote_head(self.cfg["git"])
        # Once, and before any head, so each text keeps the time of the first commit that held it.
        yield Unit(HISTORY_UNIT, "text history", {"commit": head})
        yield Unit(f"head-{head[:12]}", f"head {head[:12]}", {"commit": head})

    def fetch(self, unit: Unit) -> list[RawFile]:
        commit = unit.meta["commit"]
        folder = self.raw_root / unit.name
        if unit.name == HISTORY_UNIT:
            repo = gitrepo.ensure_clone(
                self.cfg["git"], self.ctx.cache_dir / "kev-data", commit, blobless=False
            )
            path = folder / HISTORY_FILE
            sha, size = write_text(path, text_history(repo, commit, self.cfg["json_file"]))
            url = f"{self.cfg['git']}/commits/{commit}/{self.cfg['json_file']}"
            return [RawFile(unit.name, HISTORY_FILE, url, path, sha, size, utcnow(), pinned=True)]
        raws: list[RawFile] = []
        with self.ctx.http_factory(attempts=5) as http:
            for key in ("json_file", "csv_file"):
                name = self.cfg[key]
                url = f"{self.cfg['raw']}/{commit}/{name}"
                got = http.download(url, folder / name)
                raws.append(
                    RawFile(unit.name, name, url, got.path, got.sha256, got.size, got.fetched_at, pinned=True)
                )
            feed = http.download(self.cfg["cisa_feed"], folder / "cisa_feed.json")
            raws.append(
                RawFile(
                    unit.name, "cisa_feed.json", feed.url, feed.path, feed.sha256, feed.size, feed.fetched_at
                )
            )
        repo = gitrepo.ensure_clone(self.cfg["git"], self.ctx.cache_dir / "kev-data", commit, blobless=False)
        log = gitrepo.git(
            repo,
            "log",
            "--reverse",
            "--no-renames",
            "--no-color",
            "-U0",
            "--format=commit %H %cI",
            "-p",
            commit,
            "--",
            self.cfg["json_file"],
        )
        reduced = "\n".join(
            line for line in log.splitlines() if line.startswith("commit ") or ADDED.match(line)
        )
        path = folder / "gitlog.txt.gz"
        sha, size = write_text(path, reduced + "\n")
        url = f"{self.cfg['git']}/commits/{commit}/{self.cfg['json_file']}"
        raws.append(RawFile(unit.name, "gitlog.txt.gz", url, path, sha, size, utcnow(), pinned=True))
        return raws

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        by_file = {r.file: r for r in raws}
        if HISTORY_FILE in by_file:
            history = by_file[HISTORY_FILE]
            texts, unreadable = history_rows(read_text(history.path))
            history.rows = len(texts)
            entries = len({r["cve_id"] for r in texts})
            history.meta["note"] = f"{len(texts)} texts of {entries} entries" + (
                f"; catalog unreadable at {', '.join(unreadable)}" if unreadable else ""
            )
            yield "kev_text", frame("kev_text", texts)
            return
        log = by_file["gitlog.txt.gz"]
        first_seen = first_seen_from_log(read_text(log.path))
        log.rows = len(first_seen)
        main = by_file[self.cfg["json_file"]]
        catalog = json.loads(main.path.read_bytes())
        rows = kev_rows(catalog, first_seen)
        main.rows = len(rows)
        csv_raw = by_file.get(self.cfg["csv_file"])
        csv_text = csv_raw.path.read_text(encoding="utf-8-sig") if csv_raw else None
        if csv_raw is not None and csv_text is not None:
            csv_raw.rows = sum(1 for _ in csv.DictReader(io.StringIO(csv_text)))
        feed_raw = by_file.get("cisa_feed.json")
        if feed_raw is not None:
            feed = json.loads(feed_raw.path.read_bytes())
            feed_raw.rows = len(feed.get("vulnerabilities") or [])
            note = cross_check(catalog, feed, csv_text)
            main.meta["note"] = note
            self.ctx.log(f"kev cross check: {note}")
        yield "kev", frame("kev", rows)
        yield "kev_text", frame("kev_text", kev_text_rows(catalog, main.fetched_at))
