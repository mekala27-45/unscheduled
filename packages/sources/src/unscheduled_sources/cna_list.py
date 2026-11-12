"""The CNA list as cve.org publishes it, and the filers grouped by type into config/filers.yaml.

cve.org renders its partner list from CNAsList.json in the CVEProject/cve-website repository; the
file is read at the head of its main branch, pinned by that commit. Every CNA there carries the
types it publishes for itself (Vendor, Open Source, Researcher, Bug Bounty Provider, CERT, Hosted
Service and others), and the group of a filer is the first rule its published types meet:

  MITRE                               the short name mitre
  national CERT                       CERT among the types, Vendor not among them
  research or bug bounty platform     Bug Bounty Provider among the types, or Researcher without Vendor
  open source project                 Open Source among the types
  vendor                              Vendor among the types
  other                               anything else (Hosted Service alone, Consortium, N/A)

A filer in the CVE List that the CNA list does not hold (a CNA that has left the program) is typed
by the same rule from its short name alone and marked listed: false. If the list cannot be read at
all, every filer is typed that way and the file says the list was not reachable on the day.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any, ClassVar

import polars as pl
import yaml

from unscheduled_sources import gitrepo
from unscheduled_sources.base import Context, Fetcher, Output, RawFile, Unit
from unscheduled_sources.http import FetchError

GROUPS = (
    "vendor",
    "open source project",
    "research or bug bounty platform",
    "national CERT",
    "MITRE",
    "other",
)
DASHES = {chr(0x2013): "-", chr(0x2014): "-", chr(0x2015): "-"}

HEADER = """\
# Filers grouped by type, from the CNA list as cve.org publishes it (CNAsList.json in the
# CVEProject/cve-website repository), read on the day below and pinned by its commit and digest.
# Written by packages/sources (scripts/fetch.py cna_list); edit the rule there, not this file.
# A filer's group is the first rule its published CNA types meet, in the order of the rule list.
# cves counts the records the filer assigned in the CVE List snapshot in bronze on the day read.
# Dashes inside organization names are written as plain hyphens.
"""


def group_for(short_name: str, types: list[str]) -> str:
    kinds = {t.strip() for t in types}
    if short_name.lower() == "mitre":
        return "MITRE"
    if "CERT" in kinds and "Vendor" not in kinds:
        return "national CERT"
    if "Bug Bounty Provider" in kinds or ("Researcher" in kinds and "Vendor" not in kinds):
        return "research or bug bounty platform"
    if "Open Source" in kinds:
        return "open source project"
    if "Vendor" in kinds:
        return "vendor"
    return "other"


def group_by_name(short_name: str) -> str:
    """The rule for a filer the list does not hold: only what its short name says."""
    lower = short_name.lower()
    if lower == "mitre":
        return "MITRE"
    if "cert" in lower or "csirt" in lower:
        return "national CERT"
    return "other"


def plain(text: str | None) -> str | None:
    if text is None:
        return None
    for dash, hyphen in DASHES.items():
        text = text.replace(dash, hyphen)
    return " ".join(text.split())


def assigner_counts(bronze_records: pl.DataFrame) -> dict[str, int]:
    if bronze_records.height == 0:
        return {}
    latest = bronze_records.sort("snapshot_at").unique(subset=["cve_id"], keep="last")
    counts = latest.group_by("assigner_short_name").len().drop_nulls()
    return {str(k): int(v) for k, v in counts.iter_rows()}


def build(
    cnas: list[dict[str, Any]] | None,
    counts: dict[str, int],
    *,
    read_on: date,
    source: dict[str, Any],
) -> dict[str, Any]:
    filers: dict[str, dict[str, Any]] = {}
    for cna in cnas or []:
        short = str(cna.get("shortName") or "").strip()
        if not short:
            continue
        types = [str(t) for t in (cna.get("CNA") or {}).get("type") or []]
        filers[short] = {
            "organization": plain(cna.get("organizationName")),
            "group": group_for(short, types),
            "cna_types": types,
            "country": plain(cna.get("country")),
            "listed": True,
            "cves": 0,
        }
    by_lower = {k.lower(): k for k in filers}
    for assigner, n in sorted(counts.items()):
        key = by_lower.get(assigner.lower())
        if key is not None:
            filers[key]["cves"] += n
            continue
        filers[assigner] = {
            "organization": None,
            "group": group_by_name(assigner),
            "cna_types": [],
            "country": None,
            "listed": False,
            "cves": n,
        }
    totals: Counter[str] = Counter()
    records: Counter[str] = Counter()
    for f in filers.values():
        totals[f["group"]] += 1
        records[f["group"]] += int(f["cves"])
    return {
        "read_on": read_on.isoformat(),
        "source": source,
        "rule": [
            {"MITRE": "the short name mitre"},
            {"national CERT": "CERT among the published types and Vendor not among them"},
            {
                "research or bug bounty platform": "Bug Bounty Provider among the types, or Researcher without Vendor"
            },
            {"open source project": "Open Source among the types"},
            {"vendor": "Vendor among the types"},
            {"other": "anything else; a filer the list does not hold is typed from its short name alone"},
        ],
        "groups": {g: {"filers": totals.get(g, 0), "cves": records.get(g, 0)} for g in GROUPS},
        "filers": {k: filers[k] for k in sorted(filers, key=str.lower)},
    }


def write(path: Path, data: dict[str, Any]) -> None:
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=110)
    for dash in DASHES:
        if dash in body:
            raise ValueError("a dash survived into filers.yaml")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(HEADER + body, encoding="utf-8")
    tmp.replace(path)


class CnaList(Fetcher):
    source = "cna_list"
    tables: ClassVar[tuple[str, ...]] = ()

    def __init__(self, ctx: Context) -> None:
        super().__init__(ctx)
        self.out = ctx.root / "config" / "filers.yaml"

    def units(self) -> Iterator[Unit]:
        try:
            head = gitrepo.remote_head(self.cfg["git"], f"refs/heads/{self.cfg['branch']}")
        except gitrepo.GitError as err:
            self._unreachable(str(err))
            return
        yield Unit(f"{self.cfg['branch']}-{head[:12]}", f"{self.cfg['branch']} {head[:12]}", {"commit": head})

    def fetch(self, unit: Unit) -> list[RawFile]:
        commit = unit.meta["commit"]
        url = f"{self.cfg['raw']}/{commit}/{self.cfg['file']}"
        try:
            with self.ctx.http_factory(attempts=4) as http:
                got = http.download(url, self.raw_root / unit.name / "CNAsList.json")
        except FetchError as err:
            self._unreachable(str(err))
            raise
        return [
            RawFile(
                unit.name, "CNAsList.json", url, got.path, got.sha256, got.size, got.fetched_at, pinned=True
            )
        ]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            cnas = json.loads(raw.path.read_bytes())
            raw.rows = len(cnas)
            counts = assigner_counts(
                self.ctx.bronze.read("cve_records").select("cve_id", "assigner_short_name", "snapshot_at")
            )
            data = build(
                cnas,
                counts,
                read_on=self.ctx.today,
                source={"url": raw.url, "sha256": raw.sha256, "cnas": len(cnas), "reachable": True},
            )
            write(self.out, data)
            raw.meta["note"] = ", ".join(f"{g} {v['filers']}" for g, v in data["groups"].items())
            self.ctx.log(f"cna_list: {raw.meta['note']}")
        return iter(())

    def _unreachable(self, reason: str) -> None:
        counts = assigner_counts(
            self.ctx.bronze.read("cve_records").select("cve_id", "assigner_short_name", "snapshot_at")
        )
        data = build(
            None,
            counts,
            read_on=self.ctx.today,
            source={"url": self.cfg["raw"], "reachable": False, "reason": reason[:200]},
        )
        write(self.out, data)
        self.ctx.log("cna_list: the CNA list was not reachable; filers typed by rule from their short names")

    def finish(self) -> None:
        return None
