"""CISA Vulnrichment: the SSVC decision points CISA added to each CVE, and when the file appeared.

The repository holds one CVE record per file with the CISA ADP container. It is pinned by its head
commit and cloned without blobs; one log pass lists when each file was first added, and the files
are read one year directory at a time through a sparse checkout, so the working tree never holds
more than a year. Each row carries the three SSVC points (Exploitation, Automatable, Technical
Impact), the CVSS vector and CWEs the ADP added, the first commit time of the file and the
dateUpdated of the ADP container.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from unscheduled_sources import gitrepo
from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.cvelist import cwes
from unscheduled_sources.kev import read_text, write_text
from unscheduled_sources.timeutil import parse_ts, utcnow

PATH = re.compile(r"^(\d{4})/.*(CVE-\d{4}-\d{4,})\.json$")
SSVC_KEYS = {
    "exploitation": "ssvc_exploitation",
    "automatable": "ssvc_automatable",
    "technical impact": "ssvc_technical_impact",
}


def tree_paths(tree_text: str, pattern: re.Pattern[str]) -> list[str]:
    paths: list[str] = []
    for line in tree_text.splitlines():
        meta, _, path = line.partition("\t")
        if meta.split(" ")[1:2] == ["blob"] and pattern.search(path):
            paths.append(path)
    return paths


def ssvc_points(container: dict[str, Any]) -> dict[str, str | None]:
    points: dict[str, str | None] = dict.fromkeys(SSVC_KEYS.values())
    for m in container.get("metrics") or []:
        other = m.get("other") if isinstance(m, dict) else None
        if not isinstance(other, dict) or str(other.get("type", "")).lower() != "ssvc":
            continue
        for option in (other.get("content") or {}).get("options") or []:
            for key, value in option.items():
                column = SSVC_KEYS.get(str(key).strip().lower())
                if column:
                    points[column] = str(value)
    return points


def adp_vector(container: dict[str, Any]) -> str | None:
    for m in container.get("metrics") or []:
        for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
            data = m.get(key) if isinstance(m, dict) else None
            if isinstance(data, dict) and data.get("vectorString"):
                return str(data["vectorString"])
    return None


def vulnrichment_row(record: dict[str, Any], first_added: Any) -> dict[str, Any]:
    cve_id = str(record["cveMetadata"]["cveId"])
    adps = (record.get("containers") or {}).get("adp") or []
    cisa = next(
        (
            a
            for a in adps
            if isinstance(a, dict) and (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"
        ),
        {},
    )
    return {
        "cve_id": cve_id,
        **ssvc_points(cisa),
        "adp_cvss_vector": adp_vector(cisa),
        "adp_cwes": cwes(cisa.get("problemTypes")),
        "first_added": first_added,
        "last_modified": parse_ts((cisa.get("providerMetadata") or {}).get("dateUpdated")),
    }


class Vulnrichment(Fetcher):
    source = "vulnrichment"
    tables: ClassVar[tuple[str, ...]] = ("vulnrichment",)

    @property
    def repo(self) -> Path:
        return self.ctx.cache_dir / "vulnrichment"

    def units(self) -> Iterator[Unit]:
        head = gitrepo.remote_head(self.cfg["git"])
        yield Unit(f"head-{head[:12]}", f"head {head[:12]}", {"commit": head})

    def fetch(self, unit: Unit) -> list[RawFile]:
        commit = unit.meta["commit"]
        repo = gitrepo.ensure_clone(self.cfg["git"], self.repo, commit, blobless=True)
        folder = self.raw_root / unit.name
        tree = gitrepo.ls_tree(repo, commit)
        kept = "\n".join(line for line in tree.splitlines() if PATH.search(line.partition("\t")[2])) + "\n"
        log, _ = gitrepo.first_added(repo, commit, ["*.json"])
        raws = []
        for name, text in (("tree.txt.gz", kept), ("gitlog.txt.gz", log)):
            path = folder / name
            sha, size = write_text(path, text)
            url = f"{self.cfg['git']}/tree/{commit}"
            raws.append(
                RawFile(unit.name, name, url, path, sha, size, utcnow(), pinned=True, meta={"commit": commit})
            )
        return raws

    def raw_from_entry(self, entry: Any, path: Path) -> RawFile:
        raw = super().raw_from_entry(entry, path)
        raw.meta["commit"] = str(entry.url).rsplit("/", 1)[-1]
        return raw

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        by_file = {r.file: r for r in raws}
        commit = str(by_file["tree.txt.gz"].meta["commit"])
        paths = tree_paths(read_text(by_file["tree.txt.gz"].path), PATH)
        first = gitrepo.parse_first_added(read_text(by_file["gitlog.txt.gz"].path))
        by_file["gitlog.txt.gz"].rows = len(first)
        repo = gitrepo.ensure_clone(self.cfg["git"], self.repo, commit, blobless=True)
        years: dict[str, list[str]] = defaultdict(list)
        for path in paths:
            years[path.split("/", 1)[0]].append(path)
        total = 0
        unreadable = 0
        for year in sorted(years):
            gitrepo.checkout(repo, commit, [f"/{year}/"])
            rows: list[dict[str, Any]] = []
            for path in years[year]:
                try:
                    record = json.loads((repo / path).read_bytes())
                    added = first.get(path)
                    rows.append(vulnrichment_row(record, added[1] if added else None))
                except (ValueError, KeyError, TypeError, OSError):
                    unreadable += 1
            total += len(rows)
            self.ctx.log(f"vulnrichment {year}: {len(rows)} records")
            yield "vulnrichment", frame("vulnrichment", rows)
        gitrepo.checkout(repo, commit, ["/README.md"])
        by_file["tree.txt.gz"].rows = total
        if unreadable:
            by_file["tree.txt.gz"].meta["note"] = f"unreadable files {unreadable}"

    def finish(self) -> None:
        super().finish()
        if not self.cfg.get("keep_clone", False):
            shutil.rmtree(self.repo, ignore_errors=True)
