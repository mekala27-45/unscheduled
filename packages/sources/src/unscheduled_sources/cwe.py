"""The MITRE CWE catalog: every weakness and grouping with its name, abstraction and parents.

The catalog is one zipped XML file. Weaknesses carry their Weakness_Abstraction. The entries that
gather weaknesses carry no abstraction attribute and are kept with their element kind instead:
Category up to CWE 4, Grouping from CWE 5.0 (October 2026), which renamed the section; CVE records
still cite them (CWE-16, CWE-310). Parents are the ChildOf targets in the Research Concepts view
(CWE-1000), the view that places every weakness in one hierarchy. Deprecated and obsolete entries
are kept for the same reason. The table is a snapshot, rewritten whole on each fetch, with the
catalog version recorded in the ledger note.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from typing import Any, ClassVar
from xml.etree import ElementTree

from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_catalog(xml: bytes, view: str = "1000") -> tuple[list[dict[str, Any]], dict[str, str]]:
    root = ElementTree.fromstring(xml)
    info = {k: v for k, v in root.attrib.items() if k in ("Name", "Version", "Date")}
    rows: list[dict[str, Any]] = []
    for element in root.iter():
        kind = _local(element.tag)
        if kind not in ("Weakness", "Category", "Grouping"):
            continue
        parents: list[str] = []
        for rel in element.iter():
            if _local(rel.tag) != "Related_Weakness":
                continue
            if rel.attrib.get("Nature") == "ChildOf" and rel.attrib.get("View_ID") == view:
                target = f"CWE-{rel.attrib['CWE_ID']}"
                if target not in parents:
                    parents.append(target)
        rows.append(
            {
                "cwe_id": f"CWE-{element.attrib['ID']}",
                "name": element.attrib.get("Name"),
                "abstraction": element.attrib.get("Abstraction") if kind == "Weakness" else kind,
                "parents": sorted(parents, key=lambda c: int(c.split("-")[1])),
            }
        )
    return rows, info


class Cwe(Fetcher):
    source = "cwe"
    tables: ClassVar[tuple[str, ...]] = ("cwe",)

    def units(self) -> Iterator[Unit]:
        day = self.ctx.today.isoformat()
        yield Unit(f"catalog-{day}", f"catalog {day}", {})

    def fetch(self, unit: Unit) -> list[RawFile]:
        url = self.cfg["url"]
        name = url.rsplit("/", 1)[-1]
        with self.ctx.http_factory(attempts=5) as http:
            got = http.download(url, self.raw_root / unit.name / name)
        return [RawFile(unit.name, name, url, got.path, got.sha256, got.size, got.fetched_at)]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            with zipfile.ZipFile(raw.path) as archive:
                member = next(i for i in archive.infolist() if i.filename.endswith(".xml"))
                xml = archive.read(member)
            rows, info = parse_catalog(xml, str(self.cfg.get("parent_view", "1000")))
            raw.rows = len(rows)
            raw.meta["note"] = (
                f"{info.get('Name', 'CWE')} version {info.get('Version')} dated {info.get('Date')}"
            )
            yield "cwe", frame("cwe", rows), "cwe"

    def finish(self) -> None:
        return None
