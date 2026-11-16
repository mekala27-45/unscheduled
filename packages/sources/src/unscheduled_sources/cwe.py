"""The MITRE CWE catalog: every weakness and grouping with its name, abstraction and parents, and the
text of every weakness in each catalog version.

The catalog is one zipped XML file. Weaknesses carry their Weakness_Abstraction. The entries that
gather weaknesses carry no abstraction attribute and are kept with their element kind instead:
Category up to CWE 4, Grouping from CWE 5.0 (October 2026), which renamed the section; CVE records
still cite them (CWE-16, CWE-310). Parents are the ChildOf targets in the Research Concepts view
(CWE-1000), the view that places every weakness in one hierarchy. Deprecated and obsolete entries
are kept for the same reason. The cwe table is a snapshot, rewritten whole on each fetch, with the
catalog version recorded in the ledger note.

Phase 3 reads the catalog as it stood on a date. The cwe_text table keeps one row per weakness per
catalog version: the daily unit adds the text of the latest version, and one archive unit per
version listed in config/sources.yaml adds the text of a version released since the development
window opened. An archive unit is fetched once and never touches the cwe snapshot.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from typing import Any, ClassVar
from xml.etree import ElementTree

from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.timeutil import parse_day

ARCHIVE = "archive-"
# The XHTML elements that start a paragraph of their own inside a description.
BLOCKS = frozenset({"p", "div", "li", "ul", "ol", "table", "tr"})


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


def text_of(element: ElementTree.Element) -> str:
    """The words of an element joined by single spaces, with a blank line between XHTML blocks."""
    paragraphs: list[str] = []
    words: list[str] = []

    def flush() -> None:
        if words:
            paragraphs.append(" ".join(words))
            words.clear()

    def walk(node: ElementTree.Element) -> None:
        if node.text:
            words.extend(node.text.split())
        for child in node:
            block = _local(child.tag) in BLOCKS
            if block:
                flush()
            walk(child)
            if block:
                flush()
            if child.tail:
                words.extend(child.tail.split())

    walk(element)
    flush()
    return "\n\n".join(paragraphs)


def _items(container: ElementTree.Element) -> str | None:
    """One paragraph per consequence or mitigation, each field named once with its values in order
    (a consequence often has two scopes)."""
    lines: list[str] = []
    for item in container:
        fields: dict[str, list[str]] = {}
        for field in item:
            value = " ".join(text_of(field).split())
            if value:
                fields.setdefault(_local(field.tag).lower(), []).append(value)
        if fields:
            lines.append("; ".join(f"{name}: {', '.join(values)}" for name, values in fields.items()))
    return "\n\n".join(lines) or None


def text_rows(xml: bytes) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """The text of every weakness in one catalog version, in the cwe_text shape: its name, its
    description and extended description, its common consequences and its potential mitigations.
    Categories and groupings carry a summary rather than a description and stay in the cwe table."""
    root = ElementTree.fromstring(xml)
    info = {k: v for k, v in root.attrib.items() if k in ("Name", "Version", "Date")}
    version = info.get("Version", "")
    day = parse_day(info.get("Date"))
    rows: list[dict[str, Any]] = []
    for element in root.iter():
        if _local(element.tag) != "Weakness":
            continue
        row: dict[str, Any] = {
            "cwe_id": f"CWE-{element.attrib['ID']}",
            "catalog_version": version,
            "catalog_date": day,
            "name": element.attrib.get("Name"),
            "description": None,
            "extended_description": None,
            "consequences": None,
            "mitigations": None,
        }
        for child in element:
            kind = _local(child.tag)
            if kind == "Description":
                row["description"] = text_of(child) or None
            elif kind == "Extended_Description":
                row["extended_description"] = text_of(child) or None
            elif kind == "Common_Consequences":
                row["consequences"] = _items(child)
            elif kind == "Potential_Mitigations":
                row["mitigations"] = _items(child)
        rows.append(row)
    return info, rows


class Cwe(Fetcher):
    source = "cwe"
    tables: ClassVar[tuple[str, ...]] = ("cwe", "cwe_text")

    def units(self) -> Iterator[Unit]:
        day = self.ctx.today.isoformat()
        yield Unit(f"catalog-{day}", f"catalog {day}", {})
        for version in self.cfg.get("archive") or []:
            url = str(self.cfg["archive_url"]).format(version=version)
            yield Unit(f"{ARCHIVE}{version}", f"catalog {version}", {"url": url})

    def fetch(self, unit: Unit) -> list[RawFile]:
        url = str(unit.meta.get("url") or self.cfg["url"])
        name = url.rsplit("/", 1)[-1]
        with self.ctx.http_factory(attempts=5) as http:
            got = http.download(url, self.raw_root / unit.name / name)
        return [RawFile(unit.name, name, url, got.path, got.sha256, got.size, got.fetched_at)]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            with zipfile.ZipFile(raw.path) as archive:
                member = next(i for i in archive.infolist() if i.filename.endswith(".xml"))
                xml = archive.read(member)
            info, texts = text_rows(xml)
            note = f"{info.get('Name', 'CWE')} version {info.get('Version')} dated {info.get('Date')}"
            if raw.unit.startswith(ARCHIVE):
                raw.rows = len(texts)
                raw.meta["note"] = f"{note}, archived, text only"
            else:
                rows, _ = parse_catalog(xml, str(self.cfg.get("parent_view", "1000")))
                raw.rows = len(rows)
                raw.meta["note"] = note
                yield "cwe", frame("cwe", rows), "cwe"
            yield "cwe_text", frame("cwe_text", texts)

    def finish(self) -> None:
        # The snapshot is one file already; only the text table gathers parts.
        self.ctx.bronze.compact("cwe_text")
