"""Documents: one version of an advisory, a KEV entry or a CWE entry, as known from a moment on.

A document is cut into named sections before it is chunked, so a citation can name the section that
holds a fact: an advisory has its summary, its details, its affected ranges and its references; a
KEV entry its name and short description, the required action and the notes; a CWE entry its
description, its consequences and its mitigations. Text is kept as the source wrote it, with only
the whitespace normalized; nothing is translated or summarized.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

_SPACES = re.compile(r"[ \t\f\v]+")
_BLANKS = re.compile(r"\n{3,}")


@dataclass(frozen=True)
class Section:
    name: str
    text: str


@dataclass(frozen=True)
class Document:
    doc_id: str
    source: str
    version: str
    known_from: str
    cve_ids: tuple[str, ...]
    sections: tuple[Section, ...]


def clean(text: str | None) -> str:
    """The text with its line endings unified, runs of spaces collapsed and blank runs cut to one."""
    if not text:
        return ""
    lines = [_SPACES.sub(" ", line).strip() for line in str(text).replace("\r\n", "\n").split("\n")]
    return _BLANKS.sub("\n\n", "\n".join(lines)).strip()


def _sections(pairs: Iterable[tuple[str, str]]) -> tuple[Section, ...]:
    return tuple(Section(name, text) for name, text in ((n, clean(t)) for n, t in pairs) if text)


def _affected_lines(affected: Iterable[Mapping[str, Any]]) -> str:
    """One line per affected package: its ecosystem and name, then each range as introduced and fixed
    (or last affected) versions, as the advisory states them."""
    lines = []
    for item in affected:
        package = item.get("package") or {}
        name = f"{package.get('ecosystem', '')}/{package.get('name', '')}".strip("/")
        spans = []
        for rng in item.get("ranges") or []:
            opened = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    opened = str(event["introduced"])
                elif "fixed" in event:
                    spans.append(f"from {opened or '0'} fixed in {event['fixed']}")
                    opened = None
                elif "last_affected" in event:
                    spans.append(f"from {opened or '0'} through {event['last_affected']}")
                    opened = None
            if opened is not None:
                spans.append(f"from {opened} with no fix")
        versions = item.get("versions") or []
        if not spans and versions:
            spans.append("versions " + ", ".join(str(v) for v in versions[:20]))
        lines.append(f"{name}: " + "; ".join(spans) if spans else name)
    return "\n".join(line for line in lines if line)


def _reference_lines(references: Iterable[Mapping[str, Any]]) -> str:
    return "\n".join(f"{r.get('type', 'WEB')}: {r['url']}" for r in references if r.get("url"))


def from_osv(record: Mapping[str, Any], *, source: str, known_from: str) -> Document:
    """An OSV format record (the GitHub Advisory Database writes the same format) as one document."""
    advisory_id = str(record["id"])
    cves = sorted(
        {str(a) for a in record.get("aliases") or [] if str(a).startswith("CVE-")}
        | ({advisory_id} if advisory_id.startswith("CVE-") else set())
    )
    return Document(
        doc_id=f"{source}:{advisory_id}",
        source=source,
        version=str(record.get("modified") or record.get("published") or ""),
        known_from=known_from,
        cve_ids=tuple(cves),
        sections=_sections(
            (
                ("summary", record.get("summary") or ""),
                ("details", record.get("details") or ""),
                ("affected", _affected_lines(record.get("affected") or [])),
                ("references", _reference_lines(record.get("references") or [])),
            )
        ),
    )


def from_kev(entry: Mapping[str, Any], *, catalog_version: str, known_from: str) -> Document:
    """A KEV entry of one catalog version as one document."""
    cve = str(entry["cveID"])
    name = clean(entry.get("vulnerabilityName"))
    product = clean(f"{entry.get('vendorProject', '')} {entry.get('product', '')}")
    head = "\n".join(
        line
        for line in (
            name,
            f"Product: {product}" if product else "",
            f"Added to KEV on {entry['dateAdded']}" if entry.get("dateAdded") else "",
            f"Known ransomware campaign use: {entry['knownRansomwareCampaignUse']}"
            if entry.get("knownRansomwareCampaignUse")
            else "",
        )
        if line
    )
    return Document(
        doc_id=f"kev:{cve}",
        source="kev",
        version=catalog_version,
        known_from=known_from,
        cve_ids=(cve,),
        sections=_sections(
            (
                ("entry", head),
                ("description", entry.get("shortDescription") or ""),
                ("required_action", entry.get("requiredAction") or ""),
                ("notes", entry.get("notes") or ""),
            )
        ),
    )


def from_cwe(entry: Mapping[str, Any], *, catalog_version: str, known_from: str) -> Document:
    """A CWE entry of one catalog version: its description, consequences and mitigations."""
    cwe = str(entry["cwe_id"])
    return Document(
        doc_id=f"cwe:{cwe}",
        source="cwe",
        version=catalog_version,
        known_from=known_from,
        cve_ids=(),
        sections=_sections(
            (
                ("description", f"{entry.get('name') or ''}\n\n{entry.get('description') or ''}"),
                ("extended_description", entry.get("extended_description") or ""),
                ("consequences", entry.get("consequences") or ""),
                ("mitigations", entry.get("mitigations") or ""),
            )
        ),
    )
