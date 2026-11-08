"""CycloneDX 1.6 JSON SBOMs as Syft writes them, read into components the matcher can key.

A component without a package URL cannot be matched by either engine. It is not dropped: it goes to
quarantine under rule Q07 with its name, type and where Syft found it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from unscheduled_core.model import StrictModel

from unscheduled_match import purl as purl_mod
from unscheduled_match.purl import PackageKey, PurlError

Q07 = "Q07"
# CycloneDX component types that describe something other than a package: the files Syft read and
# the distribution it found. They are counted, not quarantined: Q07 is for packages with no purl.
NON_PACKAGE_TYPES = frozenset(
    {"file", "operating-system", "data", "machine-learning-model", "cryptographic-asset"}
)


class Component(StrictModel):
    bom_ref: str
    type: str
    name: str
    version: str | None = None
    purl: str | None = None
    found_by: str | None = None
    location: str | None = None

    def key(self) -> PackageKey | None:
        if not self.purl:
            return None
        try:
            return purl_mod.key_of(self.purl)
        except PurlError:
            return None


class Quarantined(StrictModel):
    rule: str
    bom_ref: str
    type: str
    name: str
    version: str | None = None
    found_by: str | None = None
    location: str | None = None


class Sbom(StrictModel):
    path: str
    spec_version: str
    serial_number: str | None = None
    subject: str | None = None  # the metadata component: the source or image Syft read
    components: tuple[Component, ...]
    quarantined: tuple[Quarantined, ...]
    non_package: dict[str, int]  # components that are not packages, by CycloneDX type


def _property(raw: dict[str, Any], name: str) -> str | None:
    for prop in raw.get("properties") or []:
        if prop.get("name") == name:
            value = prop.get("value")
            return str(value) if value is not None else None
    return None


def component_of(raw: dict[str, Any]) -> Component:
    return Component(
        bom_ref=str(raw.get("bom-ref") or raw.get("name") or ""),
        type=str(raw.get("type") or ""),
        name=str(raw.get("name") or ""),
        version=str(raw["version"]) if raw.get("version") else None,
        purl=str(raw["purl"]) if raw.get("purl") else None,
        found_by=_property(raw, "syft:package:foundBy"),
        location=_property(raw, "syft:location:0:path"),
    )


def flatten(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for raw in components:
        out.append(raw)
        out.extend(flatten(raw.get("components") or []))
    return out


def read(path: Path) -> Sbom:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path} is not a CycloneDX SBOM")
    kept: list[Component] = []
    quarantined: list[Quarantined] = []
    non_package: dict[str, int] = {}
    for raw in flatten(data.get("components") or []):
        component = component_of(raw)
        if component.purl:
            kept.append(component)
        elif component.type in NON_PACKAGE_TYPES:
            non_package[component.type] = non_package.get(component.type, 0) + 1
        else:
            quarantined.append(
                Quarantined(
                    rule=Q07,
                    bom_ref=component.bom_ref,
                    type=component.type,
                    name=component.name,
                    version=component.version,
                    found_by=component.found_by,
                    location=component.location,
                )
            )
    subject = (data.get("metadata") or {}).get("component") or {}
    return Sbom(
        path=str(path),
        spec_version=str(data.get("specVersion") or ""),
        serial_number=data.get("serialNumber"),
        subject=str(subject.get("name")) if subject.get("name") else None,
        components=tuple(kept),
        quarantined=tuple(quarantined),
        non_package=dict(sorted(non_package.items())),
    )


def validate_cyclonedx_16(path: Path) -> str | None:
    """None when the file is valid CycloneDX 1.6 JSON by the schema cyclonedx-python-lib ships."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(path.read_text(encoding="utf-8"))
    return None if error is None else str(error)
