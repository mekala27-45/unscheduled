"""Small builders for the match tests: OSV records, all.zip files and CycloneDX SBOMs."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from unscheduled_match import cache
from unscheduled_match import ecosystems as eco_mod
from unscheduled_match.osv import Advisory, from_json
from unscheduled_match.store import AdvisoryStore

ROOT = Path(__file__).resolve().parents[2]
OSV_SCANNER = ROOT / "tools" / "bin" / "osv-scanner"


def record(
    advisory_id: str,
    ecosystem: str,
    name: str,
    events: list[dict[str, str]],
    *,
    aliases: list[str] | None = None,
    published: str = "2024-01-10T00:00:00Z",
    modified: str = "2024-01-10T00:00:00Z",
    withdrawn: str | None = None,
    range_type: str = "SEMVER",
    versions: list[str] | None = None,
    severity: list[dict[str, str]] | None = None,
    summary: str = "a planted advisory",
) -> dict[str, Any]:
    affected: dict[str, Any] = {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": [{"type": range_type, "events": events}],
    }
    if versions is not None:
        affected["versions"] = versions
    out: dict[str, Any] = {
        "schema_version": "1.6.0",
        "id": advisory_id,
        "aliases": aliases or [],
        "published": published,
        "modified": modified,
        "summary": summary,
        "affected": [affected],
    }
    if withdrawn:
        out["withdrawn"] = withdrawn
    if severity:
        out["severity"] = severity
    return out


def advisory(raw: dict[str, Any], source: str = "osv") -> Advisory:
    return from_json(raw, source)


def store_of(*records: dict[str, Any], source: str = "osv") -> AdvisoryStore:
    store = AdvisoryStore()
    for raw in records:
        store.add(advisory(raw, source))
    return store


def write_zip(path: Path, records: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for raw in records:
            archive.writestr(f"{raw['id']}.json", json.dumps(raw))
    return path


def osv_cache(root: Path, by_ecosystem: dict[str, list[dict[str, Any]]]) -> Path:
    """A data/cache in the layout the matcher reads, with a sidecar for each zip."""
    for name, records in by_ecosystem.items():
        eco = eco_mod.BY_OSV[name]
        path = write_zip(cache.osv_zip_path(root, eco), records)
        cache.sidecar(path).write_text(
            json.dumps(
                {"url": f"test://{name}", "size": path.stat().st_size, "sha256": "", "generation": "0"}
            ),
            encoding="utf-8",
        )
    return root


def sbom(path: Path, components: list[dict[str, Any]], name: str = "planted") -> Path:
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "version": 1,
        "metadata": {"component": {"bom-ref": "root", "type": "application", "name": name}},
        "components": components,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1), encoding="utf-8")
    return path


def library(name: str, version: str, purl: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "bom-ref": f"{name}@{version}",
        "type": "library",
        "name": name,
        "version": version,
    }
    if purl:
        out["purl"] = purl
    return out
