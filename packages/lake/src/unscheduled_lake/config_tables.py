"""The registered configuration as tables, so the warehouse joins on what the repository says.

config.splits       the windows of config/splits.yaml
config.status_labels the NVD vulnStatus values registered in config/labels.yaml
config.filer_types  every filer with its type, from config/filers.yaml, and every other assigner the
                    CVE List bronze names, typed by the rule for a filer the CNA list does not hold
config.sbom_components every component of every SBOM in customer/sboms, as packages/match reads it
                    (quarantine rule Q07 counts the packages among them with no package URL)

A file that does not exist yet gives an empty table of the same shape and is named in the build
report, so a filer list or an SBOM still to come is visible instead of silently assumed.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any

import duckdb
import polars as pl
import yaml
from unscheduled_sources.cna_list import group_by_name

from unscheduled_lake.db import put, run

SPLIT_SCHEMA = {"window_name": pl.String, "start_day": pl.Date, "end_day": pl.Date, "note": pl.String}
LABEL_SCHEMA = {"status": pl.String, "meaning": pl.String, "april_2026_label": pl.Boolean}
FILER_SCHEMA = {"short_name": pl.String, "org_id": pl.String, "filer_type": pl.String}
SBOM_SCHEMA = {
    "sbom": pl.String,
    "bom_ref": pl.String,
    "type": pl.String,
    "name": pl.String,
    "version": pl.String,
    "purl": pl.String,
    "package": pl.Boolean,
}
NON_PACKAGE_SCHEMA = {"sbom": pl.String, "type": pl.String, "components": pl.Int64}


def _day(value: Any) -> date | None:
    if value in (None, "open", ""):
        return None
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def splits(path: Path) -> pl.DataFrame:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rows = [
        {
            "window_name": str(name),
            "start_day": _day(spec.get("start")),
            "end_day": _day(spec.get("end")),
            "note": spec.get("note"),
        }
        for name, spec in data["windows"].items()
    ]
    return pl.DataFrame(rows, schema=SPLIT_SCHEMA).sort("start_day")


def status_labels(path: Path) -> pl.DataFrame:
    if not path.exists():
        return pl.DataFrame(schema=LABEL_SCHEMA)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = [
        {
            "status": str(status),
            "meaning": str((spec or {}).get("meaning", "")),
            "april_2026_label": bool((spec or {}).get("april_2026_label", False)),
        }
        for status, spec in (data.get("nvd_vuln_status") or {}).items()
    ]
    return pl.DataFrame(rows, schema=LABEL_SCHEMA).sort("status")


def filer_types(path: Path, assigners: Iterable[str] = ()) -> pl.DataFrame:
    """Filers by short name and organization id, with the group config/filers.yaml gives each.

    packages/sources writes the file with the filers under `filers`, a mapping from short name to
    an entry whose `group` is the filer type; a list of entries with `short_name` and `type` is
    read too. A filer without a group is left out, so the spine types it as unregistered.

    `assigners` are the short names the CVE List gives as assigners. One the file does not hold is
    added: with the group of a listed filer whose name differs only in case, or else by the rule for
    a filer the CNA list does not hold (packages/sources, cna_list.group_by_name). The file carries
    such filers too, but only when the CVE List bronze existed when it was written, which a first
    fetch from nothing does not promise (DECISIONS.md, 13 November 2026).
    """
    rows: list[dict[str, Any]] = []
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entries = data.get("filers") or []
        if isinstance(entries, dict):
            entries = [{"short_name": k, **(v or {})} for k, v in entries.items()]
        for entry in entries:
            name = entry.get("short_name") or entry.get("name")
            kind = entry.get("group") or entry.get("type") or entry.get("filer_type")
            if not name or not kind:
                continue
            rows.append({"short_name": str(name), "org_id": entry.get("org_id"), "filer_type": str(kind)})
    known = {r["short_name"] for r in rows}
    by_lower = {str(r["short_name"]).lower(): r["filer_type"] for r in rows}
    for name in sorted({str(a) for a in assigners if a}):
        if name in known:
            continue
        rows.append(
            {
                "short_name": name,
                "org_id": None,
                "filer_type": by_lower.get(name.lower()) or group_by_name(name),
            }
        )
    frame = pl.DataFrame(rows, schema=FILER_SCHEMA)
    return frame.unique(subset=["short_name", "org_id"], keep="first", maintain_order=True).sort("short_name")


def bronze_assigners(bronze: Path) -> list[str]:
    """Every short name the CVE List bronze gives as a record's assigner."""
    folder = bronze / "cve_records"
    files = sorted(str(p) for p in folder.rglob("*.parquet")) if folder.exists() else []
    if not files:
        return []
    names = pl.scan_parquet(files).select("assigner_short_name").unique().collect()
    return sorted(str(v) for v in names.get_column("assigner_short_name").drop_nulls().to_list())


def sbom_components(folder: Path) -> pl.DataFrame:
    """Every component of every CycloneDX SBOM in the folder, read by the matcher's own reader.

    packages/match (unscheduled_match.sbom) decides what a package is: a component of a CycloneDX
    type that names a package (library, framework, application and the like). Files and operating
    systems never carry a package URL, so they are kept with package false and counted apart;
    quarantine rule Q07 is for a package without a package URL, and reading the SBOMs the same way
    the matcher does keeps the two counts equal.
    """
    from unscheduled_match import sbom as reader

    rows: list[dict[str, Any]] = []
    if folder.exists():
        for path in sorted(folder.glob("*.cdx.json")):
            doc = reader.read(path)
            rel = path.name
            for c in doc.components:
                rows.append(_component(rel, c.bom_ref, c.type, c.name, c.version, c.purl, True))
            for q in doc.quarantined:
                rows.append(_component(rel, q.bom_ref, q.type, q.name, q.version, None, True))
    return pl.DataFrame(rows, schema=SBOM_SCHEMA)


def sbom_non_package(folder: Path) -> pl.DataFrame:
    """The components of each SBOM that are not packages (files, operating systems), by type."""
    from unscheduled_match import sbom as reader

    rows: list[dict[str, Any]] = []
    if folder.exists():
        for path in sorted(folder.glob("*.cdx.json")):
            for kind, count in reader.read(path).non_package.items():
                rows.append({"sbom": path.name, "type": kind, "components": count})
    return pl.DataFrame(rows, schema=NON_PACKAGE_SCHEMA)


def _component(
    sbom: str, bom_ref: str, kind: str, name: str | None, version: str | None, purl: str | None, package: bool
) -> dict[str, Any]:
    return {
        "sbom": sbom,
        "bom_ref": bom_ref,
        "type": kind,
        "name": name,
        "version": version,
        "purl": purl,
        "package": package,
    }


def load(con: duckdb.DuckDBPyConnection, root: Path) -> dict[str, int]:
    """Create the config schema in the work database; return the rows of each table."""
    frames = {
        "splits": splits(root / "config" / "splits.yaml"),
        "status_labels": status_labels(root / "config" / "labels.yaml"),
        "filer_types": filer_types(
            root / "config" / "filers.yaml", bronze_assigners(root / "data" / "bronze")
        ),
        "sbom_components": sbom_components(root / "customer" / "sboms"),
        "sbom_non_package": sbom_non_package(root / "customer" / "sboms"),
    }
    run(con, "create schema if not exists config")
    for name, frame in frames.items():
        put(con, f"config.{name}", frame)
    return {name: frame.height for name, frame in frames.items()}
