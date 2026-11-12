"""The fixture serving bundle, written to Parquet with a manifest of digests at test time.

The rows live in fixtures/bundle/*.json so a reviewer can read them; this module types them the way
the lake build will (timestamps in UTC, dates, lists of text, JSON as text) and writes the five files
and bundle_manifest.json exactly as the release carries them. A test that needs a different bundle
passes its own rows for one table and keeps the rest.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from pathlib import Path
from typing import Any

import polars as pl

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "bundle"
SBOMS = HERE / "sboms"

TIMESTAMP = pl.Datetime("us", "UTC")
TEXT_LIST = pl.List(pl.Utf8)

CVE_TYPES: dict[str, Any] = {
    "cve_id": pl.Utf8,
    "state": pl.Utf8,
    "published": TIMESTAMP,
    "last_modified": TIMESTAMP,
    "nvd_status": pl.Utf8,
    "nvd_status_since": TIMESTAMP,
    "filer": pl.Utf8,
    "filer_type": pl.Utf8,
    "description": pl.Utf8,
    "cwes": TEXT_LIST,
    "filer_cvss31_vector": pl.Utf8,
    "filer_cvss31_score": pl.Float64,
    "filer_cvss31_band": pl.Utf8,
    "filer_cvss40_vector": pl.Utf8,
    "filer_cvss40_score": pl.Float64,
    "filer_cvss40_band": pl.Utf8,
    "nvd_cvss31_vector": pl.Utf8,
    "nvd_cvss31_score": pl.Float64,
    "nvd_cvss31_band": pl.Utf8,
    "adp_cvss31_vector": pl.Utf8,
    "adp_cvss31_score": pl.Float64,
    "adp_cvss31_band": pl.Utf8,
    "ssvc_exploitation": pl.Utf8,
    "ssvc_automatable": pl.Utf8,
    "ssvc_technical_impact": pl.Utf8,
    "kev_date_added": pl.Date,
    "kev_ransomware": pl.Utf8,
    "epss_score": pl.Float64,
    "epss_percentile": pl.Float64,
    "epss_date": pl.Date,
    "exploit_first_seen": pl.Date,
    "has_cpe": pl.Boolean,
    "provenance_json": pl.Utf8,
}
EVENT_TYPES: dict[str, Any] = {
    "cve_id": pl.Utf8,
    "at": TIMESTAMP,
    "kind": pl.Utf8,
    "source": pl.Utf8,
    "detail_json": pl.Utf8,
}
PRODUCT_TYPES: dict[str, Any] = {
    "product": pl.Utf8,
    "ecosystem": pl.Utf8,
    "kind": pl.Utf8,
    "repository": pl.Utf8,
    "commit": pl.Utf8,
    "commit_date": TIMESTAMP,
    "licence": pl.Utf8,
    "stars": pl.Int64,
    "scope": pl.Utf8,
    "date_read": pl.Date,
}
FINDING_TYPES: dict[str, Any] = {
    "product": pl.Utf8,
    "component": pl.Utf8,
    "purl": pl.Utf8,
    "ecosystem": pl.Utf8,
    "package": pl.Utf8,
    "version": pl.Utf8,
    "primary_id": pl.Utf8,
    "advisory_ids": TEXT_LIST,
    "cve_aliases": TEXT_LIST,
    "upstream_cves": TEXT_LIST,
    "matches": pl.Utf8,
    "fixed_versions": TEXT_LIST,
    "fix_available": pl.Boolean,
    "severity": pl.Utf8,
    "summary": pl.Utf8,
    "known_from": TIMESTAMP,
    "known_from_rule": pl.Utf8,
    "as_of": TIMESTAMP,
}
TYPES = {"cve": CVE_TYPES, "cve_event": EVENT_TYPES, "product": PRODUCT_TYPES, "finding": FINDING_TYPES}
GENERATED_AT = "2026-11-07T05:00:00Z"
LAKE_DIGEST = "sha256:" + "0" * 64


def rows(table: str) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = json.loads((SOURCE / f"{table}.json").read_text(encoding="utf-8"))
    return data


def backlog() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((SOURCE / "backlog.json").read_text(encoding="utf-8"))
    return data


def osv_records() -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = json.loads((HERE / "osv_records.json").read_text(encoding="utf-8"))
    return data


def _typed(value: Any, dtype: Any) -> Any:
    if value is None:
        return None
    if dtype == TIMESTAMP and isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dtype == pl.Date and isinstance(value, str):
        return date.fromisoformat(value)
    return value


def frame(
    table: str, items: Sequence[Mapping[str, Any]], types: Mapping[str, Any] | None = None
) -> pl.DataFrame:
    schema = dict(types or TYPES[table])
    records = [{k: _typed(item.get(k), t) for k, t in schema.items()} for item in items]
    return pl.DataFrame(records, schema=schema, orient="row") if records else pl.DataFrame(schema=schema)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_bundle(
    dest: Path,
    *,
    tables: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    types: Mapping[str, Mapping[str, Any]] | None = None,
    backlog_value: Any = None,
    generated_at: str = GENERATED_AT,
    lake_digest: str = LAKE_DIGEST,
    row_group_size: int | None = None,
) -> dict[str, Any]:
    """Write the five files and bundle_manifest.json into dest; return the manifest."""
    dest.mkdir(parents=True, exist_ok=True)
    files: list[dict[str, Any]] = []
    for table in ("cve", "cve_event", "product", "finding"):
        items = (tables or {}).get(table)
        data = frame(table, rows(table) if items is None else items, (types or {}).get(table))
        path = dest / f"{table}.parquet"
        data.write_parquet(path, row_group_size=row_group_size)
        files.append({"file": path.name, "sha256": _sha256(path), "rows": data.height})
    backlog_path = dest / "backlog.json"
    backlog_path.write_text(
        json.dumps(backlog() if backlog_value is None else backlog_value, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    files.append({"file": backlog_path.name, "sha256": _sha256(backlog_path), "rows": None})
    manifest = {"generated_at": generated_at, "lake_digest": lake_digest, "files": files}
    (dest / "bundle_manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest
