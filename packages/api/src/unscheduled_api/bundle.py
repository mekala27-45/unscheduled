"""The serving bundle contract: what each file must hold, and how a chunk of it becomes rows.

The lake build writes the bundle (data/serving/) and the release carries it. The API trusts none of
it until the bytes match the sha256 in bundle_manifest.json and every required column is present.

    bundle_manifest.json  {generated_at, lake_digest, files: [{file, sha256, rows}], locks?, sources?}
    cve.parquet           one row per CVE, the compact current state (CVE_COLUMNS)
    cve_event.parquet     cve_id, at, kind, source, detail_json: the ruler events
    product.parquet       product_id (or product, as the exposure builder names it), and any further
                          columns (name, ecosystem, repository, commit, licence, stars), kept whole
    finding.parquet       product_id (or product), as_of, the CVE ids (cve_id, or cve_aliases and
                          upstream_cves as packages/match writes them), and any further columns
    backlog.json          the Q1 to Q6 values from the manifest, served as they are

A column listed as required must exist in the file (its values may be null). An optional column
that is missing loads as null and is listed in the data version, so a reader can tell "the source
had no value" from "the bundle did not carry the column". A row's digest is taken over its
canonical JSON, so a reload writes only the rows that changed.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import polars as pl
from unscheduled_core.hashing import canonical_json, sha256_text
from unscheduled_core.model import StrictModel

MANIFEST = "bundle_manifest.json"
BACKLOG = "backlog.json"
FILES = ("cve.parquet", "cve_event.parquet", "product.parquet", "finding.parquet", BACKLOG)


class BundleError(ValueError):
    """The bundle breaks its contract. Nothing is loaded from a bundle that raises this."""


class ManifestFile(StrictModel):
    file: str
    sha256: str
    rows: int | None = None


class BundleManifest(StrictModel):
    generated_at: str
    lake_digest: str
    files: list[ManifestFile]
    locks: dict[str, Any] | None = None
    sources: dict[str, Any] | None = None

    def entry(self, name: str) -> ManifestFile:
        for item in self.files:
            if item.file == name:
                return item
        raise BundleError(f"the manifest names no file {name}")


def parse_manifest(data: bytes) -> BundleManifest:
    try:
        raw = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise BundleError(f"{MANIFEST} is not JSON: {err}") from err
    if not isinstance(raw, dict):
        raise BundleError(f"{MANIFEST} is not a JSON object")
    known = {k: raw[k] for k in ("generated_at", "lake_digest", "files", "locks", "sources") if k in raw}
    try:
        manifest = BundleManifest.model_validate(known)
    except ValueError as err:
        raise BundleError(f"{MANIFEST} does not match the contract: {err}") from err
    names = [f.file for f in manifest.files]
    missing = [name for name in FILES if name not in names]
    if missing:
        raise BundleError(f"{MANIFEST} does not name {', '.join(missing)}")
    if len(set(names)) != len(names):
        raise BundleError(f"{MANIFEST} names a file twice")
    for item in manifest.files:
        if len(item.sha256) != 64 or any(c not in "0123456789abcdef" for c in item.sha256):
            raise BundleError(f"{item.file}: the manifest sha256 is not 64 lowercase hex digits")
        if item.rows is not None and item.rows < 0:
            raise BundleError(f"{item.file}: a negative row count")
    return manifest


@dataclass(frozen=True)
class Column:
    name: str
    kind: str  # text, timestamp, date, float, bool, text_list, json
    required: bool = True


CVE_COLUMNS: tuple[Column, ...] = (
    Column("cve_id", "text"),
    Column("state", "text", required=False),
    Column("published", "timestamp"),
    Column("last_modified", "timestamp"),
    Column("nvd_status", "text"),
    Column("nvd_status_since", "timestamp"),
    Column("filer", "text"),
    Column("filer_type", "text"),
    Column("description", "text"),
    Column("cwes", "text_list"),
    Column("filer_cvss31_vector", "text"),
    Column("filer_cvss31_score", "float"),
    Column("filer_cvss31_band", "text"),
    Column("filer_cvss40_vector", "text"),
    Column("filer_cvss40_score", "float"),
    Column("filer_cvss40_band", "text"),
    Column("nvd_cvss31_vector", "text"),
    Column("nvd_cvss31_score", "float"),
    Column("nvd_cvss31_band", "text"),
    Column("adp_cvss31_vector", "text"),
    Column("adp_cvss31_score", "float", required=False),
    Column("adp_cvss31_band", "text", required=False),
    Column("ssvc_exploitation", "text"),
    Column("ssvc_automatable", "text"),
    Column("ssvc_technical_impact", "text"),
    Column("kev_date_added", "date"),
    Column("kev_ransomware", "text"),
    Column("epss_score", "float"),
    Column("epss_percentile", "float", required=False),
    Column("epss_date", "date"),
    Column("exploit_first_seen", "date"),
    Column("has_cpe", "bool"),
    Column("provenance_json", "json"),
)
EVENT_COLUMNS: tuple[Column, ...] = (
    Column("cve_id", "text"),
    Column("at", "timestamp"),
    Column("kind", "text"),
    Column("source", "text"),
    Column("detail_json", "json"),
)
# product and finding name their product either product_id or product; checked in check_columns.
PRODUCT_KEYS: tuple[Column, ...] = ()
FINDING_KEYS: tuple[Column, ...] = (Column("as_of", "date"),)
PRODUCT_KEY_NAMES = ("product_id", "product")

# The fields of a CVE record the API serves with a source and a known_from each.
CVE_FIELDS: tuple[str, ...] = tuple(
    c.name for c in CVE_COLUMNS if c.name not in {"cve_id", "provenance_json"}
)


@dataclass(frozen=True)
class Table:
    name: str
    file: str
    key: str
    chunk_rows: int


TABLES: dict[str, Table] = {
    "cve": Table("cve", "cve.parquet", "cve_id", 20_000),
    "cve_event": Table("cve_event", "cve_event.parquet", "event_id", 100_000),
    "product": Table("product", "product.parquet", "product_id", 20_000),
    "finding": Table("finding", "finding.parquet", "finding_id", 50_000),
}


def file_columns(path: Path) -> list[str]:
    return list(pl.scan_parquet(path).collect_schema().names())


def file_rows(path: Path) -> int:
    return int(pl.scan_parquet(path).select(pl.len()).collect().item())


def check_columns(table: str, present: Sequence[str]) -> list[str]:
    """Raise when a required column is missing; return the optional ones that are."""
    spec = {"cve": CVE_COLUMNS, "cve_event": EVENT_COLUMNS, "product": PRODUCT_KEYS, "finding": FINDING_KEYS}[
        table
    ]
    have = set(present)
    missing = [c.name for c in spec if c.required and c.name not in have]
    if table in {"product", "finding"} and not have.intersection(PRODUCT_KEY_NAMES):
        missing.append("product_id or product")
    if missing:
        raise BundleError(f"{TABLES[table].file} is missing required columns: {', '.join(missing)}")
    return [c.name for c in spec if not c.required and c.name not in have]


def read_slice(path: Path, offset: int, length: int) -> list[dict[str, Any]]:
    """Rows offset to offset + length of a Parquet file, reading only the row groups that hold them."""
    frame = pl.scan_parquet(path).slice(offset, length).collect()
    return frame.to_dicts()


def iter_column(path: Path, name: str, batch: int = 200_000) -> Iterator[list[Any]]:
    total = file_rows(path)
    for start in range(0, total, batch):
        frame = pl.scan_parquet(path).select(name).slice(start, batch).collect()
        yield frame.get_column(name).to_list()


def iter_rows(path: Path, columns: Sequence[str], batch: int = 100_000) -> Iterator[list[dict[str, Any]]]:
    total = file_rows(path)
    for start in range(0, total, batch):
        yield pl.scan_parquet(path).select(list(columns)).slice(start, batch).collect().to_dicts()


# Reading values as the contract types them -------------------------------------------------------


def _timestamp(value: Any, column: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as err:
            raise BundleError(f"{column}: {value!r} is not a timestamp") from err
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    raise BundleError(f"{column}: {type(value).__name__} is not a timestamp")


def _date(value: Any, column: str) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).date() if value.tzinfo else value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return date.fromisoformat(text[:10])
        except ValueError as err:
            raise BundleError(f"{column}: {value!r} is not a date") from err
    raise BundleError(f"{column}: {type(value).__name__} is not a date")


def _float(value: Any, column: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise BundleError(f"{column}: a boolean is not a number")
    try:
        number = float(value)
    except (TypeError, ValueError) as err:
        raise BundleError(f"{column}: {value!r} is not a number") from err
    if not math.isfinite(number):
        return None
    return number


def _bool(value: Any, column: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    raise BundleError(f"{column}: {value!r} is not a boolean")


def _text(value: Any, column: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, int | float | bool):
        return str(value)
    raise BundleError(f"{column}: {type(value).__name__} is not text")


def _text_list(value: Any, column: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            try:
                value = json.loads(text)
            except json.JSONDecodeError as err:
                raise BundleError(f"{column}: {value!r} is not a list") from err
        else:
            return sorted({part.strip() for part in text.replace(";", ",").split(",") if part.strip()})
    if isinstance(value, list | tuple):
        return sorted({str(v).strip() for v in value if v is not None and str(v).strip()})
    raise BundleError(f"{column}: {type(value).__name__} is not a list")


def _json(value: Any, column: str) -> Any:
    if value is None:
        return {}
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError as err:
            raise BundleError(f"{column}: the value is not JSON") from err
    if isinstance(value, dict | list):
        return value
    raise BundleError(f"{column}: {type(value).__name__} is not JSON")


READERS = {
    "text": _text,
    "timestamp": _timestamp,
    "date": _date,
    "float": _float,
    "bool": _bool,
    "text_list": _text_list,
    "json": _json,
}


def jsonable(value: Any) -> Any:
    """A value in the form canonical JSON and JSONB take: times as ISO text, no NaN."""
    if isinstance(value, datetime):
        stamp = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        return stamp.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [jsonable(v) for v in value]
    return value


def row_digest(values: Mapping[str, Any]) -> str:
    return sha256_text(canonical_json(jsonable(dict(values))))


def cve_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for column in CVE_COLUMNS:
        value = READERS[column.kind](raw.get(column.name), column.name)
        out["provenance" if column.name == "provenance_json" else column.name] = value
    if not out["cve_id"]:
        raise BundleError("cve.parquet holds a row without a cve_id")
    if not isinstance(out["provenance"], dict):
        raise BundleError(f"{out['cve_id']}: provenance_json is not a JSON object")
    out["provenance"] = jsonable(out["provenance"])
    out["row_digest"] = row_digest(out)
    return out


def event_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    cve_id = _text(raw.get("cve_id"), "cve_id")
    at = _timestamp(raw.get("at"), "at")
    kind = _text(raw.get("kind"), "kind")
    if not cve_id or at is None or not kind:
        raise BundleError("cve_event.parquet holds a row without its cve_id, at or kind")
    detail = _json(raw.get("detail_json"), "detail_json")
    if not isinstance(detail, dict):
        raise BundleError(f"{cve_id}: an event detail_json is not a JSON object")
    out: dict[str, Any] = {
        "cve_id": cve_id,
        "at": at,
        "kind": kind,
        "source": _text(raw.get("source"), "source"),
        "detail": jsonable(detail),
    }
    out["event_id"] = row_digest(out)[:32]
    return out


def body_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Every column of a product or finding row, kept whole for the response."""
    return {str(k): jsonable(v) for k, v in sorted(raw.items())}


def _product_key(raw: Mapping[str, Any]) -> str | None:
    for name in PRODUCT_KEY_NAMES:
        value = _text(raw.get(name), name)
        if value:
            return value
    return None


def _cve_ids(raw: Mapping[str, Any]) -> list[str]:
    """Every CVE a finding names, from cve_id and from the aliases packages/match writes."""
    ids: set[str] = set()
    for name in ("cve_id", "cve_ids", "cve_aliases", "upstream_cves"):
        for item in _text_list(raw.get(name), name):
            value = item.upper()
            if value.startswith("CVE-"):
                ids.add(value)
    return sorted(ids)


def product_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    product_id = _product_key(raw)
    if not product_id:
        raise BundleError("product.parquet holds a row without a product_id")
    name = _text(raw.get("name"), "name") or product_id
    body = body_row(raw)
    return {"product_id": product_id, "name": name, "body": body, "row_digest": row_digest(body)}


def finding_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    product_id = _product_key(raw)
    as_of = _date(raw.get("as_of"), "as_of")
    if not product_id or as_of is None:
        raise BundleError("finding.parquet holds a row without a product_id or an as_of date")
    body = body_row(raw)
    digest = row_digest(body)
    given = _text(raw.get("finding_id"), "finding_id")
    return {
        "finding_id": given or digest[:32],
        "product_id": product_id,
        "as_of": as_of,
        "cve_ids": _cve_ids(raw),
        "body": body,
        "row_digest": digest,
    }


ROW_BUILDERS = {"cve": cve_row, "cve_event": event_row, "product": product_row, "finding": finding_row}
