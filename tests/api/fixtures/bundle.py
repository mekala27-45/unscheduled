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
from datetime import UTC, date, datetime
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
# The data page's part of the manifest, invented: the lake's quarantine counts and two ledger rows.
SOURCES: dict[str, Any] = {
    "quarantine": {
        "data_cut": "2026-11-07T04:00:00+00:00",
        "rules": [
            {"rule_id": "Q01", "rule": "vector does not parse", "rows": 1, "cves": 1},
            {"rule_id": "Q02", "rule": "score disagrees with its vector", "rows": 3, "cves": 3},
        ],
    },
    "ledger_recent": [
        {
            "source": "kev",
            "window": "catalog 2026.11.06",
            "rows_in": 1500,
            "rows_changed": 2,
            "digest": "0" * 64,
            "duration_s": 1.2,
            "status": "ok",
            "finished_at": "2026-11-07T03:10:00Z",
        },
        {
            "source": "nvd",
            "window": "changes 2026-11-06",
            "rows_in": 900,
            "rows_changed": 40,
            "digest": "1" * 64,
            "duration_s": 30.5,
            "status": "ok",
            "finished_at": "2026-11-07T03:40:00Z",
        },
    ],
}
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


# The scoped corpus of the fixture: a GitHub advisory and a KEV entry for CVE-2021-90001, as
# build_corpus.py writes documents and chunks and build_serving_bundle.py cuts them to the scope.
CORPUS_CVE = "CVE-2021-90001"
ADVISORY_DOC = "ghsa:GHSA-fx01-0001-aaaa"
KEV_DOC = f"kev:{CORPUS_CVE}"


def corpus_documents() -> list[dict[str, Any]]:
    return [
        {
            "doc_id": ADVISORY_DOC,
            "version": "2021-03-02T00:00:00Z",
            "source": "ghsa",
            "known_from": datetime(2021, 3, 2, tzinfo=UTC),
            "known_to": None,
            "withdrawn": None,
            "cve_ids": [CORPUS_CVE],
            "sections": {
                "summary": "Remote code execution in logkit through unsafe deserialization",
                "details": "Fixture advisory. logkit deserializes log records from the network without checks.",
                "affected": "Go/example.org/fixture/logkit: from 0 fixed in 1.2.1",
            },
        },
        {
            "doc_id": KEV_DOC,
            "version": "2021.12.10",
            "source": "kev",
            "known_from": datetime(2021, 12, 10, tzinfo=UTC),
            "known_to": None,
            "withdrawn": None,
            "cve_ids": [CORPUS_CVE],
            "sections": {
                "entry": "Fixture logkit deserialization vulnerability\nProduct: Fixture logkit\nAdded to KEV on 2021-12-10",
                "description": "Fixture logkit contains a deserialization flaw that allows remote code execution.",
                "required_action": "Apply mitigations per vendor instructions.",
            },
        },
    ]


def corpus_frames(documents: Sequence[Mapping[str, Any]] | None = None) -> tuple[pl.DataFrame, pl.DataFrame]:
    """The two bundle files of a corpus: its document versions and one chunk per section."""
    docs = list(corpus_documents() if documents is None else documents)
    times = {"known_from": TIMESTAMP, "known_to": TIMESTAMP, "withdrawn": TIMESTAMP}
    document_frame = pl.DataFrame(
        [
            {
                **{
                    k: d[k]
                    for k in ("doc_id", "version", "source", "known_from", "known_to", "withdrawn", "cve_ids")
                },
                "sections_json": json.dumps(d["sections"], sort_keys=True),
            }
            for d in docs
        ],
        schema={
            "doc_id": pl.Utf8,
            "version": pl.Utf8,
            "source": pl.Utf8,
            **times,
            "cve_ids": TEXT_LIST,
            "sections_json": pl.Utf8,
        },
        orient="row",
    )
    chunks = [
        {
            "chunk_id": f"{d['doc_id']}@{d['version']}#{ordinal}",
            "doc_id": d["doc_id"],
            "version": d["version"],
            "source": d["source"],
            "known_from": d["known_from"],
            "known_to": d["known_to"],
            "withdrawn": d["withdrawn"],
            "ordinal": ordinal,
            "sections": [section],
            "text": text,
        }
        for d in docs
        for ordinal, (section, text) in enumerate(d["sections"].items())
    ]
    chunk_frame = pl.DataFrame(
        chunks,
        schema={
            "chunk_id": pl.Utf8,
            "doc_id": pl.Utf8,
            "version": pl.Utf8,
            "source": pl.Utf8,
            **times,
            "ordinal": pl.Int32,
            "sections": TEXT_LIST,
            "text": pl.Utf8,
        },
        orient="row",
    )
    return document_frame, chunk_frame


def write_bundle(
    dest: Path,
    *,
    tables: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    types: Mapping[str, Mapping[str, Any]] | None = None,
    backlog_value: Any = None,
    generated_at: str = GENERATED_AT,
    lake_digest: str = LAKE_DIGEST,
    row_group_size: int | None = None,
    predictions: Sequence[Mapping[str, Any]] | None = None,
    models_value: Mapping[str, Any] | None = None,
    corpus: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Write the five files and bundle_manifest.json into dest, and the optional prediction file,
    models.json and the two corpus files when given; return the manifest."""
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
    if predictions is not None:
        path = dest / "prediction.parquet"
        pl.DataFrame(list(predictions)).write_parquet(path)
        files.append({"file": path.name, "sha256": _sha256(path), "rows": len(predictions)})
    if models_value is not None:
        path = dest / "models.json"
        path.write_text(json.dumps(models_value, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        files.append(
            {"file": path.name, "sha256": _sha256(path), "rows": len(models_value.get("models", []))}
        )
    if corpus is not None:
        for data, name in zip(
            corpus_frames(corpus), ("corpus_document.parquet", "corpus_chunk.parquet"), strict=True
        ):
            path = dest / name
            data.write_parquet(path)
            files.append({"file": path.name, "sha256": _sha256(path), "rows": data.height})
    manifest = {"generated_at": generated_at, "lake_digest": lake_digest, "files": files, "sources": SOURCES}
    (dest / "bundle_manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest
