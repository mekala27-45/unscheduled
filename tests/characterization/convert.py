"""Sample NVD 1.1 feed files, built from current NVD API 2.0 records.

The NVD retired its JSON 1.1 data feeds in 2023, so the legacy script can no longer be fed by the
NVD. Its characterization tests need input in the 1.1 layout, and this converter writes it from the
records in fixtures/nvd_api_2_0_sample.json: one feed per publication year, plus the recent feed
(published in the eight days before the reference day) and the modified feed (changed in those
eight days), each gzipped with no timestamp so the same input gives the same bytes.

The mapping follows the 1.1 layout: CVE_data_meta, problemtype, references, description, the
configurations as nodes with cpe_match (an AND configuration becomes a parent node whose children
hold the matches), impact with baseMetricV3 and baseMetricV2 from the NVD's own (Primary) metrics,
and publishedDate and lastModifiedDate to the minute.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nvd_api_2_0_sample.json"
WINDOW_DAYS = 8
MATCH_FIELDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def load_sample(path: Path = FIXTURE) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [v["cve"] for v in data["vulnerabilities"]]


def minute(text: str) -> str:
    return datetime.fromisoformat(text.replace("Z", "")).strftime("%Y-%m-%dT%H:%MZ")


def _match(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"vulnerable": bool(raw.get("vulnerable")), "cpe23Uri": raw["criteria"]}
    for field in MATCH_FIELDS:
        if field in raw:
            out[field] = raw[field]
    out["cpe_name"] = []
    return out


def _node(raw: dict[str, Any]) -> dict[str, Any]:
    node: dict[str, Any] = {
        "operator": raw.get("operator", "OR"),
        "children": [],
        "cpe_match": [_match(m) for m in raw.get("cpeMatch", [])],
    }
    if raw.get("negate"):
        node["negate"] = True
    return node


def configurations(cve: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    for config in cve.get("configurations", []):
        parts = [_node(n) for n in config.get("nodes", [])]
        if len(parts) == 1 and config.get("operator") != "AND":
            nodes.append(parts[0])
        else:
            nodes.append({"operator": config.get("operator", "OR"), "children": parts, "cpe_match": []})
    return {"CVE_data_version": "4.0", "nodes": nodes}


def _primary(metrics: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    for metric in metrics:
        if metric.get("type") == "Primary":
            return metric
    return None


def impact(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics", {})
    out: dict[str, Any] = {}
    v3 = _primary(metrics.get("cvssMetricV31", [])) or _primary(metrics.get("cvssMetricV30", []))
    if v3 is not None:
        out["baseMetricV3"] = {
            "cvssV3": dict(v3["cvssData"]),
            "exploitabilityScore": v3.get("exploitabilityScore"),
            "impactScore": v3.get("impactScore"),
        }
    v2 = _primary(metrics.get("cvssMetricV2", []))
    if v2 is not None:
        out["baseMetricV2"] = {
            "cvssV2": dict(v2["cvssData"]),
            "severity": v2.get("baseSeverity"),
            "exploitabilityScore": v2.get("exploitabilityScore"),
            "impactScore": v2.get("impactScore"),
            "acInsufInfo": v2.get("acInsufInfo", False),
            "obtainAllPrivilege": v2.get("obtainAllPrivilege", False),
            "obtainUserPrivilege": v2.get("obtainUserPrivilege", False),
            "obtainOtherPrivilege": v2.get("obtainOtherPrivilege", False),
            "userInteractionRequired": v2.get("userInteractionRequired", False),
        }
    return out


def item(cve: dict[str, Any]) -> dict[str, Any]:
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("lang") == "en"
        }
    )
    return {
        "cve": {
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "CVE_data_meta": {"ID": cve["id"], "ASSIGNER": cve.get("sourceIdentifier", "")},
            "problemtype": {
                "problemtype_data": [{"description": [{"lang": "en", "value": c} for c in cwes]}]
            },
            "references": {
                "reference_data": [
                    {
                        "url": r["url"],
                        "name": r["url"],
                        "refsource": r.get("source", ""),
                        "tags": r.get("tags", []),
                    }
                    for r in cve.get("references", [])
                ]
            },
            "description": {
                "description_data": [
                    {"lang": "en", "value": d["value"]}
                    for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"
                ]
            },
        },
        "configurations": configurations(cve),
        "impact": impact(cve),
        "publishedDate": minute(cve["published"]),
        "lastModifiedDate": minute(cve["lastModified"]),
    }


def feed(items: Iterable[dict[str, Any]], stamp: str) -> dict[str, Any]:
    ordered = sorted(items, key=lambda i: _id_order(i["cve"]["CVE_data_meta"]["ID"]))
    return {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
        "CVE_data_numberOfCVEs": str(len(ordered)),
        "CVE_data_timestamp": stamp,
        "CVE_Items": ordered,
    }


def _id_order(cve_id: str) -> tuple[int, int]:
    _, year, number = cve_id.split("-")
    return int(year), int(number)


def feeds(records: Sequence[dict[str, Any]], reference: date) -> dict[str, dict[str, Any]]:
    """Feed name (a year, recent or modified) to its document."""
    stamp = f"{reference.isoformat()}T00:00Z"
    start = reference - timedelta(days=WINDOW_DAYS)
    by_name: dict[str, list[dict[str, Any]]] = {"recent": [], "modified": []}
    for cve in records:
        converted = item(cve)
        published = datetime.fromisoformat(cve["published"]).date()
        modified = datetime.fromisoformat(cve["lastModified"]).date()
        by_name.setdefault(str(published.year), []).append(converted)
        if start <= published <= reference:
            by_name["recent"].append(converted)
        if start <= modified <= reference:
            by_name["modified"].append(converted)
    return {name: feed(items, stamp) for name, items in sorted(by_name.items())}


def write(out_dir: Path, records: Sequence[dict[str, Any]], reference: date) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, document in feeds(records, reference).items():
        path = out_dir / f"nvdcve-1.1-{name}.json.gz"
        raw = json.dumps(document, indent=None, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        path.write_bytes(gzip.compress(raw, mtime=0))
        written.append(path)
    return written


def years(records: Sequence[dict[str, Any]]) -> list[str]:
    return sorted({str(datetime.fromisoformat(c["published"]).year) for c in records})
