"""The customer exposure, found twice: the matcher as of each pin date and today, osv-scanner offline on
the same SBOMs and the same OSV files, every disagreement with its reason, Grype as the CPE contrast,
and the NVD status of every finding's CVE from bronze when the NVD fetch has written it.

uv run python scripts/run_exposure.py               # everything, fetching what is missing
uv run python scripts/run_exposure.py --no-grype    # reuse the saved Grype runs (its database is 3 GB)
uv run python scripts/run_exposure.py --from-saved  # redo what follows the engines from saved findings

Writes results/exposure/: findings_today.json, findings_pin.json, osv_scanner.json,
disagreements.json, grype.json, contrast.json, quarantine.json, summary.json, nvd_status.json and
severity.json; and results/parts/exposure.json, the manifest part scripts/build_manifest.py merges.

After the engines, every count is taken as of its time from bronze: KEV listing (kev), exploit code
seen (exploit_signals), the NVD status as of the time with the rule that dated it (nvd_cves and
nvd_changes), and the C9 severity baseline (cve_metrics). A table that bronze does not hold yet is
written as pending, never guessed.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import httpx
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_match import (
    baseline,
    cache,
    contrast,
    disagreements,
    grype,
    osvscanner,
    products,
    store,
    tools,
)
from unscheduled_match import ecosystems as eco_mod
from unscheduled_match.github import USER_AGENT
from unscheduled_match.matcher import Finding, MatchResult, match
from unscheduled_match.products import ProductsConfig, StandIn
from unscheduled_match.sbom import Sbom
from unscheduled_match.sbom import read as read_sbom

RESULTS = ROOT / "results" / "exposure"
PART = ROOT / "results" / "parts" / "exposure.json"
OLD_PART = RESULTS / "manifest_entries.json"
ORIGIN = "scripts/run_exposure.py"
CACHE = ROOT / "data" / "cache"
BRONZE = ROOT / "data" / "bronze"
LOCKS = ROOT / "data" / "locks"
SBOMS = ROOT / "customer" / "sboms"
BIN = ROOT / "tools" / "bin"
PRODUCTS = ROOT / "config" / "products.yaml"
GHSA_ECOSYSTEMS = (eco_mod.NPM, eco_mod.PYPI, eco_mod.GO, eco_mod.MAVEN, eco_mod.CRATES)


def stamp(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def pin_time(stand_in: StandIn) -> datetime:
    text = stand_in.commit_date or stand_in.pushed
    if not text:
        raise ValueError(f"{stand_in.product} has no pin date")
    return products.parse_github_time(text)


def load_sboms(config: ProductsConfig) -> dict[str, Sbom]:
    return {s.product: read_sbom(SBOMS / f"{s.product}.cdx.json") for s in config.stand_ins}


def osv_files(sources_lock: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Each OSV file read, with its digest, and whether the sources fetch recorded the same digest."""
    by_url: dict[str, str] = {}
    if sources_lock:
        for entry in sources_lock.get("entries", []):
            by_url.setdefault(str(entry.get("url")), str(entry.get("sha256")))
    out: list[dict[str, Any]] = []
    for eco in eco_mod.ALL:
        meta = cache.read_sidecar(cache.osv_zip_path(CACHE, eco))
        recorded = by_url.get(str(meta["url"]))
        out.append(
            {
                "ecosystem": eco.osv,
                "file": str(cache.osv_zip_path(CACHE, eco).relative_to(ROOT)),
                "sha256": meta["sha256"],
                "size": meta["size"],
                "generation": meta.get("generation"),
                "last_modified": meta.get("last_modified"),
                "fetched_at": meta.get("fetched_at"),
                "same_as_sources_lock": None if recorded is None else recorded == meta["sha256"],
            }
        )
    return out


def ensure_osv(http: httpx.Client) -> None:
    for eco in eco_mod.ALL:
        path = cache.osv_zip_path(CACHE, eco)
        if not (path.exists() and cache.sidecar(path).exists()):
            cache.fetch_osv_zip(CACHE, eco, http)


def ghsa_tree_mode() -> str:
    marker = cache.ghsa_root(CACHE).parent / "fetch.json"
    if not marker.exists():
        return "not read"
    data = read_json(marker)
    return str(data.get("mode", "unknown"))


def ensure_ghsa(osv_store: store.AdvisoryStore, http: httpx.Client) -> dict[str, Any]:
    """The reviewed GHSA records for the components' packages, unless the whole tree is on disk."""
    mode = ghsa_tree_mode()
    if mode == "full reviewed tree":
        return read_json(cache.ghsa_root(CACHE).parent / "fetch.json")  # type: ignore[no-any-return]
    wanted: list[tuple[str, str]] = []
    for advisory_id in osv_store.ids():
        if not advisory_id.startswith("GHSA-"):
            continue
        for copy in osv_store.copies(advisory_id):
            if copy.published is not None:
                wanted.append((advisory_id, copy.published.strftime("%Y-%m-%dT%H:%M:%SZ")))
                break
    return cache.fetch_ghsa_records(CACHE, wanted, http)


def build_store(
    sboms: Mapping[str, Sbom], http: httpx.Client, *, fetch_ghsa: bool
) -> tuple[store.AdvisoryStore, dict[str, Any]]:
    wanted = {(k.ecosystem, k.name) for s in sboms.values() for c in s.components if (k := c.key())}
    osv_only, _ = store.load(CACHE, eco_mod.ALL, wanted, ghsa_mode="not read")
    ghsa_summary: dict[str, Any] = {"mode": ghsa_tree_mode()}
    if fetch_ghsa:
        ghsa_summary = ensure_ghsa(osv_only, http)
    full, stats = store.load(CACHE, eco_mod.ALL, wanted, ghsa_mode=str(ghsa_summary.get("mode")))
    return full, {"load": stats.model_dump(), "ghsa": ghsa_summary, "wanted_packages": len(wanted)}


def run_matcher(
    config: ProductsConfig, sboms: Mapping[str, Sbom], advisories: store.AdvisoryStore, today: datetime
) -> tuple[dict[str, MatchResult], dict[str, MatchResult]]:
    at_pin: dict[str, MatchResult] = {}
    at_today: dict[str, MatchResult] = {}
    for stand_in in config.stand_ins:
        sbom = sboms[stand_in.product]
        at_pin[stand_in.product] = match(
            stand_in.product, sbom.components, advisories, pin_time(stand_in), sbom.quarantined
        )
        at_today[stand_in.product] = match(
            stand_in.product, sbom.components, advisories, today, sbom.quarantined
        )
    return at_pin, at_today


def normalize_release(text: str) -> str:
    """The SBOM as osv-scanner would key it if Syft wrote the major release: debian-12.8 to debian-12."""
    return re.sub(r"distro=debian-(\d+)\.\d+", r"distro=debian-\1", text)


def run_osv_scanner(
    config: ProductsConfig, work: Path
) -> tuple[dict[str, osvscanner.ScanResult], dict[str, osvscanner.ScanResult]]:
    binary = BIN / "osv-scanner"
    db = cache.osv_scanner_db_dir(CACHE, eco_mod.ALL, work / "osvdb")
    scans: dict[str, osvscanner.ScanResult] = {}
    probes: dict[str, osvscanner.ScanResult] = {}
    for stand_in in config.stand_ins:
        sbom = SBOMS / f"{stand_in.product}.cdx.json"
        out = work / f"{stand_in.product}.osv.json"
        code = osvscanner.run(binary, sbom, db, out)
        scans[stand_in.product] = osvscanner.read(out, str(sbom.relative_to(ROOT)), code)
        if stand_in.ecosystem == eco_mod.DEBIAN.osv:
            probe_dir = work / "probe"
            probe_dir.mkdir(exist_ok=True)
            probe_sbom = probe_dir / sbom.name
            probe_sbom.write_text(normalize_release(sbom.read_text(encoding="utf-8")), encoding="utf-8")
            probe_out = work / f"{stand_in.product}.probe.osv.json"
            probe_code = osvscanner.run(binary, probe_sbom, db, probe_out)
            probes[stand_in.product] = osvscanner.read(probe_out, "release-normalized copy", probe_code)
    return scans, probes


def run_grype(config: ProductsConfig, work: Path, *, keep_db: bool) -> dict[str, Any]:
    binary = BIN / "grype"
    db_dir = CACHE / "grype"
    status = grype.update_db(binary, db_dir)
    runs: dict[str, Any] = {}
    try:
        for stand_in in config.stand_ins:
            sbom = SBOMS / f"{stand_in.product}.cdx.json"
            per: dict[str, Any] = {}
            for mode, cpe in (("default", False), ("cpe", True)):
                out = work / f"{stand_in.product}.grype.{mode}.json"
                grype.run(binary, sbom, db_dir, out, cpe=cpe)
                per[mode] = grype.read(out, stand_in.product, mode).model_dump(mode="json")
            runs[stand_in.product] = per
    finally:
        if not keep_db:
            shutil.rmtree(db_dir, ignore_errors=True)
    return {
        "db": {k: status.get(k) for k in ("schemaVersion", "built", "from", "checksum", "path")},
        "products": runs,
    }


def kev_dates() -> dict[str, str]:
    files = sorted((BRONZE / "kev").rglob("*.parquet")) if (BRONZE / "kev").exists() else []
    if not files:
        return {}
    import duckdb

    con = duckdb.connect()
    try:
        rows = con.execute(
            "select cve_id, min(date_added) from read_parquet(?, union_by_name = true) group by cve_id",
            [[str(f) for f in files]],
        ).fetchall()
    finally:
        con.close()
    return {str(r[0]): str(r[1]) for r in rows}


@dataclass(frozen=True)
class Snapshot:
    """One product's findings as of one time: what everything after the engines is counted from."""

    as_of: datetime
    components: int
    findings: tuple[Finding, ...]


def snapshots(results: Mapping[str, MatchResult]) -> dict[str, Snapshot]:
    return {n: Snapshot(r.as_of, r.stats.components, r.findings) for n, r in results.items()}


def summary_row(
    snap: Snapshot, kev: Mapping[str, str], seen: Mapping[str, baseline.ExploitSeen] | None
) -> dict[str, Any]:
    findings = snap.findings
    cves = sorted({c for f in findings for c in f.cves})
    day = snap.as_of.date().isoformat()
    kev_cves = sorted(c for c in cves if c in kev and kev[c] <= day)
    kev_findings = sum(1 for f in findings if any(c in kev_cves for c in f.cves))
    exploit = baseline.exploit_counts(findings, snap.as_of, seen) if seen is not None else None
    return {
        "as_of": stamp(snap.as_of),
        "components": snap.components,
        "findings": len(findings),
        "distinct_cves": len(cves),
        "findings_without_cve": sum(1 for f in findings if not f.cves),
        "fix_available": sum(1 for f in findings if f.fix_available is True),
        "fix_unknown_at_as_of": sum(1 for f in findings if f.fix_available is None),
        "kev_listed_findings": kev_findings if kev else None,
        "kev_listed_cves": len(kev_cves) if kev else None,
        "exploit_code_findings": exploit[0] if exploit else None,
        "exploit_code_cves": exploit[1] if exploit else None,
        "dated_by_rule": sum(1 for f in findings if f.known_from_rule == "published"),
    }


def nvd_fetch_complete() -> bool:
    """True when the newest NVD full fetch in the locks covered every CVE the API reported."""
    lock, log = LOCKS / "nvd.lock.json", LOCKS / "nvd_progress.log"
    if not lock.exists() or not log.exists():
        return False
    try:
        entries = [
            e for e in read_json(lock).get("entries", []) if str(e.get("name", "")).startswith("cves-full-")
        ]
        if not entries:
            return False
        latest = max(str(e["name"]).split("-")[2] for e in entries)
        rows = sum(int(e.get("rows", 0)) for e in entries if str(e["name"]).split("-")[2] == latest)
        totals = re.findall(rf"cves full {latest} start=\d+: \d+ of (\d+)", log.read_text(encoding="utf-8"))
        return bool(totals) and rows >= int(totals[-1])
    except (ValueError, KeyError, OSError):
        return False


def _value(
    builder: ManifestBuilder, key: str, value: Any, fmt: str, population: str, note: str | None = None
) -> None:
    builder.value(key, value, fmt, origin=ORIGIN, population=population, source="match", note=note)


def manifest_part(
    summary: Mapping[str, Any],
    totals: tuple[int, int],
    contrast_out: Mapping[str, Any],
    status: Mapping[str, Any],
    severity: Mapping[str, Any],
    as_of: str,
) -> dict[str, Any]:
    """The exposure part of results/manifest.json: per product values, the NVD status table, C9."""
    builder = ManifestBuilder(as_of)
    for product, both in summary["products"].items():
        key = product.replace("-", "_")
        for when in ("pin", "today"):
            row = both[when]
            population = f"{product}, stand in SBOM, as of {row['as_of']}"
            _value(builder, f"exposure.{key}.findings_{when}", row["findings"], "int", population)
            _value(builder, f"exposure.{key}.cves_{when}", row["distinct_cves"], "int", population)
            _value(builder, f"exposure.{key}.fix_available_{when}", row["fix_available"], "int", population)
            if row["kev_listed_findings"] is not None:
                note = "KEV dateAdded on or before the as of day, from bronze kev"
                _value(
                    builder,
                    f"exposure.{key}.kev_findings_{when}",
                    row["kev_listed_findings"],
                    "int",
                    population,
                    note,
                )
            if row["exploit_code_findings"] is not None:
                note = (
                    "a Metasploit module or Nuclei template naming the CVE first committed at or before "
                    "the as of time, from bronze exploit_signals"
                )
                _value(
                    builder,
                    f"exposure.{key}.exploit_findings_{when}",
                    row["exploit_code_findings"],
                    "int",
                    population,
                    note,
                )
                _value(
                    builder,
                    f"exposure.{key}.exploit_cves_{when}",
                    row["exploit_code_cves"],
                    "int",
                    population,
                    note,
                )
    population = "matcher against osv-scanner, six SBOMs, today"
    _value(builder, "exposure.disagreements.total", totals[0], "int", population)
    _value(
        builder, "exposure.disagreements.unexplained", totals[1], "int", population, "criterion C3 evidence"
    )
    if contrast_out.get("status") in ("complete", "partial"):
        every = contrast_out["all"]
        partial = None if contrast_out["status"] == "complete" else "partial: the NVD fetch had not finished"
        if every["share_a_cpe_matcher_could_not_make"] is not None:
            population = "findings today, six SBOMs"
            _value(
                builder,
                "exposure.contrast.share_no_cpe",
                every["share_a_cpe_matcher_could_not_make"],
                "pct1",
                population,
                partial,
            )
            _value(
                builder,
                "exposure.contrast.share_no_nvd_analysis",
                every["share_without_nvd_analysis"],
                "pct1",
                population,
                partial,
            )
    if status.get("status") == "complete":
        builder.table(
            "exposure.nvd_status",
            ["Product", "When", "As of", "NVD status", "Dated by", "Findings", "CVEs"],
            ["text", "text", "text", "text", "text", "int", "int"],
            status["rows"],
            origin=ORIGIN,
            population="findings of the six stand in SBOMs at each pin date and today, and their CVEs",
            source="match",
            note=status["note"],
        )
    if severity.get("status") == "complete":
        every = severity["all"]
        population = "findings today, six stand in SBOMs"
        _value(builder, "exposure.c9.findings_today", every["findings"], "int", population)
        _value(
            builder,
            "exposure.c9.nvd_only_usable",
            every["nvd_only_usable"],
            "int",
            population,
            severity["nvd_rule"],
        )
        _value(
            builder,
            "exposure.c9.any_source_usable",
            every["any_source_usable"],
            "int",
            population,
            severity["any_rule"],
        )
        _value(
            builder,
            "exposure.c9.nvd_only_usable_share",
            every["nvd_only_usable_share"],
            "pct1",
            population,
            severity["nvd_rule"],
        )
        _value(
            builder,
            "exposure.c9.any_source_usable_share",
            every["any_source_usable_share"],
            "pct1",
            population,
            severity["any_rule"],
        )
        builder.table(
            "exposure.c9_by_product",
            ["Product", "Findings", "Usable from the NVD alone", "Usable from any source"],
            ["text", "int", "int", "int"],
            [
                [n, c["findings"], c["nvd_only_usable"], c["any_source_usable"]]
                for n, c in severity["products"].items()
            ],
            origin=ORIGIN,
            population=population,
            source="match",
            note="C9 baseline: " + severity["nvd_rule"] + "; " + severity["any_rule"],
        )
    return builder.dump()


def nvd_status(pins: Mapping[str, Snapshot], todays: Mapping[str, Snapshot]) -> dict[str, Any]:
    """Findings and CVEs by NVD status as of each pin date and today, with the rule that dated each."""
    cves = {c for snaps in (pins, todays) for s in snaps.values() for f in s.findings for c in f.cves}
    records = baseline.nvd_records(BRONZE / "nvd_cves", cves)
    history = baseline.status_events(BRONZE / "nvd_changes", cves)
    if records is None:
        return {"status": "pending", "reason": "data/bronze/nvd_cves does not exist yet"}
    events, through = history if history is not None else ({}, None)
    rows: list[list[str | int]] = []
    detail: dict[str, Any] = {}
    for product in todays:
        detail[product] = {}
        for when, snap in (("pin", pins[product]), ("today", todays[product])):
            rows.extend(baseline.status_rows(product, when, snap.as_of, snap.findings, records, events))
            per_cve = {
                c: baseline.status_at(c, snap.as_of, records, events).model_dump(exclude={"cve_id"})
                for f in snap.findings
                for c in f.cves
            }
            detail[product][when] = {"as_of": stamp(snap.as_of), "cves": dict(sorted(per_cve.items()))}
    coverage = (
        f"the NVD change history fetched through {stamp(through)}"
        if through is not None
        else "no NVD change history in bronze yet"
    )
    note = (
        "each CVE dated by the first rule that applies: no NVD record, published after the as of time, "
        "the current record when it was fetched at or before the as of time, the newest change history "
        f"status event at or before it, else the current status ({coverage}); a finding counts once, "
        "under the most advanced status among its CVEs"
    )
    return {
        "status": "complete",
        "note": note,
        "history_through": stamp(through) if through is not None else None,
        "rules": baseline.RULES,
        "status_order": list(baseline.STATUS_ORDER),
        "rows": rows,
        "products": detail,
    }


def severity_baseline(todays: Mapping[str, Snapshot]) -> dict[str, Any]:
    """C9: the share of today's findings with a usable severity from the NVD alone and from any source."""
    cves = {c for s in todays.values() for f in s.findings for c in f.cves}
    usable = baseline.usable_severity(BRONZE / "cve_metrics", cves)
    if usable is None:
        return {"status": "pending", "reason": "data/bronze/cve_metrics does not exist yet"}
    per = {n: baseline.severity_counts(s.findings, usable) for n, s in todays.items()}
    every = baseline.severity_counts([f for s in todays.values() for f in s.findings], usable)
    total = every["findings"]
    return {
        "status": "complete",
        "as_of": stamp(next(iter(todays.values())).as_of),
        "nvd_rule": "usable from the NVD alone: an NVD CVSS 3.x base score on one of the finding's CVEs",
        "any_rule": (
            "usable from any source: a CVSS 3.x or 4.0 base score from the filer (CNA), the NVD or "
            "CISA ADP on one of the finding's CVEs"
        ),
        "source": "data/bronze/cve_metrics",
        "products": per,
        "all": {
            **every,
            "nvd_only_usable_share": every["nvd_only_usable"] / total if total else None,
            "any_source_usable_share": every["any_source_usable"] / total if total else None,
        },
    }


def downstream(
    pins: Mapping[str, Snapshot],
    todays: Mapping[str, Snapshot],
    totals: tuple[int, int],
    grype_data: Mapping[str, Any] | None,
    today: datetime,
) -> dict[str, Any]:
    """Everything that follows the engines, from findings alone: contrast, baseline, status, C9, part."""
    contrast_out = write_contrast({n: list(s.findings) for n, s in todays.items()}, grype_data)
    kev = kev_dates()
    every_cve = {c for snaps in (pins, todays) for s in snaps.values() for f in s.findings for c in f.cves}
    seen = baseline.exploit_first_seen(BRONZE / "exploit_signals", every_cve)
    summary = {
        "as_of_today": stamp(today),
        "kev_source": "data/bronze/kev" if kev else "pending: data/bronze/kev is not built",
        "exploit_code": "data/bronze/exploit_signals"
        if seen is not None
        else "pending: data/bronze/exploit_signals is not built",
        "products": {
            n: {"pin": summary_row(pins[n], kev, seen), "today": summary_row(todays[n], kev, seen)}
            for n in todays
        },
    }
    write_json(RESULTS / "summary.json", summary)
    status = nvd_status(pins, todays)
    write_json(RESULTS / "nvd_status.json", status)
    severity = severity_baseline(todays)
    write_json(RESULTS / "severity.json", severity)
    write_json(PART, manifest_part(summary, totals, contrast_out, status, severity, today.date().isoformat()))
    OLD_PART.unlink(missing_ok=True)
    return {
        "contrast": contrast_out["status"],
        "status": status["status"],
        "severity": severity,
        "summary": summary,
    }


def findings_document(results: Mapping[str, MatchResult], extra: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **extra,
        "products": {
            name: {
                "as_of": stamp(r.as_of),
                "stats": r.stats.model_dump(),
                "findings": [f.model_dump(mode="json") for f in r.findings],
            }
            for name, r in results.items()
        },
    }


def saved_snapshots(path: Path) -> dict[str, Snapshot]:
    data = read_json(path)
    return {
        name: Snapshot(
            as_of=products.parse_github_time(body["as_of"]),
            components=int(body["stats"]["components"]),
            findings=tuple(Finding.model_validate(f) for f in body["findings"]),
        )
        for name, body in data["products"].items()
    }


def write_contrast(
    findings_by_product: Mapping[str, Sequence[Finding]], grype_out: Mapping[str, Any] | None
) -> dict[str, Any]:
    out = contrast.contrast(findings_by_product, BRONZE / "nvd_cves", nvd_complete=nvd_fetch_complete())
    if grype_out is not None:
        view: dict[str, Any] = {}
        for product, runs in grype_out.get("products", {}).items():
            ours = {c for f in findings_by_product.get(product, []) for c in f.cves}
            cpe_run = grype.GrypeRun.model_validate(runs["cpe"])
            default_run = grype.GrypeRun.model_validate(runs["default"])
            cpe_only = cpe_run.cves("cpe-match")
            view[product] = {
                "grype_default_cves": len(default_run.cves()),
                "grype_cpe_match_cves": len(cpe_only),
                "matcher_cves": len(ours),
                "matcher_cves_a_cpe_match_also_finds": len(ours & cpe_only),
                "matcher_cves_grype_default_also_finds": len(ours & default_run.cves()),
            }
        out["grype"] = view
    write_json(RESULTS / "contrast.json", out)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--no-grype", action="store_true")
    parser.add_argument("--keep-grype-db", action="store_true")
    parser.add_argument(
        "--no-ghsa-fetch", action="store_true", help="read only the GHSA records already on disk"
    )
    parser.add_argument(
        "--from-saved",
        action="store_true",
        help="redo the contrast, baseline, NVD status, C9 and the manifest part from the saved findings",
    )
    parser.add_argument(
        "--ghsa-full-tree",
        metavar="SOURCE",
        help="data/cache/ghsa/advisory-database holds the whole reviewed tree, fetched from SOURCE",
    )
    args = parser.parse_args()
    if args.ghsa_full_tree:
        cache.mark_full_tree(CACHE, args.ghsa_full_tree)

    if args.from_saved:
        todays = saved_snapshots(RESULTS / "findings_today.json")
        saved = read_json(RESULTS / "disagreements.json")
        grype_path = RESULTS / "grype.json"
        done = downstream(
            saved_snapshots(RESULTS / "findings_pin.json"),
            todays,
            (int(saved["disagreements"]), int(saved["unexplained"])),
            read_json(grype_path) if grype_path.exists() else None,
            next(iter(todays.values())).as_of,
        )
        report(done)
        return 0

    today = datetime.now(UTC).replace(microsecond=0)
    config = products.load_config(PRODUCTS)
    sboms = load_sboms(config)
    with httpx.Client(timeout=300, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as http:
        if not all((BIN / p.name).exists() for p in tools.PINS):
            tools.install_all(BIN, http)
        ensure_osv(http)
        advisories, store_meta = build_store(sboms, http, fetch_ghsa=not args.no_ghsa_fetch)
    sources_lock = read_json(LOCKS / "osv.lock.json") if (LOCKS / "osv.lock.json").exists() else None
    files = osv_files(sources_lock)
    meta = {"osv_files": files, **store_meta, "tools": {p.name: p.version for p in tools.PINS}}

    at_pin, at_today = run_matcher(config, sboms, advisories, today)
    write_json(
        RESULTS / "findings_pin.json",
        findings_document(at_pin, {"as_of": "the pin date of each product", **meta}),
    )
    write_json(RESULTS / "findings_today.json", findings_document(at_today, {"as_of": stamp(today), **meta}))

    with tempfile.TemporaryDirectory(prefix="unsched-exposure-") as tmp:
        work = Path(tmp)
        scans, probes = run_osv_scanner(config, work)
        comparisons = {}
        for stand_in in config.stand_ins:
            name = stand_in.product
            result = at_today[name]
            comparisons[name] = disagreements.compare(
                name,
                sboms[name].components,
                result.findings,
                scans[name],
                advisories,
                today,
                probe=probes.get(name),
                quarantined_names=[q.name for q in sboms[name].quarantined],
                unparseable=result.unparseable_versions,
                q06_ids=[q.advisory_id for q in result.range_quarantine],
            )
        grype_out = None if args.no_grype else run_grype(config, work, keep_db=args.keep_grype_db)
    saved_grype = RESULTS / "grype.json"
    contrast_grype = (
        grype_out if grype_out is not None else (read_json(saved_grype) if saved_grype.exists() else None)
    )

    write_json(
        RESULTS / "osv_scanner.json",
        {
            "as_of": stamp(today),
            "version": tools.OSV_SCANNER.version,
            "flags": list(osvscanner.FLAGS),
            "database": "the same OSV all.zip files the matcher read (osv_files in findings_today.json)",
            "products": {
                n: {
                    "sbom": s.sbom,
                    "exit_code": s.exit_code,
                    "packages": [p.model_dump() for p in s.packages if p.ids],
                    "packages_listed": len(s.packages),
                }
                for n, s in scans.items()
            },
            "release_normalized_probe": {
                n: {"packages": [p.model_dump() for p in s.packages if p.ids]} for n, s in probes.items()
            },
        },
    )
    total = sum(len(c.disagreements) for c in comparisons.values())
    unexplained = sum(c.unexplained for c in comparisons.values())
    write_json(
        RESULTS / "disagreements.json",
        {
            "as_of": stamp(today),
            "target": "zero unexplained disagreements",
            "pairs_both": sum(c.pairs_both for c in comparisons.values()),
            "disagreements": total,
            "unexplained": unexplained,
            "reasons": disagreements.REASONS,
            "by_reason": _count_reasons(comparisons.values()),
            "products": {n: c.model_dump(mode="json") for n, c in comparisons.items()},
        },
    )
    if grype_out is not None:
        write_json(
            RESULTS / "grype.json", {"as_of": stamp(today), "version": tools.GRYPE.version, **grype_out}
        )
    write_json(
        RESULTS / "quarantine.json",
        {
            "Q07": {n: [q.model_dump() for q in s.quarantined] for n, s in sboms.items()},
            "Q06": {n: [q.model_dump() for q in r.range_quarantine] for n, r in at_today.items()},
        },
    )
    done = downstream(snapshots(at_pin), snapshots(at_today), (total, unexplained), contrast_grype, today)
    for n in at_today:
        print(
            f"exposure: {n}: {len(at_pin[n].findings)} findings at the pin, {len(at_today[n].findings)} today; "
            f"{len(comparisons[n].disagreements)} disagreements, {comparisons[n].unexplained} unexplained"
        )
    print(f"exposure: {total} disagreements with osv-scanner, {unexplained} unexplained")
    report(done)
    return 1 if unexplained else 0


def report(done: Mapping[str, Any]) -> None:
    every = done["severity"].get("all") if done["severity"].get("status") == "complete" else None
    c9 = (
        f"C9 usable severity {every['nvd_only_usable_share']:.1%} from the NVD alone, "
        f"{every['any_source_usable_share']:.1%} from any source"
        if every
        else "C9 pending"
    )
    print(
        f"exposure: contrast {done['contrast']}; NVD status {done['status']}; {c9}; part {PART.relative_to(ROOT)}"
    )


def _count_reasons(comparisons: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for comparison in comparisons:
        for item in comparison.disagreements:
            for reason in item.reasons or ("unexplained",):
                counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


if __name__ == "__main__":
    sys.exit(main())
