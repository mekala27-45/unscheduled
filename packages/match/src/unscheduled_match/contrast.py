"""The CPE contrast: for every finding, whether its CVE has an NVD CPE configuration and any NVD analysis.

A matcher that works from NVD CPE names can only make a finding whose CVE the NVD has configured. The
NVD record of each CVE comes from bronze nvd_cves (the newest state bronze holds for the CVE). When
that table does not exist yet the contrast is written as pending, never guessed; while the NVD fetch
is still filling it, the contrast says how many of the findings' CVEs the table already holds.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from unscheduled_core.model import StrictModel

from unscheduled_match.matcher import Finding

# vulnStatus values that mean the NVD analyzed the CVE (Modified follows an analysis).
ANALYZED = frozenset({"Analyzed", "Modified"})


class NvdState(StrictModel):
    cve_id: str
    vuln_status: str
    has_cpe: bool
    cpe_count: int


def table_files(table: Path) -> list[Path]:
    return sorted(table.rglob("*.parquet")) if table.exists() else []


def load_states(table: Path, cves: Iterable[str]) -> dict[str, NvdState] | None:
    """The newest bronze state of each CVE asked for, or None when the table does not exist."""
    files = table_files(table)
    if not files:
        return None
    import duckdb

    wanted = sorted(set(cves))
    if not wanted:
        return {}
    con = duckdb.connect()
    try:
        con.execute("create temp table wanted(cve_id varchar)")
        con.executemany("insert into wanted values (?)", [(c,) for c in wanted])
        rows = con.execute(
            """
            select n.cve_id, n.vuln_status, coalesce(n.has_cpe, false), coalesce(n.cpe_count, 0)
            from read_parquet(?, hive_partitioning = true, union_by_name = true) n
            join wanted w using (cve_id)
            qualify row_number() over (
                partition by n.cve_id order by n.last_modified desc, n.fetched_at desc
            ) = 1
            """,
            [[str(f) for f in files]],
        ).fetchall()
    finally:
        con.close()
    return {
        str(r[0]): NvdState(cve_id=str(r[0]), vuln_status=str(r[1]), has_cpe=bool(r[2]), cpe_count=int(r[3]))
        for r in rows
    }


def product_contrast(findings: Sequence[Finding], states: Mapping[str, NvdState]) -> dict[str, Any]:
    cves = sorted({c for f in findings for c in f.cves})
    held = [c for c in cves if c in states]
    by_status = Counter(states[c].vuln_status for c in held)
    reachable = analyzed = no_cve = 0
    for finding in findings:
        own = [states[c] for c in finding.cves if c in states]
        if not finding.cves:
            no_cve += 1
        if any(s.has_cpe for s in own):
            reachable += 1
        if any(s.vuln_status in ANALYZED for s in own):
            analyzed += 1
    total = len(findings)
    return {
        "findings": total,
        "findings_without_cve": no_cve,
        "cves": len(cves),
        "cves_in_nvd_table": len(held),
        "cves_with_cpe_configuration": sum(1 for c in held if states[c].has_cpe),
        "cves_by_nvd_status": dict(sorted(by_status.items())),
        "findings_a_cpe_matcher_could_make": reachable,
        "share_a_cpe_matcher_could_not_make": (total - reachable) / total if total else None,
        "findings_with_nvd_analysis": analyzed,
        "share_without_nvd_analysis": (total - analyzed) / total if total else None,
    }


def contrast(
    findings_by_product: Mapping[str, Sequence[Finding]],
    table: Path,
    *,
    nvd_complete: bool,
) -> dict[str, Any]:
    all_cves = {c for findings in findings_by_product.values() for f in findings for c in f.cves}
    states = load_states(table, all_cves)
    if states is None:
        return {
            "status": "pending",
            "reason": f"{table} does not exist yet; the NVD fetch writes it",
            "table": str(table),
        }
    products = {name: product_contrast(findings, states) for name, findings in findings_by_product.items()}
    every = [f for findings in findings_by_product.values() for f in findings]
    return {
        "status": "complete" if nvd_complete else "partial",
        "note": None
        if nvd_complete
        else "the NVD full fetch had not finished; CVEs not yet in the table count as having no CPE "
        "configuration and no analysis, so the shares are upper bounds until it completes",
        "table": str(table),
        "cves": len(all_cves),
        "cves_in_nvd_table": len(set(states)),
        "products": products,
        "all": product_contrast(every, states),
    }
