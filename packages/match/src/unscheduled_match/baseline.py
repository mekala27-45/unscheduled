"""The exposure baseline at a time T: exploit code seen, the NVD status of each CVE as of T, and the
severity a finding can be ranked by (the C9 baseline).

Exploit code is seen at T when a Metasploit module or a Nuclei template naming the CVE was first
committed at or before T (bronze exploit_signals).

The NVD status of a CVE at T is dated by the first of these rules that applies, and every count
says which rule dated it:

    no_nvd_record            the CVE is not in bronze nvd_cves
    published_after          the NVD published the CVE after T, so at T it had no NVD status
    current_record           the record bronze holds was fetched at or before T: its status held at T
    change_history           the newest status event at or before T in the NVD change history
    current_status_fallback  no status event at or before T in the history fetched so far, so the
                             current status stands in for the status at T

Change history events become statuses by the rule of dbt/models/intermediate/int_nvd_status_events.sql,
so the baseline and the lake read the history the same way. Statuses that have no event of their
own (Awaiting Analysis, Undergoing Analysis, Deferred) cannot be dated from the history; a CVE in one
of them at T shows the status its last event gave it.

A finding names one or more CVEs. It counts once, under the most advanced status among them, in
STATUS_ORDER; a finding that names no CVE counts as No CVE.

The C9 baseline: a finding has a usable severity from the NVD alone when one of its CVEs carries an
NVD CVSS 3.x base score, and from any source when one of its CVEs carries a CVSS 3.x or 4.0 base
score from the filer (CNA), the NVD or CISA ADP (bronze cve_metrics).
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from unscheduled_core.model import StrictModel

from unscheduled_match.matcher import Finding

ANALYSIS_EVENTS = frozenset({"Initial Analysis", "Reanalysis", "Modified Analysis"})
STATUS_ORDER: tuple[str, ...] = (
    "Analyzed",
    "Modified",
    "Undergoing Analysis",
    "Awaiting Analysis",
    "Received",
    "Deferred",
    "Rejected",
    "Not in the NVD yet",
    "No NVD record",
    "No CVE",
)
RULES: dict[str, str] = {
    "no_nvd_record": "the CVE is not in bronze nvd_cves",
    "published_after": "the NVD published the CVE after the as of time",
    "current_record": "the NVD record bronze holds was fetched at or before the as of time",
    "change_history": "the newest status event at or before the as of time in the NVD change history",
    "current_status_fallback": (
        "no status event at or before the as of time in the history fetched so far; the current "
        "status stands in for it"
    ),
    "no_cve": "the finding names no CVE",
}
RULE_ORDER = tuple(RULES)
NVD_SCORE_VERSIONS = frozenset({"3.0", "3.1"})
ANY_SCORE_VERSIONS = frozenset({"3.0", "3.1", "4.0"})
ANY_SOURCE_TYPES = frozenset({"nvd", "cna", "adp"})


class ExploitSeen(StrictModel):
    cve_id: str
    first_seen: datetime
    metasploit: datetime | None = None
    nuclei: datetime | None = None


class NvdRecord(StrictModel):
    cve_id: str
    vuln_status: str
    published: datetime | None = None
    last_modified: datetime | None = None
    fetched_at: datetime | None = None


class StatusEvent(StrictModel):
    cve_id: str
    created: datetime
    change_id: str
    event_name: str
    status: str


class DatedStatus(StrictModel):
    status: str
    rule: str
    cve_id: str | None = None


class UsableScore(StrictModel):
    cve_id: str
    nvd_v3: bool  # an NVD CVSS 3.x base score
    any_source: bool  # a CVSS 3.x or 4.0 base score from the filer, the NVD or CISA ADP


def parquet_files(table: Path) -> list[Path]:
    return sorted(table.rglob("*.parquet")) if table.exists() else []


def _query(table: Path, sql: str, cves: Iterable[str], attempts: int = 3) -> list[tuple[Any, ...]] | None:
    """Rows of one bronze table for the CVEs asked for, or None when the table does not exist.

    Bronze is written by renaming finished files into place, but a run may compact a partition
    between listing its files and reading them, so a failed read lists the files again.
    """
    import duckdb

    wanted = sorted(set(cves))
    for attempt in range(attempts):
        files = parquet_files(table)
        if not files:
            return None
        if not wanted:
            return []
        con = duckdb.connect()
        try:
            con.execute("set TimeZone = 'UTC'")
            con.execute("create temp table wanted(cve_id varchar)")
            con.executemany("insert into wanted values (?)", [(c,) for c in wanted])
            return con.execute(sql, [[str(f) for f in files]]).fetchall()
        except (duckdb.IOException, duckdb.InvalidInputException):
            if attempt == attempts - 1:
                raise
            time.sleep(2.0)
        finally:
            con.close()
    return None


def exploit_first_seen(table: Path, cves: Iterable[str]) -> dict[str, ExploitSeen] | None:
    rows = _query(
        table,
        """
        select e.cve_id, min(e.first_seen),
               min(e.first_seen) filter (where lower(e.source) = 'metasploit'),
               min(e.first_seen) filter (where lower(e.source) = 'nuclei')
        from read_parquet(?, union_by_name = true) e
        join wanted w using (cve_id)
        where e.first_seen is not null
        group by e.cve_id
        """,
        cves,
    )
    if rows is None:
        return None
    return {
        str(r[0]): ExploitSeen(cve_id=str(r[0]), first_seen=r[1], metasploit=r[2], nuclei=r[3]) for r in rows
    }


def nvd_records(table: Path, cves: Iterable[str]) -> dict[str, NvdRecord] | None:
    """The newest state bronze holds for each CVE asked for."""
    rows = _query(
        table,
        """
        select n.cve_id, n.vuln_status, n.published, n.last_modified, n.fetched_at
        from read_parquet(?, hive_partitioning = true, union_by_name = true) n
        join wanted w using (cve_id)
        qualify row_number() over (
            partition by n.cve_id order by n.last_modified desc nulls last, n.fetched_at desc nulls last
        ) = 1
        """,
        cves,
    )
    if rows is None:
        return None
    return {
        str(r[0]): NvdRecord(
            cve_id=str(r[0]), vuln_status=str(r[1]), published=r[2], last_modified=r[3], fetched_at=r[4]
        )
        for r in rows
    }


def statuses_from_events(raw: Iterable[tuple[str, datetime, str, str]]) -> list[StatusEvent]:
    """The status each change event puts a CVE in, by the rule of int_nvd_status_events.sql."""
    by_cve: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)
    for cve_id, created, change_id, event_name in raw:
        by_cve[cve_id].append((created, change_id, event_name))
    out: list[StatusEvent] = []
    for cve_id in sorted(by_cve):
        analyzed = False
        for created, change_id, event_name in sorted(by_cve[cve_id]):
            status: str | None = None
            if event_name == "New CVE Received":
                status = "Received"
            elif event_name in ANALYSIS_EVENTS:
                analyzed = True
                status = "Analyzed"
            elif event_name == "CVE Modified" and analyzed:
                status = "Modified"
            elif event_name == "CVE Rejected":
                status = "Rejected"
            elif event_name == "CVE Unrejected":
                status = "Modified" if analyzed else "Received"
            if status is not None:
                out.append(
                    StatusEvent(
                        cve_id=cve_id,
                        created=created,
                        change_id=change_id,
                        event_name=event_name,
                        status=status,
                    )
                )
    return out


def status_events(
    table: Path, cves: Iterable[str]
) -> tuple[dict[str, list[StatusEvent]], datetime | None] | None:
    """Status events per CVE, oldest first, and the newest event time the fetched history holds."""
    rows = _query(
        table,
        """
        select c.cve_id, c.created, c.cve_change_id, c.event_name
        from read_parquet(?, hive_partitioning = true, union_by_name = true) c
        join wanted w using (cve_id)
        """,
        cves,
    )
    if rows is None:
        return None
    events: dict[str, list[StatusEvent]] = defaultdict(list)
    for event in statuses_from_events((str(r[0]), r[1], str(r[2]), str(r[3])) for r in rows):
        events[event.cve_id].append(event)
    through = _history_through(table)
    return dict(events), through


def _history_through(table: Path) -> datetime | None:
    import duckdb

    files = parquet_files(table)
    if not files:
        return None
    con = duckdb.connect()
    try:
        con.execute("set TimeZone = 'UTC'")
        row = con.execute(
            "select max(created) from read_parquet(?, hive_partitioning = true, union_by_name = true)",
            [[str(f) for f in files]],
        ).fetchone()
    finally:
        con.close()
    return row[0] if row else None


def status_at(
    cve_id: str, t: datetime, records: Mapping[str, NvdRecord], events: Mapping[str, Sequence[StatusEvent]]
) -> DatedStatus:
    record = records.get(cve_id)
    if record is None:
        return DatedStatus(status="No NVD record", rule="no_nvd_record", cve_id=cve_id)
    if record.published is not None and record.published > t:
        return DatedStatus(status="Not in the NVD yet", rule="published_after", cve_id=cve_id)
    if record.fetched_at is not None and record.fetched_at <= t:
        return DatedStatus(status=record.vuln_status, rule="current_record", cve_id=cve_id)
    earlier = [e for e in events.get(cve_id, ()) if e.created <= t]
    if earlier:
        latest = max(earlier, key=lambda e: (e.created, e.change_id))
        return DatedStatus(status=latest.status, rule="change_history", cve_id=cve_id)
    return DatedStatus(status=record.vuln_status, rule="current_status_fallback", cve_id=cve_id)


def _rank(item: DatedStatus) -> tuple[int, str, int, str]:
    status_rank = (
        STATUS_ORDER.index(item.status) if item.status in STATUS_ORDER else STATUS_ORDER.index("Rejected")
    )
    return status_rank, item.status, RULE_ORDER.index(item.rule), item.cve_id or ""


def finding_status(finding: Finding, by_cve: Mapping[str, DatedStatus]) -> DatedStatus:
    if not finding.cves:
        return DatedStatus(status="No CVE", rule="no_cve")
    return min((by_cve[c] for c in finding.cves), key=_rank)


def status_rows(
    product: str,
    when: str,
    t: datetime,
    findings: Sequence[Finding],
    records: Mapping[str, NvdRecord],
    events: Mapping[str, Sequence[StatusEvent]],
) -> list[list[str | int]]:
    """Rows of (product, when, as of, status, dated by, findings, CVEs), most advanced status first."""
    by_cve = {c: status_at(c, t, records, events) for f in findings for c in f.cves}
    finding_counts: dict[tuple[str, str], int] = defaultdict(int)
    for finding in findings:
        chosen = finding_status(finding, by_cve)
        finding_counts[(chosen.status, chosen.rule)] += 1
    cve_counts: dict[tuple[str, str], int] = defaultdict(int)
    for dated in by_cve.values():
        cve_counts[(dated.status, dated.rule)] += 1
    keys = sorted(
        set(finding_counts) | set(cve_counts),
        key=lambda k: _rank(DatedStatus(status=k[0], rule=k[1])),
    )
    stamp = t.strftime("%Y-%m-%dT%H:%M:%SZ")
    return [
        [
            product,
            when,
            stamp,
            status,
            rule,
            finding_counts.get((status, rule), 0),
            cve_counts.get((status, rule), 0),
        ]
        for status, rule in keys
    ]


def exploit_counts(
    findings: Sequence[Finding], t: datetime, seen: Mapping[str, ExploitSeen]
) -> tuple[int, int]:
    """Findings and distinct CVEs with exploit code first seen at or before T."""
    hit = {c for f in findings for c in f.cves if c in seen and seen[c].first_seen <= t}
    return sum(1 for f in findings if any(c in hit for c in f.cves)), len(hit)


def usable_severity(table: Path, cves: Iterable[str]) -> dict[str, UsableScore] | None:
    rows = _query(
        table,
        """
        select m.cve_id, lower(m.source_type), m.version
        from read_parquet(?, hive_partitioning = true, union_by_name = true) m
        join wanted w using (cve_id)
        where m.base_score is not null
        """,
        cves,
    )
    if rows is None:
        return None
    nvd: set[str] = set()
    anywhere: set[str] = set()
    for cve_id, source_type, version in rows:
        if source_type == "nvd" and str(version) in NVD_SCORE_VERSIONS:
            nvd.add(str(cve_id))
        if source_type in ANY_SOURCE_TYPES and str(version) in ANY_SCORE_VERSIONS:
            anywhere.add(str(cve_id))
    return {
        c: UsableScore(cve_id=c, nvd_v3=c in nvd, any_source=c in anywhere) for c in sorted(nvd | anywhere)
    }


def severity_counts(findings: Sequence[Finding], usable: Mapping[str, UsableScore]) -> dict[str, int]:
    nvd = sum(1 for f in findings if any(c in usable and usable[c].nvd_v3 for c in f.cves))
    anywhere = sum(1 for f in findings if any(c in usable and usable[c].any_source for c in f.cves))
    return {"findings": len(findings), "nvd_only_usable": nvd, "any_source_usable": anywhere}
