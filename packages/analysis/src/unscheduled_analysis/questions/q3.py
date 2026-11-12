"""Q3, what the filer gives instead.

Plan: CVEs without NVD analysis, every window; the share with a filer CVSS 3.x, a filer CVSS 4.0, a
CWE, affected versions, a CISA ADP value; the top twenty filers. Prediction: most carry a filer CVSS
score; fewer carry affected versions.
"""

from __future__ import annotations

from typing import Any

import duckdb
import polars as pl

from unscheduled_analysis import bootstrap
from unscheduled_analysis.lake import frame
from unscheduled_analysis.result import Result

SEED = bootstrap.SEED + 3
MEASURES = (
    ("has_filer_cvss3", "a filer CVSS 3.x vector"),
    ("has_filer_cvss40", "a filer CVSS 4.0 vector"),
    ("has_filer_cwe", "a filer CWE"),
    ("has_affected_versions", "affected versions in the filer record"),
    ("has_adp_value", "a CISA ADP value (CVSS, CWE or SSVC)"),
    ("has_adp_cvss", "a CISA ADP CVSS vector"),
    ("has_adp_cwe", "a CISA ADP CWE"),
    ("has_adp_ssvc", "a CISA SSVC decision"),
)

SQL = """-- Q3: for CVEs the NVD has not analyzed, what the filer and CISA supplied, for the twenty filers
-- with the most such CVEs.
select
    filer,
    any_value(filer_type) as filer_type,
    count(*) as cves,
    avg(cast(has_filer_cvss3 as integer)) as filer_cvss3,
    avg(cast(has_filer_cvss40 as integer)) as filer_cvss40,
    avg(cast(has_filer_cwe as integer)) as filer_cwe,
    avg(cast(has_affected_versions as integer)) as affected_versions,
    avg(cast(has_adp_value as integer)) as cisa_adp_value
from gold.mart_backlog_q3
group by filer
order by cves desc, filer
limit 20"""


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    r = Result(
        qid="Q3",
        title="What the filer gives instead",
        subtitle="For CVEs the NVD has not analyzed: the share with a filer CVSS, a CWE, affected versions or a CISA ADP value",
        plan=plan,
        population="CVEs without NVD analysis, rejected CVEs excluded, every window",
        window="every window (a descriptive count)",
        data_cut=cut,
        sql=SQL,
        method=(
            "A CVE is without NVD analysis when the change history shows no analysis event and its NVD status is not "
            "Analyzed or Modified. What the filer gave is read from the facts current at the cut: its own CVSS 3.0 or "
            "3.1 vector, its CVSS 4.0 vector, a CWE id it named (not an NVD placeholder), affected versions in its "
            "record; CISA's from the ADP container and Vulnrichment. Intervals are a cluster bootstrap by filer, "
            "2,000 resamples, 95 percent."
        ),
        seed=SEED,
    )
    units = frame(con, "select * from gold.mart_backlog_q3 order by cve_id")
    r.value("cves", units.height, "int", r.population, "CVEs")
    keys = units.get_column("filer").to_list()
    for column, label in MEASURES:
        r.interval(
            f"share_{column.removeprefix('has_')}",
            bootstrap.ratio(keys, units.get_column(column).cast(pl.Float64).to_numpy(), seed=SEED),
            "pct1",
            r.population,
            f"share of CVEs with {label}",
        )
    any_cvss = (
        (units.get_column("has_filer_cvss3") | units.get_column("has_filer_cvss40"))
        .cast(pl.Float64)
        .to_numpy()
    )
    r.interval(
        "share_filer_cvss_any",
        bootstrap.ratio(keys, any_cvss, seed=SEED),
        "pct1",
        r.population,
        "share of CVEs with a filer CVSS 3.x or 4.0 vector",
    )
    top = frame(con, SQL)
    r.table(
        "top_filers",
        [
            "Filer",
            "Filer type",
            "CVEs",
            "Filer CVSS 3.x",
            "Filer CVSS 4.0",
            "Filer CWE",
            "Affected versions",
            "CISA ADP value",
        ],
        ["text", "text", "int", "pct1", "pct1", "pct1", "pct1", "pct1"],
        [list(row) for row in top.iter_rows()],
        "the twenty filers with the most CVEs the NVD has not analyzed",
    )
    windows = frame(
        con,
        "select split_window, count(*) as cves, avg(cast(has_filer_cvss3 or has_filer_cvss40 as integer)) as filer_cvss, "
        "avg(cast(has_filer_cwe as integer)) as filer_cwe, avg(cast(has_affected_versions as integer)) as affected, "
        "avg(cast(has_adp_value as integer)) as adp from gold.mart_backlog_q3 group by 1 order by min(published)",
    )
    r.table(
        "by_window",
        ["Window", "CVEs", "Filer CVSS", "Filer CWE", "Affected versions", "CISA ADP value"],
        ["text", "int", "pct1", "pct1", "pct1", "pct1"],
        [list(row) for row in windows.iter_rows()],
        "CVEs without NVD analysis by the window of config/splits.yaml they were published in",
    )
    cvss = r.values["share_filer_cvss_any"]["value"]
    affected = r.values["share_affected_versions"]["value"]
    r.prediction_check = (
        f"A filer CVSS is on {cvss} of them ({'most' if cvss is not None and cvss > 0.5 else 'not most'}); "
        f"affected versions on {affected} ({'fewer' if (cvss or 0) > (affected or 0) else 'not fewer'})."
    )
    return r
