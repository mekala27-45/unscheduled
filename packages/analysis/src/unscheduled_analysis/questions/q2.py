"""Q2, after the change.

Plan: CVEs published since 2026-04-15; counts by NVD status; the share analyzed; the share of the
analyzed that are in KEV; the hours from KEV listing to NVD analysis. Prediction: most analyzed CVEs
since the change are KEV listed or critical software.

The hours are counted from the listing to the first NVD analysis event at or after it, against the
goal of one business day: the same time on the next weekday (a weekend listing has until the end of
Monday). Federal holidays are not removed, so the goal is read slightly tighter than NIST reads it.
"""

from __future__ import annotations

from typing import Any

import duckdb
import polars as pl

from unscheduled_analysis import bootstrap
from unscheduled_analysis.lake import frame
from unscheduled_analysis.result import Result

SEED = bootstrap.SEED + 2

SQL = """-- Q2: CVEs published since 2026-04-15 by NVD status, and the KEV listed among them with the
-- hours from listing to the first NVD analysis at or after the listing.
select
    nvd_status,
    count(*) as cves,
    count(*) filter (where nvd_analyzed) as analyzed,
    count(*) filter (where kev_listed) as kev_listed,
    count(*) filter (where kev_listed and analyzed_before_listing) as kev_analyzed_before_listing,
    median(hours_listing_to_analysis) as median_hours_listing_to_analysis
from gold.mart_backlog_q2
group by nvd_status
order by cves desc"""


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    r = Result(
        qid="Q2",
        title="After the change",
        subtitle="New CVEs since 15 April 2026 by NVD status, and how fast the NVD analyzes the ones in KEV",
        plan=plan,
        population="CVEs published since 2026-04-15",
        window="the shadow window, from 2026-04-15 to the data cut",
        data_cut=cut,
        sql=SQL,
        method=(
            "The status is the NVD vulnStatus at the data cut. A CVE counts as analyzed when the NVD change history "
            "shows an analysis event or its status is Analyzed or Modified. The hours run from the KEV listing (the "
            "first kev-data commit that carried it, which gives the hour, or the start of dateAdded when no commit "
            "falls on that day) to the first analysis event at or after it. Intervals are a cluster bootstrap by "
            "filer, 2,000 resamples, 95 percent."
        ),
        seed=SEED,
    )
    units = frame(con, "select * from gold.mart_backlog_q2 order by cve_id")
    r.value("cves", units.height, "int", r.population, "CVEs")
    rejected = units.filter(pl.col("state") == "REJECTED").height
    r.value("rejected", rejected, "int", "CVEs published since 2026-04-15 and since rejected", "CVEs")
    status = frame(con, SQL)
    r.table(
        "by_status",
        [
            "NVD status",
            "CVEs",
            "Analyzed",
            "KEV listed",
            "KEV analyzed before listing",
            "Median hours, listing to analysis",
        ],
        ["text", "int", "int", "int", "int", "hours1"],
        [list(row) for row in status.iter_rows()],
        "CVEs published since 2026-04-15, by their NVD status at the data cut",
    )
    for row in status.iter_rows(named=True):
        key = str(row["nvd_status"] or "none").lower().replace(" ", "_")
        r.value(
            f"status_{key}",
            row["cves"],
            "int",
            f"CVEs published since 2026-04-15 with NVD status {row['nvd_status']}",
            "CVEs",
        )
    keys = units.get_column("filer").to_list()
    analyzed = units.get_column("nvd_analyzed").cast(pl.Float64).to_numpy()
    r.interval(
        "share_analyzed",
        bootstrap.ratio(keys, analyzed, seed=SEED),
        "pct1",
        r.population,
        "share of CVEs the NVD analyzed",
    )
    a = units.filter(pl.col("nvd_analyzed"))
    r.value("analyzed", a.height, "int", "CVEs published since 2026-04-15 the NVD analyzed", "CVEs")
    if a.height:
        r.interval(
            "share_kev_among_analyzed",
            bootstrap.ratio(
                a.get_column("filer").to_list(),
                a.get_column("kev_listed").cast(pl.Float64).to_numpy(),
                seed=SEED,
            ),
            "pct1",
            "CVEs published since 2026-04-15 the NVD analyzed",
            "share of analyzed CVEs that are KEV listed",
        )
    kev = units.filter(pl.col("kev_listed"))
    r.value("kev_listed", kev.height, "int", "CVEs published since 2026-04-15 and listed in KEV", "CVEs")
    r.value(
        "kev_analyzed_before_listing",
        kev.filter(pl.col("analyzed_before_listing")).height,
        "int",
        "KEV listed CVEs published since 2026-04-15 the NVD analyzed before the listing",
        "CVEs",
    )
    after = kev.filter(pl.col("hours_listing_to_analysis").is_not_null())
    r.value(
        "kev_analyzed_after_listing",
        after.height,
        "int",
        "KEV listed CVEs published since 2026-04-15 with an NVD analysis event (initial, reanalysis or "
        "modified analysis) at or after the listing, including CVEs first analyzed before it",
        "CVEs",
    )
    r.value(
        "kev_not_analyzed",
        kev.filter(~pl.col("nvd_analyzed")).height,
        "int",
        "KEV listed CVEs published since 2026-04-15 with no NVD analysis by the cut",
        "CVEs",
    )
    if after.height:
        r.interval(
            "median_hours_listing_to_analysis",
            bootstrap.quantile(
                after.get_column("filer").to_list(),
                after.get_column("hours_listing_to_analysis").to_numpy(),
                0.5,
                seed=SEED,
            ),
            "hours1",
            "KEV listed CVEs published since 2026-04-15 analyzed at or after the listing",
            "hours from the KEV listing to the first NVD analysis",
        )
        r.interval(
            "p90_hours_listing_to_analysis",
            bootstrap.quantile(
                after.get_column("filer").to_list(),
                after.get_column("hours_listing_to_analysis").to_numpy(),
                0.9,
                seed=SEED,
            ),
            "hours1",
            "KEV listed CVEs published since 2026-04-15 analyzed at or after the listing",
            "hours, 90th percentile",
        )
    judged = kev.filter(pl.col("met_one_business_day").is_not_null())
    if judged.height:
        r.interval(
            "share_met_one_business_day",
            bootstrap.ratio(
                judged.get_column("filer").to_list(),
                judged.get_column("met_one_business_day").cast(pl.Float64).to_numpy(),
                seed=SEED,
            ),
            "pct1",
            "KEV listed CVEs published since 2026-04-15 whose one business day has passed by the cut",
            "share analyzed within one business day of the listing (or before it)",
        )
    listing_rules = frame(
        con,
        "select k.listed_dated_by, count(*) as n from gold.mart_backlog_q2 as q join silver.kev_events as k using (cve_id) "
        "group by 1 order by 1",
    )
    r.table(
        "listing_dated_by",
        ["Listing dated by", "KEV listed CVEs"],
        ["text", "int"],
        [list(row) for row in listing_rules.iter_rows()],
        "KEV listed CVEs published since 2026-04-15, by the rule that dated the listing",
    )
    r.depart(
        "prediction: critical software",
        "The prediction names KEV listed or critical software. No locked source says which software NIST counts "
        "as critical or as used by the federal government, so only the KEV share of the analyzed CVEs is measured.",
    )
    share = r.values.get("share_kev_among_analyzed", {}).get("value")
    r.prediction_check = (
        f"Of the CVEs the NVD analyzed since the change, {share} are KEV listed; the critical software part "
        "cannot be measured from the locked sources."
        if share is not None
        else "The NVD analyzed none of the CVEs published since the change by the cut."
    )
    return r
