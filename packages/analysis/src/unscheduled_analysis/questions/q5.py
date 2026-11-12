"""Q5, exploited, and when.

Plan: KEV listed CVEs published since 2021-01-01; the days from publication to listing; the share
with no NVD analysis at listing, as of; the share with exploit code before listing. Prediction: a
large share is listed within weeks; exploit code often precedes listing.

The NVD status at the moment of listing is read from the facts with the as-of join, so an analysis
that came after the listing never counts as having been there. A listing dated before the CVE's
publication is quarantine rule Q03 and is not timed.
"""

from __future__ import annotations

from typing import Any

import duckdb
import polars as pl

from unscheduled_analysis import bootstrap
from unscheduled_analysis.lake import frame, scalar
from unscheduled_analysis.result import Result

SEED = bootstrap.SEED + 5

SQL = """-- Q5: KEV listed CVEs published since 2021, days from publication to listing, the NVD status
-- as of the moment of listing, and exploit code seen before the listing.
select
    date_trunc('year', published) as published_year,
    count(*) as cves,
    median(days_to_listing) as median_days_to_listing,
    avg(cast(days_to_listing <= 30 as integer)) as listed_within_30_days,
    avg(cast(not nvd_analyzed_at_listing as integer)) as no_nvd_analysis_at_listing,
    avg(cast(exploit_before_listing as integer)) as exploit_code_before_listing
from gold.mart_kev_timing
group by 1
order by 1"""


def run(con: duckdb.DuckDBPyConnection, plan: dict[str, Any], cut: str) -> Result:
    r = Result(
        qid="Q5",
        title="Exploited, and when",
        subtitle="KEV listed CVEs published since 2021: days to listing, NVD analysis at the moment of listing, exploit code before it",
        plan=plan,
        population="KEV listed CVEs published since 2021-01-01, listings dated before publication (Q03) excluded",
        window="every window (a descriptive count)",
        data_cut=cut,
        sql=SQL,
        method=(
            "Days to listing run from the publication day to the KEV dateAdded. The NVD status at the listing is "
            "the nvd_status fact current at the listing moment (the as-of join over silver.cve_fact); a CVE counts "
            "as analyzed at listing when that status was Analyzed or Modified. Exploit code is the first commit of a "
            "Metasploit module or a Nuclei template naming the CVE, before the listing moment. Intervals are a "
            "cluster bootstrap by filer, 2,000 resamples, 95 percent."
        ),
        seed=SEED,
    )
    units = frame(con, "select * from gold.mart_kev_timing order by cve_id")
    r.value("cves", units.height, "int", r.population, "CVEs")
    q03 = scalar(
        con,
        "select count(*) from quarantine.quarantine as q join gold.cve_current as c using (cve_id) "
        "where q.rule_id = 'Q03' and c.published >= timestamptz '2021-01-01 00:00:00+00'",
    )
    r.value(
        "quarantined_q03",
        int(q03 or 0),
        "int",
        "KEV listings of CVEs published since 2021 dated before publication",
        "listings",
    )
    keys = units.get_column("filer").to_list()
    days = units.get_column("days_to_listing").cast(pl.Float64).to_numpy()
    r.interval(
        "median_days_to_listing",
        bootstrap.quantile(keys, days, 0.5, seed=SEED),
        "days1",
        r.population,
        "days from publication to listing",
    )
    r.interval(
        "p25_days_to_listing",
        bootstrap.quantile(keys, days, 0.25, seed=SEED),
        "days1",
        r.population,
        "days, 25th percentile",
    )
    r.interval(
        "p75_days_to_listing",
        bootstrap.quantile(keys, days, 0.75, seed=SEED),
        "days1",
        r.population,
        "days, 75th percentile",
    )
    for k in (7, 30, 90):
        r.interval(
            f"share_listed_within_{k}d",
            bootstrap.ratio(keys, (days <= k).astype(float), seed=SEED),
            "pct1",
            r.population,
            f"share listed within {k} days of publication",
        )
    no_analysis = (~units.get_column("nvd_analyzed_at_listing")).cast(pl.Float64).to_numpy()
    r.interval(
        "share_no_nvd_analysis_at_listing",
        bootstrap.ratio(keys, no_analysis, seed=SEED),
        "pct1",
        r.population,
        "share with no NVD analysis at the moment of listing",
    )
    for column, label in (
        ("exploit_before_listing", "Metasploit or Nuclei code"),
        ("metasploit_before_listing", "a Metasploit module"),
        ("nuclei_before_listing", "a Nuclei template"),
    ):
        r.interval(
            f"share_{column}",
            bootstrap.ratio(keys, units.get_column(column).cast(pl.Float64).to_numpy(), seed=SEED),
            "pct1",
            r.population,
            f"share with {label} before the listing",
        )
    yearly = frame(con, SQL)
    r.table(
        "by_year",
        [
            "Published",
            "CVEs",
            "Median days to listing",
            "Listed within 30 days",
            "No NVD analysis at listing",
            "Exploit code before listing",
        ],
        ["text", "int", "days1", "pct1", "pct1", "pct1"],
        [[str(row[0])[:4], *row[1:]] for row in yearly.iter_rows()],
        "KEV listed CVEs by the year they were published",
    )
    status = frame(
        con,
        "select coalesce(nvd_status_at_listing, 'not yet in the NVD') as s, count(*) from gold.mart_kev_timing group by 1 order by 2 desc",
    )
    r.table(
        "status_at_listing",
        ["NVD status at listing", "CVEs"],
        ["text", "int"],
        [list(x) for x in status.iter_rows()],
        "KEV listed CVEs by the NVD status as of their listing",
    )
    rules = frame(con, "select listed_dated_by, count(*) from gold.mart_kev_timing group by 1 order by 1")
    r.table(
        "listing_dated_by",
        ["Listing dated by", "CVEs"],
        ["text", "int"],
        [list(x) for x in rules.iter_rows()],
        "how each listing moment was dated",
    )
    within30 = r.values["share_listed_within_30d"]["value"]
    exploit = r.values["share_exploit_before_listing"]["value"]
    r.prediction_check = f"{within30} were listed within 30 days of publication and {exploit} had Metasploit or Nuclei code before the listing."
    return r
