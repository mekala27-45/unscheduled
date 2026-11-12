"""Quarantine rule Q06: each distinct range version parsed once in its ecosystem's scheme.

The schemes are univers classes per OSV ecosystem (unscheduled_lake.ranges). A GIT range names
commits and is not checked; an ecosystem with no scheme in the table is counted as unknown, not
judged.
"""

import polars as pl
from unscheduled_lake.ranges import check_version


def model(dbt, session):
    dbt.config(materialized="table")
    distinct = dbt.ref("int_advisory_range_events").filter("range_type <> 'GIT'").aggregate(
        "base_ecosystem, range_type, version", "base_ecosystem, range_type, version"
    ).pl()
    out = {"base_ecosystem": [], "range_type": [], "version": [], "status": [], "reason": []}
    for eco, kind, version in distinct.iter_rows():
        status, reason = check_version(eco, kind, version)
        out["base_ecosystem"].append(eco)
        out["range_type"].append(kind)
        out["version"].append(version)
        out["status"].append(status)
        out["reason"].append(reason)
    return pl.DataFrame(
        out,
        schema={
            "base_ecosystem": pl.String,
            "range_type": pl.String,
            "version": pl.String,
            "status": pl.String,
            "reason": pl.String,
        },
    )
