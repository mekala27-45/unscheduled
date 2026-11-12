"""Every distinct vector parsed once by the cvss library (packages/lake, unscheduled_lake.cvss).

A vector that does not parse is kept here with the library's reason and goes to quarantine as Q01;
a stored score that disagrees with the score of its vector as written by more than 0.1 goes to
quarantine as Q02.
"""

import polars as pl
from unscheduled_lake.cvss import check


def model(dbt, session):
    dbt.config(materialized="table")
    vectors = dbt.ref("int_vectors_distinct").pl()
    rows = [check(str(version), str(vector)) for version, vector in vectors.iter_rows()]
    return pl.DataFrame(
        {
            "version": [r.version for r in rows],
            "vector": [r.vector for r in rows],
            "parses": [r.parses for r in rows],
            "base_vector": [r.base_vector for r in rows],
            "base_score": [r.base_score for r in rows],
            "vector_score": [r.vector_score for r in rows],
            "error": [r.error for r in rows],
        },
        schema={
            "version": pl.String,
            "vector": pl.String,
            "parses": pl.Boolean,
            "base_vector": pl.String,
            "base_score": pl.Float64,
            "vector_score": pl.Float64,
            "error": pl.String,
        },
    )
