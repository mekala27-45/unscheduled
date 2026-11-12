# 0001. DuckDB and Parquet, not a cluster, at this size

Status: accepted, 7 November 2026

## Context

The lake holds every CVE ever published, every value each source gave it, and every change the NVD
recorded since 2017: a few hundred thousand records and a few million dated facts. It is rebuilt
from bronze on one machine in CI and on a laptop, and it must give the same content digest every
time it is rebuilt from the same bronze.

## Decision

Bronze is typed Parquet, one folder per table. The warehouse is DuckDB, built by dbt-duckdb into one
lake file that is published as a release asset with its digest. The as-of engine and every question
read that file read only.

## Consequences

- A full rebuild runs on a free GitHub runner and on a laptop with no service to start.
- The digest of every published table is stable, so reset and rederive can prove a number came
  from the bronze it names.
- One writer at a time. That is fine for a nightly build; it is the reason the API serves a slice
  from Postgres instead of reading the lake file (0002).

## Alternatives

Spark or a hosted warehouse would add a cluster, a bill or an account for data that fits in memory.
Revisit when the facts outgrow one machine, which this data will not do within the month.
