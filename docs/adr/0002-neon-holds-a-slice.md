# 0002. Neon holds a slice; Parquet holds the history

Status: accepted, 7 November 2026

## Context

The console needs fast lookups, filters and a timeline per CVE for a person reading. The free Neon
plan gives 1 GB of storage per project (the billing page, read 7 November 2026). The full history of
every fact does not fit under that with room to spare, and most of it is never asked for.

## Decision

The API serves from Postgres on Neon: the current state of every CVE, full descriptions for CVEs
published since 1 January 2021 with a link to cve.org for older ones, the ruler events for the same
CVEs, the products, the findings and the backlog values. The full history stays in the lake file.
The sync measures the database after each chunk and refuses to pass the ceiling in
config/budgets.yaml, which keeps a 20 percent margin under the plan.

## Consequences

- Lookups are answered by indexed SQL, not by scanning Parquet over the network.
- A question about the full history is answered from the lake, by the analysis or the CLI, not by
  the API.
- The serving bundle is the contract between the two: a set of files with digests, built from the
  lake and loaded by the API (0007).

## Alternatives

Reading Parquet from object storage on each request (DuckDB in the function) would avoid the copy
but make every lookup pay a cold download. A paid Postgres would hold everything; the series rule
is free tiers with no card.
