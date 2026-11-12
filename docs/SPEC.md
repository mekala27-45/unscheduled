# unscheduled: the system specification

What the system is made of, what each part promises the next, and what each error means. The
decisions behind it are in docs/adr/. Numbers in this file are limits the code enforces, read from
config/budgets.yaml or set in code; no measured value is written here, because every measured value
comes from results/manifest.json through the renderer.

## 1. The parts and the path the data takes

```
public sources --fetch.yml--> raw (Release assets by digest) --> bronze (typed Parquet)
   --> silver (dated facts) --> gold (marts, the as-of engine) --> the lake file
   --> the serving bundle (data/serving/) --publish--> a serving-<stamp> release
   --POST /internal/sync, pulled by the API--> Neon (the slice) --> the API, the CLI, the web
```

| Part | Where | What it owns |
|---|---|---|
| Sources | packages/sources, scripts/fetch.py | one fetcher per source, locks with digests, the run ledger |
| Lake | packages/lake, dbt/ | dated facts, the as-of engine, the marts, the lake file, the bundle |
| Match | packages/match | package URLs, ranges in each ecosystem's scheme, findings as of a date |
| Legacy | packages/legacy_adapter | the customer's 2019 CSV, written from findings |
| API | packages/api, alembic/, Dockerfile.vercel | the sync, the slice in Neon, every route below |
| CLI | packages/cli | `unsched`, over the same functions as the API |
| Web | web/ | the landing, the console and the docs, reading the API through openapi.json |

GitHub Actions never writes to the database and holds no credential for it. The API reads the
newest release whose tag starts `serving-` from the public GitHub API, checks every file against
the digests in its manifest, and loads it itself (ADR 0007).

## 2. The serving bundle

Six files in one release. `packages/api/src/unscheduled_api/bundle.py` is the contract in code; this
section is the same contract in words. A file is trusted only when its sha256 matches the manifest
and, where GitHub reports an asset digest, that digest too.

`bundle_manifest.json`

```
{"generated_at": "...", "lake_digest": "...",
 "files": [{"file": "cve.parquet", "sha256": "<64 hex>", "rows": 0}, ...],
 "locks": {...optional, per source...}, "sources": {...optional, freshness per source...}}
```

It must name all five data files, each once. `rows` is checked against the Parquet row count when
present. `locks` and `sources`, when present, are served by /v1/meta and /health.

`cve.parquet`, one row per CVE. Required columns (values may be null): `cve_id`, `published`,
`last_modified`, `nvd_status`, `nvd_status_since`, `filer`, `filer_type`, `description` (null before
2021, where the record links to cve.org), `cwes` (a list of text), `filer_cvss31_vector`,
`filer_cvss31_score`, `filer_cvss31_band`, `filer_cvss40_vector`, `filer_cvss40_score`,
`filer_cvss40_band`, `nvd_cvss31_vector`, `nvd_cvss31_score`, `nvd_cvss31_band`, `adp_cvss31_vector`,
`ssvc_exploitation`, `ssvc_automatable`, `ssvc_technical_impact`, `kev_date_added`,
`kev_ransomware`, `epss_score`, `epss_date`, `exploit_first_seen`, `has_cpe`, `provenance_json`.
Optional: `state`, `adp_cvss31_score`, `adp_cvss31_band`, `epss_percentile`; a missing optional
column loads as null and is named in the data version under `absent_columns`.

`provenance_json` is a JSON object keyed by field: `{"nvd_status": {"source": "nvd@nist.gov",
"known_from": "2026-04-22T03:00:00Z", "rule": "nvd change history"}}`. It is what lets the API answer
every field with its source and the time it became known.

`cve_event.parquet`, the ruler events: `cve_id`, `at`, `kind`, `source`, `detail_json`. An event that
sets a field says so in its detail, `{"field": "nvd_status", "value": "Analyzed"}`, and the as-of
view reads those; every event is drawn on the ruler. An event's key is a digest of its content, so
the same event twice is stored once.

`product.parquet`: `product_id` or `product` (the name packages/match uses), and any further
columns, kept whole. `finding.parquet`: `product_id` or `product`, `as_of` (the snapshot date, or a
time, read as its UTC date), the CVEs it names (`cve_id`, or `cve_aliases` and `upstream_cves` as
packages/match writes them), and any further columns, kept whole. `backlog.json` is any JSON object
or list; /v1/backlog serves it as it is.

## 3. The sync

`POST /internal/sync` (and `GET`, for the Vercel cron, which only sends GET) does one bounded step
and answers. It takes no input: the owner, the repository, the tag prefix and the file names are
constants in `releases.py`, and query strings and bodies are ignored.

Every call is one transaction that opens with `pg_try_advisory_xact_lock` on a fixed key. A second
caller gets `sync-busy` at once. A failed call rolls back whole, so the next call repeats the step.
The cursor lives in the settings table under `sync`, so any container instance takes the next step.

```
current state                      what one call does
nothing loading, checked < 60 s    answers current; costs the lock and one small query
nothing loading                    lists releases (with the last ETag; a 304 costs no rate limit),
                                   downloads the newest manifest, compares its digest with the
                                   loaded one: current, or start loading it (status more)
loading                            the next step of: sweep cve, load cve, sweep cve_event, load
                                   cve_event, sweep product, load product, sweep finding,
                                   load finding, backlog, finalize
```

A sweep deletes the rows whose key the new file no longer holds, before that table loads, so the
storage peak stays near one copy of the slice. A load takes one chunk (cve 20,000 rows, cve_event
100,000, finding 50,000, product 20,000), copies it into a temporary table and upserts by key, writing
only the rows whose digest changed. Before a chunk is written, the database size plus the size of
the rows that would change, times three for indexes and TOAST, is compared with
`neon.storage_ceiling_mb` (decimal megabytes); past it the call refuses with `storage-ceiling` and
writes nothing. Finalize writes the data version, the row counts and the freshness of each source,
and drops the cursor.

The answer the publish workflow loops on:

| HTTP | `status` (body) or `context.status` (problem) | What the caller does |
|---|---|---|
| 200 | `more` | call again |
| 200 | `done` | stop: the newest release is loaded, `data_version` names it |
| 200 | `current` | stop: nothing newer to load |
| 409 | `busy` | wait for Retry-After, call again |
| 429 | `rate_limited` | wait for Retry-After (the sync takes 30 calls a minute) |
| 502 | `refused`, reason bundle | stop and alert: the bundle failed a check, nothing from it is served |
| 503 | `refused`, reason upstream | wait for Retry-After: GitHub did not answer or refused |
| 507 | `refused`, reason storage | stop and alert: raise the ceiling by a dated decision, or shrink the slice |

Each 200 carries `step`, `step_index`, `steps`, `chunk` (table, offset, rows in, rows changed, rows in
the file), `chunks_done`, `chunks_total` and the storage measured after the step. Every call that did
work writes one row to `ops_run`, the run ledger.

## 4. The slice in Neon

Schema `unscheduled`, with the Alembic version table inside it, so another project in the same
database never reads these migrations. Migrations run in process when the container starts, under a
transaction level advisory lock, so two instances starting together run them once.

| Table | Rows |
|---|---|
| cve | the current state of each CVE, every field with its provenance; `row_digest` |
| cve_event | the ruler events, keyed by a digest of their content |
| product | the stand ins, `body` holding every column of the bundle row |
| finding | findings per product and snapshot date, `cve_ids` the CVEs each names |
| match_log | per uploaded SBOM: sha256, size, format, counts, time taken, status, hashed client |
| client_budget | per hashed client, UTC day and kind: the count |
| ops_run | the run ledger of the sync: step, rows in, rows changed, storage, status |
| settings | `client_salt`, `data_version`, `sync`, `release_check`, `backlog` |

The uploaded SBOM is never stored. The client address is never stored; the client is the first 32
hex digits of sha256(salt:address), with a salt the API makes on its first start.

## 5. The API

Every JSON response carries `statement` (the statement in packages/core) and `data_version` (the
newest complete bundle, `<tag>+<first 12 hex of its manifest digest>`, or `none`), and every
response carries the `X-Data-Version` header. The CSV carries the statement in
`X-Unscheduled-Statement`, since its bytes belong to the customer's format.

| Route | Answers |
|---|---|
| GET /health | status (ok, or degraded when the configured database does not answer), ready, the database facts (server version, pgvector available and installed, size against the ceiling, the migration, the names of the connection variables found), the data version, the counts, the freshness, the last sync, the newest release seen |
| GET /v1/meta | the version, the statement, the NVD notice, the GitHub Advisory Database attribution, lock digests, the bundle files with their digests, the limits |
| GET /v1/cves/{id} | every field with value, source, known_from and the rule that dated it; `as_of=YYYY-MM-DD` for the end of that day in UTC |
| GET /v1/cves | filters `published_from`, `published_to`, `nvd_status`, `kev`, `filer`, `filer_type`, `cwe`, `has_filer_score`; newest published first; `limit` 1 to 100; `cursor` |
| GET /v1/cves/{id}/timeline | the ruler events by time, then kind, then id |
| GET /v1/backlog | backlog.json as loaded |
| GET /v1/products | the stand ins with every column of their row |
| GET /v1/products/{id}/exposure | `as_of` pin (the earliest snapshot), today (the newest, the default) or a date (the newest snapshot on or before it); findings, and each CVE as known that day |
| POST /v1/match | a CycloneDX JSON or SPDX 2 JSON body up to `sbom_upload_max_bytes`; findings by packages/match over the OSV records that name the SBOM's packages |
| GET /v1/legacy/report.csv | the legacy CSV from packages/legacy_adapter |
| POST and GET /internal/sync | section 3 |

The as-of rule (the same one the lake follows): a field with events takes its newest event at or
before T; a field without events takes its current value when its known_from is at or before T; a
current value with no known_from is left out of every as-of view; before publication nothing is
known. A cursor holds the published time and id of the last row served and a digest of the filters,
so it cannot be replayed against other filters, and pages never repeat or skip a row.

Live matching reads the advisories from the OSV API: package names and ecosystems leave the API,
the document does not. The command line can match against a local file of OSV records instead.

The budget: each hashed client may make `client_budget_per_day.lookups` reads of /v1 data routes
and `sbom_matches` matches per UTC day; /health, /v1/meta and the sync are not counted. Every counted
response carries `X-Budget-Limit` and `X-Budget-Remaining`. CORS allows the origins in
`UNSCHED_CORS_ORIGINS`, a comma separated list, for GET, POST and OPTIONS.

Logs are one JSON object per line: method, route template, status, time taken, the first eight hex
digits of the hashed client. Never a connection value, a token, an SBOM or an address.

## 6. Problem types

Every error is `application/problem+json` (RFC 9457) with `type`, `title`, `status`, `detail`,
`instance`, the statement and the data version, and where it helps `retry_after_s`, `errors` (one per
field that did not validate) and `context`. The `type` is a link to one of these sections.

### problem-not-found

404. The CVE, product, snapshot or route does not exist in the serving slice. `context` names what
was asked for. A CVE that exists but is outside the slice is also not found; cve.org has it.

### problem-method-not-allowed

405. The path exists with other methods; the Allow header lists them.

### problem-invalid-request

422. A parameter did not validate: a CVE id that is not CVE-YYYY-NNNN, a date that is not a date, a
limit over 100. `errors` gives the location and the message of each.

### problem-invalid-cursor

400. The cursor was not issued by this listing, or was issued for different filters. Start the
listing again without it.

### problem-malformed-body

400. The body of POST /v1/match is not JSON.

### problem-unsupported-media-type

415. The upload was sent with a media type other than application/json,
application/vnd.cyclonedx+json or application/spdx+json. Send the file itself as the body, not a
form.

### problem-unsupported-sbom

422. The body is JSON but neither CycloneDX (bomFormat CycloneDX) nor SPDX 2 (spdxVersion SPDX-2.x),
or its component list is not a list. SPDX 3 and XML documents are not read.

### problem-payload-too-large

413. The upload is over `sbom_upload_max_bytes`, from its declared length or while it streams. The
command line has no such limit.

### problem-budget-exhausted

429. This client has used its daily budget of lookups or matches. Retry-After gives the seconds to
midnight UTC; `context` names the kind and the limit.

### problem-sync-rate-limited

429. The sync takes at most 30 calls a minute across all callers. Wait for Retry-After.

### problem-sync-busy

409. Another call holds the sync lock and is loading a step. Call again after Retry-After.

### problem-storage-ceiling

507. The next chunk would take the database past the ceiling in config/budgets.yaml. Nothing was
written. `context` has the size, the estimate and the ceiling. Raise the ceiling with a dated entry in
DECISIONS.md, or publish a smaller slice.

### problem-bundle-rejected

502. A file of the newest serving release failed a check: its digest, a missing asset, a missing
required column, a row count, a duplicate key. Nothing from that bundle is served, the load is set
aside, and the next call reads the release again. Publish a corrected release.

### problem-upstream-unavailable

503. GitHub (the release listing or a download) or the OSV API did not answer or refused. Retry-After
is the reset time GitHub reported when it reported one.

### problem-database-unavailable

503. No database is configured (none of DATABASE_URL_UNPOOLED, DATABASE_URL, POSTGRES_URL is set),
or it did not answer. The detail names the error class only, never a host or a connection value.

### problem-data-not-loaded

503. The database answers but no serving bundle has finished loading. Call the sync, or wait for the
publish workflow.

### problem-matcher-unavailable

503. This deployment's packages/match lacks the functions the API calls, so no finding is guessed.

### problem-legacy-unavailable

503. packages/legacy_adapter lacks `adapter.report`, or the stored findings do not carry the fields
of a packages/match Finding.

### problem-internal

500. The server failed while answering. The log has the error class and the frames, never the
request body.

## 7. The command line

`unsched` (packages/cli) runs the pipeline scripts (`probe`, `fetch`, `build`, `render`) and answers
from the same functions as the API (`sync`, `cve`, `cves`, `timeline`, `backlog`, `products`,
`exposure`, `match`, `legacy-report`), against the database named by the same variables. `serve` runs
the API. A data command prints the JSON the API would answer; a problem prints the same problem
document to stderr and exits 1. tests/cli runs every data command beside its route on the same
database and writes results/cli_parity.json when every answer agrees.

## 8. Deployment

`Dockerfile.vercel` builds the API container on Vercel from the repository alone: `uv sync --frozen
--no-dev`, then alembic.ini, alembic/ and config/ copied in, uvicorn on port 80. The Neon integration
writes the connection variables into the Vercel project; nobody types them. The container
migrates at start, makes the client salt if there is none, and serves /health even when the
database is missing, so the first deploy can be checked before Neon is linked.

```
DATABASE_URL_UNPOOLED, DATABASE_URL, POSTGRES_URL   read in that order; the first present is used
UNSCHED_CORS_ORIGINS                                 comma separated web origins
UNSCHED_DB_SCHEMA                                    default unscheduled
UNSCHED_MIGRATE_ON_START                             default on
UNSCHED_CACHE_DIR                                    where bundle files are kept by digest
```

## 9. Tests

tests/api runs against a real Postgres (UNSCHED_TEST_DATABASE_URL, else the local binaries, else
testcontainers; CI sets UNSCHED_REQUIRE_POSTGRES=1 so a missing database fails instead of skipping),
with a fixture bundle and a fake GitHub that answers as GitHub does. It covers the sync (digest
checks, idempotent reloads, sweeps, the lock, the rate limit, the ceiling), every route, the as-of
rule as a property test with a planted future fact, the budget and its salt, the upload limit,
CORS, the migrations against the table definitions, the committed openapi.json, schemathesis
against it, and scripts/check_persistence.py, which starts the API in a child process and reads what
it stored from a connection of its own. tests/cli holds the command line to the same answers.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
