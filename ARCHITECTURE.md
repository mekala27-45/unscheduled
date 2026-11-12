# Architecture

unscheduled is a small data platform with a product on top. Public sources come in through one
fetcher each, every value anyone published about a CVE is kept with the time it became known, and
everything a page or the API shows is computed from that record by code that a test can rerun.

```
  SOURCES   CVE List V5 . NVD CVE API and change history . KEV . EPSS . OSV .
            GitHub advisories . Vulnrichment . CWE . Metasploit and Nuclei history
               |  fetch.yml in Actions; a lock with a digest per file; the run ledger
               v
  RAW       as fetched, never edited, kept as release assets named by digest
               |  packages/sources parses each source into typed Parquet
               v
  BRONZE    records, metrics by source, weaknesses, NVD status and change events,
            KEV, EPSS at fixed offsets, advisories and ranges, SSVC, exploit signals
               |  packages/lake and dbt
               v
  SILVER    cve_fact: one row per CVE, field, source and value, with known_from,
            known_to and the rule that dated it; status history; advisory versions
               |
               v
  GOLD      cve_current, the backlog marts, filer against NVD, KEV timing, the
            domain shift sample, exposure; contracts on every model; the lake file
       +-------------------+--------------------+
       v                   v                    v
  ANALYSIS             MATCH                 SERVE
  Q1 to Q8, the        SBOMs by Syft, the    the serving bundle in a public
  manifest, the        matcher in code,      release, pulled by the API into
  rendered documents   osv-scanner, Grype    Neon; FastAPI on Vercel; the CLI
       +-------------------+--------------------+
               v
  WEB       landing, console, docs and report on Vercel, every number from the API
            or the manifest
```

## The dated fact

The unit of the lake is a fact: a CVE, a field (a CVSS vector, a severity, a CWE, the NVD status, a
KEV listing, an SSVC decision point, the first exploit code), the source that published it, the
value, and the interval in which it was known. The NVD change history dates what the NVD and the
filers changed from 2017 on; the CVE List deltas date every snapshot from the first fetch on; KEV,
Vulnrichment and the exploit repositories date their own entries; EPSS dates its scores. A value
with no dated event is dated by a named rule, and the row says which rule, so an analysis can count
how much of its answer rests on rules rather than events.

The as-of engine answers one question: what was known about these CVEs at time T. It is written
once in SQL, exposed as a Python function in packages/lake and as a dbt macro, and two tests hold it
to that: a parity test runs both on the same sample and requires identical frames, and a property
test plants a fact known after T and fails if the engine ever returns it.

## Why the parts are where they are

- DuckDB and Parquet, not a cluster: the whole history fits on one machine, and at this size a
  cluster would add cost and nothing else (ADR 0001).
- Neon holds a slice and Parquet the history: the API serves the current state and the ruler events
  for recent CVEs from a free Postgres, and the full history stays in the lake file (ADR 0002).
- Facts dated by events: snapshots alone cannot say when a value appeared, and the change history
  can (ADR 0003).
- The matcher in code, checked by a second engine: every finding comes from a range evaluated in its
  own version scheme, osv-scanner checks every one, and a disagreement needs a reason (ADR 0004).
- The API pulls its data, so GitHub Actions holds no database credential. The build publishes a
  serving bundle as a public release with a digest for every file, and the API loads it in chunks
  when asked, checking each digest, inside an advisory lock, under a storage ceiling (ADR 0007).
- One design source: every color and face on the site comes from a token in web/styles/tokens.css,
  and a validator in CI checks the chart palette (ADR 0006).

## Where to read further

- docs/SPEC.md: the system as a specification, every interface and invariant
- docs/adr/: the decisions above, one file each
- docs/ROADMAP.md: the four phases still to come
- DECISIONS.md: every choice of a window, a rule, a threshold or a name, with its source
- AGENTS.md: how to set up, test and change the repository
