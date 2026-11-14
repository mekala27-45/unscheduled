# Data card: the unscheduled lake

What the lake holds, where each part comes from, how each fact is dated, what was held back and what
the data cannot tell you. Every number here is read from results/manifest.json when the card is
rendered.

## What it is

One DuckDB file built from typed Parquet: 424,978 CVE records and 6,629,800
dated facts about them, cut at 2026-11-13. A fact is a CVE, a field, the source that
published the value, the value, and the interval in which it was known. The gold tables answer what
was known about any CVE on any day from those facts alone. The content digest of this build, taken
over every table's rows, is a49849f7ff75. The bronze it was built from is a lake
release, each archive listed with its digest in the release sums, and lake.yml publishes the lake file,
named by its digest, beside the serving bundle it fed.

## Sources

- The CVE List, every record and every change to it, from https://github.com/CVEProject/cvelistV5, fetched hourly.
- The NVD: its current record for each CVE (https://services.nvd.nist.gov/rest/json/cves/2.0) and its change history (https://services.nvd.nist.gov/rest/json/cvehistory/2.0), fetched daily.
- CISA KEV, the catalog of exploited CVEs, from https://github.com/cisagov/kev-data, fetched hourly.
- EPSS, the daily score files from FIRST, kept at its registered offsets after publication, fetched daily.
- OSV advisories for npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Debian, from https://osv-vulnerabilities.storage.googleapis.com, fetched daily.
- GitHub reviewed advisories, from https://github.com/github/advisory-database, fetched daily.
- CISA Vulnrichment, the ADP container with its SSVC decisions, from https://github.com/cisagov/vulnrichment, fetched daily.
- The CWE list, from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip, fetched daily.
- Exploit code: Metasploit modules from https://github.com/rapid7/metasploit-framework and Nuclei templates from https://github.com/projectdiscovery/nuclei-templates, fetched daily.
- The list of CVE numbering authorities, for each filer's type, from https://github.com/CVEProject/cve-website, fetched daily.

Each source's licence or terms, the day they were read and what the build keeps are in
data/PROVENANCE.md. Each raw file is locked by its digest, size, URL and fetch time, and
results/lake/locks.json lists the locks behind this cut.

## How a fact is dated

The NVD change history dates what the NVD and the filers changed from 1 January 2017 on:
2,326,025 events, covering 100.0% of the months
since it begins. 424,664 CVEs have dated history. 80,844
were published before the history begins; their values are dated by a named rule, and each such row
says which. CVEs published since 2017 with no history event: 312.
The CVE List is fetched every hour and the NVD history once a day, so the newest records, published
around or after the last daily fetch, have no history event until the next one.

## The windows

- train: 1999-01-01 to 2023-12-31
- development: 2024-01-01 to 2024-12-31
- test: 2025-01-01 to 2026-03-31
- gap: 2026-04-01 to 2026-04-14, between test and the NVD change
- shadow: 2026-04-15 to open

Descriptive counts may cover every window. An analysis that compares labels uses train,
development and shadow only, never test, which is held for Phase 2.

How many CVEs each window holds, and how many of the published ones carry a CVSS severity band
from the NVD, from the filer and from CISA ADP: the labels a model can learn from, window by
window.

| Window | CVEs | Published | NVD band | Filer band | CISA ADP band | NVD and filer band |
|---|---:|---:|---:|---:|---:|---:|
| train | 234,630 | 220,803 | 101,427 | 46,113 | 11,981 | 39,128 |
| development | 40,675 | 39,924 | 23,272 | 27,947 | 10,339 | 16,732 |
| test | 66,229 | 63,304 | 22,453 | 49,497 | 11,388 | 18,161 |
| gap | 3,130 | 3,101 | 1,017 | 2,623 | 699 | 905 |
| shadow | 80,312 | 78,676 | 7,782 | 60,973 | 13,548 | 5,818 |
| outside | 2 | 0 | 0 | 0 | 0 | 0 |

## The labels

The NVD status values this build has seen, each registered with its meaning in config/labels.yaml
before any analysis read it: Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected. A value that is not
registered stops the fetch until a person adds it.

## What was held back

Rows that fail a named rule are kept in the quarantine tables with the rule they failed, never
dropped:

| Rule | What it catches | Rows | CVEs |
|---|---|---:|---:|
| Q01 | vector does not parse | 2 | 1 |
| Q02 | score disagrees with its vector | 815 | 815 |
| Q03 | KEV listing before publication | 62 | 62 |
| Q04 | duplicate CVE in one snapshot | 0 | 0 |
| Q05 | rejected CVE that still carries metrics | 4 | 2 |
| Q06 | advisory range that does not parse in its scheme | 70 | 0 |
| Q07 | SBOM component without a package URL | 8 | 0 |
| Q08 | change event for an unknown CVE | 0 | 0 |

## The tables

| Table | Rows |
|---|---:|
| config.bronze_tables | 13 |
| config.filer_types | 634 |
| config.lake_build | 1 |
| config.splits | 5 |
| config.status_labels | 7 |
| gold.cve_current | 424,978 |
| gold.mart_backlog_q1 | 277,391 |
| gold.mart_backlog_q2 | 80,312 |
| gold.mart_backlog_q3 | 80,526 |
| gold.mart_backlog_q6 | 9,909 |
| gold.mart_domain_shift | 78,676 |
| gold.mart_filer_vs_nvd | 47,641 |
| gold.mart_kev_timing | 1,025 |
| quarantine.quarantine | 961 |
| quarantine.quarantine_counts | 8 |
| silver.advisory_versions | 405,474 |
| silver.cve_fact | 6,629,800 |
| silver.exploit_first_seen | 7,278 |
| silver.kev_events | 1,779 |
| silver.nvd_status_history | 1,023,092 |

## What the data cannot tell you

- Filer scores are labels from parties with an interest in them, and the NVD's scores are labels
  made by people too. The agreement between them (report/backlog.md, Q4) is between two labels,
  neither of them the true severity.
- NVD analysis after 15 April 2026 is a selected sample: the NVD chooses what to analyze (Q8), so a
  model trained on NVD labels alone learns that choice.
- KEV is a lower bound on exploitation.
- EPSS is kept at 0, 1, 7, 30 and 90 days after publication, and every day only for KEV listed
  CVEs.
- The API serves a slice: CVEs published since 1 January 2021 and every KEV listed CVE. The lake
  holds them all.
- History before 2017 is dated by rule, not by event.

## Uses

Built to measure the NVD backlog and to find a fictional customer's exposure, in a portfolio
demonstration. It is not for security, legal or regulatory decisions, and no value in it is an
official score.

## Rebuild it

scripts/restore_release.py restores the bronze of a lake release, and scripts/build_lake.py builds
the lake from it. scripts/reset_and_rederive.py does both in a fresh worktree and compares every
number with the committed manifest (results/rederive.json).

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
