# Results

Phase 1 of 5. Every number on this page comes from results/manifest.json, which the build writes
from what each step saved, and the claim gate in CI renders the page again and fails on any
difference. The lake behind the numbers was cut at 2026-11-12 (lake digest
66812c5bfe50).

## The lake

424,534 CVE records and 6,620,931 dated facts about them, each with its
source and the time it became known. The NVD change history behind the facts holds
2,325,791 events and covers 100.0% of the
months since it begins. The as-of engine answered 1,200 frames with
0 mismatches between its two implementations, and returned
0 of 480,000 facts planted after
the time asked. dbt built 45 models and passed 65
of 65 tests. Rows that failed a named rule were held back, never dropped:

| Rule | What it catches | Rows | CVEs |
|---|---|---:|---:|
| Q01 | vector does not parse | 2 | 1 |
| Q02 | score disagrees with its vector | 815 | 815 |
| Q03 | KEV listing before publication | 62 | 62 |
| Q04 | duplicate CVE in one snapshot | 0 | 0 |
| Q05 | rejected CVE that still carries metrics | 6 | 2 |
| Q06 | advisory range that does not parse in its scheme | 70 | 0 |
| Q07 | SBOM component without a package URL | 8 | 0 |
| Q08 | change event for an unknown CVE | 0 | 0 |

## The backlog

report/backlog.md answers each question in full. One line for each:

- Q1. The NVD analyzed 80.2% of new CVEs within 30 days before
  2025, 43.6% from 2025 to the change and
  40.4% since.
- Q2. Of 79,870 CVEs published since 15 April 2026 it has analyzed
  37.4%; 30,612 are Deferred; KEV
  listings met the one business day goal 96.9% of the time.
- Q3. For CVEs it has not analyzed, the filer gave a CVSS score for
  83.9% and affected versions for
  94.3%.
- Q4. Filer and NVD agree on the attack vector at kappa 0.84 and on the
  band at weighted kappa 0.49.
- Q5. Half of the KEV listed CVEs since 2021 were listed within
  26.0 days; 45.9%
  had no NVD analysis when listed.
- Q6. The ten filers that grew most carry 76.7% of the growth in
  volume since 2020.
- Q7. Across the six stand in products, 1,069 findings today;
  33.0% usable from the NVD alone,
  90.1% from any source.
- Q8. A classifier separates the CVEs the NVD analyzed from the ones it skipped at an AUC of
  0.886.

## The memos

- report/discovery.md, what the change means for the customer and the criteria it signed.
- report/legacy.md, why the nightly report went quiet and how the adapter replaces it.
- report/criteria.md, the criteria with the phase that produces the evidence for each.
- report/data_card.md, what the lake holds, how each fact is dated and what it cannot tell you.

## The checklist

A line is marked done when the file its step writes exists, which shows that the step ran and
says nothing about whether its output is right.

| Item | Status | Line | Evidence |
|---:|---|---|---|
| 1 | done | The setup done by the build with no typed secret; the probes ran first | results/probe.json, results/probe_platform.json, results/setup.json |
| 2 | done | Every source fetched and locked by digest with licences and terms recorded | results/lake/locks.json, data/PROVENANCE.md |
| 3 | done | Every change to every CVE dated; the as-of engine passes parity and the planted future fact test | results/lake/asof_tests.json |
| 4 | done | dbt contracts and tests pass; quarantine counts in the manifest; status vocabulary registered | results/lake/dbt_results.json, config/labels.yaml |
| 5 | done | The month criteria and the Phase 1 plan hashed before any test CVE was scored | evaluation/registration.json |
| 6 | done | Q1 to Q8 answered with intervals and every chart with its table and SQL | results/backlog/q1.json, results/backlog/q8.json |
| 7 | done | The customer name checked; six stand ins pinned by rule; SBOMs committed | results/name_check.json, config/products.yaml |
| 8 | done | The matcher and osv-scanner agree; the CPE contrast measured | results/exposure/disagreements.json, results/exposure/summary.json |
| 9 | done | The legacy script characterized and replaced by the adapter | report/legacy.md |
| 10 | not done | The API live on Vercel with Neon, loaded only by the sync, verified from a separate client | results/live/api_verify.json |
| 11 | not done | Persistence observed independently; schemathesis green; the load test with the cold start | results/load/c8.json |
| 12 | done | The CLI gives the same answers as the API on the same inputs | results/cli_parity.json |
| 13 | done | The design system in place with the palette validator green in CI | web/styles/tokens.css, results/design/palette.json |
| 14 | not done | The console, the ruler, the landing, the docs and the report live on Vercel | results/live/web_verify.json |
| 15 | done | sloplint, axe and Lighthouse green; the look reviewed or marked pending | results/design/gates.json |
| 16 | done | README with the matrix, RESULTS, DECISIONS, the memos and notebooks; the humanizer pass | RESULTS.md, report/discovery.md, report/backlog.md, report/legacy.md, notebooks/01_the_first_backlog_chart.ipynb, notebooks/02_kappa_on_everything.ipynb, notebooks/03_the_matcher_without_schemes.ipynb, results/humanizer.json |
| 17 | not done | The live check awake and asleep; reset and rederive reproduced every number | results/live_check.json, results/rederive.json |
| 18 | not done | At least fifty conventional commits; v0.1.0 tagged; BUILD_STATE.md written for Phase 2 | results/release.json |

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
