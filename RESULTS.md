# Results

Phase 1 of 5. Every number on this page comes from results/manifest.json, which the build writes
from what each step saved, and the claim gate in CI renders the page again and fails on any
difference. The lake behind the numbers was cut at 2026-11-13 (lake digest
97ad3bce0c4b).

## The lake

424,978 CVE records and 6,629,800 dated facts about them, each with its
source and the time it became known. The NVD change history behind the facts holds
2,326,025 events and covers 100.0% of the
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
| Q05 | rejected CVE that still carries metrics | 4 | 2 |
| Q06 | advisory range that does not parse in its scheme | 70 | 0 |
| Q07 | SBOM component without a package URL | 8 | 0 |
| Q08 | change event for an unknown CVE | 0 | 0 |

## The backlog

report/backlog.md answers each question in full. One line for each:

- Q1. The NVD analyzed 80.2% of new CVEs within 30 days before
  2025, 43.6% from 2025 to the change and
  41.4% since.
- Q2. Of 80,312 CVEs published since 15 April 2026 it has analyzed
  37.2%; 30,632 are Deferred; KEV
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
  33.2% usable from the NVD alone,
  90.1% from any source.
- Q8. A classifier separates the CVEs the NVD analyzed from the ones it skipped at an AUC of
  0.887.

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
| 10 | done | The API live on Vercel with Neon, loaded only by the sync, verified from a separate client | results/live/api_verify.json |
| 11 | done | Persistence observed independently; schemathesis green; the load test with the cold start | results/load/c8.json |
| 12 | done | The CLI gives the same answers as the API on the same inputs | results/cli_parity.json |
| 13 | done | The design system in place with the palette validator green in CI | web/styles/tokens.css, results/design/palette.json |
| 14 | done | The console, the ruler, the landing, the docs and the report live on Vercel | results/live/web_verify.json |
| 15 | done | sloplint, axe and Lighthouse green; the look reviewed or marked pending | results/design/gates.json |
| 16 | done | README with the matrix, RESULTS, DECISIONS, the memos and notebooks; the humanizer pass | RESULTS.md, report/discovery.md, report/backlog.md, report/legacy.md, notebooks/01_the_first_backlog_chart.ipynb, notebooks/02_kappa_on_everything.ipynb, notebooks/03_the_matcher_without_schemes.ipynb, results/humanizer.json |
| 17 | done | The live check awake and asleep; reset and rederive reproduced every number | results/live_check.json, results/rederive.json |
| 18 | done | At least fifty conventional commits; v0.1.0 tagged; BUILD_STATE.md written for Phase 2 | results/release.json |

## The Phase 2 checklist

14 of the 18 lines are done. A line is done
only when its evidence says pass, and a file an earlier phase wrote counts here only with what Phase 2
writes into it.

| Item | Status | Line | Evidence |
|---:|---|---|---|
| 1 | done | The probes extended and read by every model step; the scoped model gate in CI with its three tests | results/probe.json |
| 2 | done | The Phase 2 plan hashed as registration stage two before any model saw a test CVE | evaluation/registration.json |
| 3 | done | The training sets built point in time, the leakage test passing, the sets published by digest | results/models/sets.json |
| 4 | done | Every model has a floor trained on the same rows; every comparison has a paired interval | results/models/floors.json, results/models/c1.json, results/models/c2.json |
| 5 | done | The affected product retrieval measured against the NVD CPE configurations | results/models/product.json |
| 6 | done | The exploitation model tuned on time ordered folds; the survival model checked in R | results/models/rank.json, results/models/survival.json |
| 7 | done | ModernBERT run on Kaggle by a committed request inside the GPU budget, or its fallback named; ONNX parity passing | results/parts/gpu.json, results/models/fallback.json, results/models/onnx.json |
| 8 | done | Calibration and conformal sets fit on development, with coverage on test | results/models/calibration.json, results/models/conformal.json, results/models/test_scoring.json |
| 9 | done | The plain and reweighted views reported with the effective sample size | results/models/reweighting.json |
| 10 | done | MLflow runs and the registry; the model cards rendered from the manifest | results/registry/registry.json, report/models.md, report/models/band.md |
| 11 | done | Test scored once by scripts/score_test.py; C1 and C2 evidence with their verdicts | results/models/c1.json, results/models/c2.json |
| 12 | done | EPSS beside every exploitation number; ties named | results/models/c2.json |
| 13 | done | Slices with Benjamini-Hochberg; the failure taxonomy in the manifest | results/models/test_scoring.json, results/parts/taxonomy.json |
| 14 | not done | The predictions in the serving bundle and the API; /v1/predict live; Neon under its ceiling | results/models/predictions.json, results/live/api_verify.json |
| 15 | not done | The console shows every prediction with its model, version and uncertainty; design gates green; the look reviewed by Ajay | results/design/gates.json, results/design/look_review.json |
| 16 | done | The docs, ADRs 0008 to 0010, report/models.md and notebooks 04 to 06; the humanizer pass done | docs/models.md, docs/adr/0008-predictions-from-a-batch.md, docs/adr/0009-the-gpu-as-a-committed-request.md, docs/adr/0010-the-fill-model-earns-its-place.md, report/models.md, notebooks/04_the_random_split.ipynb, notebooks/05_reading_the_misses.ipynb, notebooks/06_epss_on_day_30.ipynb, results/humanizer.json |
| 17 | not done | The live check awake and asleep; reset and rederive reproduced every CPU model number | results/live_check.json, results/rederive.json |
| 18 | not done | At least fifty conventional commits; the release record passing; v0.2.0 pushed by Ajay; BUILD_STATE.md written for Phase 3 | results/release.json |

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
