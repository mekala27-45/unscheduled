# Build state

The hand off between sessions and phases. Every session reads it first and updates it last. It is
rendered from its template in docs/templates by make render, so every number in it is read from
the manifest or a committed file: edit the template, then render.

## Where it stands

```
Phase            2 of 5, the models: the probes and the scoped model gate, the plan hashed as the
                 models stage 8e72e6298a18, the point in time sets, the floors, the fallback
                 text model (behind its floor), the exploitation models (the run with the numeric
                 kernels pinned, reproduced on a second processor), the survival models checked in
                 R, the ONNX exports at parity, calibration and conformal sets on development, the
                 shadow window weighted, and the misses read are in; the method notes, the six model
                 cards and ADRs 0008 to 0010 are written, read for AI tells, and fill in as results
                 land; the product models wait for a lake release with the CPE dictionary; the
                 prompt is claude/unscheduled-phase-2-prompt.md in the Project
Phase 1          the ground truth, tagged v0.1.0 on the commit that adds the release record;
                 its checklist 18 of 18 lines done (RESULTS.md)
Repository       public; every commit conventional; CI, web and exposure green on main
Vercel           unscheduled-api (container) at unscheduled-api.vercel.app
                 unscheduled (web) at unscheduled-triage.vercel.app: the landing with its
                 character field, the console, the docs with six archify diagrams, the
                 report, status and design
Neon             project unscheduled, free plan, ceiling 800 MB (config/budgets.yaml)
Data             the committed numbers come from the lake cut 2026-11-13T06:00:00+00:00
                 rebuilt here from the lake release lake-20261112
Look approval    approved by Ajay on the evening of 11 November, New York time, after the
                 landing, docs, report and ruler screens: everything is good so far
```

## Next action

Phase 2 runs from the hand off below, and DECISIONS.md holds every choice made on the way. Done: the
probes and the scoped model gate; the plan hashed as the models stage; the sets, 220,803 train,
39,924 development, 63,304 test and 78,676 shadow rows; the floors, where the band floor reaches a
development kappa of 0.669; the fallback text model, at 0.594; the exploitation models, where
LightGBM holds 49.6% of the development listings in its top five percent and the floor
40.9%, from the run with the numeric kernels pinned, the one of 4 runs that reproduced
on a second processor; the survival models, checked in R (pass); the ONNX exports
(pass); calibration, conformal sets and the shadow weights on development; the misses read; the
humanizer pass; the predict scenario of the load test, written and waiting for the batch. Waiting: the product models (step five), for the
first lake release that carries the CPE dictionary; the daily fetch carries it from its next run.
Next, in order: the product step in the models workflow with that release, then the operating
points frozen and hashed, the registry, test scored once, the batch and its serving measures, the
live check, reset and rederive with the test recheck, and the release record. Every script whose
numbers are committed runs with the numeric pins (AGENTS.md).

## Open problems

- Releases and tags come only from Ajay: this session cannot create a release or start a workflow
  that creates one, and its git access cannot push a tag, so v0.2.0 is pushed from his machine.
- Kaggle and Databricks secrets are not set. Step eight took its CPU fallback (DECISIONS.md, step
  eight takes the fallback), and KAGGLE_USERNAME with KAGGLE_KEY would let ModernBERT run; without
  the Databricks pair, the registry uses the file store.
- The CPE dictionary is fetched daily; the product models wait for the first lake release that
  carries it. No daily fetch had finished since cpe joined its schedule when this was written, and
  this session may not start one, so Ajay was asked to start fetch.yml by hand with the source cpe.
- The exploitation search picks its trees on noise: over four runs on the same rows, LightGBM's
  development recall in the top five percent moved by more than twenty points while the floor held
  within one. The numeric kernels are now pinned, so a run reproduces on any processor
  (DECISIONS.md, the pinned exploitation run reproduces, and is the model), but a reproducible draw
  is still one draw; a search that averages over seeds or folds is a change for a later phase.
- The schedules fire hours late and less often than they ask: the hourly fetch has run a few times
  a day since 12 November, and the daily fetch and lake build several hours after their times. The
  newest lake release changes with each hourly run until the next daily one, so the committed
  numbers come from the release before it (DECISIONS.md, 13 November).
- config/filers.yaml, as the first fetch wrote it, holds the listed filers without their record
  counts. The lake types the other assigners from the CVE List bronze, and the fetcher writes the
  counts again when the CNA list next changes (DECISIONS.md, 13 November).
- k6 cannot be downloaded on the build machine; the load test runs the same scenario on httpx
  (DECISIONS.md, 12 November).
- The legacy CSV dates a CVE outside the serving slice by its advisories, since the slice holds no
  record for it.

## The ground truth Phase 1 handed on

- The lake: cut 2026-11-13T06:00:00+00:00, content digest a49849f7ff75e3dfc19e73701b189cbea8ad7d37b79de233268f709bff1e4a78, file digest
  97ad3bce0c4bf0c19460db803a6b8ac67a82219a83125c8965a7fb1f7130f683, from the release lake-20261112.
- The registration: hash 78bf9cdfad9dc5f3ecb7b5251055be570c1c37d0ad0b054b5861f4e31afaa30c, over config/criteria.yaml, config/splits.yaml, config/budgets.yaml, evaluation/phase1_plan.yaml, config/labels.yaml, config/samples.yaml.
- The splits, by the date a CVE was published (config/splits.yaml):
  - train: 1999-01-01 to 2023-12-31, 234,630 CVEs
  - development: 2024-01-01 to 2024-12-31, 40,675 CVEs
  - test: 2025-01-01 to 2026-03-31, 66,229 CVEs
  - gap: 2026-04-01 to 2026-04-14, 3,130 CVEs
  - shadow: 2026-04-15 to open, 80,312 CVEs
- The status vocabulary (config/labels.yaml): Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected.
  Since 15 April 2026 Deferred is the value the NVD gives the CVEs it does not schedule.
- The label coverage by window: how many published CVEs carry a CVSS severity band from each
  source.

| Window | CVEs | Published | NVD band | Filer band | CISA ADP band | NVD and filer band |
|---|---:|---:|---:|---:|---:|---:|
| train | 234,630 | 220,803 | 101,427 | 46,113 | 11,981 | 39,128 |
| development | 40,675 | 39,924 | 23,272 | 27,947 | 10,339 | 16,732 |
| test | 66,229 | 63,304 | 22,453 | 49,497 | 11,388 | 18,161 |
| gap | 3,130 | 3,101 | 1,017 | 2,623 | 699 | 905 |
| shadow | 80,312 | 78,676 | 7,782 | 60,973 | 13,548 | 5,818 |
| outside | 2 | 0 | 0 | 0 | 0 | 0 |

- Q8: the domain classifier separates the CVEs the NVD analyzed from the rest of the shadow window
  at an AUC of 0.887 (0.824 to 0.927) on the held out half of 78,676 CVEs.
  The strongest feature toward skipped is published month (months since 2026-04), so part of the shift is
  time since the change; the next ones are filer or type: filer_Wordfence; filer or type: filer_WPScan; filer or type: filer_Patchstack; filer or type: filer_AMD.
  Toward analyzed: filer or type: filer_microsoft; filer or type: filer_Chrome; word: n8n; word: flowise; filer or type: filer_adobe.
- The API: the first lookup after 20.0 min idle took 147 ms; warm, p50
  95 ms and p95 265 ms over 300 lookups (lookups met (p95 265 ms against 1,500 ms); the triage run is measured in Phase 4).
- The look: approved by Ajay on the evening of 11 November, New York time; he asked for no change.
- Kaggle GPU hours: 8 for the month (config/budgets.yaml), none used in Phase 1.

## The hand off to Phase 3

- The models the API and the console serve, each the chosen version of its registered model, with
  its model file's digest (results/registry/registry.json):
  - unscheduled-band, version 3 (band model): frozen bge-small embeddings beside the filer and CISA block, logistic regression;
    model file 4a881a3821fb, from results/models/fallback.json, Actions run 43580024886
  - unscheduled-metrics, version 3 (metrics model): frozen bge-small embeddings beside the filer and CISA block, logistic regression;
    model file 4a881a3821fb, from results/models/fallback.json, Actions run 43580024886
  - unscheduled-cwe, version 3 (cwe model): frozen bge-small embeddings beside the filer and CISA block, logistic regression;
    model file 4a881a3821fb, from results/models/fallback.json, Actions run 43580024886
  - unscheduled-exploit, version 2 (exploitation model): LightGBM on the same features, tuned by Optuna on time ordered folds;
    model file 5a1143b352a2, from results/models/rank.json, Actions run 43590255274
  - unscheduled-survival, version 1 (survival Cox): lifelines Cox proportional hazards on the day 0 features without the text;
    model file 0e97cd191606, from results/models/survival.json, Actions run 43563265777
  - unscheduled-product, version 1 (product floor): normalized vendor and product strings, an exact match, then a token set ratio;
    no model file, from results/models/product.json, Actions run 43595717893
- The registry: MLflow's SQLite store, packed as results/registry/registry-27093b0cce17.tar.gz and attached to
  the release; results/registry/registry.json is the export the API and the console read, and
  scripts/build_registry.py --check holds it to the run records.
- C1 is not met: the band's test kappa is 0.591 (0.364 to 0.693), the floor's
  0.649, the paired difference -0.057 (-0.108 to -0.019), and the calibration error
  0.053.
- C2 is not met: the top five percent holds 43.6% (36.6% to 50.0%) of the 211 test
  listings, the floor 41.7% (tie); EPSS holds 41.7% on day 1 (tie),
  66.8% on day 7 (behind) and 75.8% on day 30 (behind).
- The operating points: config/operating_points.yaml, hashed as the operating_points stage
  406e8887f350. The fill model is fallback (joint design) beside floors, the
  exploitation model exploit_lgbm beside exploit_floor; the conformal sets aim at 0.9 coverage,
  and the product floor's threshold is 90.
- How predictions are served: the batch df00a8d7e396, 181,904 rows in
  models/serving/predictions.parquet, travels in the serving bundle and the sync loads it with the
  rest; POST /v1/predict scores a submitted description with the ONNX band floor and LightGBM, and
  a known CVE's answer always comes from the batch (ADR 0008).
- Neon: 84.4 percent of the ceiling of 800 MB in use when the API was
  checked at 2026-11-13T23:52:20Z, holding serving-202611131326+7a6e339ce211 (results/live/api_verify.json).
- Kaggle GPU hours this month: 0.0 used and 8.0 left of 8.0 (requests/gpu/).
- The look: the Phase 2 screens wait for Ajay's review.
- The open problems, in order, are the list above.

