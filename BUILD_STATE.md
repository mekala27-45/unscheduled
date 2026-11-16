# Build state

The hand off between sessions and phases. Every session reads it first and updates it last. It is
rendered from its template in docs/templates by make render, so every number in it is read from
the manifest or a committed file: edit the template, then render.

## Where it stands

```
Phase            3 of 5, the agent: 2 of 18 checklist lines done (RESULTS.md); the
                 prompt is claude/unscheduled-phase-3-prompt.md in the Project
Phase 2          the models, tagged v0.2.0 on the commit that adds the release record;
                 its checklist 18 of 18 lines done (RESULTS.md)
Phase 1          the ground truth, tagged v0.1.0 on the commit that adds the release record;
                 its checklist 18 of 18 lines done (RESULTS.md)
Repository       public; every commit conventional; CI, web and exposure green on main
Vercel           unscheduled-api (container) at unscheduled-api.vercel.app
                 unscheduled (web) at unscheduled-triage.vercel.app: the landing with its
                 character field, the console, the docs with six archify diagrams, the
                 report, status and design
Neon             project unscheduled, free plan, ceiling 800 MB (config/budgets.yaml)
                 87.6 percent in use when the API read it at 2026-11-16T03:12:16Z, after the room plan (ADR 0011)
Data             the committed numbers come from the lake cut 2026-11-13T06:00:00+00:00
                 rebuilt here from the lake release lake-20261112
Look approval    Phase 1: approved by Ajay on the evening of 11 November, New York time, after
                 the landing, docs, report and ruler screens: everything is good so far
                 Phase 2: approved by Ajay on the evening of 15 November, New York time, after the
                 CVE page with predictions and the models page: everything is good
                 Phase 3: the run viewer and the approval inbox wait for his review
```

Open checklist lines, Phase 3 (2 of 18 done):

- 3. The Phase 3 plan and the red team hashed as the agent stage before any evaluation
- 4. The advisory corpus built point in time, the leakage test passing, the corpus published by digest
- 5. Retrieval measured against its lexical floor with paired intervals; pgvector compared with the file index
- 6. The router with budgets, fallbacks, the no model floor and replays; no live call in CI
- 7. Prompts versioned and hashed; every output validated against its schema
- 8. The LangGraph agent with checkpoints in Postgres, the approval interrupt, replay and time travel
- 9. C5 evidence: every claim checked by code; zero unverified citations in approved drafts
- 10. C7 evidence: the property test over every path, passing
- 11. C6 evidence: zero planted instructions followed in the registered red team set, its held out half scored once
- 12. The agent evals on KEV listings with the floor beside every router configuration, the choices frozen before the shadow window was scored once; tokens, latency and cost per node and per run; the judge calibrated against the labels Ajay gave
- 13. One step built in three frameworks, compared in ADR 0012
- 14. /v1/triage, runs, approvals and search live; the MCP server over both transports; the CLI
- 15. The console shows every run with its claims and checks, and the inbox; design gates green; the look reviewed by Ajay
- 16. The docs, ADRs 0011 to 0013, report/agent.md and notebooks 07 to 09; the humanizer pass done
- 17. The live check awake and asleep with a triage run and an MCP session; reset and rederive reproduced every retrieval and eval number
- 18. At least fifty conventional commits; the release record passing; v0.3.0 pushed by Ajay; BUILD_STATE.md written for Phase 4

## Next action

Phase 3 runs from its prompt in the Project and the hand off below, and DECISIONS.md holds every
choice made on the way. Done: step 1, step 2.
Next: step 3, the Phase 3 plan and the red team hashed as the agent stage before any evaluation. The
room in Neon comes before anything new loads, the plan is hashed before any evaluation, and every
script whose numbers are committed runs with the numeric pins (AGENTS.md).

## Open problems

- C1 is not met and C2 is not met, each scored once (the hand off below has the numbers). The fill model is
  the CPU fallback, behind its TF-IDF floor on development and on test; the exploitation model ties
  its floor and EPSS on day 1. Test cannot be scored again without a change request that keeps both
  results (evaluation/phase2_plan.yaml), so a better model is judged in a later phase, against the
  same floors.
- Under load the prediction route waits: with 5 clients at once its 95th percentile was
  1,189 ms, against 376 ms for one client alone, and scoring is a few milliseconds of each call
  (ADR 0008). The API records no server timing yet, so where the calls wait is open for Phase 4.
- The room in Neon is planned to 13 December (ADR 0011): 754.1 MB projected against the
  800 MB ceiling, with the corpus, the run store and the daily growth counted. The projection
  rests on the new rows of one day of the lake; the daily probe reads Neon through the API, and two
  more trims are measured for when the readings ask for them.
- No model provider has a key yet: the probe found none of GROQ_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, CEREBRAS_API_KEY.
  The agent runs on its no model floor until Ajay adds at least GROQ_API_KEY and GEMINI_API_KEY as
  Actions secrets and Vercel variables (Part 4 of the Phase 3 prompt); nobody types a key here.
- Kaggle and Databricks secrets are not set. Step eight took its CPU fallback (DECISIONS.md, step
  eight takes the fallback), and KAGGLE_USERNAME with KAGGLE_KEY would let ModernBERT run; without
  the Databricks pair, the registry uses the file store.
- The exploitation search picks its trees on noise: over four runs on the same rows, LightGBM's
  development recall in the top five percent moved by more than twenty points while the floor held
  within one. The numeric kernels are now pinned, so a run reproduces on any processor
  (DECISIONS.md, the pinned exploitation run reproduces, and is the model), but a reproducible draw
  is still one draw; a search that averages over seeds or folds is a change for a later phase.
- Vercel's Hobby plan refused deployments for part of 14 November after many pushes (the commit
  statuses read: Deployment rate limited). A commit that needs no deploy now carries [skip deploy],
  so only the last commit of a batch builds, and a change reaches the site only once a deploy of it
  succeeds.
- Releases and tags come only from Ajay: this session cannot create a release or start a workflow
  that creates one, and its git access cannot push a tag, so v0.3.0 is pushed from his machine.
- The schedules fire hours late and less often than they ask: on 14 November the daily fetch ran
  about seven hours after its time and the lake build too, before the batch existed, so the live
  API gets new predictions only from a lake run after they are committed. The newest lake release
  changes with each hourly run until the next daily one, so the committed numbers come from the
  release before it (DECISIONS.md, 13 November).
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
- The API: its Phase 1 measures are in BUILD_STATE.md at the tag v0.1.0; the line for the API as it
  stands, with the predictions loaded, is in the hand off below.
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
- The API with the predictions loaded, from a separate client: the first lookup after
  20.0 min idle took 140 ms; warm, p50 100 ms and p95 177 ms over 300 lookups (lookups met (p95 177 ms against 1,500 ms); the triage run is measured in Phase 4).
- Neon: 94.1 percent of the ceiling of 800 MB in use when the API was
  checked at 2026-11-15T22:07:25Z, holding serving-202611152200+f89ae3f7e825 (results/live/api_verify.json).
- Kaggle GPU hours this month: 0.0 used and 8.0 left of 8.0 (requests/gpu/).
- The look: approved by Ajay on the evening of 15 November, New York time, after the CVE page with predictions and the models page: everything is good
- The open problems, in order, are the list above.

