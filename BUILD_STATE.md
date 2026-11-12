# Build state

The hand off between sessions and phases. Every session reads it first and updates it last. It is
rendered from its template in docs/templates by make render, so every number in it is read from
the manifest or a committed file: edit the template, then render.

## Where it stands

```
Phase            1 of 5, the ground truth
Checklist        13 of 18 lines done (RESULTS.md)
Repository       public; every commit conventional; CI, web and exposure green on main
Vercel           unscheduled-api (container) at unscheduled-api.vercel.app
                 unscheduled (web) at unscheduled-triage.vercel.app: the landing with its
                 character field, the console, the docs with six archify diagrams, the
                 report, status and design
Neon             project unscheduled, free plan, ceiling 800 MB (config/budgets.yaml)
Data             the committed numbers come from the lake cut 2026-11-12T00:21:46+00:00
                 built here; the first lake release replaces them, rebuilt from its bronze
Look approval    approved by Ajay on the evening of 11 November, New York time, after the
                 landing, docs, report and ruler screens: everything is good so far
```

Open checklist lines:

- The API live on Vercel with Neon, loaded only by the sync, verified from a separate client
- Persistence observed independently; schemathesis green; the load test with the cold start
- The console, the ruler, the landing, the docs and the report live on Vercel
- The live check awake and asleep; reset and rederive reproduced every number
- At least fifty conventional commits; v0.1.0 tagged; BUILD_STATE.md written for Phase 2

## Next action

The first fetch in Actions (fetch.yml with bootstrap, started by Ajay on 12 November) fetched every
source and stopped in the NVD change history, two windows from the end, on a server error from the
NVD's network. The lake release it wrote holds the ledger, so the next run resumes from that page,
and every server error is now retried. Ajay starts fetch.yml again with sources nvd and bootstrap
set; it publishes the full lake release and starts lake.yml, which builds the lake, publishes the
serving release and loads the API. Once the API answers ready: restore the lake release bronze here
(scripts/restore_release.py) and rebuild the lake, the backlog, the field and the manifest from it;
then scripts/verify_api.py, scripts/load_test.py with twenty idle minutes, web/scripts/live-check.mjs
awake and asleep, scripts/reset_and_rederive.py; then the cut-a-release skill.

## Open problems

- Releases come only from workflows Ajay starts: this session's automatic approvals refuse to
  create a release, so a workflow that publishes one, and the version tag that starts release.yml,
  need his start or his yes.
- No scheduled run has fired in the repository yet, so the hourly and daily refresh is not running:
  the one fetch so far was started by hand. A commit Ajay makes himself to a workflow file, or
  turning the workflow off and on in the Actions tab, usually brings the schedule back.
- k6 cannot be downloaded on the build machine; the load test runs the same scenario on httpx
  (DECISIONS.md, 12 November).
- The legacy CSV dates a CVE outside the serving slice by its advisories, since the slice holds no
  record for it.

## The hand off to Phase 2

- The lake: cut 2026-11-12T00:21:46+00:00, content digest 6a7ad73d0035aeb780d2ada250bfaee01d760a547aa8aa85e86aaacd3743ff64, file digest
  66812c5bfe50d61521e75391f29ef2afc7e73549d6e628733bd90c9e5e2c4142.
- The registration: hash 78bf9cdfad9dc5f3ecb7b5251055be570c1c37d0ad0b054b5861f4e31afaa30c, over config/criteria.yaml, config/splits.yaml, config/budgets.yaml, evaluation/phase1_plan.yaml, config/labels.yaml, config/samples.yaml.
- The splits, by the date a CVE was published (config/splits.yaml):
  - train: 1999-01-01 to 2023-12-31
  - development: 2024-01-01 to 2024-12-31
  - test: 2025-01-01 to 2026-03-31
  - gap: 2026-04-01 to 2026-04-14
  - shadow: 2026-04-15 to open
- The status vocabulary (config/labels.yaml): Received, Awaiting Analysis, Undergoing Analysis, Analyzed, Modified, Deferred, Rejected.
  Since 15 April 2026 Deferred is the value the NVD gives the CVEs it does not schedule.
- Q8: the domain classifier separates the CVEs the NVD analyzed from the rest of the shadow window
  at an AUC of 0.886 (0.827 to 0.928) on the held out half of 78,243 CVEs.
  The strongest feature toward skipped is published month (months since 2026-04), so part of the shift is
  time since the change; the next ones are filer or type: filer_Wordfence; filer or type: filer_WPScan; filer or type: filer_Patchstack; filer or type: filer_AMD.
  Toward analyzed: filer or type: filer_microsoft; filer or type: filer_Chrome; word: n8n; word: flowise; filer or type: filer_adobe.
- The look: approved by Ajay on the evening of 11 November, New York time; he asked for no change.
- Kaggle GPU hours: 8 for the month (config/budgets.yaml), none used in Phase 1.
