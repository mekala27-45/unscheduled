# Build state

The hand off between sessions and phases. Every session reads it first and updates it last. It is
rendered from its template in docs/templates by make render, so every number in it is read from
the manifest or a committed file: edit the template, then render.

## Where it stands

```
Phase            1 of 5, the ground truth
Checklist        18 of 18 lines done (RESULTS.md)
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

Phase 1 is built and checked. The committed numbers are rebuilt from the settled lake release named
above, and every checklist line holds its evidence. The release record, results/release.json,
passes: the gates, ruff, mypy, pytest, the manifest and the claim gate on a clean checkout, with the
live API check, the load test, the live check awake and asleep, the reset and rederive and the
design gates as its evidence. Next: Ajay pushes the tag v0.1.0 on the commit that adds the release
record, or replies yes, push the v0.1.0 tag; release.yml reruns the gates on the tag and publishes
the notes. Then the Phase 2 prompt is written from this repository as it stands.

## Open problems

- Releases come only from workflows Ajay starts: this session's automatic approvals refuse to
  create a release, so a workflow that publishes one, and the version tag that starts release.yml,
  need his start or his yes.
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

## The hand off to Phase 2

- The lake: cut 2026-11-13T06:00:00+00:00, content digest 8d97104c0ad0454895cf98e904a676a5c4d6ee23592638bbe139370d7b9a7d7a, file digest
  00ce926255dcb3209af24407910f53c149d7aa2c814a9560ff3377c02d7326ae, from the release lake-20261112.
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
