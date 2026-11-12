# Build state

The hand off between sessions and phases. Every session reads it first and updates it last.

```
Phase            1 of 5, the ground truth
Step reached     16 of 18 built; the first fetch in Actions started 12 November 03:16 UTC
                 (fetch.yml with bootstrap, started by Ajay); lake.yml follows it
Repository       public; every commit conventional; CI, web and exposure green on main
Vercel           unscheduled-api (container) at unscheduled-api.vercel.app, migration
                 0001, no data until the first sync
                 unscheduled (web) at unscheduled-triage.vercel.app: the landing with its
                 character field, the console, the docs, the report, status and design
Neon             project unscheduled, free plan, ceiling 800 MB (config/budgets.yaml);
                 the serving bundle loaded locally takes the size in
                 results/live/local_load.json
Data versions    the committed numbers come from a lake built here, cut 2026-11-12 00:21
                 UTC; the first lake release replaces them, rederived from its bronze
Look approval    pending: the screens were sent to Ajay, no answer yet
Checklist        13 of 18 lines done (RESULTS.md); open: 10 the API live, 11 the load
                 test, 14 the site live, 17 the live check and the rederive, 18 the release
Next action      once lake.yml has published the serving release and the API answers
                 ready: restore the lake release bronze here and rebuild the lake, the
                 backlog, the field and the manifest from it; then scripts/verify_api.py,
                 scripts/load_test.py --idle-minutes 20, web/scripts/live-check.mjs awake
                 and asleep, scripts/reset_and_rederive.py; then the cut-a-release skill
```

## Open problems

- Releases come only from workflows Ajay starts: this session's automatic approvals refuse to
  create a release, so a workflow that publishes one, and the v0.1.0 tag that starts
  release.yml, need his start or his yes.
- k6 cannot be downloaded on the build machine; the load test runs the same scenario on httpx
  (DECISIONS.md, 12 November).
- The legacy CSV dates a CVE outside the serving slice by its advisories, since the slice holds no
  record for it.
