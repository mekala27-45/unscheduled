# unscheduled

Triage for the CVEs the NVD no longer analyzes.

**Phase 1 of 5 is in progress.** 0 of 18 checklist lines are done. Still missing:

- The setup done by the build with no typed secret; the probes ran first
- Every source fetched and locked by digest with licences and terms recorded
- Every change to every CVE dated; the as-of engine passes parity and the planted future fact test
- dbt contracts and tests pass; quarantine counts in the manifest; status vocabulary registered
- The month criteria and the Phase 1 plan hashed before any test CVE was scored
- Q1 to Q8 answered with intervals and every chart with its table and SQL
- The customer name checked; six stand ins pinned by rule; SBOMs committed
- The matcher and osv-scanner agree; the CPE contrast measured
- The legacy script characterized and replaced by the adapter
- The API live on Vercel with Neon, loaded only by the sync, verified from a separate client
- Persistence observed independently; schemathesis green; the load test with the cold start
- The CLI gives the same answers as the API on the same inputs
- The design system in place with the palette validator green in CI
- The console, the ruler, the landing, the docs and the report live on Vercel
- sloplint, axe and Lighthouse green; the look reviewed or marked pending
- README with the matrix, RESULTS, DECISIONS, the memos and notebooks; the humanizer pass
- The live check awake and asleep; reset and rederive reproduced every number
- At least fifty conventional commits; v0.1.0 tagged; BUILD_STATE.md written for Phase 2

## What it is

Since 15 April 2026 the NVD enriches CVEs in the CISA KEV catalog, CVEs in software the federal
government uses and CVEs in critical software first, and labels every other CVE lowest priority,
not scheduled for immediate enrichment. Since 11 September 2026 a maker of a product sold in the EU
must send an early warning within 24 hours of learning that a vulnerability in it is actively
exploited. unscheduled measures that gap, finds it in a company SBOM, and over five phases fills,
ranks and routes the CVEs nobody scheduled, with a person approving every plan.

## The skills, and where each one is

Only what is built is listed; docs/ROADMAP.md holds the plan for the rest.

| Skill | Where | What it shows |
|---|---|---|
| API integration | packages/sources | NVD, CVE List, KEV, EPSS, OSV, GitHub advisories, GLEIF and EDGAR |
| CI and DevOps | .github/workflows, Dockerfile.vercel | the gates, gitleaks, zizmor, actions pinned by commit, Vercel deploys |

## Where things are

- AGENTS.md: setup, tests, gates and rules
- ARCHITECTURE.md: the path from the sources to the web, and why each part is where it is
- BUILD_STATE.md: where the build stands
- DECISIONS.md: every decision with its source
- config/criteria.yaml and report/criteria.md: what the customer signed

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
