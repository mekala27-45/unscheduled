# unscheduled

Triage for the CVEs the NVD no longer analyzes.

**Phase 1 of 5 is in progress.** 12 of 18 checklist lines are done. Still missing:

- The API live on Vercel with Neon, loaded only by the sync, verified from a separate client
- Persistence observed independently; schemathesis green; the load test with the cold start
- The console, the ruler, the landing, the docs and the report live on Vercel
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
| Python and the data stack | packages/sources, packages/lake | polars, DuckDB and pyarrow |
| SQL and analytics engineering | dbt/models, dbt/macros | staging, intermediate and marts, and the as-of macro |
| Data quality | dbt/tests | contracts on every mart and the named quarantine rules |
| Point in time correctness | packages/lake, tests/lake | the as-of engine, its parity test and the planted future fact |
| Statistics | packages/analysis | cluster bootstrap, Cohen and weighted kappa, Benjamini-Hochberg, the domain classifier |
| APIs | packages/api, openapi.json | FastAPI over Neon, typed problem documents, the committed schema |
| API integration | packages/sources | NVD, CVE List, KEV, EPSS, OSV, GitHub advisories, GLEIF and EDGAR |
| Supply chain security | packages/match, customer/sboms | the matcher in code, checked by osv-scanner, with Grype as the CPE contrast |
| Legacy code | customer/legacy, tests/characterization, packages/legacy_adapter | characterization tests first, then a strangler with a byte for byte contract |
| CLI | packages/cli | the same services as the API |
| Modular design and trade offs | packages, docs/adr | one package per concern and a record for every decision |
| Coding agents | AGENTS.md, CLAUDE.md, .claude/skills | one source of rules and four skills in the Agent Skills format |
| CI and DevOps | .github/workflows, Dockerfile.vercel | the gates, gitleaks, zizmor, actions pinned by commit, Vercel deploys |
| Frontend and design systems | web, web/styles/tokens.css, tools/hallmark | tokens first, shadcn/ui themed through them, the palette validator |
| Accessibility and performance | .github/workflows/web.yml | axe and Lighthouse in CI |

## Where things are

- AGENTS.md: setup, tests, gates and rules
- ARCHITECTURE.md: the path from the sources to the web, and why each part is where it is
- BUILD_STATE.md: where the build stands
- DECISIONS.md: every decision with its source
- config/criteria.yaml and report/criteria.md: what the customer signed

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
