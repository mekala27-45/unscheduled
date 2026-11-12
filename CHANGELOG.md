# Changelog

Every version tag with the conventional commits it carries, newest first, written by
scripts/changelog.py from the history before each tag. A subject reads as it was committed.

## v0.1.0

### Added

- web: the docs and the report, rendered from the repository (49e3096)
- web: the hero field draws the lake, the CPE contrast reads the manifest (9e3cd77)
- report: the backlog, in words and numbers, and the discovery and legacy memos (cc90650)
- web: the console reads the generated API contract through one adapter (259aae2)
- api: events that set several fields, fields dated by the row, and the data page in meta (d9c519d)
- serving: a bundle in the API's contract, checked by its readers and sized for the free plan (5aae67d)
- lake: the lake, the warehouse and the backlog questions on the full history (1858a3f)
- agents: four skills in the Agent Skills format (7040cd4)
- exposure: the first exposure of the six stand ins, from the 8 November bronze (d7d91c6)
- exposure: the baseline per product, at its pin and today (ca4a5bd)
- exposure: what a CPE matcher cannot see, with Grype as the contrast (a56fa0b)
- exposure: osv-scanner checks every finding, and a disagreement needs a reason (005f1a1)
- web: the ruler, one CVE as a line in real time (cc9678d)
- web: the console, nine destinations over the API with every state drawn (fdf0a70)
- web: the landing, a map of the system and the field of the CVE stream (d5d95e0)
- web: the Cobalt desk, every color and face through a token (f2711ce)
- cli: unsched, the same services as the API from the command line (f36932e)
- api: live SBOM matching and the customer report written from findings (b59dee2)
- api: every CVE with its history as of any date, the backlog and the exposure (dec0246)
- sync: the API pulls the newest serving release in checked chunks (62b9f74)
- api: the serving slice in Neon, migrated at start under an advisory lock (7da6d73)
- probe: every source answers before a deploy step trusts it (b49a5d5)
- sources: OSV and GitHub advisories, and when exploit code first appeared (8718fdf)
- sources: CVE List V5, KEV with its history, EPSS at fixed offsets, SSVC and CWE (059c8ba)
- sources: the NVD records and every change event since 2017, with no key (b252b19)
- sources: one run loop for every source, resumable from the ledger (3147b3f)
- match: the matcher in code, each range read in its own version scheme (9a1164f)
- products: six stand ins chosen by a written rule, and their SBOMs by Syft (d6cca49)
- legacy: the 2019 report job, characterized first, then replaced byte for byte (5340f4b)
- customer: the fictional customer, its name checked against GLEIF and EDGAR (0b7a06a)
- probe: the NVD 1.1 feed files the legacy job reads, beside their successors (ad6768b)
- probe: the live API and web timed, and what the consoles showed (cf7a49a)
- release: publish the serving bundle as a release the API pulls, checked by digest (7237538)
- web: the first page, with the statement on every route (5256acb)
- api: a health stub and Dockerfile.vercel for the first hour import (e9b86cd)

### Fixed

- api: the legacy report reads the rows the serving bundle writes (971e109)
- lake: the locks the lake was built from are recorded in a committed report (8561107)
- web: what the first look on real data showed (afca9c2)
- backlog: a CVE younger than k days is not judged at k days (3fdab98)
- plan: the status vocabulary is hashed without the fetcher's counters (ab9eb80)
- gates: the pre-push hook checks what is committed (e49dfa5)
- gates: vendored sloplint is not ours to edit, and a removed file is skipped (bd7233b)
- plan: type the registration record for mypy strict (f64303a)

### Documents

- the method notes open with where every number comes from (8163cb9)
- the README links the live site and the API and shows the architecture (e5b36d0)
- the quickstart names what the fetch command writes (53e31f4)
- decision record 0004 opens with a match as a sequence (da7b743)
- the NVD status lifecycle on the as-of page, and every API parameter described (a9382b9)
- quickstart, the as-of model, method notes, the API reference and the slice tables (2485ff8)
- the look approved by Ajay (546001c)
- web: the sync drawn as a sequence, on its decision record (f8f0b6f)
- report: the data card for the lake (84694a7)
- the build state while the first fetch runs (79d4513)
- the humanizer pass over the README, the memos and the landing (343a4ce)
- notebooks: the three dead ends, run against the lake (d2f79d0)
- decisions: the repairs of the first full build and the cut to the free plan (fea4887)
- adr: the seven decisions behind the layout (cd93983)
- spec: the system as a specification (c6a0f20)
- data: where every source comes from, its terms, what is kept and its limit (1cba59a)
- decisions: the name check, the stand in rule and the firmware image (0deb722)
- diagrams: the architecture, drawn with archify, in both themes (28988e9)
- decisions: the windows, the nine thresholds and the budgets with their sources (f756792)
- readme: the skills matrix lists a row only once its paths are committed (5033d97)
- runbooks: rotate the database credential and read the consoles again (b2a477a)
- criteria: the signed criteria rendered from the file that defines them (5895581)
- the architecture and the roadmap for the four phases still to come (2c8a4b5)
- decisions: the web domain, the Neon region and the link by the existing account (994228d)
- AGENTS.md, the build state, the first decisions and CI (45a42e4)

### Tests

- api: persistence read back from an independent connection (9de3ede)
- api: the live verifier, the load test and the live check (0d8e147)
- serving: the lock summary is tested on locks the test writes (dd46497)
- web: every route at two widths and both themes, with axe and the notices (aa5ac67)

### Continuous integration

- fetch: a bootstrap run hands over to the lake build (c19c2eb)
- exposure: without a lake release the committed exposure is checked, not recomputed (cab134d)
- fetch: a bootstrap run starts the first lake release from nothing (836bc80)
- the API tests must find a Postgres in CI, never skip (c7ebf44)
- fetch: a scheduled run waits for the first lake release (405bf61)
- web: the design gates in CI, written down as evidence (bec220c)
- fetch: the hourly and daily fetch, resumed from the newest lake release (81fc78d)
- release: a version tag reruns every gate and publishes notes from the manifest (779d868)
- gates: every color and face in web/ goes through a token (c0f4cc8)
- gitleaks over every commit, zizmor over every workflow, actions pinned by commit (ddaa294)
- the claim gate renders README from the manifest, with the printed checklist (d7ee1f2)
- the dash, vocabulary, statement, secret and no model gates, three tests each (cf5b8cf)

### Chores

- restore a lake release into the checkout, as lake.yml does (d6b39f1)
- the phase gate writes its record (b04986d)
- reset and rederive in a worktree, from the lake release (d040300)
- deploy: a daily Vercel cron calls the sync as a backstop (0336db3)
- deploy: the web project skips a commit marked skip deploy too (6134058)
- deploy: a commit marked skip deploy builds nothing on Vercel (1007013)
- plan: hash the plan before the lake exists, in two stages (ead4393)
- setup: record the hosting setup by name, with no value of any secret (ed7b630)
- snapshot of the sources, match and web builders in progress [skip ci] (6fbfc44)
- plan: the month criteria C1 to C9, the splits, the budgets and the Phase 1 plan (91fd592)
- scaffold the uv workspace with the core and renderer ported from readback (0702f45)
