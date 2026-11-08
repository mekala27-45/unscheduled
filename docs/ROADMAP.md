# Roadmap

unscheduled is built in five phases, one week each, and each phase is tagged before the next one is
written. This page holds the plan for the phases not yet built. The README skills matrix lists only
what exists; everything below is a plan until its tag, and a page never shows it as built.

The criteria the phases answer to are in config/criteria.yaml, hashed with the splits, the budgets
and the Phase 1 plan before any result was computed (evaluation/registration_plan.json).

## Phase 1, the ground truth (v0.1.0)

Every public source fetched and locked by digest; every change to every CVE dated in a lake with an
as-of engine; dbt marts with contracts, tests and named quarantine rules; the backlog measured (Q1 to
Q8 in evaluation/phase1_plan.yaml); the fictional customer, six stand in products and their SBOMs;
the matcher in code checked by osv-scanner; the legacy report characterized and replaced; the API
live on Vercel over Neon, loaded only by a pull sync; the console, the landing and the docs.

Evidence for C3 (find), the lookup half of C8 (service) and the baseline of C9 (value).

## Phase 2, the models (v0.2.0)

- Point in time training sets built through the as-of engine, with a leakage test that plants a
  future fact.
- A TF-IDF floor for every task first, then a ModernBERT model fine tuned on a free Kaggle GPU for
  the CVSS base metrics, the severity band and the CWE, within the GPU budget in
  config/budgets.yaml.
- The affected product by retrieval over the NVD CPE dictionary.
- An exploitation model and a time to exploitation model, with EPSS reported beside every number.
- Calibration and conformal prediction sets; error analysis by filer, weakness and vendor; the
  selection bias that Q8 measures, handled and reported.
- Experiment tracking and a model registry on a free tier; the models served in the API; model
  cards.

Evidence for C1 (fill) and C2 (rank), scored once on the test window.

## Phase 3, the agent (v0.3.0)

- Embeddings in pgvector, hybrid search, a reranker and a retrieval evaluation.
- A triage agent that matches, fills, ranks, retrieves, plans, verifies and drafts the early
  warning, and stops for a person to approve before anything is marked ready.
- An MCP server over the same services; free model providers behind a router with a no model floor
  and recorded replays for CI.
- A red team set of planted instructions; agent evaluations on historical KEV listings; tokens,
  latency and cost per run; the run viewer and the approval inbox in the console.

Evidence for C5 (cited), C6 (injection) and C7 (control).

## Phase 4, production (v0.4.0)

- Images built, scanned and signed; unscheduled triages its own SBOM.
- A Helm chart deployed to kind in Actions with smoke and pod kill tests; Terraform for a reference
  cloud stack, tested with mock providers and no account.
- Traces and metrics with service level objectives; scheduled fetches and a daily retrain with
  drift gates; shadow, canary and a kill switch; a load test.
- The GitHub Action that comments the exposure on a pull request in a demo customer repository.
- Runbooks and an incident drill.

Evidence for C4 (clock) and the rest of C8 (service).

## Phase 5, ship and hand over (v1.0.0)

The verdict against all nine criteria with every evidence row; the value memo with its sensitivity
band (C9); the data card, the runbook and the open risks; a short demo; the humanizer pass over
every page of prose; rederive in a clean worktree reproducing every number; the release.
