# AGENTS.md

The single source for working in this repository. CLAUDE.md and .github/copilot-instructions.md
point here.

## What this is

unscheduled is a triage platform for the CVEs the NVD no longer analyzes. The month is built in five
phases; this repository is in Phase 1, the ground truth (BUILD_STATE.md says where it stands).

## Setup

```
uv sync                      # Python 3.12, the uv workspace under packages/
cd web && pnpm install       # Next.js, the console, the landing and the docs
```

## Before every commit

```
make gates                   # dash, vocabulary, statement, secret and no model gates
make lint types test         # ruff, mypy strict, pytest
```

## Rules that hold everywhere

- No em dashes or en dashes in any authored file. Ranges use to.
- Every number in a document or a page comes from results/manifest.json through the renderer in
  packages/render. A number typed by hand fails the claim gate.
- The statement in packages/core/src/unscheduled_core/statements.py appears on every surface.
- Time, not chance: every fact carries known_from; the as-of engine never returns a fact known after
  the time asked for. No random split anywhere.
- Nobody types a secret. The database connection reaches Vercel through the Neon integration and
  GitHub Actions holds no credential. scripts/check_secrets.py fails on anything that looks like one.
- Phase 1 has no prediction model and no language model. scripts/check_no_model.py enforces it.
- Conventional commits, one module at a time. Pushed history is never rewritten.

## Files not to edit by hand

- results/manifest.json and every rendered document (edit the template or the query instead)
- data/locks/*.json (written by the fetchers)
- the six registered files (config/criteria.yaml, splits.yaml, budgets.yaml, labels.yaml,
  samples.yaml and evaluation/phase1_plan.yaml) and evaluation/registration_plan.json and
  registration.json once hashed; `make gates` fails on any edit, and a change is a dated
  DECISIONS.md entry with both verdicts
