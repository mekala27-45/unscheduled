---
name: cut-a-release
description: The phase gate for unscheduled, every command in order before a version tag. Use before tagging v0.N.0 or v1.0.0.
---

# Cut a release

Run from a clean checkout of main, with nothing uncommitted.

1. `make gates` (dash, vocabulary, statement, secrets, no model, tokens, registration).
2. `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`, `uv run pytest`.
3. `uv run python scripts/build_manifest.py` then `uv run python scripts/check_published_numbers.py`:
   every published number renders from results/manifest.json.
4. In web/: `pnpm build`, `pnpm test`, `pnpm exec playwright test`, then
   `node web/scripts/design-gates.mjs --base <served site>` from the root.
5. The live check: `uv run python scripts/probe_platform.py`, the API verify against
   https://unscheduled-api.vercel.app, and the site opened in a real browser at both widths.
6. Reset and rederive in a fresh worktree (`uv run python scripts/reset_and_rederive.py`): every
   value in the manifest must come back the same from the published bronze.
7. The checklist in RESULTS.md: every line done, or the README says which are not.
8. Count the commits since the last tag; a phase tag needs at least fifty conventional commits.
9. Tag `vX.Y.0` on the checked commit and push the tag; release.yml reruns the gates on it and
   publishes the notes from the manifest. Update BUILD_STATE.md for the next phase.
