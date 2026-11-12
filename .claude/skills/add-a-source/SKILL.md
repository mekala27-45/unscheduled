---
name: add-a-source
description: Add a public feed to unscheduled, from its fetcher and bronze contract to its lock, licence entry and tests. Use when a new source of CVE, advisory, exploit or scoring data should enter the lake.
---

# Add a source

1. **Read the terms first.** Find the licence or terms of use and the rate limit the publisher
   states, and the date you read them. If the terms forbid redistribution or need a key you would
   have to paste, stop and ask.
2. **Write the fetcher** in packages/sources/src/unscheduled_sources/<name>.py as a subclass of
   base.Fetcher: `units()` yields resumable units of work, `fetch()` returns RawFile objects (never
   parsed data), `parse()` yields typed frames for each bronze table. Register it in registry.py and
   give it a section in config/sources.yaml with its URL pattern, schedule and limit.
3. **Declare its bronze tables** in contract.py, with every column typed. A column the contract does
   not name fails the parse.
4. **Lock it.** Run `uv run python scripts/fetch.py <name>`; the run writes
   data/locks/<name>.lock.json with every raw file's digest and a ledger row per unit. Rerun it and
   check that it resumes instead of starting again.
5. **Record it** in data/PROVENANCE.md: where, terms with the date read, what is kept, the limit, and
   any notice the terms require on the site.
6. **Test it** in tests/sources with a small gzipped fixture of the real format: one parse test, one
   resume test, one refusal (a value outside config/labels.yaml, a bad digest).
7. Run `make gates`, `uv run ruff check .`, `uv run mypy` and `uv run pytest tests/sources`, then
   commit as `feat(sources): ...`, one source per commit.
