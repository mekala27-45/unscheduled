# 0007. The API pulls its data, so no database secret exists in Actions

Status: accepted, 7 November 2026

## Context

The lake is built in GitHub Actions. The obvious way to load the API's database is a workflow that
connects to Neon and writes, which puts a database credential in the repository's secrets, readable
by any workflow and exposed to every action it runs.

## Decision

The build publishes a serving bundle as a public release of this repository, with a manifest that
lists every file and its sha256. The API loads it itself: GET or POST /internal/sync lists the
releases of mekala27-45/unscheduled (owner and name fixed in code), checks each file against the
digest in the manifest, and loads one bounded chunk per call inside a Postgres advisory lock,
answering more, done or current. The connection reaches the API through the Neon integration for
Vercel and nowhere else.

## Why a public trigger is safe here

- It takes no input. Nobody can choose what it loads, only ask it to load the newest release of a
  repository fixed in code.
- Everything it loads is public already, and checked by digest before a row is written.
- It is idempotent: when the data is current it costs one small query and answers current.
- It is rate limited and runs under one advisory lock, so a burst of calls loads nothing twice.
- It refuses to grow the database past the storage ceiling.

The publish workflow calls it until it answers done, and a daily Vercel cron calls it as a
backstop.

## Consequences

- GitHub Actions holds no credential for the database, and no workflow can leak one.
- A bad bundle is refused, not half loaded, and the API keeps serving the version it had.

## Alternatives

A push with a database secret in Actions, or a signed webhook with a shared secret, would both put a
secret where a compromised action could read it.
