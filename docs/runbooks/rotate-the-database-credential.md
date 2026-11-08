# Rotate the database credential

The API reads its Postgres connection from DATABASE_URL_UNPOOLED, then DATABASE_URL. Both are
written into the unscheduled-api project on Vercel by the Neon integration for Vercel. Nobody types
them, nobody copies them, and GitHub Actions never holds them. Rotating means asking Neon for a new
password and letting the integration carry it.

## When

- A connection string may have been exposed (a log line, a screenshot, a paste).
- A person who could read the Vercel project no longer should.
- As a routine, once per phase.

## Steps

1. In the Neon console, open the project unscheduled, then Roles, and reset the password of the
   role the integration created. Neon shows the new value once; do not copy it anywhere.
2. In Vercel, open unscheduled-api, Settings, Environment Variables, and confirm that
   DATABASE_URL and DATABASE_URL_UNPOOLED show a recent update time. The integration writes them;
   if they did not change, open Integrations, Neon, Manage, and reconnect the project.
3. Redeploy the latest production deployment of unscheduled-api, so the container starts with the
   new value.
4. Check `GET https://unscheduled-api.vercel.app/health`: the database block must say connected.
5. Run `python scripts/probe_platform.py` and commit results/probe_platform.json.

## What not to do

- Never paste a connection string into an issue, a commit, a chat or a terminal that logs.
- Never add a database variable to GitHub Actions. The API pulls its data from the public serving
  release (ADR 0007), so no workflow needs one.
