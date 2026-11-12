# Quickstart

The console, the API and the command line read the same data, and the command line runs the same
code as the API, so an answer from one is the answer from the other (results/cli_parity.json).

## The console

Open https://unscheduled-triage.vercel.app/app and type a CVE id, or press the slash key to search.
A CVE page draws every dated event on its ruler and lists every field with the source that
published it and since when. Set the date under As known on to see the record as it stood that day.
The match page takes a CycloneDX or SPDX JSON SBOM and keeps only its digest.

## The API

Every route, with its parameters and its answers, is on the API reference page and in openapi.json
at the root of the repository. No key is needed. Each client has a daily budget of lookups and of
SBOM matches (config/budgets.yaml), and every data answer says what is left in X-Budget-Remaining.

```
curl https://unscheduled-api.vercel.app/v1/cves/CVE-2021-44228
curl "https://unscheduled-api.vercel.app/v1/cves/CVE-2021-44228?as_of=2021-12-09"
curl "https://unscheduled-api.vercel.app/v1/cves?nvd_status=Deferred&limit=5"
curl https://unscheduled-api.vercel.app/v1/cves/CVE-2021-44228/timeline
curl -X POST -H "content-type: application/json" \
  --data-binary @customer/sboms/rust-cli.cdx.json \
  https://unscheduled-api.vercel.app/v1/match
curl https://unscheduled-api.vercel.app/v1/legacy/report.csv
```

Every answer carries the statement and the data version it was read from. An error is a problem
document whose type links to its entry in docs/SPEC.md.

## The command line

The command line reads the database the API reads, named by DATABASE_URL. To have one of your own,
point DATABASE_URL at a Postgres you run and load the newest serving release into it:

```
uv sync
export DATABASE_URL=postgresql://localhost/unscheduled
uv run unsched sync --until-done
uv run unsched cve CVE-2021-44228 --as-of 2021-12-09
uv run unsched match customer/sboms/rust-cli.cdx.json
uv run unsched legacy-report > report.csv
uv run unsched serve
```

unsched serve runs the API on your machine, migrations first, as the container does.

## The build, from the published data

Every number on the site comes from the lake, and the lake rebuilds from a published release:

```
uv run python scripts/restore_release.py
uv run python scripts/build_lake.py
uv run python scripts/run_analysis.py
uv run python scripts/backlog_charts.py
uv run python scripts/build_manifest.py
uv run unsched render
```

To fetch from the sources yourself instead, uv run unsched fetch all writes the locks, the run
ledger and bronze; the NVD part runs without a key, under the keyless rate limit, and resumes from
the ledger. scripts/reset_and_rederive.py rebuilds the lake in a fresh worktree and compares every
number with the committed manifest.
