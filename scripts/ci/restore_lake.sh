#!/usr/bin/env bash
# The bronze of the newest lake release, checked by its SHA256SUMS, built into the lake's work
# database (data/cache/lake/unscheduled.duckdb) without publishing anything. Used by the workflows
# that evaluate the agent; lake.yml is the one that publishes.
set -euo pipefail
last="$(gh release list --repo "$REPO" --limit 200 --json tagName --jq '[.[].tagName | select(startswith("lake-"))] | sort | last // ""')"
if [ -z "$last" ]; then echo "No lake release yet."; exit 1; fi
mkdir -p restore data/bronze
gh release download "$last" --repo "$REPO" --dir restore --pattern 'bronze-*.tar' --pattern 'locks.tar.gz' --pattern 'config.tar.gz' --pattern 'SHA256SUMS'
( cd restore && sha256sum --check --ignore-missing --quiet SHA256SUMS )
for t in restore/bronze-*.tar; do tar -xf "$t" -C data/bronze; done
tar -xzf restore/locks.tar.gz -C data
tar -xzf restore/config.tar.gz -C config
rm -rf restore
uv run python scripts/build_lake.py --memory 10GB --threads 4 --keep-work --no-checks
echo "The work database of $last."
