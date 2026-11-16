#!/usr/bin/env bash
# pgvector with halfvec for every Postgres major version on an Ubuntu runner, from the PostgreSQL
# apt repository (the Ubuntu archive of 24.04 carries 0.6, which has no halfvec). Used by ci.yml for
# the retrieval tests and by retrieval.yml for the evaluation.
set -euo pipefail
. /etc/os-release
key=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
sudo install -d "$(dirname "$key")"
sudo curl -fsSL -o "$key" https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=$key] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
  | sudo tee /etc/apt/sources.list.d/pgdg.list > /dev/null
sudo apt-get update -qq
packages=""
for version in $(ls /usr/lib/postgresql); do packages="$packages postgresql-$version-pgvector"; done
# shellcheck disable=SC2086
sudo apt-get install -y -qq $packages
for version in $(ls /usr/lib/postgresql); do
  ls "/usr/share/postgresql/$version/extension/" | grep -E '^vector--[0-9.]+\.sql$' | sort -V | tail -1
done
