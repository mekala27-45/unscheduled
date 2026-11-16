#!/usr/bin/env bash
# The corpus files and the findings of the newest serving release that holds a corpus, under the
# names the scripts read (data/corpus/*.parquet, data/corpus/manifest.json, data/serving/finding.parquet).
set -euo pipefail
tag="$(gh api "repos/$REPO/releases?per_page=60" --jq '[.[] | select(any(.assets[]; .name | startswith("corpus-manifest-")))][0].tag_name // ""')"
if [ -z "$tag" ]; then echo "No release has a corpus yet."; exit 1; fi
mkdir -p data/corpus data/serving
gh release download "$tag" --repo "$REPO" --dir data/corpus --pattern 'corpus-*'
gh release download "$tag" --repo "$REPO" --dir data/serving --pattern 'finding.parquet' --clobber
cd data/corpus
mv corpus-manifest-*.json manifest.json
mv corpus-queries-*.parquet queries.parquet
mv corpus-documents-*.parquet documents.parquet
mv corpus-[0-9a-f]*.parquet chunks.parquet
echo "The corpus of $tag."
