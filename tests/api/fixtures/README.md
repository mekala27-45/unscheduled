# Test fixtures for the API and the CLI

Invented rows, not measurements. The CVE ids are made up (numbers in the 90000s), the filers are
named fixture-oss and fixture-vendor, and every description begins with "Fixture record". The shapes are real: `bundle/` holds the serving bundle contract of
`packages/api/src/unscheduled_api/bundle.py` as JSON, and `bundle.py` writes it to Parquet with a
manifest of sha256 digests at test time, so no binary file is committed. `osv_records.json` holds
OSV records in the format api.osv.dev serves, and `sboms/` one CycloneDX 1.6 and one SPDX 2.3
document with the same four components: two that the records reach, one they do not, and one
without a package URL.
