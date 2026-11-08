# The customer

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.

Velloran Systems is fictional. It makes building access controllers sold in the EU, has its main
establishment in Belgium and two security engineers, and ships six products. Its file is
`config/customer.yaml`. The name was checked against GLEIF and SEC EDGAR on 7 November 2026 by
`scripts/check_name.py`; the result, including EDGAR's refusal of a client that sends no email, is in
`results/name_check.json`.

## The stand ins

None of the code here is the customer's. Each product is played by a public repository, or for the
firmware a public image, chosen by the rule in `config/products.yaml` and pinned to its last commit
before 1 January 2025, so that the vulnerabilities found since then are there to find. The file
records each pick with its commit, licence, stars and the day they were read, and every repository
the rule passed over with the test it failed.

| Product | Stand in | Pinned at |
|---|---|---|
| door controller firmware | the Debian image `debian:bookworm-20241223-slim`, linux/arm64 | its platform digest |
| cloud dashboard | `freeCodeCamp/freeCodeCamp` | `c864299c3009` |
| edge service (Go) | `avelino/awesome-go` | `f038ca533006` |
| integration service (Java) | `macrozheng/mall` | `782f0d43aa95` |
| installer tool (Rust) | `rustdesk/rustdesk` | `98b00cdb3d44` |
| data jobs (Python) | `TheAlgorithms/Python` | `12b1023a9d97` |

The rule is mechanical, so some stand ins look little like the product they play: the Go pick is a
curated list whose site generator has a small module graph. That is the rule working as written,
and the reason the rule is written down before the search instead of picks made by taste.

## The SBOMs

`sboms/` holds one CycloneDX 1.6 JSON SBOM per product, written by Syft 1.57.0 (downloaded by
`scripts/make_sboms.py` and checked against its release checksum). `sboms/sboms.lock.json` records
the SHA-256 of each SBOM, the files Syft read with their digests, what Syft could not name with a
package URL (quarantine rule Q07) and what it listed that is not a package.

What Syft sees is what the root lockfile says. For the Java stand in there is no lockfile: the poms
declare dependencies and the versions that come from a parent BOM stay unresolved, so those
components carry no version and neither engine can match them.

## The legacy report

`legacy/vuln_report.py` is a fixture written for this build in the style of the nightly cron job
the customer says it has run since 2019, as its header says. It reads the NVD 1.1 JSON feeds, keeps
the CVEs whose CPE vendor is on a watch list, writes a CSV and mails it. Its download failure is
swallowed by a bare except, so since the 1.1 feeds were retired it has mailed a report with a header
and no rows. It is never run against the live NVD: `tests/characterization` runs it on sample feeds
in the 1.1 layout and pins what it does, the silent failure included, and
`packages/legacy_adapter` writes the same CSV from the matcher's findings.

## Running it again

```
uv run python scripts/check_name.py      # the name, on the day
uv run python scripts/make_sboms.py all  # tools, the rule, the SBOMs
uv run python scripts/run_exposure.py    # both engines, the disagreements, the CPE contrast
```
