# Provenance

Where every source comes from, the licence or terms it is published under, the date those terms
were read, what the build keeps, and the limit it respects. The fetchers are in packages/sources;
each raw file they read is locked by its SHA-256, size, URL and fetch time in
data/locks/<source>.lock.json, and every unit of work is a row of data/locks/ledger.jsonl. Raw
files live as Release assets named by digest, never in git. Every request names the project in its
User-Agent (unscheduled/0.1 (+https://github.com/mekala27-45/unscheduled)) and carries no contact
address and no secret.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.

All terms below were read on 8 November 2026 (UTC) unless the entry says otherwise.

## CVE List V5 (cvelist)

- **Where:** github.com/CVEProject/cvelistV5, the release assets: the newest daily baseline
  (YYYY-MM-DD_all_CVEs_at_midnight.zip.zip) and every hourly delta after it
  (YYYY-MM-DD_delta_CVEs_at_HHMMZ.zip, each holding every record changed since that midnight).
  Release tags are read with git ls-remote; assets are downloaded from the release URLs.
- **Terms:** the repository README says its content may be used per the CVE Program Terms of Use.
  Those terms, as published on cve.org (read from the cve-website repository that renders the
  page), grant a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
  copyright license to reproduce, prepare derivative works of, publicly display, publicly perform,
  sublicense and distribute CVE, provided that any copy reproduces MITRE's copyright designation
  and the license. CVE is a trademark of The MITRE Corporation; the records are provided as is,
  without warranty.
- **Kept:** per record the id, state, dates, assigner, English description, CWEs, affected block,
  reference count and whether the CISA ADP container is present (cve_records), every CVSS metric
  by provider (cve_metrics) and every CWE by provider (cve_weaknesses).

## NVD CVE API 2.0 and CVE Change History API 2.0 (nvd)

- **Where:** services.nvd.nist.gov/rest/json/cves/2.0 (the full set by startIndex pages of 2,000,
  then lastModified windows of at most 120 days) and /rest/json/cvehistory/2.0 (every change
  event from 1 January 2017 by change date windows of at most 120 days, pages of 5,000).
- **Notice:** This product uses data from the NVD API but is not endorsed or certified by the NVD.
  The notice is on every surface that shows NVD data.
- **Limit:** keyless, 5 requests in any rolling 30 seconds, as the NVD start here page documents
  it (50 with a key). nvd.nist.gov answered this build with a bot challenge on the day, so the
  limit was read from the pontos NVD client documentation, which quotes that page, and measured by
  the probe (results/probe.json). The fetcher keeps a 10 percent margin on the window and a floor
  of one second between requests. When the environment holds NVD_API_KEY the key travels in the
  apiKey header only, never in a URL, a lock or a log, and the limiter moves to the keyed limit.
- **Terms:** the NVD terms of use page answered with the same bot challenge on the day; it is to
  be read again when it can be. The values the NVD gives vulnStatus are read from the data and
  registered in config/labels.yaml.
- **Kept:** per CVE its status, dates, source, whether it has CPE configurations and how many,
  and the KEV date the NVD carries (nvd_cves); its metrics and CWEs by provider (cve_metrics and
  cve_weaknesses, origin nvd_api); every change event with its details (nvd_changes).

## CISA Known Exploited Vulnerabilities (kev)

- **Where:** github.com/cisagov/kev-data, known_exploited_vulnerabilities.json and .csv read at the
  head commit (pinned by its SHA), the git log of the JSON file for when each entry first
  appeared, and the cisa.gov feed for a cross check (catalog version and CVE set).
- **Licence:** the repository LICENSE: the KEV database is distributed under the Creative Commons
  0 1.0 License; information from third parties linked from the catalog may carry its own terms.
- **Note:** the kev-data history starts on 27 January 2025, so first_seen_commit for an entry
  added to the catalog before then is the first commit of the repository; dateAdded is the date
  CISA states.

## EPSS (epss)

- **Where:** the FIRST daily score files (epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz)
  from 14 April 2021, the first day published; api.first.org/data/v1/epss with
  scope=time-series only if the daily file host cannot be reached.
- **Terms:** the FIRST EPSS usage agreement grants the use of EPSS scores freely to the public,
  subject to its conditions, and asks for attribution. The agreement section of first.org/epss did
  not render for a non browser client on the day; it was read through the ScanCode LicenseDB copy
  (first-epss-usage), which names first.org/epss as its source. Attribution: EPSS scores from
  FIRST, the Forum of Incident Response and Security Teams.
- **Kept:** for every CVE published on or after 1 January 2020, the score on days 0, 1, 7, 30 and
  90 after publication; for every CVE in KEV, the score on every day (offset -1); with the model
  version and score date read from each file header (the earliest files have no header). Every
  daily file is locked by its digest; the files themselves are not kept. A day the bucket has no
  file for (it answers 403 AccessDenied) is recorded as empty in the ledger.

## OSV (osv)

- **Where:** osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip for npm, PyPI, Go,
  Maven, crates.io, RubyGems, NuGet, Packagist and Debian.
- **Licences, by the database prefix of each advisory (source_db), as the OSV data page lists
  them:** GHSA, the GitHub Advisory Database, CC BY 4.0; PYSEC, the PyPI Advisory Database, CC BY
  4.0; GO, the Go Vulnerability Database, CC BY 4.0; RUSTSEC, the Rust Advisory Database, CC0 1.0;
  DRUPAL, the Drupal Advisory Database, MIT; GSD, the Global Security Database, CC0 1.0; MAL,
  OpenSSF Malicious Packages, Apache 2.0; EEF, the Erlang Ecosystem Foundation CNA, CC BY 4.0;
  OSV, OSS-Fuzz, CC BY 4.0. DEBIAN, DSA, DLA and DTSA are Debian security advisories and CVE are
  NVD records, both converted by the OSV.dev team; the OSV data page states no licence for the
  converted data, so their upstream terms (the Debian security tracker, the NVD notice above)
  apply.
- **Kept:** per advisory its id, ecosystem, aliases, dates, summary, severity and affected blocks
  (osv_advisories), keyed by id, ecosystem and modified, so each new version is a new row.

## GitHub Advisory Database (ghsa)

- **Where:** github.com/github/advisory-database, the reviewed advisories under
  advisories/github-reviewed at the head commit, read one year directory at a time.
- **Licence:** CC BY 4.0 (the repository LICENSE.md). Advisory data from the GitHub Advisory
  Database, licensed under CC BY 4.0 (https://github.com/github/advisory-database). The attribution
  is on every page that uses it.
- **Kept:** per advisory its GHSA id, CVE aliases, dates, severity, CWEs and affected ranges, and
  first_seen_commit, the commit time of the first commit that added the file under
  github-reviewed. That time needs the whole history; its clone without blobs is several gigabytes,
  so the log pass runs only where the disk allows it, and the ledger says when it did not.

## CISA Vulnrichment (vulnrichment)

- **Where:** github.com/cisagov/vulnrichment at the head commit: one CVE record per file with the
  CISA ADP container, and one git log pass for when each file was first added.
- **Licence:** CC0 1.0 Universal (the repository LICENSE).
- **Kept:** per CVE the three SSVC decision points (Exploitation, Automatable, Technical Impact),
  the CVSS vector and CWEs the ADP added, the first commit time of the file and the dateUpdated of
  the ADP container.

## CWE (cwe)

- **Where:** cwe.mitre.org/data/xml/cwec_latest.xml.zip (CWE 5.0, dated 28 October 2026, which
  renamed the Categories section to Groupings).
- **Terms:** CWE is free to use by any organization or individual for any research, development
  and commercial purposes, per the CWE Terms of Use; any copy must reproduce MITRE's copyright
  designation and the license. Copyright 2006-2026, The MITRE Corporation. CWE is a trademark of
  The MITRE Corporation.
- **Kept:** per weakness and grouping its id, name, abstraction (or element kind) and its ChildOf
  parents in the Research Concepts view (CWE-1000).

## Exploit code signals (exploits)

- **Metasploit:** github.com/rapid7/metasploit-framework at the head commit; the modules that
  name a CVE in their references, and the first commit time of each module file from one git log
  pass over a clone without blobs. The framework is provided under the 3-clause BSD license
  (Copyright 2006-2026, Rapid7, Inc.).
- **Nuclei:** github.com/projectdiscovery/nuclei-templates at the head commit; the templates named
  after a CVE and the first commit time of each, taken over every path a file of that name has had
  (the repository moved its CVE templates under http/ in March 2023). MIT License (Copyright 2025
  ProjectDiscovery, Inc.).
- **Kept:** only the CVE id, the source, the path and the first commit time (exploit_signals). No
  module or template content is stored or republished. A Metasploit module moved within the
  repository is dated at the path it has now.

## Registries for the name check (registries)

- **GLEIF:** api.gleif.org/api/v1/lei-records, searched by legal name and in full text for each
  name in config/sources.yaml. The LEI data available through the GLEIF access service is
  provided under the CC0 licence (the GLEIF LEI data terms of use).
- **SEC EDGAR:** www.sec.gov/files/company_tickers.json, requested with the project User-Agent and
  no contact address. The SEC asks automated clients to declare a contact address in their
  User-Agent; it answered this request with HTTP 403 (Request Rate Threshold Exceeded) on the day,
  which is recorded in the ledger and in results/probe.json as a refusal, not retried.
- **Kept:** the answers, locked by digest, and the number of matches in the ledger note. Nothing
  goes to bronze.

## The CNA list (cna_list)

- **Where:** CNAsList.json in github.com/CVEProject/cve-website (the file cve.org renders its
  partner list from) at the head of its main branch, pinned by commit and digest.
- **Terms:** the CVE Program Terms of Use above.
- **Kept:** config/filers.yaml, each filer with its published CNA types, the group the rule in
  packages/sources/src/unscheduled_sources/cna_list.py gives it, and the number of CVE records it
  assigned.
