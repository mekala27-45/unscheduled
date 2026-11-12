# Legacy memo: the nightly report that went quiet

Velloran Systems handed over the nightly vulnerability report the security team has run from cron since 2019: customer/legacy/vuln_report.py,
configured by customer/legacy/vuln_report.ini. The script is a fixture written for this build in the style of that job, as its header says. It is never run against the live NVD; the characterization tests run it on sample files in the NVD 1.1 feed layout.

## Why it went quiet

The script downloads the NVD 1.1 JSON data feeds, keeps the CVEs whose CPE vendor is on a watch
list, writes a CSV and mails it. NIST retired those feeds in 2023. Asked on
2026-11-08, the addresses in the handed over config answered
403, 403, 403,
while the feeds that replaced them answered
206, 206.

The download sits inside a bare except, so a refused download is not an error: the script carries
on with no data, writes a CSV that holds only its header, mails it, and exits with code
0. Run on the retired
feeds, this is all it prints:

```
exit code 0
wrote <reports>/vuln_report_<day>.csv with 0 rows
```

Every night since the feeds went away, the team has received a report that looks like a quiet
night, and because nothing fails, nothing has told them otherwise.

## Characterization first

Before anything was changed, tests/characterization pinned what the script does today. A converter
writes sample files in the 1.1 JSON layout from the current NVD data, and golden master tests run the
script on them and on retired feeds, comparing the CSV, the mail and the console line byte for byte.
The tests keep the silent failure as behavior to reproduce, not a bug to fix in place, and they
record two things the team did not know: a CVE whose product appears only inside a configuration is
never reported, and a CVE the NVD has not analyzed, which since April is most of them, never
reaches the report at all, because it has no CPE to match.

## The strangler

packages/legacy_adapter writes the same CSV from the new API: the same columns in the same order,
dates as DD/MM/YYYY, the same types, rows deduplicated the way the old script did. It is served at
/v1/legacy/report.csv, so the spreadsheet downstream keeps working. Its columns, read from the
golden master:

```
CVE,Published,Last Modified,Vendor,Product,CVSS3 Score,CVSS3 Severity,CVSS2 Score,Summary
```

A contract test compares the header byte for byte and every cell's type with the golden master,
and a second test writes the CSV from the real findings and checks every cell against the same
contract. Where the old report took a date or a score from the NVD, the adapter takes it from the
record, from the filer or from CISA, and says which.

## Deprecation plan

- Run both for two weeks: the old script as it is, the adapter's CSV beside it, compared every
  morning by the contract test.
- Compare: every CVE in the old report must be in the new one; the new one may hold more, the
  CVEs the old one could not see.
- Switch: the cron job fetches /v1/legacy/report.csv instead of running the script.
- Remove the script and its config, and keep the golden master as the record of what it did.

The security lead would push back: the script is a fixture written for this build, in the style of
the customer's job, so the memo describes the fixture as it behaves. The failure it shows (a
retired feed, a bare except, a header only CSV) is a common way for such jobs to go quiet.

> unscheduled is a portfolio demonstration. Its customer is fictional, and public open source repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official scores. It is not for security, legal or regulatory decisions. It never files a report and never applies a patch: a person approves every plan and files every report. This product uses data from the NVD API but is not endorsed or certified by the NVD.
