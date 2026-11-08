#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_report.py - nightly vulnerability report for the product security team

FIXTURE. This file was written in November 2026 for the unscheduled demonstration, in the style
of the cron job that the fictional customer Velloran Systems says it has run every night since
2019. It is not anyone's production code. It is never run against the live NVD: the tests in
tests/characterization run it on sample files in the NVD 1.1 feed layout, built by a converter,
and pin what it does today, the silent failure included.

As handed over:

    # /etc/cron.d/secops
    15 2 * * * secops /usr/bin/python3 /opt/secops/vuln_report.py -c /opt/secops/vuln_report.ini

Downloads the NVD JSON 1.1 data feeds (recent, modified and the years in the config), keeps the
CVEs whose CPE vendor is on the watch list, writes them to a CSV and mails it to the team.

    2019-03-11  first version (T.)
    2019-06-02  add CVSS v3 columns, dates as DD/MM/YYYY for the spreadsheet
    2020-01-20  also read the modified feed so updated CVEs show up again
    2021-11-08  dedupe rows, the team was getting the same CVE three times
"""

import argparse
import configparser
import csv
import datetime
import gzip
import json
import os
import smtplib
import sys
import urllib.request
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

FEED_FILE = "nvdcve-1.1-{}.json.gz"
COLUMNS = [
    "CVE",
    "Published",
    "Last Modified",
    "Vendor",
    "Product",
    "CVSS3 Score",
    "CVSS3 Severity",
    "CVSS2 Score",
    "Summary",
]
NVD_DATE = "%Y-%m-%dT%H:%MZ"
SHEET_DATE = "%d/%m/%Y"


def read_config(path):
    cfg = configparser.ConfigParser()
    if not cfg.read(path):
        print("cannot read config %s" % path)
        sys.exit(2)
    return cfg


def feed_names(cfg):
    names = ["recent"]
    if cfg.getboolean("feeds", "include_modified", fallback=True):
        names.append("modified")
    for year in cfg.get("feeds", "years", fallback="").split(","):
        if year.strip():
            names.append(year.strip())
    return names


def download_feed(base_url, name):
    url = base_url + FEED_FILE.format(name)
    resp = urllib.request.urlopen(url, timeout=120)
    data = gzip.decompress(resp.read())
    return json.loads(data.decode("utf-8"))


def fetch_items(cfg):
    base_url = cfg.get("feeds", "base_url")
    items = []
    for name in feed_names(cfg):
        try:
            feed = download_feed(base_url, name)
            items.extend(feed["CVE_Items"])
        except:
            # NVD is flaky at night, the next run picks it up
            pass
    return items


def watched_vendors(cfg):
    return [v.strip().lower() for v in cfg.get("filter", "vendors").split(",") if v.strip()]


def cpe_matches(item):
    # every cpe_match of the configuration nodes
    out = []
    for node in item.get("configurations", {}).get("nodes", []):
        for match in node.get("cpe_match", []):
            if match.get("vulnerable"):
                out.append(match["cpe23Uri"])
    return out


def sheet_date(value):
    return datetime.datetime.strptime(value, NVD_DATE).strftime(SHEET_DATE)


def summary_of(item):
    for desc in item["cve"]["description"]["description_data"]:
        if desc.get("lang") == "en":
            return " ".join(desc["value"].split())
    return ""


def scores(item):
    impact = item.get("impact", {})
    v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
    v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
    v3_score = v3.get("baseScore")
    v2_score = v2.get("baseScore")
    return (
        "" if v3_score is None else str(float(v3_score)),
        v3.get("baseSeverity", ""),
        "" if v2_score is None else str(float(v2_score)),
    )


def build_rows(items, vendors):
    rows = []
    seen = set()
    for item in items:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        for uri in cpe_matches(item):
            parts = uri.split(":")
            vendor, product = parts[3], parts[4]
            if vendor not in vendors:
                continue
            if (cve_id, vendor, product) in seen:
                continue
            seen.add((cve_id, vendor, product))
            v3_score, v3_severity, v2_score = scores(item)
            rows.append(
                [
                    cve_id,
                    sheet_date(item["publishedDate"]),
                    sheet_date(item["lastModifiedDate"]),
                    vendor,
                    product,
                    v3_score,
                    v3_severity,
                    v2_score,
                    summary_of(item),
                ]
            )
    return rows


def write_csv(rows, directory, today):
    if not os.path.isdir(directory):
        os.makedirs(directory)
    path = os.path.join(directory, "vuln_report_%s.csv" % today.strftime("%Y%m%d"))
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for row in rows:
            writer.writerow(row)
    return path


def send_mail(cfg, path, count, today):
    msg = MIMEMultipart()
    msg["Subject"] = "[secops] NVD report %s: %d CVEs" % (today.strftime("%d/%m/%Y"), count)
    msg["From"] = cfg.get("mail", "from")
    msg["To"] = cfg.get("mail", "to")
    body = "Attached: %d CVEs for the watched vendors (%s).\n" % (count, cfg.get("filter", "vendors"))
    msg.attach(MIMEText(body, "plain", "utf-8"))
    part = MIMEBase("text", "csv")
    with open(path, "rb") as handle:
        part.set_payload(handle.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=os.path.basename(path))
    msg.attach(part)
    server = smtplib.SMTP(cfg.get("mail", "smtp_host"), cfg.getint("mail", "smtp_port"), timeout=60)
    try:
        server.sendmail(msg["From"], [a.strip() for a in msg["To"].split(",")], msg.as_string())
    finally:
        server.quit()


def main():
    parser = argparse.ArgumentParser(description="nightly NVD report")
    parser.add_argument("-c", "--config", default="/opt/secops/vuln_report.ini")
    args = parser.parse_args()
    cfg = read_config(args.config)
    today = datetime.date.today()
    items = fetch_items(cfg)
    rows = build_rows(items, watched_vendors(cfg))
    path = write_csv(rows, cfg.get("output", "directory"), today)
    send_mail(cfg, path, len(rows), today)
    print("wrote %s with %d rows" % (path, len(rows)))


if __name__ == "__main__":
    main()
