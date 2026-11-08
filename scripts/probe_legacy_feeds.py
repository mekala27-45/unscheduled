"""Ask the NVD whether the feed files the legacy script reads still answer, beside their successors.

    python scripts/probe_legacy_feeds.py    # writes results/legacy/feed_probe.json

The customer's 2019 job (customer/legacy/vuln_report.py, a fixture) downloads the NVD JSON 1.1
feed files. The legacy memo says why the job went quiet, and this probe is its evidence for today:
the status each 1.1 file and each 2.0 file answers with, read with a generic user agent and no key.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = "unscheduled-probe/0.1 (+https://github.com/mekala27-45/unscheduled)"
BASE = "https://nvd.nist.gov/feeds/json/cve"
URLS = {
    "json_1_1_modified_meta": f"{BASE}/1.1/nvdcve-1.1-modified.meta",
    "json_1_1_recent_meta": f"{BASE}/1.1/nvdcve-1.1-recent.meta",
    "json_1_1_year_2019": f"{BASE}/1.1/nvdcve-1.1-2019.json.gz",
    "json_2_0_modified_meta": f"{BASE}/2.0/nvdcve-2.0-modified.meta",
    "json_2_0_recent_meta": f"{BASE}/2.0/nvdcve-2.0-recent.meta",
}


def status(url: str) -> int | None:
    request = urllib.request.Request(
        url, method="GET", headers={"User-Agent": AGENT, "Range": "bytes=0-1023"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)
    except (urllib.error.URLError, TimeoutError):
        return None


def main() -> int:
    checked = {name: {"url": url, "status": status(url)} for name, url in URLS.items()}
    legacy_ok = [v["status"] for k, v in checked.items() if k.startswith("json_1_1")]
    current_ok = [v["status"] for k, v in checked.items() if k.startswith("json_2_0")]
    out = {
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": checked,
        "legacy_feed_answers": all(s in {200, 206} for s in legacy_ok),
        "current_feed_answers": all(s in {200, 206} for s in current_ok),
    }
    path = ROOT / "results" / "legacy" / "feed_probe.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(
        f"legacy feeds: 1.1 answers {out['legacy_feed_answers']}, 2.0 answers {out['current_feed_answers']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
