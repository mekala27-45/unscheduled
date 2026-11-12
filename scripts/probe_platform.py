"""The platform probes: the live API and web, and what the consoles showed, with no credential.

    python scripts/probe_platform.py    # writes results/probe_platform.json

Live numbers come from the public routes: the API health route timed on a first and on ten warm
requests, the CORS answer for the web origin, and the landing with its statement and NVD notice.
What only a console shows (the Neon plan and storage, the Vercel variable names, the Actions
settings) is read in the browser by the build and kept in data/console_readings.yaml with the date
it was read; this script copies it beside the live numbers and refuses a reading over thirty days
old, so a deploy step never trusts a stale plan limit.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
API = "https://unscheduled-api.vercel.app"
WEB = "https://unscheduled-triage.vercel.app"
AGENT = "unscheduled-probe/0.1 (+https://github.com/mekala27-45/unscheduled)"
MAX_AGE_DAYS = 30


def fetch(url: str, method: str = "GET", headers: dict[str, str] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url, method=method, headers={"User-Agent": AGENT, **(headers or {})})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
            status, head = response.status, dict(response.headers)
    except urllib.error.HTTPError as error:
        body, status, head = error.read(), error.code, dict(error.headers)
    except (urllib.error.URLError, TimeoutError) as error:
        return {"status": None, "error": str(error)[:200], "ms": None}
    return {
        "status": status,
        "ms": round((time.perf_counter() - started) * 1000),
        "headers": head,
        "body": body,
    }


def probe_api() -> dict[str, Any]:
    first = fetch(f"{API}/health")
    warm = [fetch(f"{API}/health") for _ in range(10)]
    timings = [w["ms"] for w in warm if w["status"] == 200]
    health: dict[str, Any] = {}
    if first["status"] == 200:
        health = json.loads(first["body"])
    preflight = fetch(
        f"{API}/v1/meta",
        method="OPTIONS",
        headers={"Origin": WEB, "Access-Control-Request-Method": "GET"},
    )
    allowed = {k.lower(): v for k, v in (preflight.get("headers") or {}).items()}.get(
        "access-control-allow-origin"
    )
    return {
        "health_status": first["status"],
        "first_request_ms": first["ms"],
        "warm_p50_ms": round(statistics.median(timings)) if timings else None,
        "warm_max_ms": max(timings) if timings else None,
        "version": health.get("version"),
        "database": health.get("database"),
        "cors_allows_web_origin": allowed == WEB,
    }


def probe_web() -> dict[str, Any]:
    page = fetch(WEB)
    text = page.get("body", b"").decode("utf-8", errors="replace") if page["status"] == 200 else ""
    return {
        "status": page["status"],
        "ms": page["ms"],
        "statement_present": "is a portfolio demonstration" in text,
        "nvd_notice_present": "not endorsed or certified by the NVD" in text,
    }


def readings(path: Path = ROOT / "data" / "console_readings.yaml") -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    read_on = (
        data["read_on"] if isinstance(data["read_on"], date) else date.fromisoformat(str(data["read_on"]))
    )
    age = (datetime.now(UTC).date() - read_on).days
    if age > MAX_AGE_DAYS:
        raise SystemExit(f"probe: the console readings are {age} days old; read the consoles again")
    data["read_on"] = read_on.isoformat()
    data["age_days"] = age
    return data


def fill_probe(path: Path, out: dict[str, Any]) -> None:
    """Write the Neon and Vercel sections of results/probe.json, which scripts/probe_hosts.py leaves
    pending for this step, so the deploy steps read one file."""
    if not path.exists():
        return
    probe: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    consoles = out["consoles"]
    probe["neon"] = {
        "status": "probed",
        "probed_at": out["probed_at"],
        "console": consoles.get("neon"),
        "from_the_api": out["api"].get("database"),
    }
    probe["vercel"] = {
        "status": "probed",
        "probed_at": out["probed_at"],
        "console": consoles.get("vercel"),
        "api": {
            k: out["api"][k] for k in ("health_status", "first_request_ms", "warm_p50_ms", "warm_max_ms")
        },
        "web": out["web"],
    }
    path.write_text(json.dumps(probe, indent=1) + "\n", encoding="utf-8")


def main() -> int:
    api, web = probe_api(), probe_web()
    out: dict[str, Any] = {
        "probed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "api": api,
        "web": web,
        "consoles": readings(),
    }
    path = ROOT / "results" / "probe_platform.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    fill_probe(ROOT / "results" / "probe.json", out)
    print(
        f"probe: api {api['health_status']} first {api['first_request_ms']} ms, warm p50 {api['warm_p50_ms']} ms; "
        f"web {web['status']}, statement {web['statement_present']}"
    )
    return 0 if api["health_status"] == 200 and web["status"] == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
