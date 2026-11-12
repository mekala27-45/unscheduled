"""Probe every host the build depends on and write results/probe.json.

Every source answers with a size and a date. The NVD answers without a key (and with one when
NVD_API_KEY is present), and the probe times a burst of requests within the documented allowance
to measure the limit the NVD enforces without exceeding it. GitHub release downloads are checked
on a real asset, uploads where a token exists. The Fontsource packages are looked up on npm. The
Neon and Vercel sections are kept as written by the step that probes them, or left pending.

A probe that fails is recorded with its error and the run goes on; the file always says what was
reachable on the day, which every deploy step reads.

    uv run python scripts/probe_hosts.py [--skip-nvd-burst]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from unscheduled_core import paths
from unscheduled_sources import gitrepo
from unscheduled_sources.cvelist import release_tags
from unscheduled_sources.http import USER_AGENT
from unscheduled_sources.registry import load_config

FONTSOURCE = ("@fontsource/rethink-sans", "@fontsource/anek-latin", "@fontsource/mononoki")
FONT_VERSION = "5.3.0"
REPOSITORY = "mekala27-45/unscheduled"
BURST = 5


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


def guarded(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return fn()
    except Exception as error:
        return {"ok": False, "error": f"{type(error).__name__}: {str(error)[:300]}"}


class Probe:
    def __init__(self) -> None:
        self.client = httpx.Client(
            headers={"User-Agent": USER_AGENT}, timeout=httpx.Timeout(60.0), follow_redirects=True
        )
        self.cfg = load_config(paths.root())["sources"]

    def head(self, url: str, *, ranged: bool = False, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Size and date of a file: a HEAD, or a one byte range when the host answers HEAD badly."""
        if ranged:
            response = self.client.get(url, headers={"Range": "bytes=0-0"}, params=params)
        else:
            response = self.client.head(url, params=params)
        size: int | None = None
        content_range = response.headers.get("content-range", "")
        if "/" in content_range:
            tail = content_range.rsplit("/", 1)[1]
            size = int(tail) if tail.isdigit() else None
        elif response.headers.get("content-length", "").isdigit():
            size = int(response.headers["content-length"])
        return {
            "url": url,
            "status": response.status_code,
            "ok": response.status_code in (200, 206),
            "size": size,
            "date": http_date(response.headers.get("last-modified"))
            or http_date(response.headers.get("date")),
        }

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> tuple[dict[str, Any], Any]:
        started = time.monotonic()
        response = self.client.get(url, params=params)
        result: dict[str, Any] = {
            "url": str(response.url),
            "status": response.status_code,
            "ok": response.status_code == 200,
            "size": len(response.content),
            "elapsed_s": round(time.monotonic() - started, 3),
            "date": http_date(response.headers.get("date")),
        }
        body = response.json() if response.status_code == 200 else None
        return result, body

    def cvelist(self) -> dict[str, Any]:
        tags = release_tags(self.cfg["cvelist"]["git"])
        day, hour = tags[-1]
        baseline_tag = self.cfg["cvelist"]["tag"].format(day=day, hour="0000")
        asset = self.cfg["cvelist"]["baseline_asset"].format(day=day)
        out = self.head(f"{self.cfg['cvelist']['release_download']}/{baseline_tag}/{asset}", ranged=True)
        out["date"] = f"{day}T{hour[:2]}:{hour[2:]}:00Z"
        out["newest_release"] = f"cve_{day}_{hour}Z"
        out["releases_listed"] = len(tags)
        return out

    def nvd(self, url: str, key: str) -> dict[str, Any]:
        result, body = self.get_json(url, {"resultsPerPage": 1})
        if body is not None:
            result["date"] = body.get("timestamp")
            result["total_results"] = body.get("totalResults")
            result[key] = True
        return result

    def nvd_burst(self, api_key: str | None) -> dict[str, Any]:
        """Time a burst of BURST requests, the documented keyless allowance in any 30 seconds."""
        url = self.cfg["nvd"]["cves_url"]
        headers = {"apiKey": api_key} if api_key else {}
        statuses: list[int] = []
        latencies: list[float] = []
        started = time.monotonic()
        for _ in range(BURST):
            t0 = time.monotonic()
            response = self.client.get(url, params={"resultsPerPage": 1}, headers=headers)
            latencies.append(round(time.monotonic() - t0, 3))
            statuses.append(response.status_code)
        elapsed = round(time.monotonic() - started, 3)
        answered = sum(1 for s in statuses if s == 200)
        return {
            "requests": BURST,
            "answered": answered,
            "refused": BURST - answered,
            "statuses": statuses,
            "latencies_s": latencies,
            "elapsed_s": elapsed,
            "measured": (
                f"{answered} of {BURST} requests sent within {elapsed} s were answered; "
                + (
                    "the enforced limit is at least the documented allowance"
                    if answered == BURST
                    else "the NVD enforced a limit below the documented allowance"
                )
            ),
        }

    def git_head(self, url: str) -> dict[str, Any]:
        """A repository answers with its head commit time and the size of its head tree listing.

        The head is fetched one commit deep without blobs into a throwaway repository: enough for the
        commit time, the number of files and the bytes the listing took, and nothing else.
        """
        import tempfile

        started = time.monotonic()
        head = gitrepo.remote_head(url)
        with tempfile.TemporaryDirectory(prefix="probe-") as tmp:
            repo = Path(tmp)
            gitrepo.git(repo, "init", "--quiet", "--bare")
            gitrepo.git(repo, "fetch", "--quiet", "--depth", "1", "--filter=blob:none", url, head)
            date = gitrepo.git(repo, "log", "-1", "--format=%cI", head).strip()
            files = len(gitrepo.git(repo, "ls-tree", "-r", "--name-only", head).splitlines())
            size = sum(p.stat().st_size for p in (repo / "objects").rglob("*") if p.is_file())
        return {
            "url": url,
            "ok": True,
            "head": head,
            "date": date,
            "size": size,
            "size_is": "bytes of the head commit and its trees, fetched without blobs",
            "files_at_head": files,
            "elapsed_s": round(time.monotonic() - started, 3),
        }

    def kev(self) -> dict[str, Any]:
        head = gitrepo.remote_head(self.cfg["kev"]["git"])
        result, body = self.get_json(f"{self.cfg['kev']['raw']}/{head}/{self.cfg['kev']['json_file']}")
        if body is not None:
            result["date"] = body.get("dateReleased")
            result["catalog_version"] = body.get("catalogVersion")
            result["entries"] = body.get("count")
        result["head"] = head
        return result

    def cisa_feed(self) -> dict[str, Any]:
        result, body = self.get_json(self.cfg["kev"]["cisa_feed"])
        if body is not None:
            result["date"] = body.get("dateReleased")
            result["catalog_version"] = body.get("catalogVersion")
        return result

    def epss_daily(self) -> dict[str, Any]:
        today = datetime.now(UTC).date()
        last: dict[str, Any] = {}
        for back in range(4):
            day = today.fromordinal(today.toordinal() - back)
            last = self.head(self.cfg["epss"]["daily_url"].format(day=day.isoformat()))
            if last["ok"]:
                last["file_day"] = day.isoformat()
                return last
        return last

    def epss_api(self) -> dict[str, Any]:
        result, body = self.get_json(self.cfg["epss"]["api_url"], {"cve": "CVE-2021-44228"})
        if body is not None and body.get("data"):
            result["date"] = body["data"][0].get("date")
        return result

    def osv(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        bucket = str(self.cfg["osv"]["bucket"])
        for eco in self.cfg["osv"]["ecosystems"]:
            url = f"{bucket}/{eco}/all.zip"

            def one(u: str = url) -> dict[str, Any]:
                return self.head(u)

            out[str(eco)] = guarded(one)
        out["ok"] = all(v.get("ok") for v in out.values() if isinstance(v, dict))
        return out

    def gleif(self) -> dict[str, Any]:
        name = self.cfg["registries"]["names"][0]
        result, body = self.get_json(self.cfg["registries"]["gleif"], {"filter[entity.legalName]": name})
        if body is not None:
            result["records_for_name"] = len(body.get("data") or [])
        return result

    def edgar(self) -> dict[str, Any]:
        response = self.client.get(self.cfg["registries"]["edgar"])
        refused = response.status_code in (401, 403)
        return {
            "url": self.cfg["registries"]["edgar"],
            "status": response.status_code,
            "ok": response.status_code == 200,
            "refused": refused,
            "size": len(response.content),
            "date": http_date(response.headers.get("date")),
            "note": (
                "the SEC refused a client that names the project and gives no contact address; "
                "recorded as the result, not retried"
                if refused
                else None
            ),
        }

    def cna_list(self) -> dict[str, Any]:
        c = self.cfg["cna_list"]
        head = gitrepo.remote_head(c["git"], f"refs/heads/{c['branch']}")
        result = self.head(f"{c['raw']}/{head}/{c['file']}")
        result["head"] = head
        return result

    def github_release(self) -> dict[str, Any]:
        download = guarded(self.cvelist)
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        upload: dict[str, Any]
        if token and shutil.which("gh"):
            listed = subprocess.run(
                ["gh", "api", f"repos/{REPOSITORY}/releases?per_page=1"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            upload = {
                "tested": True,
                "can_list_releases": listed.returncode == 0,
                "note": "fetch.yml uploads with the workflow token and contents: write",
            }
        else:
            upload = {
                "tested": False,
                "note": "no GitHub token on this host; fetch.yml uploads with the workflow token",
            }
        return {"download": download, "upload": upload}

    def fontsource(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for package in FONTSOURCE:

            def one(p: str = package) -> dict[str, Any]:
                result, body = self.get_json(f"https://registry.npmjs.org/{p}")
                if body is not None:
                    result["latest"] = (body.get("dist-tags") or {}).get("latest")
                    result[f"has_{FONT_VERSION}"] = FONT_VERSION in (body.get("versions") or {})
                    result["date"] = (body.get("time") or {}).get("modified")
                    result["size"] = None
                return result

            out[package] = guarded(one)
        return out


def run(skip_burst: bool) -> dict[str, Any]:
    probe = Probe()
    nvd_cfg = probe.cfg["nvd"]
    api_key = os.environ.get(nvd_cfg.get("key_env", "NVD_API_KEY")) or None
    sources: dict[str, Any] = {
        "cvelist": guarded(probe.cvelist),
        "nvd_cves": guarded(lambda: probe.nvd(nvd_cfg["cves_url"], "answered_keyless")),
        "nvd_history": guarded(lambda: probe.nvd(nvd_cfg["history_url"], "answered_keyless")),
        "kev": guarded(probe.kev),
        "kev_cisa_feed": guarded(probe.cisa_feed),
        "epss_daily": guarded(probe.epss_daily),
        "epss_api": guarded(probe.epss_api),
        "osv": guarded(probe.osv),
        "ghsa": guarded(lambda: probe.git_head(probe.cfg["ghsa"]["git"])),
        "vulnrichment": guarded(lambda: probe.git_head(probe.cfg["vulnrichment"]["git"])),
        "cwe": guarded(lambda: probe.head(probe.cfg["cwe"]["url"])),
        "metasploit": guarded(lambda: probe.git_head(probe.cfg["exploits"]["metasploit"]["git"])),
        "nuclei": guarded(lambda: probe.git_head(probe.cfg["exploits"]["nuclei"]["git"])),
        "gleif": guarded(probe.gleif),
        "edgar": guarded(probe.edgar),
        "cna_list": guarded(probe.cna_list),
    }
    limit = nvd_cfg["limit"]
    nvd_limit: dict[str, Any] = {
        "documented": {
            "keyless": limit["keyless"],
            "keyed": limit["keyed"],
            "read_on": "2026-11-08",
            "read_from": (
                "the NVD start here page, quoted in the pontos NVD client documentation; "
                "nvd.nist.gov answered this build with a bot challenge on the day"
            ),
        },
        "key_present": api_key is not None,
        "fetcher_setting": {
            "requests": limit["keyed" if api_key else "keyless"]["requests"],
            "window_s": limit["keyed" if api_key else "keyless"]["window_s"],
            "margin": limit["margin"],
        },
    }
    if skip_burst:
        nvd_limit["burst"] = {"skipped": True, "note": "an NVD fetch was running and shares the limit"}
    else:
        time.sleep(32)  # let the requests above leave the rolling window before the burst
        nvd_limit["burst"] = guarded(lambda: probe.nvd_burst(None))
        if api_key:
            nvd_limit["with_key"] = guarded(lambda: probe.nvd(nvd_cfg["cves_url"], "answered_with_key"))
    every = [v for v in sources.values() if isinstance(v, dict)]
    return {
        "probed_at": now(),
        "user_agent": USER_AGENT,
        "summary": {
            "sources": len(every),
            "answered": sum(1 for v in every if v.get("ok")),
            "refused": sorted(k for k, v in sources.items() if isinstance(v, dict) and v.get("refused")),
            "failed": sorted(
                k
                for k, v in sources.items()
                if isinstance(v, dict) and not v.get("ok") and not v.get("refused")
            ),
        },
        "sources": sources,
        "nvd_limit": nvd_limit,
        "github_release": guarded(probe.github_release),
        "fontsource": probe.fontsource(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--skip-nvd-burst", action="store_true")
    parser.add_argument("--out", type=Path, default=paths.results_dir() / "probe.json")
    args = parser.parse_args(argv)
    result = run(args.skip_nvd_burst)
    previous: dict[str, Any] = {}
    if args.out.exists():
        try:
            previous = json.loads(args.out.read_text(encoding="utf-8"))
        except ValueError:
            previous = {}
    old_burst = (previous.get("nvd_limit") or {}).get("burst") or {}
    if args.skip_nvd_burst and old_burst.get("answered") is not None:
        result["nvd_limit"]["burst"] = {
            **old_burst,
            "measured_at": old_burst.get("measured_at", previous.get("probed_at")),
        }
    elif "answered" in result["nvd_limit"].get("burst", {}):
        result["nvd_limit"]["burst"]["measured_at"] = result["probed_at"]
    pending = {"status": "pending", "note": "probed by the setup step, which writes this section"}
    result["neon"] = previous.get("neon", pending)
    result["vercel"] = previous.get("vercel", pending)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    s = result["summary"]
    print(
        f"probe: {s['answered']} of {s['sources']} sources answered; refused {s['refused']}; failed {s['failed']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
