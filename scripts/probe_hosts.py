"""Probe every host the build depends on and write results/probe.json.

Every source answers with a size and a date. The NVD answers without a key (and with one when
NVD_API_KEY is present), and the probe times a burst of requests within the documented allowance
to measure the limit the NVD enforces without exceeding it. GitHub release downloads are checked
on a real asset, uploads where a token exists. The Fontsource packages are looked up on npm. The
Neon and Vercel sections are kept as written by the step that probes them, or left pending.
Phase 2 adds the model libraries and weights, Kaggle, Databricks and R. Phase 3 adds each library
with the release its pin rule picks (config/agent.yaml), each model provider when its secret exists
(config/providers.yaml), the mlspend price book by digest, the Neon room as the API reads it, and
the function duration the API runs under.

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
from datetime import UTC, date, datetime, timedelta
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


def phase2(probe: Probe, root: Path) -> dict[str, Any]:
    """What Phase 2 needs before it starts: the libraries on PyPI, the weights on the Hugging Face
    Hub, the Kaggle and Databricks accounts when their secrets exist (answered or not, never a
    value), R with the survival package, and the image size, measured at the serving step."""
    import yaml

    cfg = yaml.safe_load((root / "config" / "models.yaml").read_text(encoding="utf-8"))
    libraries: dict[str, Any] = {}
    for name in cfg["libraries"]:

        def lib(n: str = name) -> dict[str, Any]:
            result, body = probe.get_json(f"https://pypi.org/pypi/{n}/json")
            if body is not None:
                info = body.get("info") or {}
                latest = str(info.get("version"))
                files = (body.get("releases") or {}).get(latest) or []
                result["latest"] = latest
                result["released"] = (files[0].get("upload_time_iso_8601") or "")[:10] if files else None
                result["requires_python"] = info.get("requires_python")
            return result

        libraries[name] = guarded(lib)
    weights: dict[str, Any] = {}
    for key, weight in cfg["weights"].items():

        def hub(w: dict[str, Any] = weight) -> dict[str, Any]:
            revision = w.get("revision") or "main"
            result, body = probe.get_json(
                f"https://huggingface.co/api/models/{w['id']}/revision/{revision}?blobs=true"
            )
            if body is not None:
                result["id"] = w["id"]
                result["pinned"] = w.get("revision")
                result["resolved"] = body.get("sha")
                result["last_modified"] = body.get("lastModified")
                result["license"] = (body.get("cardData") or {}).get("license")
                result["bytes"] = sum(int(s.get("size") or 0) for s in body.get("siblings") or [])
            return result

        weights[key] = guarded(hub)
    return {
        "libraries": libraries,
        "weights": weights,
        "kaggle": guarded(lambda: secret_gated_kaggle(probe)),
        "databricks": guarded(lambda: secret_gated_databricks(probe)),
        "r": guarded(r_survival),
        "image": {
            "status": "pending",
            "note": "measured at step 13 from a build of Dockerfile.vercel with onnxruntime added",
        },
    }


def secret_gated_kaggle(probe: Probe) -> dict[str, Any]:
    """The Kaggle API answers for the account, read with the two secrets when they exist. Nothing is
    pushed, and neither the username nor the key is written anywhere."""
    user, key = os.environ.get("KAGGLE_USERNAME"), os.environ.get("KAGGLE_KEY")
    if not user or not key:
        return {
            "ok": True,
            "token_present": False,
            "note": "KAGGLE_USERNAME and KAGGLE_KEY are not set; step 8 takes its CPU fallback",
        }
    response = probe.client.get(
        "https://www.kaggle.com/api/v1/kernels/list",
        params={"user": user, "pageSize": 1},
        auth=(user, key),
    )
    return {"ok": response.status_code == 200, "token_present": True, "status": response.status_code}


def secret_gated_databricks(probe: Probe) -> dict[str, Any]:
    """The workspace MLflow answers, read with the two secrets when they exist. The host is not
    written either: only whether it answered."""
    host, token = os.environ.get("DATABRICKS_HOST"), os.environ.get("DATABRICKS_TOKEN")
    if not host or not token:
        return {
            "ok": True,
            "token_present": False,
            "note": "DATABRICKS_HOST and DATABRICKS_TOKEN are not set; the registry uses the file store",
        }
    response = probe.client.get(
        f"{host.rstrip('/')}/api/2.0/mlflow/experiments/search",
        params={"max_results": 1},
        headers={"Authorization": f"Bearer {token}"},
    )
    return {"ok": response.status_code == 200, "token_present": True, "status": response.status_code}


def r_survival() -> dict[str, Any]:
    """R and its survival package on this machine, for the Cox cross check."""
    rscript = shutil.which("Rscript")
    if rscript is None:
        return {"ok": False, "note": "Rscript is not on this machine; models.yml installs R in Actions"}
    version = subprocess.run([rscript, "--version"], capture_output=True, text=True, check=False)
    survival = subprocess.run(
        [rscript, "-e", 'cat(as.character(packageVersion("survival")))'],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "ok": survival.returncode == 0,
        "r": (version.stdout or version.stderr).strip().splitlines()[0][:120],
        "survival": survival.stdout.strip() or None,
    }


API = "https://unscheduled-api.vercel.app"
VERCEL_DURATION = {
    "documented_max_s": 300,
    "documented_default_s": 300,
    "read_from": "https://vercel.com/docs/functions/configuring-functions/duration",
    "page_updated": "2026-08-24",
    "read_on": "2026-11-15",
    "note": "the Hobby plan with fluid compute; C8 asks a triage run for 30 s at the 95th percentile",
}


def phase3(probe: Probe, root: Path) -> dict[str, Any]:
    """What Phase 3 needs before it starts: each library with the release the pin rule picks, each
    model provider when its secret exists (answered or not, its listed models and the limits it
    reports on one short answer, never a key), the price book locked by digest, the Neon room as the
    API reads it, and the function duration the API runs under."""
    import yaml

    agent = yaml.safe_load((root / "config" / "agent.yaml").read_text(encoding="utf-8"))
    # YAML reads a bare date as a date; the probe writes JSON, so every value becomes plain text.
    providers = json.loads(
        json.dumps(
            yaml.safe_load((root / "config" / "providers.yaml").read_text(encoding="utf-8")), default=str
        )
    )
    rule = agent["pin_rule"]
    cutoff = date.fromisoformat(str(agent["phase_start"])) - timedelta(days=int(rule["min_age_days"]))
    libraries: dict[str, Any] = {}
    for name in agent["libraries"]:

        def lib(n: str = name) -> dict[str, Any]:
            result, body = probe.get_json(f"https://pypi.org/pypi/{n}/json")
            if body is not None:
                result.update(pinned_release(body, cutoff, bool(rule.get("skip_prereleases", True))))
            return result

        libraries[name] = guarded(lib)
    answers: dict[str, Any] = {}
    for name, cfg in providers["providers"].items():

        def one(n: str = name, c: dict[str, Any] = cfg) -> dict[str, Any]:
            return probe_provider(probe.client, n, c, providers, os.environ.get(str(c["key_env"])))

        answers[name] = guarded(one)
    return {
        "pin_rule": {
            "phase_start": str(agent["phase_start"]),
            "min_age_days": int(rule["min_age_days"]),
            "released_on_or_before": cutoff.isoformat(),
        },
        "libraries": libraries,
        "providers": answers,
        "providers_with_a_key": sorted(n for n, a in answers.items() if a.get("token_present")),
        "retired": providers.get("retired", {}),
        "price_book": guarded(lambda: price_book(probe.client, providers["price_book"])),
        "neon": guarded(lambda: neon_from_the_api(probe.client)),
        "vercel": vercel_duration(root),
    }


def _released(files: list[dict[str, Any]]) -> str | None:
    times = sorted(
        str(f.get("upload_time_iso_8601") or "")[:10] for f in files if f.get("upload_time_iso_8601")
    )
    return times[0] if times else None


def pinned_release(body: dict[str, Any], cutoff: date, skip_prereleases: bool = True) -> dict[str, Any]:
    """The newest release and the one the pin rule picks: the highest version, not yanked and not a
    prerelease, whose first file was uploaded on or before the cutoff."""
    from packaging.version import InvalidVersion, Version

    info = body.get("info") or {}
    releases: dict[str, list[dict[str, Any]]] = body.get("releases") or {}
    latest = str(info.get("version"))
    eligible: list[tuple[Version, str, str]] = []
    for text, files in releases.items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            version = Version(text)
        except InvalidVersion:
            continue
        if skip_prereleases and (version.is_prerelease or version.is_devrelease):
            continue
        released = _released(files)
        if released is not None and released <= cutoff.isoformat():
            eligible.append((version, text, released))
    pin = max(eligible)[1:] if eligible else (None, None)
    return {
        "latest": latest,
        "latest_released": _released(releases.get(latest) or []),
        "pin": pin[0],
        "pin_released": pin[1],
        "requires_python": info.get("requires_python"),
    }


def probe_provider(
    client: httpx.Client, name: str, cfg: dict[str, Any], common: dict[str, Any], key: str | None
) -> dict[str, Any]:
    """One provider: absent without its key; with it, the model list and one short answer, whose
    rate limit headers are the limits the provider says it enforces. Nothing from the key or the
    answer text is kept."""
    out: dict[str, Any] = {
        "ok": True,
        "token_present": bool(key),
        "key_env": cfg["key_env"],
        "base_url": cfg["base_url"],
        "documented": cfg.get("documented"),
    }
    if not key:
        out["note"] = f"{cfg['key_env']} is not set, so the router skips {name} and the floor answers"
        return out
    headers = {"Authorization": f"Bearer {key}"}
    listed = client.get(f"{cfg['base_url']}/models", headers=headers)
    ids: list[str] = []
    if listed.status_code == 200:
        ids = sorted(str(m.get("id")) for m in (listed.json().get("data") or []) if m.get("id"))
    wanted = [str(m) for m in cfg.get("models") or []]
    out.update(
        ok=listed.status_code == 200,
        models_status=listed.status_code,
        models_listed=len(ids),
        wanted={m: m in ids for m in wanted},
    )
    guards = [str(m) for m in cfg.get("guard_models") or []]
    if guards:
        out["guards"] = {m: m in ids for m in guards}
    suffix = cfg.get("model_suffix")
    pool = [i for i in ids if i.endswith(str(suffix))] if suffix else ids
    if not wanted:
        out["models"] = pool[:80]
    model = next((m for m in wanted if m in ids), None) or (pool[0] if pool else None)
    if model is None:
        return out
    started = time.monotonic()
    answer = client.post(
        f"{cfg['base_url']}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "messages": [{"role": "user", "content": str(common["probe_prompt"])}],
            "max_tokens": int(common["probe_max_tokens"]),
        },
    )
    usage = answer.json().get("usage") if answer.status_code == 200 else None
    out["one_line"] = {
        "model": model,
        "status": answer.status_code,
        "elapsed_s": round(time.monotonic() - started, 3),
        "limits": {k.lower(): v for k, v in answer.headers.items() if "ratelimit" in k.lower()},
        "usage": {k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens") if k in usage}
        if isinstance(usage, dict)
        else None,
    }
    return out


def price_book(client: httpx.Client, cfg: dict[str, Any]) -> dict[str, Any]:
    """The mlspend price book, locked by the digest of the exact bytes read."""
    import hashlib

    url = f"https://raw.githubusercontent.com/{cfg['repository']}/{cfg['ref']}/{cfg['path']}"
    response = client.get(url)
    body = response.content
    out: dict[str, Any] = {"ok": response.status_code == 200, "status": response.status_code, "url": url}
    if response.status_code != 200:
        return out
    rows = json.loads(body).get("rows") or []
    tokens = [r for r in rows if "token" in str(r.get("unit", "")).lower()]
    out.update(
        sha256=hashlib.sha256(body).hexdigest(),
        bytes=len(body),
        rows=len(rows),
        token_rows=len(tokens),
        token_skus=sorted({str(r.get("sku")) for r in tokens}),
        providers=sorted({str(r.get("provider")) for r in rows}),
        retrieved=sorted({str(r.get("retrieved_date")) for r in rows}),
    )
    return out


NEON_FIELDS = (
    "reachable",
    "migration",
    "server_version",
    "pgvector_available",
    "pgvector_version",
    "pgvector_installed",
    "pg_search_available",
    "database_size_bytes",
    "storage_ceiling_bytes",
    "storage_share_used",
    "tables",
    "schemas",
)


def neon_from_the_api(client: httpx.Client) -> dict[str, Any]:
    """The room in Neon as the API reads it: only the API can reach the database, and /health says
    what it holds without a credential."""
    response = client.get(f"{API}/health")
    out: dict[str, Any] = {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "read_at": now(),
    }
    if response.status_code != 200:
        return out
    body = response.json()
    database = body.get("database") or {}
    out.update({k: database.get(k) for k in NEON_FIELDS})
    out["data_version"] = body.get("data_version")
    return out


def vercel_duration(root: Path) -> dict[str, Any]:
    """The longest a request to the API may run: what vercel.json sets, else the documented default."""
    cfg = json.loads((root / "vercel.json").read_text(encoding="utf-8"))
    configured = {
        path: spec.get("maxDuration")
        for path, spec in (cfg.get("functions") or {}).items()
        if isinstance(spec, dict) and "maxDuration" in spec
    }
    return {"ok": True, "configured_max_duration_s": configured or None, **VERCEL_DURATION}


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
        "phase2": phase2(probe, paths.root()),
        "phase3": phase3(probe, paths.root()),
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
