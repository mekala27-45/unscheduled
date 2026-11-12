"""Verify the live API from a separate client: every route of section 12, answered as the spec says.

    python scripts/verify_api.py [--base-url https://unscheduled-api.vercel.app] [--out FILE]

This runs on a machine that holds no database credential and is not the web. Each check sends real
requests and keeps the status, the time taken and what it compared. The data the API serves is
checked against the newest serving release of the repository, read from GitHub by this client, so
data loaded any other way than by the sync shows as a mismatch. The record goes to
results/live/api_verify.json (or --out); the exit code is 1 when any check fails.

Every /v1 data route counts against this client's daily budget; one run spends about thirty
lookups and one SBOM match.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from unscheduled_core.statements import GHSA_ATTRIBUTION, NVD_NOTICE, STATEMENT

ROOT = Path(__file__).resolve().parents[1]

LIVE = "https://unscheduled-api.vercel.app"
WEB_ORIGIN = "https://unscheduled-triage.vercel.app"
REPOSITORY = "mekala27-45/unscheduled"
OUT = ROOT / "results" / "live" / "api_verify.json"
SBOM = ROOT / "customer" / "sboms" / "rust-cli.cdx.json"
GOLDEN_HEADER = ROOT / "tests" / "characterization" / "golden" / "sample_feeds.csv"
PROBLEM_BASE = f"https://github.com/{REPOSITORY}/blob/main/docs/SPEC.md#problem-"
USER_AGENT = f"unscheduled-verify/0.1 (+https://github.com/{REPOSITORY})"


@dataclass
class Check:
    name: str
    route: str
    ok: bool = False
    status: int | None = None
    ms: float | None = None
    detail: str = ""
    facts: dict[str, Any] = field(default_factory=dict)


class Verifier:
    def __init__(self, base: str, client: httpx.Client, github: httpx.Client) -> None:
        self.base = base.rstrip("/")
        self.client = client
        self.github = github
        self.checks: list[Check] = []
        self.data_version: str | None = None

    def call(self, method: str, path: str, **kwargs: Any) -> tuple[httpx.Response, float]:
        t0 = time.perf_counter()
        response = self.client.request(method, self.base + path, **kwargs)
        return response, round((time.perf_counter() - t0) * 1000, 1)

    def check(self, name: str, route: str, fn: Callable[[Check], None]) -> Check:
        record = Check(name=name, route=route)
        try:
            fn(record)
            record.ok = not record.detail
        except (httpx.HTTPError, AssertionError, KeyError, ValueError, TypeError) as err:
            record.ok = False
            record.detail = record.detail or f"{type(err).__name__}: {err}"
        self.checks.append(record)
        mark = "pass" if record.ok else "FAIL"
        print(f"verify: {mark} {name}{'' if record.ok else ': ' + record.detail}")
        return record

    def json_of(self, record: Check, method: str, path: str, status: int = 200, **kwargs: Any) -> Any:
        response, ms = self.call(method, path, **kwargs)
        record.status, record.ms = response.status_code, ms
        if response.status_code != status:
            raise AssertionError(f"{method} {path} answered {response.status_code}, expected {status}")
        body = response.json()
        self.common(record, response, body)
        return body

    def common(self, record: Check, response: httpx.Response, body: Any) -> None:
        """What every answer carries: the statement and, once data is loaded, the same data version."""
        if isinstance(body, dict) and body.get("statement") != STATEMENT:
            record.detail = "the statement field is missing or differs from the canonical statement"
        version = response.headers.get("x-data-version")
        if version and self.data_version and version != self.data_version:
            record.detail = f"X-Data-Version {version} differs from {self.data_version}"

    def newest_serving_release(self) -> dict[str, Any] | None:
        response = self.github.get(
            f"https://api.github.com/repos/{REPOSITORY}/releases", params={"per_page": 50}
        )
        response.raise_for_status()
        serving = [
            r
            for r in response.json()
            if str(r.get("tag_name", "")).startswith("serving-") and not r.get("draft")
        ]
        serving.sort(key=lambda r: str(r.get("published_at") or ""), reverse=True)
        return serving[0] if serving else None


def run(base: str) -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT}
    with (
        httpx.Client(timeout=60.0, headers=headers) as client,
        httpx.Client(timeout=30.0, headers=headers) as github,
    ):
        v = Verifier(base, client, github)
        state: dict[str, Any] = {}

        def health(r: Check) -> None:
            body = v.json_of(r, "GET", "/health")
            data = body.get("data") or {}
            db = body.get("database") or {}
            v.data_version = body.get("data_version")
            state["tag"] = data.get("tag")
            state["lake_digest"] = data.get("lake_digest")
            r.facts = {
                "ready": body.get("ready"),
                "data_version": body.get("data_version"),
                "tag": data.get("tag"),
                "loaded_at": data.get("loaded_at"),
                "counts": data.get("counts"),
                "database_reachable": db.get("reachable"),
                "migration": db.get("migration"),
                "storage_share_used": db.get("storage_share_used"),
                "storage_ceiling_mb": db.get("storage_ceiling_mb"),
            }
            if not body.get("ready"):
                r.detail = "the API reports no data loaded"
            elif not db.get("reachable"):
                r.detail = "the database is not reachable"
            elif (db.get("storage_share_used") or 0) > 1:
                r.detail = "the database is over its storage ceiling"

        def release(r: Check) -> None:
            newest = v.newest_serving_release()
            r.status = 200
            if newest is None:
                raise AssertionError("the repository has no serving release")
            r.facts = {
                "newest_serving_release": newest["tag_name"],
                "published_at": newest.get("published_at"),
            }
            if state.get("tag") != newest["tag_name"]:
                r.detail = (
                    f"the API serves {state.get('tag')}, the newest serving release is {newest['tag_name']}"
                )

        def meta(r: Check) -> None:
            body = v.json_of(r, "GET", "/v1/meta")
            text = json.dumps(body)
            r.facts = {"keys": sorted(body)}
            for needed, label in (
                (NVD_NOTICE, "the NVD notice"),
                (GHSA_ATTRIBUTION[:60], "the GitHub advisory attribution"),
            ):
                if needed not in text:
                    r.detail = f"{label} is missing"

        def search(r: Check) -> None:
            since = (date.today() - timedelta(days=120)).isoformat()
            state["search"] = {"nvd_status": "Deferred", "published_from": since, "limit": 100}
            body = v.json_of(r, "GET", "/v1/cves", params=state["search"])
            items = body.get("items") or []
            if not items:
                raise AssertionError("no Deferred CVE published in the last 120 days")
            if any(i.get("nvd_status") != "Deferred" for i in items):
                r.detail = "the nvd_status filter let another status through"
            state["unscheduled"] = items[0]["cve_id"]
            state["unscheduled_published"] = items[0]["published"]
            state["cursor"] = body.get("next_cursor")
            state["first_page"] = [i["cve_id"] for i in items]
            r.facts = {"returned": len(items), "limit": body.get("limit"), "first": items[0]["cve_id"]}

        def next_page(r: Check) -> None:
            if not state.get("cursor"):
                r.status, r.facts = 200, {"note": "one page held every match"}
                return
            # A cursor is bound to the filters it was issued for, so the same filters go with it.
            body = v.json_of(r, "GET", "/v1/cves", params={**state["search"], "cursor": state["cursor"]})
            ids = [i["cve_id"] for i in body.get("items") or []]
            overlap = set(ids) & set(state["first_page"])
            r.facts = {"returned": len(ids), "overlap_with_first_page": len(overlap)}
            if overlap:
                r.detail = "the second page repeats CVEs of the first"

        def filters(r: Check) -> None:
            cases = {
                "kev": {"kev": "true", "limit": 5},
                "filer_type": {"filer_type": "research or bug bounty platform", "limit": 5},
                "cwe": {"cwe": "CWE-79", "limit": 5},
                "has_filer_score": {"has_filer_score": "true", "limit": 5},
            }
            counts: dict[str, int] = {}
            for name, params in cases.items():
                body = v.json_of(r, "GET", "/v1/cves", params=params)
                items = body.get("items") or []
                counts[name] = len(items)
                if name == "kev" and any(not i.get("kev_date_added") for i in items):
                    r.detail = "the kev filter let an unlisted CVE through"
                if name == "cwe" and any("CWE-79" not in (i.get("cwes") or []) for i in items):
                    r.detail = "the cwe filter let another CWE through"
            r.facts = counts
            if not all(counts.values()):
                r.detail = r.detail or f"a filter returned nothing: {counts}"

        def lookup(r: Check) -> None:
            cve = state["unscheduled"]
            body = v.json_of(r, "GET", f"/v1/cves/{cve}")
            fields = body.get("fields") or {}
            missing = [
                k
                for k, f in fields.items()
                if isinstance(f, dict) and ("source" not in f or "known_from" not in f)
            ]
            r.facts = {
                "cve": cve,
                "fields": len(fields),
                "nvd_status": (fields.get("nvd_status") or {}).get("value"),
            }
            if missing:
                r.detail = f"fields without a source or a known_from: {missing[:5]}"

        def as_of(r: Check) -> None:
            cve = state["unscheduled"]
            day = (
                datetime.fromisoformat(state["unscheduled_published"].replace("Z", "+00:00"))
                - timedelta(days=1)
            ).date()
            body = v.json_of(r, "GET", f"/v1/cves/{cve}", params={"as_of": day.isoformat()})
            r.facts = {
                "cve": cve,
                "as_of": day.isoformat(),
                "known": body.get("known"),
                "note": body.get("note"),
            }
            if body.get("known") is not False:
                r.detail = "a CVE asked about before its publication came back as known"

        def timeline(r: Check) -> None:
            cve = state["unscheduled"]
            body = v.json_of(r, "GET", f"/v1/cves/{cve}/timeline")
            times = [e["at"] for e in body.get("events") or []]
            r.facts = {"cve": cve, "events": len(times)}
            if not times:
                r.detail = "no events"
            elif times != sorted(times):
                r.detail = "the events are not in time order"

        def backlog(r: Check) -> None:
            body = v.json_of(r, "GET", "/v1/backlog")
            questions = (body.get("backlog") or {}).get("questions") or []
            r.facts = {"questions": len(questions)}
            if len(questions) < 6:
                r.detail = f"{len(questions)} backlog questions, expected Q1 to Q6"

        def products(r: Check) -> None:
            body = v.json_of(r, "GET", "/v1/products")
            items = body.get("products") or []
            state["products"] = [p["product_id"] for p in items]
            r.facts = {"products": state["products"]}
            if len(items) != 6:
                r.detail = f"{len(items)} products, expected the six stand ins"

        def exposure(r: Check) -> None:
            product = sorted(state["products"])[0]
            today = v.json_of(r, "GET", f"/v1/products/{product}/exposure")
            pin = v.json_of(r, "GET", f"/v1/products/{product}/exposure", params={"as_of": "pin"})
            r.facts = {
                "product": product,
                "today": {"snapshot": today.get("snapshot"), "findings": len(today.get("findings") or [])},
                "pin": {"snapshot": pin.get("snapshot"), "findings": len(pin.get("findings") or [])},
            }
            if today.get("snapshot") == pin.get("snapshot"):
                r.detail = "the pin and today returned the same snapshot"

        def match(r: Check) -> None:
            body = v.json_of(
                r,
                "POST",
                "/v1/match",
                content=SBOM.read_bytes(),
                headers={"content-type": "application/json"},
            )
            r.facts = {
                "sbom": SBOM.name,
                "findings": len(body.get("findings") or []),
                "engine": body.get("engine"),
                "sbom_summary": body.get("sbom"),
                "stored": body.get("stored"),
            }
            if not body.get("findings"):
                r.detail = "the SBOM of a stand in matched nothing"

        def legacy(r: Check) -> None:
            response, ms = v.call("GET", "/v1/legacy/report.csv")
            r.status, r.ms = response.status_code, ms
            if response.status_code != 200:
                raise AssertionError(f"answered {response.status_code}: {response.text[:200]}")
            header = GOLDEN_HEADER.read_bytes().splitlines()[0]
            lines = response.content.splitlines()
            r.facts = {"rows": max(len(lines) - 1, 0), "content_type": response.headers.get("content-type")}
            if not lines or lines[0] != header:
                r.detail = "the header differs from the golden master"

        def problems(r: Check) -> None:
            cases: list[tuple[str, str, int, str, dict[str, Any]]] = [
                ("GET", "/v1/cves/CVE-1999-0000000", 404, "not-found", {}),
                ("GET", "/v1/cves", 400, "invalid-cursor", {"params": {"cursor": "not-a-cursor"}}),
                (
                    "POST",
                    "/v1/match",
                    415,
                    "unsupported-media-type",
                    {"content": b"x", "headers": {"content-type": "text/plain"}},
                ),
            ]
            seen: dict[str, Any] = {}
            for method, path, status, kind, kwargs in cases:
                response, _ = v.call(method, path, **kwargs)
                body = response.json() if "json" in response.headers.get("content-type", "") else {}
                seen[f"{method} {path}"] = {"status": response.status_code, "type": body.get("type")}
                if response.status_code != status or body.get("type") != PROBLEM_BASE + kind:
                    r.detail = f"{method} {path}: {response.status_code} {body.get('type')}, expected {status} {kind}"
                if body.get("statement") != STATEMENT:
                    r.detail = f"{method} {path}: the problem document carries no statement"
            r.status, r.facts = 200, seen

        def cors(r: Check) -> None:
            response, ms = v.call(
                "OPTIONS",
                "/v1/cves",
                headers={"Origin": WEB_ORIGIN, "Access-Control-Request-Method": "GET"},
            )
            r.status, r.ms = response.status_code, ms
            allowed = response.headers.get("access-control-allow-origin")
            r.facts = {"allow_origin": allowed}
            if allowed != WEB_ORIGIN:
                r.detail = f"the web origin is not allowed (got {allowed})"

        def sync(r: Check) -> None:
            body = v.json_of(r, "POST", "/internal/sync")
            r.facts = {k: body.get(k) for k in ("status", "detail", "target", "checked_release")}
            if body.get("status") != "current":
                r.detail = f"a sync call on loaded data answered {body.get('status')}, not current"

        steps: list[tuple[str, str, Callable[[Check], None]]] = [
            ("health, with the database and the data", "GET /health", health),
            ("the data is the newest serving release", "GitHub releases", release),
            ("meta, with the notices", "GET /v1/meta", meta),
            ("search by NVD status and date", "GET /v1/cves", search),
            ("the next page by cursor", "GET /v1/cves?cursor=", next_page),
            ("filters by KEV, filer type, CWE and filer score", "GET /v1/cves", filters),
            ("one CVE the NVD did not schedule, every field sourced", "GET /v1/cves/{id}", lookup),
            ("the same CVE the day before its publication", "GET /v1/cves/{id}?as_of=", as_of),
            ("its ruler events in time order", "GET /v1/cves/{id}/timeline", timeline),
            ("the backlog", "GET /v1/backlog", backlog),
            ("the six stand ins", "GET /v1/products", products),
            ("one exposure at the pin and today", "GET /v1/products/{id}/exposure", exposure),
            ("one of the six SBOMs matched", "POST /v1/match", match),
            ("the legacy report with the golden header", "GET /v1/legacy/report.csv", legacy),
            ("typed problem documents", "errors", problems),
            ("CORS for the web origin", "OPTIONS /v1/cves", cors),
            ("a sync call on current data", "POST /internal/sync", sync),
        ]
        for name, route, fn in steps:
            if name != "the data is the newest serving release" and state.get("halt"):
                break
            record = v.check(name, route, fn)
            if name.startswith("health") and not record.ok:
                state["halt"] = True

    passed = sum(c.ok for c in v.checks)
    return {
        "base_url": base,
        "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client": "scripts/verify_api.py, a separate process with no database credential",
        "data_version": v.data_version,
        "passed": passed,
        "total": len(v.checks),
        "result": "pass" if passed == len(v.checks) and len(v.checks) == len(steps) else "fail",
        "checks": [c.__dict__ for c in v.checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default=LIVE)
    parser.add_argument(
        "--out", type=Path, default=None, help="default results/live/api_verify.json for the live URL"
    )
    args = parser.parse_args(argv)
    record = run(args.base_url)
    out = args.out or (OUT if args.base_url.rstrip("/") == LIVE else None)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=1, sort_keys=False) + "\n", encoding="utf-8")
        print(f"verify: wrote {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    print(f"verify: {record['passed']} of {record['total']} checks pass against {args.base_url}")
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
