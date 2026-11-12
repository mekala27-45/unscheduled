"""The NVD CVE API 2.0 and the CVE Change History API 2.0.

Three parts, in order, each paged with the largest page the API allows and resumable from the
ledger page by page:

- cves full: every CVE record by startIndex pages, once, from a start time T0.
- cves modified: increments by lastModified windows of at most 120 days, from the end of the last
  full set or increment to the start of this run.
- history: every change event from 1 January 2017 by change date windows of at most 120 days.

Keyless by default, at the documented keyless limit (5 requests in any rolling 30 seconds). When
the environment holds NVD_API_KEY the key travels in the apiKey header, never in a URL, a lock or a
log, and the limiter moves to the keyed limit. A page that carries a vulnStatus value the registry
does not hold stops the parse with UnregisteredStatus; the ledger row says which, and the fetch
resumes from that page once the value is registered.
"""

from __future__ import annotations

import gzip
import json
import re
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from unscheduled_core.hashing import canonical_json

from unscheduled_sources import labels, ledger
from unscheduled_sources.base import Context, Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.limiter import Limit, RateLimiter
from unscheduled_sources.locks import content_digest
from unscheduled_sources.timeutil import iso, parse_ts, utcnow

NVD_SOURCE = "nvd@nist.gov"
# The CISA ADP container is credited by its organization id in NVD answers.
CISA_ADP_IDS = frozenset({"134c704f-9b21-4f2e-91b3-4a467353bcc0"})
METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_WINDOW = re.compile(r"^(?P<part>cves full|cves modified|history) (?P<span>\S+) start=(?P<start>\d+)$")
_NOTE = re.compile(r"total=(?P<total>\d+) count=(?P<count>\d+)(?P<last> last)?")


def compact(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def api_time(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def hour(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


class Nvd(Fetcher):
    source = "nvd"
    tables: ClassVar[tuple[str, ...]] = ("nvd_cves", "cve_metrics", "cve_weaknesses", "nvd_changes")

    def __init__(self, ctx: Context, parts: tuple[str, ...] = ("cves", "history")) -> None:
        super().__init__(ctx)
        self.parts = parts
        self.key = ctx.env.get(self.cfg.get("key_env", "NVD_API_KEY")) or None
        lim = self.cfg["limit"]
        chosen = lim["keyed"] if self.key else lim["keyless"]
        self.limit = Limit(
            requests=int(chosen["requests"]),
            window_s=float(chosen["window_s"]),
            min_interval_s=float(lim.get("min_interval_s", 0.0)),
            margin=float(lim.get("margin", 0.1)),
        )
        self.limiter = RateLimiter(self.limit)
        # The NVD answers a client over its limit with 403, so 403 is retried here, slowly.
        self.http = ctx.http_factory(
            limiter=self.limiter,
            retry_statuses=frozenset({403, 429, 500, 502, 503, 504}),
            attempts=8,
            backoff_s=8.0,
            max_backoff_s=180.0,
        )
        self.labels_path = ctx.root / "config" / "labels.yaml"
        self.known = labels.registered(self.labels_path)
        self.seen: dict[str, list[Any]] = {}
        self._last: dict[str, int] = {}
        self.run_start = hour(utcnow())

    def close(self) -> None:
        self.http.close()

    @property
    def headers(self) -> dict[str, str]:
        return {"apiKey": self.key} if self.key else {}

    # Planning, from the ledger.

    def _ledger_pages(self) -> dict[str, tuple[int, int, bool]]:
        out: dict[str, tuple[int, int, bool]] = {}
        for row in ledger.rows(self.ctx.locks_dir, self.source):
            if row.status != "ok" or not row.note:
                continue
            m = _NOTE.search(row.note)
            if m:
                out[row.window] = (int(m["total"]), int(m["count"]), bool(m["last"]))
        return out

    def _complete_spans(self, part: str, pages: dict[str, tuple[int, int, bool]]) -> set[str]:
        spans: set[str] = set()
        for window, (_, _, last) in pages.items():
            m = _WINDOW.match(window)
            if m and m["part"] == part and last:
                spans.add(m["span"])
        return spans

    def _pages(
        self, part: str, span: str, params: dict[str, Any], size: int, meta: dict[str, Any]
    ) -> Iterator[Unit]:
        pages = self._ledger_pages()
        start = 0
        while True:
            window = f"{part} {span} start={start:07d}"
            name = f"{part.replace(' ', '-')}-{span.replace('/', '-').replace(':', '')}-{start:07d}"
            if window in pages:
                total, count, last = pages[window]
            else:
                yield Unit(name, window, {**meta, "params": {**params, "startIndex": start}, "size": size})
                total, count = self._last.get("total", 0), self._last.get("count", 0)
                last = start + count >= total or count == 0
            if last:
                return
            start += size

    def units(self) -> Iterator[Unit]:
        if "cves" in self.parts:
            yield from self._cve_units()
        if "history" in self.parts:
            yield from self._history_units()

    def _cve_units(self) -> Iterator[Unit]:
        pages = self._ledger_pages()
        size = int(self.cfg["cves_page_size"])
        url = self.cfg["cves_url"]
        full_runs: dict[str, bool] = {}
        for window, (_, _, last) in pages.items():
            m = _WINDOW.match(window)
            if m and m["part"] == "cves full":
                full_runs[m["span"]] = full_runs.get(m["span"], False) or last
        complete = sorted(s for s, done in full_runs.items() if done)
        partial = sorted(s for s, done in full_runs.items() if not done)
        if not complete:
            t0_text = partial[-1] if partial else compact(self.run_start)
            yield from self._pages("cves full", t0_text, {}, size, {"part": "cves", "url": url})
            pages = self._ledger_pages()
            if not any(
                (m := _WINDOW.match(w)) and m["part"] == "cves full" and m["span"] == t0_text and v[2]
                for w, v in pages.items()
            ):
                return
            frontier = datetime.strptime(t0_text, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        else:
            frontier = datetime.strptime(complete[-1], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        for span in self._complete_spans("cves modified", pages):
            end = parse_ts(span.split("/")[1])
            if end is not None and end > frontier:
                frontier = end
        end_at = self.run_start
        days = int(self.cfg["window_days"])
        cursor = frontier
        while cursor < end_at:
            upper = min(cursor + timedelta(days=days), end_at)
            span = f"{iso(cursor)}/{iso(upper)}"
            params = {"lastModStartDate": api_time(cursor), "lastModEndDate": api_time(upper)}
            yield from self._pages("cves modified", span, params, size, {"part": "cves", "url": url})
            cursor = upper

    def _history_units(self) -> Iterator[Unit]:
        pages = self._ledger_pages()
        complete = self._complete_spans("history", pages)
        ends: dict[datetime, datetime] = {}
        for span in complete:
            a, b = (parse_ts(x) for x in span.split("/"))
            if a is not None and b is not None:
                ends[a] = max(ends.get(a, b), b)
        start = parse_ts(self.cfg["history_start"])
        assert start is not None
        days = int(self.cfg["window_days"])
        size = int(self.cfg["history_page_size"])
        url = self.cfg["history_url"]
        end_at = self.run_start
        cursor = start
        while cursor < end_at:
            if cursor in ends:
                cursor = ends[cursor]
                continue
            upper = min(cursor + timedelta(days=days), end_at)
            span = f"{iso(cursor)}/{iso(upper)}"
            params = {"changeStartDate": api_time(cursor), "changeEndDate": api_time(upper)}
            yield from self._pages("history", span, params, size, {"part": "history", "url": url})
            cursor = upper

    # Fetch and parse.

    def fetch(self, unit: Unit) -> list[RawFile]:
        params = {**unit.meta["params"], "resultsPerPage": unit.meta["size"]}
        response = self.http.get(unit.meta["url"], params=params, headers=self.headers)
        body = json.loads(response.content)
        total = int(body.get("totalResults", 0))
        key = "vulnerabilities" if unit.meta["part"] == "cves" else "cveChanges"
        count = len(body.get(key) or [])
        self._last = {"total": total, "count": count}
        start = int(params["startIndex"])
        last = start + count >= total or count == 0
        path = self.raw_root / unit.name / "page.json.gz"
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.GzipFile(path, "wb", mtime=0) as handle:
            handle.write(response.content)
        sha, size = content_digest(path)
        note = f"total={total} count={count}" + (" last" if last else "")
        self.ctx.log(f"nvd {unit.window}: {count} of {total} in {response.elapsed_s:.1f}s")
        return [
            RawFile(
                unit=unit.name,
                file="page.json.gz",
                url=response.url,
                path=path,
                sha256=sha,
                size=size,
                fetched_at=response.fetched_at,
                meta={"note": note, "part": unit.meta["part"]},
            )
        ]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            with gzip.open(raw.path, "rb") as handle:
                body = json.loads(handle.read())
            if "cveChanges" in body:
                rows = parse_history(body)
                raw.rows = len(rows)
                yield "nvd_changes", frame("nvd_changes", rows)
            else:
                cves, metrics, weaknesses = parse_cves(body, raw.fetched_at, self.known)
                self._observe(cves, raw.fetched_at.date())
                raw.rows = len(cves)
                yield "nvd_cves", frame("nvd_cves", cves)
                yield "cve_metrics", frame("cve_metrics", metrics)
                yield "cve_weaknesses", frame("cve_weaknesses", weaknesses)

    def raw_from_entry(self, entry: Any, path: Path) -> RawFile:
        raw = super().raw_from_entry(entry, path)
        raw.meta["part"] = "history" if raw.unit.startswith("history") else "cves"
        return raw

    def _observe(self, cves: list[dict[str, Any]], day: date) -> None:
        for row in cves:
            status = row["vuln_status"]
            if status is None:
                continue
            first, last, count = self.seen.get(status, [day, day, 0])
            self.seen[status] = [min(first, day), max(last, day), count + 1]

    def finish(self) -> None:
        super().finish()
        if self.seen:
            labels.observe(
                self.labels_path,
                {k: labels.Seen(v[0], v[1], v[2]) for k, v in sorted(self.seen.items())},
            )


def parse_cves(
    body: dict[str, Any], fetched_at: datetime, known: frozenset[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    vulns = [v["cve"] for v in body.get("vulnerabilities") or []]
    labels.check((c.get("vulnStatus") for c in vulns), known)
    cves: list[dict[str, Any]] = []
    metrics: list[dict[str, Any]] = []
    weaknesses: list[dict[str, Any]] = []
    for cve in vulns:
        cve_id = cve["id"]
        cpe_count = 0
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                cpe_count += len(node.get("cpeMatch") or [])
        cves.append(
            {
                "cve_id": cve_id,
                "vuln_status": cve.get("vulnStatus"),
                "published": parse_ts(cve.get("published")),
                "last_modified": parse_ts(cve.get("lastModified")),
                "source_identifier": cve.get("sourceIdentifier"),
                "has_cpe": cpe_count > 0,
                "cpe_count": cpe_count,
                "cisa_exploit_add": _date(cve.get("cisaExploitAdd")),
                "fetched_at": fetched_at,
            }
        )
        for key, version in METRIC_KEYS:
            for m in (cve.get("metrics") or {}).get(key) or []:
                data = m.get("cvssData") or {}
                source = m.get("source")
                metrics.append(
                    {
                        "cve_id": cve_id,
                        "source": source,
                        "source_type": source_type(source, cve.get("sourceIdentifier")),
                        "version": data.get("version") or version,
                        "vector": data.get("vectorString"),
                        "base_score": _float(data.get("baseScore")),
                        "base_severity": data.get("baseSeverity") or m.get("baseSeverity"),
                        "origin": "nvd_api",
                        "observed_at": fetched_at,
                    }
                )
        for w in cve.get("weaknesses") or []:
            for d in w.get("description") or []:
                value = d.get("value")
                if value:
                    weaknesses.append(
                        {
                            "cve_id": cve_id,
                            "source": w.get("source"),
                            "cwe_id": value,
                            "origin": "nvd_api",
                            "observed_at": fetched_at,
                        }
                    )
    return cves, metrics, weaknesses


def source_type(source: str | None, filer: str | None) -> str:
    """Who supplied a metric the NVD carries: the NVD itself, the CISA ADP, the filer, or another.

    The NVD marks each metric Primary or Secondary; since April 2026 it also marks a filer's score
    Primary when it does not score the CVE itself, so the type says how the NVD used a score, not who
    wrote it. The provider is what the analysis compares, so it is what bronze keeps; the type stays
    in the raw page, locked by its digest.
    """
    if source == NVD_SOURCE:
        return "nvd"
    if source in CISA_ADP_IDS:
        return "adp"
    if source is not None and source == filer:
        return "cna"
    return "secondary"


def parse_history(body: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in body.get("cveChanges") or []:
        change = item.get("change") or {}
        rows.append(
            {
                "cve_id": change.get("cveId"),
                "event_name": change.get("eventName"),
                "cve_change_id": change.get("cveChangeId"),
                "source_identifier": change.get("sourceIdentifier"),
                "created": parse_ts(change.get("created")),
                "details_json": canonical_json(change.get("details") or []),
            }
        )
    return rows


def _float(value: Any) -> float | None:
    return float(value) if value is not None else None


def _date(value: Any) -> date | None:
    if not value:
        return None
    return date.fromisoformat(str(value)[:10])
