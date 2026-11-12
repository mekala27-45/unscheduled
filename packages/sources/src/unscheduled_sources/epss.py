"""EPSS from FIRST: the daily score files, kept only at the registered offsets.

Each daily file (epss_scores-YYYY-MM-DD.csv.gz) starts with a header line naming the model version
and the score date; the earliest files have no header, and for them the model version is left
empty and the score date is the date in the file name. From each file the build keeps:

- for every CVE published on or after 2020-01-01 (publication date from the CVE List), its score
  on the days 0, 1, 7, 30 and 90 after publication, with that offset;
- for every CVE in the KEV catalog, its score on every day, with offset -1.

Every file is hashed and its digest kept in the lock; the file itself is deleted once parsed. When
the daily file host cannot be reached at all, the scores of the last thirty days come from
api.first.org with scope=time-series instead, and the ledger says so.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from typing import Any, ClassVar

import httpx
import polars as pl

from unscheduled_sources import ledger, locks
from unscheduled_sources.base import Context, Fetcher, Output, RawFile, Unit
from unscheduled_sources.contract import conform, frame
from unscheduled_sources.http import Downloaded, Http, Refused
from unscheduled_sources.timeutil import parse_ts


def read_header(first_line: str) -> tuple[str | None, date | None]:
    """model_version and score date from '#model_version:v2025.03.14,score_date:2025-03-17T00:00:00+0000'."""
    if not first_line.startswith("#"):
        return None, None
    fields: dict[str, str] = {}
    for part in first_line[1:].strip().split(","):
        key, _, value = part.partition(":")
        fields[key.strip()] = value.strip()
    when = parse_ts(fields.get("score_date")) if fields.get("score_date") else None
    return fields.get("model_version") or None, when.date() if when else None


def read_scores(data: bytes, file_day: date) -> tuple[pl.DataFrame, str | None, date]:
    text = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
    first = text[: text.find(b"\n")].decode("utf-8", "replace")
    model, score_day = read_header(first)
    body = text[text.find(b"\n") + 1 :] if first.startswith("#") else text
    scores = pl.read_csv(io.BytesIO(body), schema_overrides={"cve": pl.String, "epss": pl.Float64})
    if "percentile" not in scores.columns:
        scores = scores.with_columns(pl.lit(None, dtype=pl.Float64).alias("percentile"))
    scores = scores.select(
        pl.col("cve").str.strip_chars().alias("cve_id"),
        pl.col("epss").cast(pl.Float64),
        pl.col("percentile").cast(pl.Float64),
    )
    return scores, model, score_day or file_day


def kept_rows(
    scores: pl.DataFrame,
    model: str | None,
    score_day: date,
    published: pl.DataFrame,
    kev_ids: pl.Series,
    offsets: list[int],
    published_from: date,
) -> pl.DataFrame:
    """The offset rows and the daily KEV rows of one day, typed by the contract."""
    pubs = published.filter(pl.col("pub_day") >= published_from)
    with_offset = (
        scores.join(pubs, on="cve_id", how="inner")
        .with_columns(
            (pl.lit(score_day) - pl.col("pub_day")).dt.total_days().cast(pl.Int32).alias("offset_days")
        )
        .filter(pl.col("offset_days").is_in(offsets))
        .drop("pub_day")
    )
    daily = scores.filter(pl.col("cve_id").is_in(kev_ids.implode())).with_columns(
        pl.lit(-1, dtype=pl.Int32).alias("offset_days")
    )
    out = pl.concat([with_offset, daily], how="vertical").with_columns(
        pl.lit(score_day).alias("score_date"),
        pl.lit(model, dtype=pl.String).alias("model_version"),
    )
    return conform(
        "epss_offsets",
        out.select("cve_id", "score_date", "epss", "percentile", "model_version", "offset_days"),
    )


DAY_FILE = re.compile(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$")
MISSING = re.compile(r"missing ((?:\d{4}-\d{2}-\d{2} ?)+)")


class Epss(Fetcher):
    source = "epss"
    tables: ClassVar[tuple[str, ...]] = ("epss_offsets",)

    def __init__(self, ctx: Context) -> None:
        super().__init__(ctx)
        self.offsets = [int(x) for x in self.cfg["offsets"]]
        self.published_from = date.fromisoformat(self.cfg["published_from"])
        self._published: pl.DataFrame | None = None
        self._kev: pl.Series | None = None
        self.http: Http = ctx.http_factory(attempts=5)
        self.pool = ThreadPoolExecutor(max_workers=int(self.cfg.get("concurrency", 4)))
        self.fallback = False

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.http.close()

    def _url(self, day: date) -> str:
        return str(self.cfg["daily_url"]).format(day=day.isoformat())

    def _latest(self) -> date | None:
        """The newest day whose file exists: today, or one of the three days before it."""
        for back in range(4):
            day = self.ctx.today - timedelta(days=back)
            try:
                response = self.http.client.head(self._url(day))
            except httpx.TransportError:
                return None
            if response.status_code == 200:
                return day
        return self.ctx.today - timedelta(days=4)

    def done_days(self) -> set[date]:
        """Days already read: every daily file in the lock, and every day a unit found missing."""
        if not self.ctx.resume:
            return set()
        done = {
            date.fromisoformat(m.group(1))
            for e in locks.load(self.ctx.locks_dir, self.source).entries
            if (m := DAY_FILE.search(e.name))
        }
        for row in ledger.rows(self.ctx.locks_dir, self.source):
            if row.status in ("ok", "empty") and row.window.startswith("day "):
                done.add(date.fromisoformat(row.window.removeprefix("day ")))
            if row.status == "ok" and row.note and (m := MISSING.search(row.note)):
                done.update(date.fromisoformat(d) for d in m.group(1).split())
        return done

    def units(self) -> Iterator[Unit]:
        """One unit per month of daily files, holding the days of that month not read yet."""
        latest = self._latest()
        if latest is None:
            self.fallback = True
            yield Unit("api-time-series", f"api time-series to {self.ctx.today.isoformat()}", {"api": True})
            return
        done = self.done_days()
        months: dict[str, list[date]] = {}
        day = date.fromisoformat(self.cfg["first_day"])
        while day <= latest:
            if day not in done:
                months.setdefault(day.strftime("%Y-%m"), []).append(day)
            day += timedelta(days=1)
        for month, days in months.items():
            first, last = days[0], days[-1]
            yield Unit(
                f"month-{month}-{first.day:02d}-{last.day:02d}",
                f"month {month} days {first.isoformat()} to {last.isoformat()}",
                {"days": days},
            )

    # Inputs from bronze, read once.

    def published(self) -> pl.DataFrame:
        if self._published is None:
            records = self.ctx.bronze.read("cve_records").select("cve_id", "date_published", "snapshot_at")
            latest = records.sort("snapshot_at").unique(subset=["cve_id"], keep="last")
            self._published = latest.filter(pl.col("date_published").is_not_null()).select(
                "cve_id", pl.col("date_published").dt.date().alias("pub_day")
            )
        return self._published

    def kev_ids(self) -> pl.Series:
        if self._kev is None:
            self._kev = self.ctx.bronze.read("kev").get_column("cve_id").unique().sort()
        return self._kev

    # Fetch the days of a month in a small pool, parse them, write the month once.

    def _download(self, unit: str, day: date) -> Downloaded | None:
        dest = self.raw_root / unit / f"epss_scores-{day.isoformat()}.csv.gz"
        try:
            return self.http.download(self._url(day), dest)
        except Refused as refusal:
            # The bucket answers 403 AccessDenied, not 404, for a day that has no file.
            if refusal.status == 404 or (refusal.status == 403 and "AccessDenied" in refusal.excerpt):
                return None
            raise

    def fetch(self, unit: Unit) -> list[RawFile]:
        if unit.meta.get("api"):
            return self._fetch_api(unit)
        futures = [(d, self.pool.submit(self._download, unit.name, d)) for d in unit.meta["days"]]
        raws: list[RawFile] = []
        missing: list[date] = []
        for day, future in futures:
            got = future.result()
            if got is None:
                missing.append(day)
                continue
            raws.append(
                RawFile(
                    unit.name,
                    got.path.name,
                    got.url,
                    got.path,
                    got.sha256,
                    got.size,
                    got.fetched_at,
                    pinned=True,
                )
            )
        if missing and raws:
            raws[0].meta["note"] = "missing " + " ".join(d.isoformat() for d in missing)
        if not raws:
            with contextlib.suppress(OSError):
                (self.raw_root / unit.name).rmdir()
        return raws

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        kept_frames: list[pl.DataFrame] = []
        models: set[str] = set()
        for raw in raws:
            if raw.file.endswith(".json.gz"):
                yield from self._parse_api(raw)
                continue
            match = DAY_FILE.search(raw.file)
            assert match is not None
            scores, model, score_day = read_scores(raw.path.read_bytes(), date.fromisoformat(match.group(1)))
            raw.rows = scores.height
            models.add(model or "not stated")
            kept_frames.append(
                kept_rows(
                    scores,
                    model,
                    score_day,
                    self.published(),
                    self.kev_ids(),
                    self.offsets,
                    self.published_from,
                )
            )
        if kept_frames:
            kept = pl.concat(kept_frames, how="vertical")
            note = f"models {', '.join(sorted(models))}; kept {kept.height}"
            raws[0].meta["note"] = "; ".join(x for x in (raws[0].meta.get("note"), note) if x)
            yield "epss_offsets", kept

    # The fallback when the daily file host cannot be reached.

    def _fetch_api(self, unit: Unit) -> list[RawFile]:
        import gzip as gz
        import json

        from unscheduled_sources.locks import content_digest

        horizon = self.ctx.today - timedelta(days=30)
        pubs = self.published().filter(pl.col("pub_day") >= horizon - timedelta(days=90))
        wanted = sorted(set(pubs.get_column("cve_id").to_list()) | set(self.kev_ids().to_list()))
        answers: list[Any] = []
        first_fetch: datetime | None = None
        for i in range(0, len(wanted), 100):
            batch = ",".join(wanted[i : i + 100])
            response = self.http.get(self.cfg["api_url"], params={"cve": batch, "scope": "time-series"})
            first_fetch = first_fetch or response.fetched_at
            answers.append(json.loads(response.content))
        path = self.raw_root / unit.name / "api.json.gz"
        path.parent.mkdir(parents=True, exist_ok=True)
        with gz.GzipFile(path, "wb", mtime=0) as handle:
            handle.write(json.dumps(answers, sort_keys=True).encode("utf-8"))
        sha, size = content_digest(path)
        assert first_fetch is not None or not wanted
        fetched = first_fetch or parse_ts(self.ctx.today.isoformat())
        assert fetched is not None
        return [
            RawFile(
                unit.name,
                "api.json.gz",
                self.cfg["api_url"] + "?scope=time-series",
                path,
                sha,
                size,
                fetched,
                meta={"note": "daily file host unreachable, scores from api.first.org time-series"},
            )
        ]

    def _parse_api(self, raw: RawFile) -> Iterator[Output]:
        import gzip as gz
        import json

        with gz.open(raw.path, "rb") as handle:
            answers = json.loads(handle.read())
        rows: list[dict[str, Any]] = []
        for answer in answers:
            model = answer.get("model_version")
            for item in answer.get("data") or []:
                points = [item, *(item.get("time-series") or [])]
                for p in points:
                    rows.append(
                        {
                            "cve_id": item["cve"],
                            "score_date": date.fromisoformat(str(p["date"])[:10]),
                            "epss": float(p["epss"]),
                            "percentile": float(p["percentile"]) if p.get("percentile") is not None else None,
                            "model_version": model,
                        }
                    )
        raw.rows = len(rows)
        if not rows:
            yield "epss_offsets", frame("epss_offsets", [])
            return
        allpoints = pl.DataFrame(
            rows,
            schema={
                "cve_id": pl.String,
                "score_date": pl.Date,
                "epss": pl.Float64,
                "percentile": pl.Float64,
                "model_version": pl.String,
            },
        ).unique(subset=["cve_id", "score_date"], keep="first", maintain_order=True)
        for (score_day,), day_scores in allpoints.group_by(["score_date"], maintain_order=True):
            assert isinstance(score_day, date)
            model = day_scores.get_column("model_version")[0]
            yield (
                "epss_offsets",
                kept_rows(
                    day_scores.select("cve_id", "epss", "percentile"),
                    model,
                    score_day,
                    self.published(),
                    self.kev_ids(),
                    self.offsets,
                    self.published_from,
                ),
            )
