"""The pull based sync: the API loads the newest serving release into Neon, one bounded step per call.

GitHub Actions holds no database credential, so nothing pushes data in. The publish workflow and a
daily Vercel cron call POST (or GET) /internal/sync instead, until the answer says done. The call
takes no input: the repository, the tag prefix and the file names are constants (releases.py), so
the most a stranger can do with the trigger is make the API check sooner, inside the rate limit.

Every call runs in one transaction that opens with pg_try_advisory_xact_lock. A second caller gets
sync-busy at once instead of waiting; a call that fails rolls back whole, so a retry repeats the
same step. The cursor (which bundle, which step, which row offset) lives in the settings table, so
any instance of the container can take the next step.

A target bundle is loaded in this order, one step per call:

    sweep cve, load cve (chunks), sweep cve_event, load cve_event (chunks), sweep product,
    load product, sweep finding, load finding, backlog, finalize

A sweep deletes the rows the new file no longer holds, before its load, so the storage peak stays
near one copy of the slice. A load chunk is copied into a temporary table and upserted by key with a
row digest, so a rerun writes nothing and a daily bundle writes only what changed. Before a chunk is
written the database size plus the size of the rows that would change, times an allowance for
indexes and TOAST, is compared with the ceiling in config/budgets.yaml; past it the call refuses
with storage-ceiling and nothing is written. Finalize flips the data version that every response
carries. Until then responses name the previous complete version.

When the data is current and the release was checked within the last minute, a call costs the lock
and one small query.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import sqlalchemy as sa
import structlog
from unscheduled_core.hashing import canonical_json, sha256_bytes

from unscheduled_api import bundle as bnd
from unscheduled_api.bundle import BundleError, BundleManifest
from unscheduled_api.db import qualified
from unscheduled_api.problems import ProblemError
from unscheduled_api.releases import (
    OWNER,
    REPO,
    TAG_PREFIX,
    Asset,
    BundleCache,
    GitHubReleases,
    Listing,
    UpstreamError,
)
from unscheduled_api.settings import Settings

log = structlog.get_logger("unscheduled.sync")

# A fixed key for pg_try_advisory_xact_lock: the first 60 bits of a digest of the name.
LOCK_KEY = int(sha256_bytes(b"unscheduled.sync")[:15], 16)
CHECK_INTERVAL = timedelta(seconds=60)
CALLS_PER_MINUTE = 30
STORAGE_ALLOWANCE = 3.0  # bytes written per byte of row, for heap, TOAST and indexes; deliberately high
MANIFEST_MAX_BYTES = 1_000_000
BACKLOG_MAX_BYTES = 5_000_000

Step = tuple[str, str | None]
PLAN: tuple[Step, ...] = (
    ("sweep", "cve"),
    ("load", "cve"),
    ("sweep", "cve_event"),
    ("load", "cve_event"),
    ("sweep", "product"),
    ("load", "product"),
    ("sweep", "finding"),
    ("load", "finding"),
    ("backlog", None),
    ("finalize", None),
)
CVE_DB_COLUMNS = tuple("provenance" if c.name == "provenance_json" else c.name for c in bnd.CVE_COLUMNS)
DB_COLUMNS: dict[str, tuple[str, ...]] = {
    "cve": (*CVE_DB_COLUMNS, "row_digest"),
    "cve_event": ("event_id", "cve_id", "at", "kind", "source", "detail"),
    "product": ("product_id", "name", "body", "row_digest"),
    "finding": ("finding_id", "product_id", "as_of", "cve_ids", "body", "row_digest"),
}
JSON_COLUMNS = frozenset({"provenance", "detail", "body"})
DIGESTED = frozenset({"cve", "product", "finding"})  # cve_event rows are immutable: their key is their digest

SyncStatus = Literal["current", "more", "done"]


class StorageCeiling(RuntimeError):
    def __init__(self, size: int, estimate: int, ceiling: int) -> None:
        super().__init__(
            f"the database holds {size} bytes; this chunk adds up to {estimate}; the ceiling is {ceiling}"
        )
        self.size = size
        self.estimate = estimate
        self.ceiling = ceiling


@dataclass(frozen=True)
class Chunk:
    table: str
    offset: int
    rows_in: int
    rows_changed: int
    rows_total: int


@dataclass(frozen=True)
class Outcome:
    status: SyncStatus
    detail: str
    target: str | None
    step: str | None
    step_index: int | None
    steps: int
    chunk: Chunk | None
    chunks_done: int | None
    chunks_total: int | None
    storage_bytes: int | None
    storage_ceiling_bytes: int
    checked_release: bool


def version_label(tag: str, manifest_sha256: str) -> str:
    return f"{tag}+{manifest_sha256[:12]}"


def _now_iso(now: datetime) -> str:
    return now.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso(text: Any) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def chunks_for(rows: int, chunk_rows: int) -> int:
    return max(math.ceil(rows / chunk_rows), 1)


def plan_chunks(files: Sequence[dict[str, Any]]) -> int | None:
    """Every call a full load takes: one per sweep, per load chunk, the backlog and the finalize."""
    rows = {str(f["file"]): f.get("rows") for f in files}
    total = 2  # backlog and finalize
    for table in bnd.TABLES.values():
        count = rows.get(table.file)
        if count is None:
            return None
        total += 1 + chunks_for(int(count), table.chunk_rows)
    return total


def _copy_text(value: Any, column: str) -> Any:
    if column in JSON_COLUMNS:
        return canonical_json(value)
    return value


class Sync:
    def __init__(
        self,
        engine: sa.Engine,
        settings: Settings,
        releases: GitHubReleases,
        *,
        clock: Callable[[], datetime] | None = None,
        on_done: Callable[[], None] | None = None,
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.releases = releases
        self.cache = BundleCache(settings.cache_dir, releases)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.on_done = on_done
        self.schema = settings.schema
        self.ceiling = settings.budgets.storage_ceiling_bytes

    # Names -------------------------------------------------------------------------------------

    def t(self, table: str) -> str:
        return qualified(self.schema, table)

    # The call ----------------------------------------------------------------------------------

    def run_once(self) -> Outcome:
        now = self.clock()
        with self.engine.connect() as conn:
            locked = bool(
                conn.execute(sa.text("select pg_try_advisory_xact_lock(:k)"), {"k": LOCK_KEY}).scalar()
            )
            if not locked:
                conn.rollback()
                raise ProblemError(
                    "sync-busy",
                    "another sync call is loading a step; call again in a few seconds",
                    retry_after_s=5,
                    context={"status": "busy"},
                )
            state, recent = self._state(conn, now)
            loaded = state.get("data_version")
            current = state.get("sync")
            check = state.get("release_check") or {}
            checked_at = _parse_iso(check.get("checked_at"))
            if current is None and checked_at is not None and now - checked_at < CHECK_INTERVAL:
                conn.commit()
                return self._current(
                    loaded, "the newest serving release is loaded; checked within the minute"
                )
            if recent >= CALLS_PER_MINUTE:
                conn.rollback()
                raise ProblemError(
                    "sync-rate-limited",
                    f"the sync takes at most {CALLS_PER_MINUTE} calls a minute",
                    retry_after_s=60,
                    context={"status": "rate_limited"},
                )
            try:
                if current is None:
                    outcome, record = self._check(conn, loaded, check, now)
                else:
                    outcome, record = self._step(conn, current, now)
                self._record(conn, now, record)
                conn.commit()
            except BundleError as err:
                conn.rollback()
                self._rejected(now, current, str(err))
                raise ProblemError(
                    "bundle-rejected",
                    f"{err}. The bundle was set aside; nothing from it is served.",
                    context={"status": "refused", "reason": "bundle"},
                ) from err
            except UpstreamError as err:
                conn.rollback()
                self._failed(now, current, "upstream", str(err))
                raise ProblemError(
                    "upstream-unavailable",
                    str(err),
                    retry_after_s=err.retry_after_s,
                    context={"status": "refused", "reason": "upstream"},
                ) from err
            except StorageCeiling as err:
                conn.rollback()
                self._failed(
                    now,
                    current,
                    "refused",
                    str(err),
                    storage=err.size,
                )
                raise ProblemError(
                    "storage-ceiling",
                    f"{err}. Nothing was written. Raise the ceiling with a dated decision or publish a "
                    "smaller bundle.",
                    context={
                        "status": "refused",
                        "reason": "storage",
                        "database_size_bytes": err.size,
                        "chunk_estimate_bytes": err.estimate,
                        "storage_ceiling_bytes": err.ceiling,
                    },
                ) from err
        if outcome.status == "done" and self.on_done is not None:
            self.on_done()
        log.info(
            "sync",
            status=outcome.status,
            target=outcome.target,
            step=outcome.step,
            rows_in=outcome.chunk.rows_in if outcome.chunk else None,
            rows_changed=outcome.chunk.rows_changed if outcome.chunk else None,
            storage_bytes=outcome.storage_bytes,
        )
        return outcome

    def _state(self, conn: sa.Connection, now: datetime) -> tuple[dict[str, Any], int]:
        row = conn.execute(
            sa.text(
                f"select coalesce((select jsonb_object_agg(key, value) from {self.t('settings')} "
                "where key in ('data_version', 'sync', 'release_check')), '{}'::jsonb) as state, "
                f"(select count(*) from {self.t('ops_run')} where kind = 'sync' "
                "and started_at > :since) as recent"
            ),
            {"since": now - timedelta(seconds=60)},
        ).one()
        state: dict[str, Any] = dict(row.state or {})
        return state, int(row.recent)

    def _current(self, loaded: dict[str, Any] | None, detail: str, *, checked: bool = False) -> Outcome:
        label = version_label(loaded["tag"], loaded["manifest_sha256"]) if loaded else None
        return Outcome(
            status="current",
            detail=detail,
            target=label,
            step=None,
            step_index=None,
            steps=len(PLAN),
            chunk=None,
            chunks_done=None,
            chunks_total=None,
            storage_bytes=None,
            storage_ceiling_bytes=self.ceiling,
            checked_release=checked,
        )

    # Checking the release --------------------------------------------------------------------

    def _check(
        self, conn: sa.Connection, loaded: dict[str, Any] | None, check: dict[str, Any], now: datetime
    ) -> tuple[Outcome, dict[str, Any]]:
        listing: Listing = self.releases.newest(check.get("etag"))
        newest: dict[str, Any] | None
        if listing.not_modified:
            newest = check.get("newest")
        elif listing.release is None:
            newest = None
        else:
            newest = self._describe(listing)
        self._put(
            conn, "release_check", {"checked_at": _now_iso(now), "etag": listing.etag, "newest": newest}
        )
        if newest is None:
            outcome = self._current(
                loaded, f"no release of {OWNER}/{REPO} has a tag starting {TAG_PREFIX}", checked=True
            )
            return outcome, {"status": "checked", "detail": {"newest": None}}
        if loaded is not None and loaded.get("manifest_sha256") == newest["manifest_sha256"]:
            outcome = self._current(loaded, f"{newest['tag']} is loaded", checked=True)
            return outcome, {
                "status": "checked",
                "bundle": newest["tag"],
                "detail": {"newest": newest["tag"]},
            }
        target = self._target(newest)
        cursor = {"target": target, "step": 0, "offset": 0, "started_at": _now_iso(now), "absent_columns": {}}
        self._put(conn, "sync", cursor)
        label = version_label(target["tag"], target["manifest_sha256"])
        outcome = Outcome(
            status="more",
            detail=f"started loading {label}",
            target=label,
            step="start",
            step_index=0,
            steps=len(PLAN),
            chunk=None,
            chunks_done=0,
            chunks_total=target.get("chunks_total"),
            storage_bytes=None,
            storage_ceiling_bytes=self.ceiling,
            checked_release=True,
        )
        return outcome, {"status": "started", "bundle": label, "step": "start"}

    def _describe(self, listing: Listing) -> dict[str, Any]:
        release = listing.release
        assert release is not None
        manifest_asset = release.assets.get(bnd.MANIFEST)
        if manifest_asset is None:
            raise BundleError(f"release {release.tag} has no {bnd.MANIFEST}")
        data = self.releases.read_bytes(manifest_asset, max_bytes=MANIFEST_MAX_BYTES)
        sha = sha256_bytes(data)
        if manifest_asset.digest is not None and manifest_asset.digest != sha:
            raise BundleError(f"{bnd.MANIFEST} of {release.tag} does not match the digest GitHub reports")
        manifest = bnd.parse_manifest(data)
        return {
            "tag": release.tag,
            "release_id": release.release_id,
            "published_at": release.published_at,
            "manifest_sha256": sha,
            "manifest": json.loads(manifest.model_dump_json()),
            "assets": {
                name: {"url": a.url, "size": a.size, "digest": a.digest}
                for name, a in sorted(release.assets.items())
            },
        }

    def _target(self, newest: dict[str, Any]) -> dict[str, Any]:
        manifest = BundleManifest.model_validate(newest["manifest"])
        assets: dict[str, Any] = newest["assets"]
        files: list[dict[str, Any]] = []
        for name in bnd.FILES:
            entry = manifest.entry(name)
            asset = assets.get(name)
            if asset is None:
                raise BundleError(f"release {newest['tag']} has no asset named {name}")
            if asset.get("digest") and asset["digest"] != entry.sha256:
                raise BundleError(f"{name}: GitHub reports a digest that differs from the manifest")
            files.append({"file": name, "sha256": entry.sha256, "rows": entry.rows})
        return {
            "tag": newest["tag"],
            "release_id": newest["release_id"],
            "published_at": newest["published_at"],
            "manifest_sha256": newest["manifest_sha256"],
            "generated_at": manifest.generated_at,
            "lake_digest": manifest.lake_digest,
            "locks": manifest.locks,
            "sources": manifest.sources,
            "files": files,
            "assets": {name: assets[name] for name in bnd.FILES},
            "chunks_total": plan_chunks(files),
        }

    # Steps -------------------------------------------------------------------------------------

    def _local(self, target: dict[str, Any], name: str, max_bytes: int | None = None) -> Path:
        info = target["assets"][name]
        entry = next(f for f in target["files"] if f["file"] == name)
        asset = Asset(name=name, url=info["url"], size=int(info.get("size") or 0), digest=info.get("digest"))
        if max_bytes is not None:
            cap = max_bytes
        elif asset.size:
            cap = asset.size
        else:
            cap = self.ceiling
        return self.cache.ensure(asset, entry["sha256"], max_bytes=cap)

    def _step(
        self, conn: sa.Connection, cursor: dict[str, Any], now: datetime
    ) -> tuple[Outcome, dict[str, Any]]:
        target: dict[str, Any] = cursor["target"]
        index = int(cursor["step"])
        kind, table = PLAN[index]
        label = version_label(target["tag"], target["manifest_sha256"])
        chunk: Chunk | None = None
        done = False
        record: dict[str, Any] = {"bundle": label, "step": f"{kind} {table}" if table else kind}
        if kind == "sweep":
            assert table is not None
            path = self._local(target, bnd.TABLES[table].file)
            absent = self._verify_file(target, table, path)
            cursor["absent_columns"][table] = absent
            deleted = self._sweep(conn, table, path)
            chunk = Chunk(table, 0, 0, deleted, bnd.file_rows(path))
            cursor["step"], cursor["offset"] = index + 1, 0
            record.update(status="swept", rows_changed=deleted, detail={"absent_columns": absent})
        elif kind == "load":
            assert table is not None
            path = self._local(target, bnd.TABLES[table].file)
            offset = int(cursor["offset"])
            chunk = self._load(conn, table, path, offset)
            if offset + chunk.rows_in >= chunk.rows_total:
                cursor["step"], cursor["offset"] = index + 1, 0
            else:
                cursor["offset"] = offset + chunk.rows_in
            record.update(status="loaded", rows_in=chunk.rows_in, rows_changed=chunk.rows_changed)
            record["detail"] = {"table": table, "offset": offset, "rows_total": chunk.rows_total}
        elif kind == "backlog":
            path = self._local(target, bnd.BACKLOG, BACKLOG_MAX_BYTES)
            try:
                backlog = json.loads(path.read_bytes())
            except (UnicodeDecodeError, json.JSONDecodeError) as err:
                raise BundleError(f"{bnd.BACKLOG} is not JSON") from err
            if not isinstance(backlog, dict | list):
                raise BundleError(f"{bnd.BACKLOG} is neither a JSON object nor a list")
            self._put(conn, "backlog", backlog)
            cursor["step"] = index + 1
            record.update(status="loaded", rows_in=1, rows_changed=1)
        else:
            version = self._finalize(conn, target, cursor, now)
            self._put(conn, "data_version", version)
            conn.execute(sa.text(f"delete from {self.t('settings')} where key = 'sync'"))
            done = True
            record.update(status="done", detail={"counts": version["counts"]})
        chunks_done = int(cursor.get("calls", 0)) + 1
        cursor["calls"] = chunks_done
        if not done:
            self._put(conn, "sync", cursor)
        size = self._size(conn)
        record["storage_bytes"] = size
        step_name = f"{kind} {table}" if table else kind
        outcome = Outcome(
            status="done" if done else "more",
            detail=f"{label} is loaded" if done else f"{step_name} for {label}",
            target=label,
            step=step_name,
            step_index=index,
            steps=len(PLAN),
            chunk=chunk,
            chunks_done=chunks_done,
            chunks_total=target.get("chunks_total"),
            storage_bytes=size,
            storage_ceiling_bytes=self.ceiling,
            checked_release=False,
        )
        return outcome, record

    def _verify_file(self, target: dict[str, Any], table: str, path: Path) -> list[str]:
        absent = bnd.check_columns(table, bnd.file_columns(path))
        entry = next(f for f in target["files"] if f["file"] == bnd.TABLES[table].file)
        rows = bnd.file_rows(path)
        if entry.get("rows") is not None and int(entry["rows"]) != rows:
            raise BundleError(f"{entry['file']} holds {rows} rows and the manifest states {entry['rows']}")
        return absent

    def _keys(self, table: str, path: Path) -> Iterable[list[str]]:
        if table == "cve":
            for batch in bnd.iter_column(path, "cve_id"):
                yield [str(k) for k in batch if k is not None]
        elif table == "product":
            for rows in bnd.iter_rows(path, bnd.file_columns(path)):
                yield [bnd.product_row(r)["product_id"] for r in rows]
        elif table == "cve_event":
            columns = [c.name for c in bnd.EVENT_COLUMNS]
            for rows in bnd.iter_rows(path, columns):
                yield [bnd.event_row(r)["event_id"] for r in rows]
        else:
            columns = bnd.file_columns(path)
            for rows in bnd.iter_rows(path, columns):
                yield [bnd.finding_row(r)["finding_id"] for r in rows]

    def _sweep(self, conn: sa.Connection, table: str, path: Path) -> int:
        """Delete the rows of a table whose key the new file does not hold. Returns how many went."""
        key = bnd.TABLES[table].key
        conn.execute(sa.text("create temp table sync_keys (key text not null) on commit drop"))
        raw = conn.connection.driver_connection
        assert raw is not None
        with raw.cursor() as cur, cur.copy("copy pg_temp.sync_keys (key) from stdin") as copy:
            for batch in self._keys(table, path):
                for value in batch:
                    copy.write_row((value,))
        if table != "cve_event":
            dupe = conn.execute(
                sa.text("select key from pg_temp.sync_keys group by key having count(*) > 1 limit 1")
            ).scalar()
            if dupe is not None:
                raise BundleError(f"{bnd.TABLES[table].file} holds the key {dupe} twice")
        conn.execute(sa.text("analyze pg_temp.sync_keys"))
        result = conn.execute(
            sa.text(
                f"delete from {self.t(table)} t where not exists "
                f"(select 1 from pg_temp.sync_keys k where k.key = t.{key})"
            )
        )
        conn.execute(sa.text("drop table pg_temp.sync_keys"))
        return int(result.rowcount or 0)

    def _load(self, conn: sa.Connection, table: str, path: Path, offset: int) -> Chunk:
        spec = bnd.TABLES[table]
        total = bnd.file_rows(path)
        raws = bnd.read_slice(path, offset, spec.chunk_rows)
        build = bnd.ROW_BUILDERS[table]
        rows = [build(r) for r in raws]
        if not rows:
            return Chunk(table, offset, 0, 0, total)
        size = self._size(conn)
        if size > self.ceiling:
            raise StorageCeiling(size, 0, self.ceiling)
        columns = DB_COLUMNS[table]
        names = ", ".join(columns)
        conn.execute(
            sa.text(f"create temp table sync_rows (like {self.t(table)} including defaults) on commit drop")
        )
        raw = conn.connection.driver_connection
        assert raw is not None
        with raw.cursor() as cur, cur.copy(f"copy pg_temp.sync_rows ({names}) from stdin") as copy:
            for row in rows:
                copy.write_row(tuple(_copy_text(row[c], c) for c in columns))
        key = spec.key
        changed_filter = f"t.{key} is null" + (
            " or t.row_digest is distinct from s.row_digest" if table in DIGESTED else ""
        )
        estimate_row = conn.execute(
            sa.text(
                "select count(*) as n, coalesce(sum(pg_column_size(s.*)), 0) as bytes "
                f"from pg_temp.sync_rows s left join {self.t(table)} t on t.{key} = s.{key} "
                f"where {changed_filter}"
            )
        ).one()
        estimate = int(int(estimate_row.bytes) * STORAGE_ALLOWANCE)
        if int(estimate_row.n) and size + estimate > self.ceiling:
            raise StorageCeiling(size, estimate, self.ceiling)
        if table in DIGESTED:
            updates = ", ".join(f"{c} = excluded.{c}" for c in columns if c != key)
            conflict = (
                f"on conflict ({key}) do update set {updates} "
                "where t.row_digest is distinct from excluded.row_digest"
            )
        else:
            conflict = f"on conflict ({key}) do nothing"
        result = conn.execute(
            sa.text(
                f"insert into {self.t(table)} as t ({names}) select {names} from pg_temp.sync_rows {conflict}"
            )
        )
        conn.execute(sa.text("drop table pg_temp.sync_rows"))
        return Chunk(table, offset, len(rows), int(result.rowcount or 0), total)

    def _finalize(
        self, conn: sa.Connection, target: dict[str, Any], cursor: dict[str, Any], now: datetime
    ) -> dict[str, Any]:
        counts = {
            table: int(conn.execute(sa.text(f"select count(*) from {self.t(table)}")).scalar() or 0)
            for table in bnd.TABLES
        }
        latest = conn.execute(
            sa.text(
                "select max(published) as published, max(last_modified) as last_modified, "
                "max(nvd_status_since) as nvd_status_since, max(kev_date_added) as kev_date_added, "
                "max(epss_date) as epss_date, max(exploit_first_seen) as exploit_first_seen "
                f"from {self.t('cve')}"
            )
        ).one()
        event_at = conn.execute(sa.text(f"select max(at) from {self.t('cve_event')}")).scalar()
        freshness = {
            "cve_published_latest": bnd.jsonable(latest.published),
            "cve_modified_latest": bnd.jsonable(latest.last_modified),
            "nvd_status_change_latest": bnd.jsonable(latest.nvd_status_since),
            "kev_added_latest": bnd.jsonable(latest.kev_date_added),
            "epss_date_latest": bnd.jsonable(latest.epss_date),
            "exploit_code_latest": bnd.jsonable(latest.exploit_first_seen),
            "event_latest": bnd.jsonable(event_at),
        }
        for table in bnd.TABLES:
            conn.execute(sa.text(f"analyze {self.t(table)}"))
        conn.execute(sa.text(f"delete from {self.t('client_budget')} where day < current_date - 31"))
        conn.execute(
            sa.text(f"delete from {self.t('ops_run')} where started_at < now() - interval '90 days'")
        )
        return {
            "tag": target["tag"],
            "release_id": target["release_id"],
            "published_at": target["published_at"],
            "manifest_sha256": target["manifest_sha256"],
            "generated_at": target["generated_at"],
            "lake_digest": target["lake_digest"],
            "locks": target.get("locks"),
            "sources": target.get("sources"),
            "files": target["files"],
            "absent_columns": cursor.get("absent_columns", {}),
            "counts": counts,
            "freshness": freshness,
            "loaded_at": _now_iso(now),
            "started_at": cursor.get("started_at"),
        }

    # Bookkeeping -------------------------------------------------------------------------------

    def _put(self, conn: sa.Connection, key: str, value: Any) -> None:
        conn.execute(
            sa.text(
                f"insert into {self.t('settings')} (key, value, updated_at) values (:k, cast(:v as jsonb), now()) "
                "on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at"
            ),
            {"k": key, "v": canonical_json(value)},
        )

    def _size(self, conn: sa.Connection) -> int:
        return int(conn.execute(sa.text("select pg_database_size(current_database())")).scalar() or 0)

    def _record(self, conn: sa.Connection, started: datetime, record: dict[str, Any]) -> None:
        conn.execute(
            sa.text(
                f"insert into {self.t('ops_run')} "
                "(kind, started_at, finished_at, status, bundle, step, rows_in, rows_changed, storage_bytes, detail) "
                "values ('sync', :started, :finished, :status, :bundle, :step, :rows_in, :rows_changed, "
                ":storage, cast(:detail as jsonb))"
            ),
            {
                "started": started,
                "finished": self.clock(),
                "status": record.get("status", "checked"),
                "bundle": record.get("bundle"),
                "step": record.get("step"),
                "rows_in": record.get("rows_in"),
                "rows_changed": record.get("rows_changed"),
                "storage": record.get("storage_bytes"),
                "detail": canonical_json(record.get("detail") or {}),
            },
        )

    def _failed(
        self,
        started: datetime,
        cursor: dict[str, Any] | None,
        status: str,
        message: str,
        *,
        storage: int | None = None,
    ) -> None:
        bundle = None
        if cursor is not None:
            target = cursor["target"]
            bundle = version_label(target["tag"], target["manifest_sha256"])
        with self.engine.connect() as conn:
            self._record(
                conn,
                started,
                {
                    "status": status,
                    "bundle": bundle,
                    "storage_bytes": storage,
                    "detail": {"error": message[:500]},
                },
            )
            conn.commit()

    def _rejected(self, started: datetime, cursor: dict[str, Any] | None, message: str) -> None:
        """Set a rejected target aside under the lock, so the next call checks the release again."""
        with self.engine.connect() as conn:
            conn.execute(sa.text("select pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})
            bundle = None
            if cursor is not None:
                target = cursor["target"]
                bundle = version_label(target["tag"], target["manifest_sha256"])
                conn.execute(
                    sa.text(
                        f"delete from {self.t('settings')} where key = 'sync' "
                        "and value -> 'target' ->> 'manifest_sha256' = :sha"
                    ),
                    {"sha": target["manifest_sha256"]},
                )
            # The release check is cleared too, so the next call reads the release again instead of
            # reusing the listing that pointed at the rejected bundle.
            conn.execute(sa.text(f"delete from {self.t('settings')} where key = 'release_check'"))
            self._record(
                conn, started, {"status": "rejected", "bundle": bundle, "detail": {"error": message[:500]}}
            )
            conn.commit()
