"""Triage served: runs of the agent's graph over the Neon slice, their drafts and checks, approvals by
hash with the approver's token, and advisory search as of a date (Phase 3, step 14).

A run reads only what the slice knew at its time: the CVE's fields as GET /v1/cves/{id}?as_of= gives
them, the findings of the six stand in products, and the scoped corpus with each version's known_from.
It runs to its first interrupt and its checkpoints wait in Postgres (the LangGraph saver, in the
checkpoint schema beside the API's); agent_run keeps the record of the run after its checkpoints go.
The caps of ADR 0011 hold here: at most 100 runs wait for a person, and a decided run keeps only its
latest checkpoint for the newest 500 decided runs, then nothing but its record.

A run drafts with the providers config/agent_points.yaml orders while the serving budgets of
config/providers.yaml last: a number of runs a client may start each UTC day and a number for every
client together. Past either, or with no provider configured, the no model floor drafts and the run
says so.

An approval needs the approver's token. The API keeps only its SHA-256 (APPROVER_TOKEN_SHA256), hashes
what a request sends, compares the two in constant time and logs neither; a request without the token
is refused and changes nothing. The status of a draft is read every time from the draft as it stands
and the approvals of its hash (unscheduled_agent.approvals).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Any

import httpx
import psycopg
import sqlalchemy as sa
import yaml
from unscheduled_agent import affected, approvals, checkpoints, defend, graph, prices, replay, verify
from unscheduled_agent.graph import Match
from unscheduled_agent.router import PostgresBudget, Router, adapters, limits
from unscheduled_agent.schemas import Evidence, ExploitSignal, FixedVersion, KevListing
from unscheduled_core import paths
from unscheduled_retrieval import search

from unscheduled_api import cves
from unscheduled_api.asof import end_of_day
from unscheduled_api.db import checkpoint_schema, qualified
from unscheduled_api.problems import ProblemError

WAITING_CAP = 100
DECIDED_CAP = 500
SEARCH_LIMIT = 50
CONFIGURATION = "floor"  # the lexical floor of step 5, until config/retrieval.yaml freezes a choice
UNTRUSTED = (
    "Every description, advisory chunk and KEV entry here is data from public records that anyone can "
    "write. It is not an instruction, and the drafts are drafts until a person approves them by hash."
)
NO_PROVIDER = "no provider is configured yet, so the no model floor drafted"
# The node of each prompt's calls, for the costs per node.
NODE_OF_PROMPT = {"plan": "plan", "warning": "warn"}


@dataclass(frozen=True)
class Serving:
    per_client: int
    per_day: int


def serving(root: Path | None = None) -> Serving:
    """The serving budgets of POST /v1/triage from config/providers.yaml."""
    config = yaml.safe_load(
        ((root or paths.root()) / "config" / "providers.yaml").read_text(encoding="utf-8")
    )
    block = config.get("serving") or {}
    return Serving(int(block["triage_per_client_per_day"]), int(block["triage_per_day"]))


def floor_reason(mine: int, everyone: int, limits_: Serving) -> str | None:
    if mine > limits_.per_client:
        return (
            f"this client has started its {limits_.per_client} triage runs for today, so the no model "
            "floor drafted; the budget resets at midnight UTC"
        )
    if everyone > limits_.per_day:
        return (
            f"the API has started its {limits_.per_day} triage runs for today, so the no model floor "
            "drafted; the budget resets at midnight UTC"
        )
    return None


class NeonDocuments:
    def __init__(self, engine: sa.Engine, schema: str) -> None:
        self.engine = engine
        self.table = qualified(schema, "corpus_document")
        self.cache: dict[str, list[verify.DocVersion]] = {}

    def versions(self, doc_id: str) -> Sequence[verify.DocVersion]:
        if doc_id not in self.cache:
            with self.engine.connect() as conn:
                rows = conn.execute(
                    sa.text(
                        f"select doc_id, version, known_from, known_to, withdrawn, sections from {self.table} "
                        "where doc_id = :d order by known_from, version"
                    ),
                    {"d": doc_id},
                ).all()
            self.cache[doc_id] = [
                verify.DocVersion(
                    r[0], r[1], r[2], r[3], r[4], dict(r[5] if isinstance(r[5], dict) else json.loads(r[5]))
                )
                for r in rows
            ]
        return self.cache[doc_id]


class NeonSources:
    """The sources of one run over the slice, each answer as of the run time."""

    def __init__(
        self, engine: sa.Engine, schema: str, statement: str, data_version: str, store: search.Store | None
    ) -> None:
        self.engine = engine
        self.schema = schema
        self.statement = statement
        self.data_version = data_version
        self.store = store
        self.docs = NeonDocuments(engine, schema)
        self.records: dict[tuple[str, date], dict[str, Any]] = {}

    @property
    def documents(self) -> verify.Documents:
        return self.docs

    def _fields(self, cve_id: str, at: datetime) -> dict[str, Any]:
        key = (cve_id, at.date())
        if key not in self.records:
            with self.engine.connect() as conn:
                record = cves.get_cve(
                    conn, cve_id, at.date(), statement=self.statement, data_version=self.data_version
                )
            self.records[key] = {name: value.model_dump(mode="json") for name, value in record.fields.items()}
        return self.records[key]

    def _known(self, doc_id: str, at: datetime) -> verify.DocVersion | None:
        known = [
            v
            for v in self.docs.versions(doc_id)
            if v.known_from <= at and (v.withdrawn is None or v.withdrawn > at)
        ]
        return known[-1] if known else None

    def _advisories(self, cve_id: str, at: datetime) -> list[verify.DocVersion]:
        with self.engine.connect() as conn:
            ids = (
                conn.execute(
                    sa.text(
                        f"select distinct doc_id from {qualified(self.schema, 'corpus_document')} "
                        "where cve_ids @> array[:c]::text[] and source in ('ghsa', 'osv') order by doc_id"
                    ),
                    {"c": cve_id},
                )
                .scalars()
                .all()
            )
        return [v for d in ids if (v := self._known(str(d), at)) is not None]

    def description(self, cve_id: str, at: datetime) -> str | None:
        value = (self._fields(cve_id, at).get("description") or {}).get("value")
        return str(value) if value else None

    def match(self, cve_id: str, at: datetime) -> Match | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                sa.text(
                    f"select product_id, body from {qualified(self.schema, 'finding')} "
                    "where cve_ids @> array[:c]::text[] order by product_id, finding_id limit 1"
                ),
                {"c": cve_id},
            ).first()
        if row is not None:
            body = row[1] if isinstance(row[1], dict) else json.loads(row[1])
            found: Match = {"product": str(row[0])}
            for key, name in (
                ("component", "package"),
                ("ecosystem", "ecosystem"),
                ("installed_version", "version"),
            ):
                if body.get(name):
                    found[key] = str(body[name])  # type: ignore[literal-required]
            if "component" in found:
                return found
        known = self._advisories(cve_id, at)
        if known:
            newest = max(known, key=lambda v: (v.known_from, v.doc_id))
            first = (newest.sections.get("affected") or "").split("\n")[0]
            if ":" in first:
                ecosystem, _, rest = first.partition("/")
                return {"component": rest.split(": ")[0], "ecosystem": ecosystem}
        kev = self.kev(cve_id, at)
        return {"component": kev.product} if kev is not None and kev.product else None

    def fixed_versions(self, cve_id: str, match: Match | None, at: datetime) -> list[FixedVersion]:
        if not match or "ecosystem" not in match:
            return []
        known = [
            (v.doc_id, v.version, v.sections.get("affected") or "") for v in self._advisories(cve_id, at)
        ]
        return affected.fixed_versions(
            known, match["ecosystem"], match["component"], match.get("installed_version")
        )

    def predictions(self, cve_id: str, at: datetime) -> dict[str, Any]:
        # The Phase 2 predictions were made in one batch in November 2026; none was known at a past
        # run time, and a run now reads them through the CVE record the console shows beside it.
        return {}

    def kev(self, cve_id: str, at: datetime) -> KevListing | None:
        added = self._fields(cve_id, at).get("kev_date_added")
        if not added or not added.get("value"):
            return None
        text = self._known(f"kev:{cve_id}", at)
        entry = (text.sections.get("entry") or "") if text else ""
        lines = entry.split("\n")
        product = next((x.removeprefix("Product: ") for x in lines if x.startswith("Product: ")), None)
        day = date.fromisoformat(str(added["value"])[:10])
        listed = datetime.fromisoformat(added["known_from"]) if added.get("known_from") else end_of_day(day)
        return KevListing(
            source=f"kev:{cve_id}",
            doc_version=text.version if text else None,
            listed_at=listed,
            date_added=day,
            vulnerability_name=lines[0] if entry else None,
            product=product,
        )

    def exploits(self, cve_id: str, at: datetime) -> list[ExploitSignal]:
        seen = self._fields(cve_id, at).get("exploit_first_seen")
        if not seen or not seen.get("value"):
            return []
        day = date.fromisoformat(str(seen["value"])[:10])
        return [
            ExploitSignal(
                source=str(seen.get("source") or "exploit code"),
                first_seen=datetime.combine(day, time.min, tzinfo=UTC),
            )
        ]

    def epss(self, cve_id: str, at: datetime) -> float | None:
        value = (self._fields(cve_id, at).get("epss_score") or {}).get("value")
        return float(value) if value is not None else None

    def retrieve(self, query: str, at: datetime, k: int) -> list[Evidence]:
        if self.store is None:
            return []
        return evidences(self.engine, self.schema, self.store.floor(query, at, limit=k))


def evidences(engine: sa.Engine, schema: str, hits: Sequence[search.Hit]) -> list[Evidence]:
    """The chunks of some hits as evidence, in the order of the hits, in one query."""
    if not hits:
        return []
    with engine.connect() as conn:
        rows = {
            r[0]: r
            for r in conn.execute(
                sa.text(
                    f"select chunk_id, version, sections, known_from, text from {qualified(schema, 'corpus_chunk')} "
                    "where chunk_id = any(:ids)"
                ),
                {"ids": [h[0] for h in hits]},
            ).all()
        }
    return [
        Evidence(
            chunk_id=chunk_id,
            doc_id=doc_id,
            version=rows[chunk_id][1],
            sections=list(rows[chunk_id][2]),
            known_from=rows[chunk_id][3],
            text=rows[chunk_id][4],
            score=score,
        )
        for chunk_id, doc_id, score in hits
        if chunk_id in rows
    ]


def plain(url: str) -> str:
    """The libpq form of a SQLAlchemy URL, for the connections psycopg opens itself."""
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def router(conn: psycopg.Connection[Any], schema: str, root: Path | None = None) -> Router | None:
    """The providers config/agent_points.yaml orders, each with its key, counted in agent_budget; with
    no order, or no provider that has a key, None, and the floor drafts."""
    root = root or paths.root()
    points_path = root / "config" / "agent_points.yaml"
    if not points_path.exists():
        return None
    order = [
        tuple(x)
        for x in (yaml.safe_load(points_path.read_text(encoding="utf-8")) or {}).get("router_order") or []
    ]
    if not order:
        return None
    config = yaml.safe_load((root / "config" / "providers.yaml").read_text(encoding="utf-8"))
    transport: httpx.BaseTransport = (
        httpx.HTTPTransport(retries=0)
        if replay.live_allowed()
        else replay.Replay(replay.Cassette(root / "tests" / "replays" / "serving.jsonl.gz"))
    )
    chosen = adapters(config, order, transport, prices.load(root))
    if not chosen:
        return None
    budget = PostgresBudget(conn, f'"{schema}"', limits(config), create=False)
    return Router(chosen, budget)


def node_costs(timings: dict[str, Any], calls: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Milliseconds, calls, tokens and shadow price per node, in the order the nodes ran."""
    out: dict[str, dict[str, Any]] = {
        name: {"ms": float(ms), "calls": 0, "tokens_in": 0, "tokens_out": 0, "shadow_usd": 0.0}
        for name, ms in timings.items()
    }
    for call in calls:
        prompt = str(call.get("prompt_id") or "")
        node = NODE_OF_PROMPT.get(prompt, prompt)
        entry = out.setdefault(
            node, {"ms": 0.0, "calls": 0, "tokens_in": 0, "tokens_out": 0, "shadow_usd": 0.0}
        )
        entry["calls"] += 1
        entry["tokens_in"] += int(call.get("tokens_in") or 0)
        entry["tokens_out"] += int(call.get("tokens_out") or 0)
        entry["shadow_usd"] = round(entry["shadow_usd"] + float(call.get("shadow_usd") or 0.0), 6)
    return out


def _facts(values: dict[str, Any]) -> dict[str, Any]:
    """What the run read, as it read it: the description, the match, the KEV listing, the exploit
    signals, EPSS and the retrieved chunks with their scores."""
    return {
        "description": values.get("description"),
        "match": values.get("match"),
        "fixed_versions": values.get("fixed_versions") or [],
        "kev": values.get("kev"),
        "exploits": values.get("exploits") or [],
        "epss": values.get("epss"),
        "evidence": values.get("evidence") or [],
    }


def _summary(row: Any) -> dict[str, Any]:
    value = row[4]
    if isinstance(value, dict):
        return value
    return dict(json.loads(value)) if value else {}


class Triage:
    def __init__(
        self,
        engine: sa.Engine,
        url: str,
        schema: str,
        statement: str,
        data_version: str,
        *,
        root: Path | None = None,
    ) -> None:
        self.engine = engine
        self.url = plain(url)
        self.schema = schema
        self.statement = statement
        self.data_version = data_version
        self.root = root
        self.runs_table = qualified(schema, "agent_run")

    @contextmanager
    def _connect(self) -> Iterator[psycopg.Connection[Any]]:
        with psycopg.connect(self.url, autocommit=True, connect_timeout=10) as conn:
            conn.execute("set time zone 'UTC'")
            yield conn

    @contextmanager
    def _session(self, models: bool) -> Iterator[tuple[Any, Any, psycopg.Connection[Any], bool]]:
        """A compiled graph over this request's connections: one for the corpus, the budget and the
        approvals, one for the checkpoints. Both close when the request ends."""
        with self._connect() as conn, checkpoints.saver(self.url, checkpoint_schema(self.schema)) as saver:
            store = search.Store(conn, self.schema, chunks="corpus_chunk")
            sources = defend.Guard(
                NeonSources(self.engine, self.schema, self.statement, self.data_version, store)
            )
            chosen = router(conn, self.schema, self.root) if models else None
            yield graph.build(sources, chosen).compile(checkpointer=saver), saver, conn, chosen is not None

    def _room(self) -> None:
        with self.engine.connect() as conn:
            waiting = conn.execute(
                sa.text(f"select count(*) from {self.runs_table} where status = 'waiting'")
            ).scalar_one()
        if int(waiting) >= WAITING_CAP:
            raise ProblemError(
                "run-store-full",
                f"{WAITING_CAP} runs already wait for a person; decide some before starting another",
                context={"waiting": int(waiting)},
            )

    def start(self, cve_id: str, as_of: date | None, *, reason: str | None = None) -> dict[str, Any]:
        """Run the graph for a CVE to its first interrupt. reason, when given, is why the floor drafts."""
        cve = cves.normalize_id(cve_id)
        at = end_of_day(as_of) if as_of else datetime.now(UTC)
        with self.engine.connect() as conn:
            record = cves.get_cve(conn, cve, as_of, statement=self.statement, data_version=self.data_version)
        if not record.known:
            raise ProblemError(
                "not-found",
                f"{cve} was not yet published on {as_of.isoformat() if as_of else 'that day'}; there is nothing to triage",
                context={"cve_id": cve},
            )
        self._room()
        run_id = uuid.uuid4().hex
        now = datetime.now(UTC)
        with self.engine.begin() as conn:
            conn.execute(
                sa.text(
                    f"insert into {self.runs_table} (run_id, cve_id, as_of, created_at, updated_at, status) "
                    "values (:r, :c, :a, :n, :n, 'running')"
                ),
                {"r": run_id, "c": cve, "a": at, "n": now},
            )
        try:
            with self._session(models=reason is None) as (compiled, _saver, conn, live):
                compiled.invoke(graph.start(cve, at, run_id), graph.config(run_id))
                note = reason or (None if live else NO_PROVIDER)
                return self._record(compiled, conn, run_id, note, budget_floor=reason is not None)
        except Exception:
            self._status(run_id, "failed")
            raise

    def _status(self, run_id: str, status: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                sa.text(f"update {self.runs_table} set status = :s, updated_at = :n where run_id = :r"),
                {"s": status, "n": datetime.now(UTC), "r": run_id},
            )

    def _record(
        self,
        compiled: Any,
        conn: psycopg.Connection[Any],
        run_id: str,
        note: str | None,
        budget_floor: bool = False,
    ) -> dict[str, Any]:
        snapshot = compiled.get_state(graph.config(run_id))
        values = dict(snapshot.values)
        waiting = [i.value for t in snapshot.tasks for i in t.interrupts]
        status = "waiting" if waiting else str(values.get("status") or "decided")
        view = self.view(conn, run_id, values, waiting, status, note)
        summary = {
            "nodes": view["nodes"],
            "cost": view["cost"],
            "drafts": {
                k: {"status": d["status"], "by": d["by"], "sha256": d["sha256"]}
                for k, d in view["drafts"].items()
            },
            "note": note,
            "budget_floor": budget_floor,
        }
        with self.engine.begin() as db:
            db.execute(
                sa.text(
                    f"update {self.runs_table} set status = :s, updated_at = :n, plan_sha256 = :p, "
                    "warning_sha256 = :w, summary = cast(:j as jsonb) where run_id = :r"
                ),
                {
                    "s": status,
                    "n": datetime.now(UTC),
                    "p": (values.get("plan_check") or {}).get("sha256"),
                    "w": (values.get("warning_check") or {}).get("sha256"),
                    "j": json.dumps(summary, default=str),
                    "r": run_id,
                },
            )
        return view

    def view(
        self,
        conn: psycopg.Connection[Any],
        run_id: str,
        values: dict[str, Any],
        waiting: list[dict[str, Any]],
        status: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        store = approvals.PostgresStore(conn, f'"{self.schema}"', create=False)
        drafts = {}
        kinds: tuple[approvals.Kind, ...] = ("plan", "warning")
        for kind in kinds:
            check = values.get(f"{kind}_check")
            if check:
                drafts[kind] = {
                    "status": approvals.status(store, run_id, kind, check),
                    "by": check.get("by"),
                    "sha256": check.get("sha256"),
                    "check": check,
                }
        calls = values.get("calls") or []
        return {
            "run_id": run_id,
            "cve_id": values.get("cve_id"),
            "as_of": values.get("as_of"),
            "parent_run_id": values.get("parent_run_id"),
            "status": status,
            "waiting_for": [{"kind": w["kind"], "sha256": w["sha256"]} for w in waiting],
            "drafts": drafts,
            "approvals": [r.row() for r in store.records(run_id)],
            "facts": _facts(values),
            "nodes": node_costs(values.get("timings") or {}, calls),
            "calls": calls,
            "cost": {
                "tokens_in": sum(int(c.get("tokens_in") or 0) for c in calls),
                "tokens_out": sum(int(c.get("tokens_out") or 0) for c in calls),
                "shadow_usd": round(sum(float(c.get("shadow_usd") or 0.0) for c in calls), 6),
            },
            "checkpoints": "kept",
            "note": note,
            "untrusted": UNTRUSTED,
        }

    def _row(self, run_id: str) -> Any:
        with self.engine.connect() as conn:
            return conn.execute(
                sa.text(
                    f"select run_id, cve_id, as_of, status, summary, checkpoints, parent_run_id from {self.runs_table} "
                    "where run_id = :r"
                ),
                {"r": run_id},
            ).first()

    def read(self, run_id: str) -> dict[str, Any]:
        row = self._row(run_id)
        if row is None:
            raise ProblemError("not-found", f"there is no run {run_id}", context={"run_id": run_id})
        summary = _summary(row)
        if row[5] == "gone" or row[3] in ("running", "failed"):
            return self._from_record(row, summary)
        with self._session(models=False) as (compiled, _saver, conn, _live):
            snapshot = compiled.get_state(graph.config(run_id))
            if not snapshot.values:
                return self._from_record(row, summary)
            waiting = [i.value for t in snapshot.tasks for i in t.interrupts]
            return self.view(conn, run_id, dict(snapshot.values), waiting, str(row[3]), summary.get("note"))

    def _from_record(self, row: Any, summary: dict[str, Any]) -> dict[str, Any]:
        """A run whose checkpoints are gone, or that never reached one: its record in agent_run."""
        with self._connect() as conn:
            records = approvals.PostgresStore(conn, f'"{self.schema}"', create=False).records(str(row[0]))
        return {
            "run_id": str(row[0]),
            "cve_id": str(row[1]),
            "as_of": row[2].astimezone(UTC).isoformat(),
            "parent_run_id": row[6],
            "status": str(row[3]),
            "waiting_for": [],
            "drafts": summary.get("drafts") or {},
            "approvals": [r.row() for r in records],
            "facts": {},
            "nodes": summary.get("nodes") or {},
            "calls": [],
            "cost": summary.get("cost") or {},
            "checkpoints": "gone" if row[5] == "gone" else "none",
            "note": summary.get("note")
            or ("the run failed before its first checkpoint" if row[3] == "failed" else None),
            "untrusted": UNTRUSTED,
        }

    def runs(self, limit: int) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = (
                conn.execute(
                    sa.text(
                        f"select run_id, cve_id, as_of, status, created_at, plan_sha256, warning_sha256 from {self.runs_table} "
                        "order by created_at desc, run_id limit :l"
                    ),
                    {"l": limit},
                )
                .mappings()
                .all()
            )
        return [dict(r) for r in rows]

    def decide(
        self, run_id: str, kind: approvals.Kind, sha256: str, decision: str, token: str | None, by: str
    ) -> dict[str, Any]:
        """A person's decision on the draft that waits, named by its hash. Without the token, or on a
        hash that is not the hash of the draft that waits, nothing is recorded and the run stays."""
        if not approvals.token_ok(token):
            raise ProblemError(
                "approval-refused", "a decision needs the approver's token; nothing was recorded"
            )
        row = self._row(run_id)
        if row is None:
            raise ProblemError("not-found", f"there is no run {run_id}", context={"run_id": run_id})
        summary = _summary(row)
        # A run the serving budget sent to the floor drafts its warning with the floor too.
        budget_floor = bool(summary.get("budget_floor"))
        with self._session(models=not budget_floor) as (compiled, saver, conn, live):
            snapshot = compiled.get_state(graph.config(run_id))
            shown = [i.value for t in snapshot.tasks for i in t.interrupts]
            if not shown:
                raise ProblemError(
                    "not-found", f"run {run_id} waits for no decision", context={"run_id": run_id}
                )
            if shown[0]["sha256"] != sha256 or (kind == "plan") != (shown[0]["kind"] == "patch_plan"):
                raise ProblemError(
                    "approval-refused",
                    "the hash is not the hash of the draft that waits; nothing was recorded",
                )
            verdict: approvals.Decision = "approve" if decision == "approve" else "reject"
            approvals.record(
                approvals.PostgresStore(conn, f'"{self.schema}"', create=False),
                run_id,
                kind,
                sha256,
                verdict,
                by,
                token,
            )
            graph.decide(compiled, run_id, verdict, sha256, by)
            note = summary.get("note") if budget_floor else (None if live else NO_PROVIDER)
            out = self._record(compiled, conn, run_id, note, budget_floor=budget_floor)
            if not out["waiting_for"]:
                saver.prune([run_id], strategy="keep_latest")
                self._cap(saver)
            return out

    def _cap(self, saver: Any) -> None:
        """Past the newest 500 decided runs, a run keeps nothing but its record."""
        with self.engine.begin() as conn:
            old = (
                conn.execute(
                    sa.text(
                        f"select run_id from {self.runs_table} where status not in ('waiting', 'running') "
                        "and checkpoints = 'kept' order by updated_at desc, run_id offset :n"
                    ),
                    {"n": DECIDED_CAP},
                )
                .scalars()
                .all()
            )
            if old:
                saver.prune(list(old), strategy="delete")
                conn.execute(
                    sa.text(f"update {self.runs_table} set checkpoints = 'gone' where run_id = any(:ids)"),
                    {"ids": list(old)},
                )

    def search(self, query: str, as_of: date, limit: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            hits = search.Store(conn, self.schema, chunks="corpus_chunk").floor(
                query, end_of_day(as_of), limit=min(limit, SEARCH_LIMIT)
            )
        return [
            {**e.model_dump(mode="json"), "untrusted": True}
            for e in evidences(self.engine, self.schema, hits)
        ]
