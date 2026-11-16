"""The router: one adapter per provider behind one interface, budgets counted in Postgres, and the
no model floor last.

An adapter generates one structured object from a prompt and its inputs, under a timeout and a token
limit, and returns it with the record of the call: the request hash, the model, the tokens in and
out, the milliseconds, the retries, the outcome and the shadow price. Every provider of
config/providers.yaml offers the OpenAI chat completions endpoint, so one adapter speaks to all of
them over httpx, and the transport under it is either the network, a recording of it, or a replay.

The router tries the providers in its order (chosen on development by the eval, config/agent_points.yaml)
and moves to the next one when a provider is past its daily budget, times out, refuses, answers with
an error, or fails the schema twice (one retry); when the run's deadline would not leave a provider
its timeout; and last it asks the floor, which always answers. A model never sees a key: the adapter
reads it from the environment variable the config names and sends it only in the Authorization
header, which no recording keeps.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx
import psycopg
from pydantic import BaseModel, ValidationError
from unscheduled_core.hashing import canonical_json

from unscheduled_agent.prices import Book

FLOOR = "floor"


@dataclass(frozen=True)
class Prompt:
    """A prompt as a versioned file gives it (prompts/, step 7): its text and the hash of that text."""

    id: str
    version: str
    text: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@dataclass
class CallRecord:
    provider: str
    model: str
    prompt_id: str
    prompt_version: str
    prompt_sha256: str
    request_sha256: str
    outcome: str  # ok, schema, timeout, refused, error, budget, deadline, floor
    tokens_in: int = 0
    tokens_out: int = 0
    ms: float = 0.0
    retries: int = 0
    shadow_usd: float = 0.0
    error: str | None = None
    at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    def row(self) -> dict[str, Any]:
        return asdict(self)


class Budget(Protocol):
    def allow(self, provider: str, model: str) -> bool: ...

    def spend(self, provider: str, model: str, tokens: int) -> None: ...


@dataclass(frozen=True)
class Limit:
    requests_per_day: int
    tokens_per_day: int


class MemoryBudget:
    """A day's budget held in memory, for tests and replays."""

    def __init__(self, limits: dict[str, Limit]) -> None:
        self.limits = limits
        self.used: dict[tuple[str, str], tuple[int, int]] = {}

    def allow(self, provider: str, model: str) -> bool:
        limit = self.limits.get(provider)
        if limit is None:
            return False
        requests, tokens = self.used.get((provider, model), (0, 0))
        return requests < limit.requests_per_day and tokens < limit.tokens_per_day

    def spend(self, provider: str, model: str, tokens: int) -> None:
        requests, used = self.used.get((provider, model), (0, 0))
        self.used[(provider, model)] = (requests + 1, used + tokens)


BUDGET_TABLE = """
create table if not exists {schema}.agent_budget (
    provider text not null,
    model text not null,
    day date not null,
    requests integer not null default 0,
    tokens integer not null default 0,
    primary key (provider, model, day)
)
"""


class PostgresBudget:
    """The budget of each provider and model for the current UTC day, counted in Postgres so every
    function instance of the API reads the same count."""

    def __init__(self, conn: psycopg.Connection[Any], schema: str, limits: dict[str, Limit]) -> None:
        self.conn = conn
        self.schema = schema
        self.limits = limits
        with conn.cursor() as cur:
            cur.execute(BUDGET_TABLE.format(schema=schema))
        conn.commit()

    def allow(self, provider: str, model: str) -> bool:
        limit = self.limits.get(provider)
        if limit is None:
            return False
        with self.conn.cursor() as cur:
            cur.execute(
                f"select requests, tokens from {self.schema}.agent_budget "
                "where provider = %s and model = %s and day = (now() at time zone 'utc')::date",
                (provider, model),
            )
            row = cur.fetchone()
        requests, tokens = (int(row[0]), int(row[1])) if row else (0, 0)
        return requests < limit.requests_per_day and tokens < limit.tokens_per_day

    def spend(self, provider: str, model: str, tokens: int) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                f"insert into {self.schema}.agent_budget (provider, model, day, requests, tokens) "
                "values (%s, %s, (now() at time zone 'utc')::date, 1, %s) "
                "on conflict (provider, model, day) do update set requests = agent_budget.requests + 1, "
                "tokens = agent_budget.tokens + excluded.tokens",
                (provider, model, tokens),
            )
        self.conn.commit()


class Adapter(Protocol):
    name: str
    model: str
    timeout_s: float

    def generate(
        self, prompt: Prompt, inputs: dict[str, Any], schema: type[BaseModel], max_tokens: int
    ) -> tuple[BaseModel | None, CallRecord]: ...


def request_body(
    prompt: Prompt, inputs: dict[str, Any], schema: type[BaseModel], model: str, max_tokens: int
) -> dict[str, Any]:
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": prompt.text},
            {"role": "user", "content": canonical_json(inputs)},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema(), "strict": False},
        },
        "max_tokens": max_tokens,
        "temperature": 0,
        "seed": 20261116,
    }


class OpenAICompatible:
    """One provider and model behind the chat completions endpoint."""

    def __init__(
        self,
        name: str,
        base_url: str,
        key_env: str,
        model: str,
        *,
        transport: httpx.BaseTransport,
        timeout_s: float,
        book: Book,
        shadow_sku: str,
        environ: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self.timeout_s = timeout_s
        self.base_url = base_url.rstrip("/")
        self.key_env = key_env
        self.book = book
        self.shadow_sku = shadow_sku
        self.environ = environ if environ is not None else dict(os.environ)
        self.client = httpx.Client(transport=transport, timeout=httpx.Timeout(timeout_s))

    @property
    def available(self) -> bool:
        return bool(self.environ.get(self.key_env))

    def generate(
        self, prompt: Prompt, inputs: dict[str, Any], schema: type[BaseModel], max_tokens: int
    ) -> tuple[BaseModel | None, CallRecord]:
        body = request_body(prompt, inputs, schema, self.model, max_tokens)
        record = CallRecord(
            provider=self.name,
            model=self.model,
            prompt_id=prompt.id,
            prompt_version=prompt.version,
            prompt_sha256=prompt.sha256,
            request_sha256=hashlib.sha256(canonical_json(body).encode()).hexdigest(),
            outcome="error",
        )
        headers = {"Authorization": f"Bearer {self.environ.get(self.key_env, '')}"}
        started = time.perf_counter()
        for attempt in range(2):
            record.retries = attempt
            try:
                response = self.client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
            except httpx.TimeoutException:
                record.outcome, record.error = "timeout", f"no answer within {self.timeout_s:.0f} s"
                break
            except httpx.HTTPError as err:
                record.outcome, record.error = "error", type(err).__name__
                break
            if 400 <= response.status_code < 500:
                record.outcome, record.error = "refused", f"HTTP {response.status_code}"
                break
            if response.status_code >= 500:
                record.outcome, record.error = "error", f"HTTP {response.status_code}"
                break
            answer = response.json()
            usage = answer.get("usage") or {}
            record.tokens_in += int(usage.get("prompt_tokens") or 0)
            record.tokens_out += int(usage.get("completion_tokens") or 0)
            content = ((answer.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            try:
                parsed = schema.model_validate_json(content)
            except ValidationError as err:
                record.outcome, record.error = "schema", f"{len(err.errors())} schema errors"
                # One retry, told what failed: the answer, then the first errors, then the ask again.
                problems = "; ".join(
                    f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in err.errors()[:3]
                )
                body = {
                    **body,
                    "messages": [
                        *body["messages"],
                        {"role": "assistant", "content": content},
                        {
                            "role": "user",
                            "content": f"That answer does not match the schema ({problems}). Answer again with JSON that matches it.",
                        },
                    ],
                }
                continue
            record.outcome, record.error = "ok", None
            record.ms = round((time.perf_counter() - started) * 1000, 1)
            record.shadow_usd = self.book.shadow_usd(self.shadow_sku, record.tokens_in, record.tokens_out)
            return parsed, record
        record.ms = round((time.perf_counter() - started) * 1000, 1)
        record.shadow_usd = self.book.shadow_usd(self.shadow_sku, record.tokens_in, record.tokens_out)
        return None, record


class Router:
    def __init__(self, adapters: Sequence[OpenAICompatible], budget: Budget) -> None:
        self.adapters = list(adapters)
        self.budget = budget

    def generate(
        self,
        prompt: Prompt,
        inputs: dict[str, Any],
        schema: type[BaseModel],
        floor: Callable[[], BaseModel],
        *,
        max_tokens: int,
        deadline: float | None = None,
    ) -> tuple[BaseModel, list[CallRecord]]:
        """The first valid answer in the router's order, else the floor's; every attempt recorded."""
        calls: list[CallRecord] = []
        for adapter in self.adapters:
            if not adapter.available:
                continue
            base = CallRecord(
                adapter.name, adapter.model, prompt.id, prompt.version, prompt.sha256, "", "budget"
            )
            if deadline is not None and time.monotonic() + adapter.timeout_s > deadline:
                base.outcome, base.error = "deadline", "the run's deadline leaves no room for this provider"
                calls.append(base)
                continue
            if not self.budget.allow(adapter.name, adapter.model):
                base.error = "past the daily budget"
                calls.append(base)
                continue
            answer, record = adapter.generate(prompt, inputs, schema, max_tokens)
            self.budget.spend(adapter.name, adapter.model, record.tokens_in + record.tokens_out)
            calls.append(record)
            if answer is not None:
                return answer, calls
        started = time.perf_counter()
        draft = floor()
        calls.append(
            CallRecord(
                FLOOR,
                FLOOR,
                prompt.id,
                prompt.version,
                prompt.sha256,
                hashlib.sha256(canonical_json(inputs).encode()).hexdigest(),
                "floor",
                ms=round((time.perf_counter() - started) * 1000, 3),
            )
        )
        return draft, calls


def limits(config: dict[str, Any]) -> dict[str, Limit]:
    out: dict[str, Limit] = {}
    for name, provider in (config.get("providers") or {}).items():
        budget = provider.get("budget")
        if budget:
            out[name] = Limit(int(budget["requests_per_day"]), int(budget["tokens_per_day"]))
    return out


def adapters(
    config: dict[str, Any],
    order: Sequence[tuple[str, str]],
    transport: httpx.BaseTransport,
    book: Book,
    environ: dict[str, str] | None = None,
) -> list[OpenAICompatible]:
    """The adapters of the router in its order, each (provider, model) as config/agent_points.yaml names it."""
    out: list[OpenAICompatible] = []
    for name, model in order:
        provider = config["providers"][name]
        out.append(
            OpenAICompatible(
                name,
                provider["base_url"],
                provider["key_env"],
                model,
                transport=transport,
                timeout_s=float(provider.get("timeout_s", 20)),
                book=book,
                shadow_sku=str(config["shadow_sku"]),
                environ=environ,
            )
        )
    return out


def dumps(calls: Sequence[CallRecord]) -> str:
    return json.dumps([c.row() for c in calls], indent=1)
