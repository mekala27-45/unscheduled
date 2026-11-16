"""Recorded provider calls: one transport records every call into tests/replays, one serves them.

A cassette is a gzipped file of JSON lines, one per call, keyed by the request hash: the method, the
host and path, and the request body in canonical JSON. A line keeps the request body, the status,
the response body and the few response headers that carry the provider's limits. It never keeps a
request header, so the key that travels in Authorization is never written, and scripts/check_secrets.py
reads every cassette to make sure. CI serves cassettes only (UNSCHED_REPLAY_ONLY=1 makes any other
transport an error); agent-record.yml records them when Ajay starts it.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from unscheduled_core.hashing import canonical_json

REPLAY_ONLY = "UNSCHED_REPLAY_ONLY"
KEPT_HEADERS = ("content-type", "retry-after")
KEPT_PREFIXES = ("x-ratelimit-",)


class ReplayMissing(LookupError):
    """A request no cassette holds: record it, or the test asked for something it should not."""


def _body(content: bytes) -> Any:
    try:
        return json.loads(content) if content else None
    except ValueError:
        return content.decode("utf-8", "replace")


def request_key(request: httpx.Request) -> str:
    body = _body(request.content)
    text = f"{request.method} {request.url.host}{request.url.path}\n{canonical_json(body)}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Cassette:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.entries: dict[str, dict[str, Any]] = {}
        if path.exists():
            for line in gzip.decompress(path.read_bytes()).decode("utf-8").splitlines():
                if line.strip():
                    entry = json.loads(line)
                    self.entries[entry["key"]] = entry

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = "".join(canonical_json(self.entries[k]) + "\n" for k in sorted(self.entries))
        with gzip.GzipFile(self.path, "wb", mtime=0) as handle:
            handle.write(lines.encode("utf-8"))


def _response(entry: dict[str, Any], request: httpx.Request) -> httpx.Response:
    body = entry["response"]
    content = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    return httpx.Response(
        entry["status"], headers=entry.get("headers") or {}, content=content, request=request
    )


class Replay(httpx.BaseTransport):
    """Serves the recorded calls of one cassette and refuses everything else."""

    def __init__(self, cassette: Cassette) -> None:
        self.cassette = cassette
        self.served: list[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        key = request_key(request)
        entry = self.cassette.entries.get(key)
        if entry is None:
            raise ReplayMissing(f"no recorded call {key[:12]} for {request.method} {request.url.path}")
        self.served.append(key)
        return _response(entry, request)


class Recording(httpx.BaseTransport):
    """Forwards every call to the provider and writes what came back, without any request header."""

    def __init__(self, cassette: Cassette, inner: httpx.BaseTransport | None = None) -> None:
        inner = inner or httpx.HTTPTransport(retries=0)
        if os.environ.get(REPLAY_ONLY) == "1" and isinstance(inner, httpx.HTTPTransport):
            raise RuntimeError(f"{REPLAY_ONLY} is set: this run may only serve recorded calls")
        self.cassette = cassette
        self.inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self.inner.handle_request(request)
        content = response.read()
        headers = {
            k.lower(): v
            for k, v in response.headers.items()
            if k.lower() in KEPT_HEADERS or k.lower().startswith(KEPT_PREFIXES)
        }
        key = request_key(request)
        self.cassette.entries[key] = {
            "key": key,
            "method": request.method,
            "url": f"{request.url.host}{request.url.path}",
            "request": _body(request.content),
            "status": response.status_code,
            "headers": headers,
            "response": _body(content),
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        self.cassette.save()
        return httpx.Response(response.status_code, headers=headers, content=content, request=request)


def live_allowed() -> bool:
    return os.environ.get(REPLAY_ONLY) != "1"
