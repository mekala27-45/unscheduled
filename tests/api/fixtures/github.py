"""A stand in for GitHub, served through httpx's mock transport, that answers the way GitHub does.

The release listing comes from api.github.com with an ETag and a 304 for a matching If-None-Match,
asset digests in the sha256:<hex> form, and a 403 with x-ratelimit-remaining 0 when told to refuse.
An asset download answers with a 302 to another host, as github.com does, and the bytes come from
there. Counters let a test assert how many API calls and downloads a sync made.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
from unscheduled_api.releases import OWNER, REPO

OBJECTS = "https://objects.fixture.test"


class FakeGitHub:
    def __init__(self) -> None:
        self.releases: list[dict[str, Any]] = []
        self.files: dict[str, bytes] = {}
        self.api_calls = 0
        self.not_modified = 0
        self.downloads = 0
        self.refuse_listing: int | None = None
        self.down = False
        self._next_id = 1000

    def publish(
        self,
        bundle: Path,
        tag: str,
        published_at: str,
        *,
        digests: bool = True,
        omit: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        assets = []
        for path in sorted(p for p in bundle.iterdir() if p.is_file() and p.name not in omit):
            data = path.read_bytes()
            url = f"https://github.com/{OWNER}/{REPO}/releases/download/{tag}/{path.name}"
            self.files[url] = data
            assets.append(
                {
                    "name": path.name,
                    "browser_download_url": url,
                    "size": len(data),
                    "digest": f"sha256:{hashlib.sha256(data).hexdigest()}" if digests else None,
                }
            )
        self._next_id += 1
        release = {
            "id": self._next_id,
            "tag_name": tag,
            "draft": False,
            "prerelease": True,
            "published_at": published_at,
            "assets": assets,
        }
        self.releases.insert(0, release)
        return release

    def replace_bytes(self, tag: str, name: str, data: bytes) -> None:
        """Swap an asset's bytes and leave its stated digest alone: a tampered or corrupted upload."""
        self.files[f"https://github.com/{OWNER}/{REPO}/releases/download/{tag}/{name}"] = data

    def _listing(self, request: httpx.Request) -> httpx.Response:
        self.api_calls += 1
        if self.down:
            raise httpx.ConnectError("the fixture GitHub is down", request=request)
        if self.refuse_listing is not None:
            return httpx.Response(
                self.refuse_listing,
                headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4102444800"},
                json={"message": "API rate limit exceeded"},
            )
        body = json.dumps(self.releases, sort_keys=True).encode()
        etag = '"' + hashlib.sha256(body).hexdigest()[:20] + '"'
        if request.headers.get("if-none-match") == etag:
            self.not_modified += 1
            return httpx.Response(304, headers={"etag": etag})
        return httpx.Response(200, content=body, headers={"etag": etag, "content-type": "application/json"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.url.host == "api.github.com" and request.url.path == f"/repos/{OWNER}/{REPO}/releases":
            return self._listing(request)
        if request.url.host == "github.com" and url in self.files:
            return httpx.Response(302, headers={"location": url.replace("https://github.com", OBJECTS, 1)})
        if url.startswith(OBJECTS):
            original = url.replace(OBJECTS, "https://github.com", 1)
            if original in self.files:
                self.downloads += 1
                return httpx.Response(200, content=self.files[original])
        return httpx.Response(404, json={"message": "Not Found"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler), follow_redirects=True)
