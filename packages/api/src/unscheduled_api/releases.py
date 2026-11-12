"""The one place the API reads its data from: the newest serving release of this repository.

The owner, the repository and the tag prefix are constants. Nothing a caller sends can point the
sync at another repository, another tag or another file, which is what makes a public trigger safe
(docs/adr/0007). The release listing goes through the public GitHub REST API without a token: 60
requests an hour per address, so the listing is asked with the ETag of the last answer (a 304 does
not count against the limit) and the sync asks it at most once a minute. Asset bytes come from the
release download URLs, which are not API calls.

Every file is hashed as it streams to disk and compared with the sha256 the bundle manifest states,
and with the digest GitHub reports for the asset when it reports one. A file that does not match is
deleted and the bundle is rejected before a single row is read from it.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from unscheduled_api import VERSION
from unscheduled_api.bundle import BundleError

OWNER = "mekala27-45"
REPO = "unscheduled"
TAG_PREFIX = "serving-"
API_ROOT = "https://api.github.com"
LISTING_URL = f"{API_ROOT}/repos/{OWNER}/{REPO}/releases"
MAX_PAGES = 4
USER_AGENT = f"unscheduled-api/{VERSION} (+https://github.com/{OWNER}/{REPO})"


class UpstreamError(RuntimeError):
    """GitHub did not answer, or answered with a refusal; the sync tries again later."""

    def __init__(self, message: str, retry_after_s: int = 60) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    size: int
    digest: str | None  # sha256 hex, when GitHub reports the asset digest


@dataclass(frozen=True)
class Release:
    tag: str
    release_id: int
    published_at: str
    assets: Mapping[str, Asset]


@dataclass(frozen=True)
class Listing:
    not_modified: bool
    etag: str | None
    release: Release | None


def _asset(raw: Mapping[str, Any]) -> Asset:
    digest = raw.get("digest")
    sha = None
    if isinstance(digest, str) and digest.startswith("sha256:"):
        sha = digest.removeprefix("sha256:").lower()
    return Asset(
        name=str(raw["name"]),
        url=str(raw["browser_download_url"]),
        size=int(raw.get("size") or 0),
        digest=sha,
    )


def newest_serving(releases: list[Mapping[str, Any]]) -> Release | None:
    """The newest published release whose tag starts with the serving prefix."""
    candidates = [
        r
        for r in releases
        if not r.get("draft") and str(r.get("tag_name", "")).startswith(TAG_PREFIX) and r.get("published_at")
    ]
    if not candidates:
        return None
    chosen = max(candidates, key=lambda r: (str(r["published_at"]), int(r["id"])))
    assets = {a.name: a for a in (_asset(raw) for raw in chosen.get("assets") or [])}
    return Release(
        tag=str(chosen["tag_name"]),
        release_id=int(chosen["id"]),
        published_at=str(chosen["published_at"]),
        assets=assets,
    )


def _retry_after(response: httpx.Response, clock: Callable[[], float]) -> int:
    header = response.headers.get("retry-after")
    if header and header.isdigit():
        return max(int(header), 1)
    reset = response.headers.get("x-ratelimit-reset")
    if reset and reset.isdigit():
        return max(int(reset) - int(clock()), 1)
    return 60


class GitHubReleases:
    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        self.clock = clock

    def newest(self, etag: str | None) -> Listing:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if etag:
            headers["If-None-Match"] = etag
        url: str | None = f"{LISTING_URL}?per_page=100"
        first_etag: str | None = None
        seen: list[Mapping[str, Any]] = []
        later_pages = {k: v for k, v in headers.items() if k != "If-None-Match"}
        for page in range(MAX_PAGES):
            if url is None:
                break
            try:
                response = self.client.get(url, headers=headers if page == 0 else later_pages)
            except httpx.HTTPError as err:
                raise UpstreamError(
                    f"the GitHub release listing did not answer ({type(err).__name__})"
                ) from err
            if page == 0 and response.status_code == 304:
                return Listing(not_modified=True, etag=etag, release=None)
            if response.status_code in (403, 429):
                raise UpstreamError(
                    f"GitHub refused the release listing with HTTP {response.status_code}",
                    _retry_after(response, self.clock),
                )
            if response.status_code >= 400:
                raise UpstreamError(f"GitHub answered the release listing with HTTP {response.status_code}")
            if page == 0:
                first_etag = response.headers.get("etag")
            body = response.json()
            if not isinstance(body, list):
                raise UpstreamError("the GitHub release listing is not a list")
            seen.extend(r for r in body if isinstance(r, dict))
            found = newest_serving(seen)
            if found is not None:
                return Listing(not_modified=False, etag=first_etag, release=found)
            url = response.links.get("next", {}).get("url")
        return Listing(not_modified=False, etag=first_etag, release=None)

    def read_bytes(self, asset: Asset, *, max_bytes: int) -> bytes:
        """A small asset (the manifest, the backlog) read into memory, within a size cap."""
        chunks: list[bytes] = []
        total = 0
        try:
            with self.client.stream("GET", asset.url) as response:
                if response.status_code >= 400:
                    raise UpstreamError(f"{asset.name}: the download answered HTTP {response.status_code}")
                for chunk in response.iter_bytes(1 << 16):
                    total += len(chunk)
                    if total > max_bytes:
                        raise BundleError(f"{asset.name} is larger than {max_bytes} bytes")
                    chunks.append(chunk)
        except httpx.HTTPError as err:
            raise UpstreamError(f"{asset.name}: the download failed ({type(err).__name__})") from err
        return b"".join(chunks)

    def download(self, asset: Asset, dest: Path, *, max_bytes: int) -> str:
        """Stream an asset to dest, hashing as it arrives; returns the sha256 of what was written."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".part")
        digest = hashlib.sha256()
        total = 0
        try:
            with self.client.stream("GET", asset.url) as response, partial.open("wb") as handle:
                if response.status_code >= 400:
                    raise UpstreamError(f"{asset.name}: the download answered HTTP {response.status_code}")
                for chunk in response.iter_bytes(1 << 20):
                    total += len(chunk)
                    if total > max_bytes:
                        raise BundleError(f"{asset.name} is larger than {max_bytes} bytes")
                    digest.update(chunk)
                    handle.write(chunk)
        except httpx.HTTPError as err:
            partial.unlink(missing_ok=True)
            raise UpstreamError(f"{asset.name}: the download failed ({type(err).__name__})") from err
        except (UpstreamError, BundleError):
            partial.unlink(missing_ok=True)
            raise
        partial.replace(dest)
        return digest.hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class BundleCache:
    """Downloaded bundle files on local disk, named by their digest, checked every time they are used."""

    def __init__(self, root: Path, source: GitHubReleases) -> None:
        self.root = root
        self.source = source

    def path(self, sha256: str, name: str) -> Path:
        return self.root / f"{sha256[:16]}-{name}"

    def ensure(self, asset: Asset, sha256: str, *, max_bytes: int) -> Path:
        if asset.digest is not None and asset.digest != sha256:
            raise BundleError(
                f"{asset.name}: GitHub reports sha256 {asset.digest[:12]} for the asset and the manifest "
                f"states {sha256[:12]}"
            )
        target = self.path(sha256, asset.name)
        if target.exists():
            if sha256_path(target) == sha256:
                return target
            target.unlink()
        got = self.source.download(asset, target, max_bytes=max_bytes)
        if got != sha256:
            target.unlink(missing_ok=True)
            raise BundleError(
                f"{asset.name}: downloaded sha256 {got[:12]} differs from the manifest {sha256[:12]}"
            )
        return target
