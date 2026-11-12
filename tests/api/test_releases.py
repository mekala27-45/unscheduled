"""The release listing and the downloads, against the fake GitHub and a few hand made answers."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from unscheduled_api.bundle import BundleError
from unscheduled_api.releases import Asset, BundleCache, GitHubReleases, UpstreamError, newest_serving

from tests.api.fixtures.github import FakeGitHub


def release(tag: str, published: str, rid: int, *, draft: bool = False) -> dict[str, object]:
    return {"id": rid, "tag_name": tag, "draft": draft, "published_at": published, "assets": []}


def test_the_newest_serving_release_wins_and_others_are_ignored() -> None:
    found = newest_serving(
        [
            release("v0.1.0", "2026-11-09T00:00:00Z", 1),
            release("serving-a", "2026-11-07T00:00:00Z", 2),
            release("serving-b", "2026-11-08T00:00:00Z", 3),
            release("serving-c", "2026-11-10T00:00:00Z", 4, draft=True),
            release("raw-locks", "2026-11-11T00:00:00Z", 5),
        ]
    )
    assert found is not None and found.tag == "serving-b"
    assert newest_serving([release("v1", "2026-11-09T00:00:00Z", 1)]) is None


def test_a_listing_follows_the_next_page_until_a_serving_release_appears() -> None:
    pages = {
        "https://api.github.com/repos/mekala27-45/unscheduled/releases?per_page=100": (
            [release("raw-1", "2026-11-09T00:00:00Z", 9)],
            '<https://api.github.com/repositories/1/releases?per_page=100&page=2>; rel="next"',
        ),
        "https://api.github.com/repositories/1/releases?per_page=100&page=2": (
            [release("serving-old", "2026-11-01T00:00:00Z", 1)],
            "",
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body, link = pages[str(request.url)]
        headers = {"etag": '"page"', "link": link} if link else {"etag": '"page"'}
        return httpx.Response(200, json=body, headers=headers)

    listing = GitHubReleases(httpx.Client(transport=httpx.MockTransport(handler))).newest(None)
    assert listing.release is not None and listing.release.tag == "serving-old"


def test_a_listing_that_does_not_answer_is_an_upstream_error() -> None:
    github = FakeGitHub()
    github.down = True
    with pytest.raises(UpstreamError, match="did not answer"):
        GitHubReleases(github.client()).newest(None)


def test_an_unchanged_listing_is_a_304_that_costs_nothing() -> None:
    github = FakeGitHub()
    source = GitHubReleases(github.client())
    first = source.newest(None)
    second = source.newest(first.etag)
    assert first.not_modified is False and second.not_modified is True and github.not_modified == 1


def test_a_download_is_hashed_as_it_streams_and_capped(tmp_path: Path) -> None:
    github = FakeGitHub()
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "backlog.json").write_text('{"q1": 1}\n', encoding="utf-8")
    published = github.publish(bundle, "serving-x", "2026-11-07T00:00:00Z")
    raw = published["assets"][0]
    asset = Asset(name="backlog.json", url=raw["browser_download_url"], size=raw["size"], digest=None)
    source = GitHubReleases(github.client())
    cache = BundleCache(tmp_path / "cache", source)
    sha = raw["digest"].removeprefix("sha256:")
    path = cache.ensure(asset, sha, max_bytes=1000)
    assert path.read_text(encoding="utf-8") == '{"q1": 1}\n' and github.downloads == 1
    cache.ensure(asset, sha, max_bytes=1000)
    assert github.downloads == 1  # kept by digest, checked again, not downloaded again
    with pytest.raises(BundleError, match="differs from the manifest"):
        cache.ensure(asset, "0" * 64, max_bytes=1000)
    with pytest.raises(BundleError, match="larger than"):
        BundleCache(tmp_path / "other", source).ensure(asset, sha, max_bytes=3)
    assert not list((tmp_path / "other").glob("*.part"))
