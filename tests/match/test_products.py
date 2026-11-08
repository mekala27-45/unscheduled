"""The stand ins: the rule applied by code, the picks it recorded, and the unauthenticated GitHub pacing."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from unscheduled_match import products
from unscheduled_match.github import GitHub
from unscheduled_match.products import EcosystemRule, ImageRule, OsiList

from tests.match import helpers

CONFIG = products.load_config(helpers.ROOT / "config" / "products.yaml")
CUTOFF = products.parse_github_time(CONFIG.rule.cutoff)
# A sanity floor, not the list the rule used: these SPDX ids are OSI approved by any reading.
WELL_KNOWN_OSI = {
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "AGPL-3.0",
    "GPL-3.0",
    "GPL-2.0",
    "MPL-2.0",
    "ISC",
    "Unlicense",
}


def test_six_stand_ins_one_per_ecosystem_and_one_image() -> None:
    stand_ins = CONFIG.stand_ins
    assert len(stand_ins) == 6
    assert sorted(s.ecosystem for s in stand_ins) == sorted(
        ["npm", "PyPI", "Go", "Maven", "crates.io", "Debian"]
    )
    assert [s.kind for s in stand_ins].count("image") == 1
    assert {s.product for s in stand_ins} == {r.product for r in CONFIG.ecosystems} | {CONFIG.image.product}


@pytest.mark.parametrize(
    "stand_in", [s for s in CONFIG.stand_ins if s.kind == "repository"], ids=lambda s: s.product
)
def test_each_repository_meets_the_rule_as_recorded(stand_in: products.StandIn) -> None:
    rule = next(r for r in CONFIG.ecosystems if r.product == stand_in.product)
    assert stand_in.commit and re.fullmatch(r"[0-9a-f]{40}", stand_in.commit)
    assert stand_in.commit_date and products.parse_github_time(stand_in.commit_date) < CUTOFF
    assert stand_in.stars is not None and stand_in.stars >= CONFIG.rule.min_stars
    assert stand_in.licence in WELL_KNOWN_OSI
    assert stand_in.lockfiles and set(stand_in.lockfiles) <= set(rule.lockfiles)
    assert stand_in.date_read and stand_in.licence_file_sha256
    for passed in stand_in.passed_over:
        assert passed.reason
        assert passed.stars >= stand_in.stars, "a repository passed over has fewer stars than the pick"


def test_the_image_is_pinned_by_a_platform_digest_before_the_cutoff() -> None:
    image = next(s for s in CONFIG.stand_ins if s.kind == "image")
    assert image.digest and re.fullmatch(r"sha256:[0-9a-f]{64}", image.digest)
    assert image.index_digest and image.index_digest != image.digest
    assert image.platform and image.platform.startswith(CONFIG.image.platform)
    assert image.tag and re.match(CONFIG.image.tag_pattern, image.tag)
    assert image.pushed and products.parse_github_time(image.pushed) < CUTOFF


class FakeGitHub:
    """Search results, commits and files as GitHub would answer them."""

    def __init__(
        self,
        repos: list[dict[str, Any]],
        commits: dict[str, list[str]],
        files: dict[tuple[str, str, str], bytes],
    ) -> None:
        self.repos, self.commits, self.files = repos, commits, files

    def repositories(self, query: str, page: int = 1, per_page: int = 100) -> list[dict[str, Any]]:
        language = query.split()[0].split(":")[1]
        return [r for r in self.repos if r["language"] == language] if page == 1 else []

    def commits_before(self, repo: str, cutoff_date: str, per_page: int = 5) -> list[dict[str, Any]]:
        return [
            {"sha": sha, "commit": {"committer": {"date": date}}}
            for sha, date in (c.split("@") for c in self.commits.get(repo, []))
        ]

    def raw(self, repo: str, ref: str, path: str) -> bytes | None:
        return self.files.get((repo, ref, path))

    def raw_exists(self, repo: str, ref: str, path: str) -> bool:
        return (repo, ref, path) in self.files


def repo(name: str, stars: int, language: str = "Rust", licence: str = "MIT", **extra: Any) -> dict[str, Any]:
    return {
        "full_name": name,
        "stargazers_count": stars,
        "language": language,
        "license": {"spdx_id": licence},
        "created_at": "2019-01-01T00:00:00Z",
        "default_branch": "main",
        "fork": False,
        "archived": False,
        **extra,
    }


RULE = EcosystemRule(
    product="rust-cli",
    ecosystem="crates.io",
    languages=("Rust",),
    lockfiles=("Cargo.lock",),
    manifests=("Cargo.toml",),
)
OSI = OsiList(version="test", approved=frozenset({"MIT", "Apache-2.0"}), read_at="2026-11-07T00:00:00Z")
SHA = "a" * 40


def test_the_rule_takes_the_most_starred_repository_that_passes_and_keeps_the_rest() -> None:
    licence = b"MIT License\nCopyright (c) 2024 someone\n"
    gh = FakeGitHub(
        [
            repo("big/proprietary", 9000, licence="NOASSERTION"),
            repo("big/no-lock", 8000),
            repo("b/tied", 7000),
            repo("a/tied", 7000),
            repo("small/also-good", 6000),
        ],
        {
            "big/no-lock": [f"{'b' * 40}@2024-12-31T10:00:00Z"],
            "a/tied": [f"{SHA}@2024-12-30T10:00:00Z"],
            "b/tied": [f"{'c' * 40}@2024-12-30T10:00:00Z"],
        },
        {
            ("a/tied", SHA, "Cargo.lock"): b"lock",
            ("a/tied", SHA, "LICENSE"): licence,
            ("a/tied", "main", "LICENSE"): licence.replace(b"2024", b"2026"),
            ("b/tied", "c" * 40, "Cargo.lock"): b"lock",
        },
    )
    pick = products.select(RULE, CUTOFF, 1000, OSI, gh)  # type: ignore[arg-type]
    assert pick.repository == "a/tied", "a tie is broken by name"
    assert pick.commit == SHA and pick.lockfiles == ("Cargo.lock",) and pick.licence == "MIT"
    assert [(p.repository, p.reason.split(" ")[0]) for p in pick.passed_over] == [
        ("big/proprietary", "no"),
        ("big/no-lock", "no"),
    ]


def test_a_commit_after_the_cutoff_is_never_the_pin_and_a_changed_licence_fails() -> None:
    gh = FakeGitHub(
        [repo("x/late", 5000), repo("y/relicensed", 4000)],
        {"x/late": [f"{SHA}@2025-01-01T00:00:00Z"], "y/relicensed": [f"{SHA}@2024-06-01T00:00:00Z"]},
        {
            ("y/relicensed", SHA, "Cargo.lock"): b"lock",
            ("y/relicensed", SHA, "LICENSE"): b"MIT License",
            ("y/relicensed", "main", "LICENSE"): b"Business Source License 1.1",
        },
    )
    with pytest.raises(LookupError):
        products.select(RULE, CUTOFF, 1000, OSI, gh, max_pages=1)  # type: ignore[arg-type]
    item = repo("x/late", 5000)
    _, reason = products.check_candidate(item, RULE, CUTOFF, 1000, OSI, gh)  # type: ignore[arg-type]
    assert reason == "no commit on the default branch before the cutoff"
    _, reason = products.check_candidate(repo("y/relicensed", 4000), RULE, CUTOFF, 1000, OSI, gh)  # type: ignore[arg-type]
    assert reason == "the licence file changed after the pin"


def test_the_image_rule_takes_the_last_dated_tag_before_the_cutoff() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        images = [
            {"os": "linux", "architecture": "amd64", "digest": "sha256:" + "1" * 64},
            {
                "os": "linux",
                "architecture": "arm64",
                "variant": "v8",
                "digest": "sha256:" + "2" * 64,
                "last_pushed": "2024-12-24T21:34:21Z",
            },
        ]
        results = [
            {"name": "bookworm-20250113-slim", "digest": "sha256:" + "9" * 64, "images": images},
            {"name": "bookworm-20241223-slim", "digest": "sha256:" + "8" * 64, "images": images},
            {"name": "bookworm-20241223", "digest": "sha256:" + "7" * 64, "images": images},
            {"name": "bookworm-20241202-slim", "digest": "sha256:" + "6" * 64, "images": images},
        ]
        return httpx.Response(200, json={"results": results, "next": None})

    rule = ImageRule(
        product="door-controller-firmware",
        ecosystem="Debian",
        registry="docker.io",
        repository="library/debian",
        tag_prefix="bookworm-",
        tag_pattern=r"^bookworm-(?P<date>\d{8})-slim$",
        platform="linux/arm64",
    )
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pick = products.select_image(rule, CUTOFF, client)
    assert (pick.tag, pick.digest, pick.platform) == (
        "bookworm-20241223-slim",
        "sha256:" + "2" * 64,
        "linux/arm64/v8",
    )


def test_the_github_client_waits_out_a_spent_window_and_never_sends_a_token() -> None:
    clock = [1000.0]
    slept: list[float] = []
    answers = [
        httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1060", "x-ratelimit-limit": "10"},
        ),
        httpx.Response(
            200,
            json={"items": [{"full_name": "a/b"}]},
            headers={"x-ratelimit-remaining": "9", "x-ratelimit-limit": "10"},
        ),
    ]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answers.pop(0)

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        gh = GitHub(client, sleep=sleep, clock=lambda: clock[0])
        assert gh.repositories("language:Rust") == [{"full_name": "a/b"}]
    assert slept and slept[0] >= 60
    assert all("authorization" not in r.headers for r in seen)


def test_the_config_round_trips_through_its_writer(tmp_path: Any) -> None:
    text = products.dump_config(CONFIG)
    path = tmp_path / "products.yaml"
    path.write_text(text, encoding="utf-8")
    assert products.load_config(path) == CONFIG
    assert text.startswith(products.HEADER)


def test_stand_ins_were_read_on_one_day() -> None:
    days = {s.date_read for s in CONFIG.stand_ins}
    assert len(days) == 1
    read = {
        datetime.fromisoformat(s.read_at.replace("Z", "+00:00")).astimezone(UTC).date()
        for s in CONFIG.stand_ins
    }
    assert len(read) == 1
