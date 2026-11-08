"""The stand in products, chosen by the rule in config/products.yaml and recorded with what was read.

For each ecosystem the rule walks GitHub's repositories in that ecosystem's languages, most stars
first, ties broken by name, and keeps the first one that passes every test:

1. created before the cutoff, not a fork, not archived, at least the minimum stars
2. a licence GitHub detects whose SPDX id the SPDX licence list marks OSI approved
3. a commit on the default branch committed before the cutoff (the newest such commit is the pin)
4. a lockfile of the ecosystem at the repository root at the pinned commit
5. the licence file at the pin is the licence file of today, so today's detected licence held then

Every repository passed over is kept with the test it failed, so the choice can be checked by hand.
The firmware image is the last dated Debian slim tag before the cutoff, pinned by the digest of the
platform manifest the controllers run.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, date, datetime
from typing import Any

import httpx
from unscheduled_core.model import StrictModel

from unscheduled_match.github import GitHub

SPDX_LICENSES = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
DOCKER_HUB = "https://hub.docker.com/v2"
LICENCE_FILES = (
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
    "LICENCE.md",
    "COPYING",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "LICENSE_MIT",
    "LICENSE-APACHE-2.0",
    "UNLICENSE",
    "LICENSE.rst",
)


class EcosystemRule(StrictModel):
    product: str
    ecosystem: str  # OSV name: npm, PyPI, Go, Maven, crates.io
    languages: tuple[str, ...]
    lockfiles: tuple[str, ...]
    manifests: tuple[str, ...] = ()


class ImageRule(StrictModel):
    product: str
    ecosystem: str
    registry: str
    repository: str  # namespace/name on Docker Hub, library/debian for an official image
    tag_prefix: str  # narrows the tag listing; the pattern decides
    tag_pattern: str  # a regular expression with a named group `date` (YYYYMMDD)
    platform: str
    mirrors: tuple[str, ...] = ()


class Rule(StrictModel):
    cutoff: str  # RFC 3339, UTC
    min_stars: int
    statement: str


class PassedOver(StrictModel):
    repository: str
    stars: int
    reason: str


class StandIn(StrictModel):
    product: str
    ecosystem: str
    kind: str  # repository or image
    repository: str | None = None
    url: str | None = None
    default_branch: str | None = None
    commit: str | None = None
    commit_date: str | None = None
    licence: str | None = None
    licence_file: str | None = None
    licence_file_sha256: str | None = None
    stars: int | None = None
    lockfiles: tuple[str, ...] = ()
    image: str | None = None
    tag: str | None = None
    index_digest: str | None = None
    digest: str | None = None
    platform: str | None = None
    pushed: str | None = None
    mirrors: tuple[str, ...] = ()
    scope: str
    date_read: str
    read_at: str
    passed_over: tuple[PassedOver, ...] = ()


class OsiList(StrictModel):
    version: str
    approved: frozenset[str]
    read_at: str


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_date() -> str:
    return date.today().isoformat()


def read_osi(client: httpx.Client) -> OsiList:
    response = client.get(SPDX_LICENSES)
    response.raise_for_status()
    data = response.json()
    approved = frozenset(lic["licenseId"] for lic in data["licenses"] if lic.get("isOsiApproved"))
    return OsiList(version=str(data.get("licenseListVersion", "")), approved=approved, read_at=utc_now())


def parse_github_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def _normalized_licence(text: bytes) -> str:
    lines = text.decode("utf-8", errors="replace").splitlines()
    kept = [line for line in lines if "copyright" not in line.lower()]
    return " ".join(" ".join(kept).split())


def licence_at(gh: GitHub, repo: str, ref: str) -> tuple[str, bytes] | None:
    for name in LICENCE_FILES:
        body = gh.raw(repo, ref, name)
        if body is not None:
            return name, body
    return None


def check_candidate(
    item: dict[str, Any],
    rule: EcosystemRule,
    cutoff: datetime,
    min_stars: int,
    osi: OsiList,
    gh: GitHub,
) -> tuple[StandIn | None, str | None]:
    """The stand in this repository would be, or the reason it fails the rule."""
    repo = str(item["full_name"])
    stars = int(item.get("stargazers_count", 0))
    if item.get("fork"):
        return None, "a fork"
    if item.get("archived"):
        return None, "archived"
    if stars < min_stars:
        return None, f"{stars} stars, under {min_stars}"
    if parse_github_time(str(item["created_at"])) >= cutoff:
        return None, "created after the cutoff"
    licence = (item.get("license") or {}).get("spdx_id")
    if not licence or licence == "NOASSERTION":
        return None, "no licence GitHub can name"
    if licence not in osi.approved:
        return None, f"licence {licence} is not OSI approved"
    commits = gh.commits_before(repo, cutoff.date().isoformat())
    before = [c for c in commits if parse_github_time(str(c["commit"]["committer"]["date"])) < cutoff]
    if not before:
        return None, "no commit on the default branch before the cutoff"
    pin = before[0]
    sha = str(pin["sha"])
    committed = parse_github_time(str(pin["commit"]["committer"]["date"]))
    present = tuple(name for name in rule.lockfiles if gh.raw_exists(repo, sha, name))
    if not present:
        return None, f"no root lockfile ({', '.join(rule.lockfiles)}) at the pinned commit {sha[:12]}"
    then = licence_at(gh, repo, sha)
    if then is None:
        return None, f"no licence file at the pinned commit {sha[:12]}"
    branch = str(item.get("default_branch") or "main")
    now = licence_at(gh, repo, branch)
    if now is None or _normalized_licence(now[1]) != _normalized_licence(then[1]):
        return None, "the licence file changed after the pin"
    return (
        StandIn(
            product=rule.product,
            ecosystem=rule.ecosystem,
            kind="repository",
            repository=repo,
            url=str(item.get("html_url") or f"https://github.com/{repo}"),
            default_branch=branch,
            commit=sha,
            commit_date=committed.strftime("%Y-%m-%dT%H:%M:%SZ"),
            licence=licence,
            licence_file=then[0],
            licence_file_sha256=hashlib.sha256(then[1]).hexdigest(),
            stars=stars,
            lockfiles=present,
            scope=scope_note(rule, present, tuple(m for m in rule.manifests if gh.raw_exists(repo, sha, m))),
            date_read=local_date(),
            read_at=utc_now(),
        ),
        None,
    )


def scope_note(rule: EcosystemRule, present: tuple[str, ...], manifests: tuple[str, ...] = ()) -> str:
    """What Syft reads for this stand in: the root lockfiles found and the manifests that exist."""
    files = ", ".join([*present, *(m for m in manifests if m not in present)])
    note = f"Syft reads the root files {files} at the pinned commit"
    if rule.ecosystem == "Maven" and "gradle.lockfile" not in present:
        note += (
            " and the module poms the root pom declares; a pom declares dependencies and is not a lock, "
            "so only declared dependencies with versions the poms resolve are seen, with no transitive "
            "resolution"
        )
    return note


def search_query(language: str, rule_stars: int, cutoff: datetime) -> str:
    return f"language:{language} stars:>={rule_stars} archived:false created:<{cutoff.date().isoformat()}"


def select(
    rule: EcosystemRule,
    cutoff: datetime,
    min_stars: int,
    osi: OsiList,
    gh: GitHub,
    *,
    max_pages: int = 3,
) -> StandIn:
    """The most starred repository of the ecosystem that passes the rule, with the trail of the rest."""
    passed: list[PassedOver] = []
    seen: set[str] = set()
    for page in range(1, max_pages + 1):
        items: list[dict[str, Any]] = []
        for language in rule.languages:
            items.extend(gh.repositories(search_query(language, min_stars, cutoff), page=page))
        items = [i for i in items if str(i["full_name"]) not in seen]
        items.sort(key=lambda i: (-int(i.get("stargazers_count", 0)), str(i["full_name"]).lower()))
        for item in items:
            seen.add(str(item["full_name"]))
            stand_in, reason = check_candidate(item, rule, cutoff, min_stars, osi, gh)
            if stand_in is not None:
                return stand_in.model_copy(update={"passed_over": tuple(passed)})
            passed.append(
                PassedOver(
                    repository=str(item["full_name"]),
                    stars=int(item.get("stargazers_count", 0)),
                    reason=reason or "",
                )
            )
    raise LookupError(f"no {rule.ecosystem} repository passed the rule in {max_pages} pages")


def select_image(rule: ImageRule, cutoff: datetime, client: httpx.Client) -> StandIn:
    """The last dated tag before the cutoff, pinned by the digest of the rule's platform manifest."""
    pattern = re.compile(rule.tag_pattern)
    best: tuple[str, dict[str, Any]] | None = None
    namespace, _, name = rule.repository.partition("/")
    url: str | None = (
        f"{DOCKER_HUB}/namespaces/{namespace}/repositories/{name}/tags?page_size=100&name={rule.tag_prefix}"
    )
    while url:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
        for tag in data.get("results", []):
            found = pattern.match(str(tag.get("name", "")))
            if not found:
                continue
            stamp = found.group("date")
            tag_day = datetime.strptime(stamp, "%Y%m%d").replace(tzinfo=UTC)
            if tag_day >= cutoff:
                continue
            if best is None or stamp > best[0]:
                best = (stamp, tag)
        url = data.get("next")
    if best is None:
        raise LookupError(f"no {rule.repository} tag matches {rule.tag_pattern} before the cutoff")
    tag = best[1]
    os_name, _, arch = rule.platform.partition("/")
    images = [i for i in tag.get("images", []) if i.get("os") == os_name and i.get("architecture") == arch]
    if not images:
        raise LookupError(f"{tag['name']} has no {rule.platform} image")
    image = images[0]
    return StandIn(
        product=rule.product,
        ecosystem=rule.ecosystem,
        kind="image",
        image=f"{rule.registry}/{rule.repository}",
        tag=str(tag["name"]),
        index_digest=str(tag.get("digest")),
        digest=str(image["digest"]),
        platform=f"{rule.platform}" + (f"/{image['variant']}" if image.get("variant") else ""),
        pushed=str(image.get("last_pushed") or tag.get("last_updated")),
        mirrors=rule.mirrors,
        scope="Syft reads every package the image's dpkg database lists, pulled by the platform digest",
        date_read=local_date(),
        read_at=utc_now(),
    )


class ProductsConfig(StrictModel):
    rule: Rule
    ecosystems: tuple[EcosystemRule, ...]
    image: ImageRule
    osi_list: dict[str, str] | None = None
    stand_ins: tuple[StandIn, ...] = ()

    def stand_in(self, product: str) -> StandIn:
        for item in self.stand_ins:
            if item.product == product:
                return item
        raise KeyError(f"no stand in recorded for {product}")


HEADER = """\
# The stand in products of the fictional customer in config/customer.yaml.
# Public open source repositories, and one public image, stand in for its six products; none of
# them is the customer's code and every page that shows one names it as a stand in.
# The rule below is fixed. `uv run python scripts/make_sboms.py select` applies it and rewrites
# this file with stand_ins as read on the day, each with the repositories passed over and why.
# Edit the rule, never the picks.
"""


def load_config(path: Any) -> ProductsConfig:
    import yaml

    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return ProductsConfig.model_validate(data)


def dump_config(config: ProductsConfig) -> str:
    import yaml

    data = config.model_dump(mode="json", exclude_none=True)
    for item in data.get("stand_ins", []):
        for key in ("mirrors", "lockfiles"):
            if item.get(key) == []:
                del item[key]
    body = yaml.safe_dump(data, sort_keys=False, width=100, allow_unicode=False)
    return HEADER + body
