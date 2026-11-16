"""The fixed version of a matched component, read by code from the affected section of an advisory as
the corpus writes it (one line a package: ecosystem/name, then each range as from A fixed in B), the
same text the verifier checks a citation against. With an installed version, the lowest fix above
it; without one, the first the advisory states."""

from __future__ import annotations

import re
from collections.abc import Iterable

from unscheduled_agent.schemas import FixedVersion

FIXED = re.compile(r"fixed in ([^\s;]+)")


def version_key(version: str) -> tuple[tuple[int, str], ...]:
    return tuple((int(p), "") if p.isdigit() else (-1, p) for p in re.split(r"[.\-+_]", version) if p)


def fixed_versions(
    advisories: Iterable[tuple[str, str, str]],
    ecosystem: str,
    component: str,
    installed: str | None,
) -> list[FixedVersion]:
    """advisories: (doc_id, version, affected section text) of each advisory version known then."""
    prefix = f"{ecosystem}/{component}: "
    found: list[FixedVersion] = []
    for doc_id, version, affected in advisories:
        for line in (affected or "").split("\n"):
            if line.startswith(prefix):
                found.extend(
                    FixedVersion(version=v, source=doc_id, doc_version=version) for v in FIXED.findall(line)
                )
    if installed:
        above = sorted(
            (f for f in found if version_key(f.version) > version_key(installed)),
            key=lambda f: version_key(f.version),
        )
        return above[:1]
    return found[:1]
