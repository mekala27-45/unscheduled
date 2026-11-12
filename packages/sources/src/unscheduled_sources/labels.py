"""The status vocabulary, read from the data and registered in config/labels.yaml.

Every NVD vulnStatus value the build has seen is registered with its meaning, where the meaning was
read, and the first and last date the build saw it in an NVD answer. A value the registry does not
hold stops the NVD parse with UnregisteredStatus, so a new label (the NVD added one in April 2026)
can never be counted as if it were an old one: a person reads what it means and registers it, then
the fetch resumes from the ledger.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

HEADER = """\
# The status vocabulary: every value of the NVD vulnStatus field this build has seen, registered with
# its meaning and where that meaning was read. first_seen and last_seen are the first and the last
# day this build saw the value in an NVD CVE API answer, and cves_at_last_fetch is how many records
# carried it then; the fetcher keeps those three fields current and refuses any value not listed
# here (UnregisteredStatus), so a new label fails the fetch until a person registers it.
"""


class UnregisteredStatus(ValueError):
    """The NVD answered with a vulnStatus value config/labels.yaml does not hold."""

    def __init__(self, values: Iterable[str]) -> None:
        self.values = sorted(set(values))
        super().__init__(
            "unregistered NVD vulnStatus values: "
            + ", ".join(repr(v) for v in self.values)
            + "; read their meaning and register them in config/labels.yaml, then resume the fetch"
        )


@dataclass(frozen=True)
class Seen:
    first: date
    last: date
    count: int


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"nvd_vuln_status": {}}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    data.setdefault("nvd_vuln_status", {})
    return data


def registered(path: Path) -> frozenset[str]:
    return frozenset(load(path)["nvd_vuln_status"])


def check(values: Iterable[str | None], known: frozenset[str]) -> None:
    unknown = {v for v in values if v is not None and v not in known}
    if unknown:
        raise UnregisteredStatus(unknown)


def dump(path: Path, data: Mapping[str, Any]) -> None:
    body = yaml.safe_dump(dict(data), sort_keys=False, allow_unicode=False, width=100)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(HEADER + body, encoding="utf-8")
    tmp.replace(path)


def observe(path: Path, seen: Mapping[str, Seen]) -> dict[str, Any]:
    """Move first_seen, last_seen and the count forward for registered values; refuse others."""
    data = load(path)
    statuses: dict[str, Any] = data["nvd_vuln_status"]
    check(seen, frozenset(statuses))
    for value, s in seen.items():
        entry = statuses[value]
        first = entry.get("first_seen")
        entry["first_seen"] = min(_day(first), s.first).isoformat() if first else s.first.isoformat()
        last = entry.get("last_seen")
        entry["last_seen"] = max(_day(last), s.last).isoformat() if last else s.last.isoformat()
        entry["cves_at_last_fetch"] = s.count
    dump(path, data)
    return data


def _day(value: Any) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))
