"""The NVD CPE dictionary from the Products API 2.0 (the CPE API), one row per CPE name.

The affected product models of Phase 2 match a CVE's filer strings, and retrieve by meaning, over
the vendor and product names of the dictionary. A name the NVD created after a CVE's day 0 is often
one it created while analyzing that CVE, so the models take only names created by day 0; bronze
keeps, for every CPE name, its part, vendor and product, when the NVD created it, when it last
changed it and whether it is deprecated. The version fields, titles and references stay in the raw
pages, locked by their digests.

Paged and resumed exactly as the NVD CVE API is (unscheduled_sources.nvd): every name once by
startIndex pages of the largest size the API allows, then increments by lastModified windows of at
most 120 days. Keyless by default at the documented keyless limit; the key, when the environment
holds NVD_API_KEY, travels in the apiKey header only. A name that is not a CPE 2.3 formatted string
with one of the three parts stops the parse with UnparsableCpe, and the ledger row says which.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any, ClassVar

from unscheduled_sources.base import Context, Output, RawFile, Unit
from unscheduled_sources.contract import frame
from unscheduled_sources.nvd import Nvd
from unscheduled_sources.timeutil import parse_ts

PARTS = frozenset({"a", "o", "h"})
FIELDS = 13  # cpe, 2.3, part, vendor, product, version, update, edition, language, sw, target sw, hw, other


class UnparsableCpe(ValueError):
    """A CPE name that is not a CPE 2.3 formatted string the dictionary should hold."""


def split_cpe(name: str) -> list[str]:
    """The components of a CPE 2.3 formatted string. A backslash quotes the next character, so a
    colon after a backslash belongs to its component; the quoting is kept as written."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    for ch in name:
        if quoted:
            current.append(ch)
            quoted = False
        elif ch == "\\":
            current.append(ch)
            quoted = True
        elif ch == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    if len(parts) != FIELDS or parts[0] != "cpe" or parts[1] != "2.3" or parts[2] not in PARTS:
        raise UnparsableCpe(f"not a CPE 2.3 name of an application, system or device: {name!r}")
    return parts


def parse_cpes(body: dict[str, Any], fetched_at: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in body.get("products") or []:
        cpe = item.get("cpe") or {}
        parts = split_cpe(str(cpe.get("cpeName") or ""))
        rows.append(
            {
                "cpe_name_id": cpe.get("cpeNameId"),
                "part": parts[2],
                "vendor": parts[3],
                "product": parts[4],
                "created": parse_ts(cpe.get("created")),
                "last_modified": parse_ts(cpe.get("lastModified")),
                "deprecated": bool(cpe.get("deprecated")),
                "fetched_at": fetched_at,
            }
        )
    return rows


class Cpe(Nvd):
    source = "cpe"
    tables: ClassVar[tuple[str, ...]] = ("cpe_names",)

    def __init__(self, ctx: Context) -> None:
        super().__init__(ctx, parts=("cpes",))

    def units(self) -> Iterator[Unit]:
        yield from self._snapshot_units("cpes", self.cfg["cpes_url"], int(self.cfg["cpes_page_size"]))

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            with gzip.open(raw.path, "rb") as handle:
                body = json.loads(handle.read())
            rows = parse_cpes(body, raw.fetched_at)
            raw.rows = len(rows)
            yield "cpe_names", frame("cpe_names", rows)
