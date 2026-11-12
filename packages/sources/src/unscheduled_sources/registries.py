"""The registries for the fictional name check: GLEIF LEI records and SEC EDGAR company tickers.

GLEIF is searched by legal name, exactly and in full text, for every name in config/sources.yaml.
EDGAR's company_tickers.json is requested with the project User-Agent and no contact address; the
SEC asks automated clients for a contact address and may refuse one without it, and a refusal is
recorded in the ledger as a result (status refused), never retried and never a crash. Nothing here
goes to bronze: the answers are locked by digest and the matches are counted in the ledger note,
which name_check reads back.
"""

from __future__ import annotations

import gzip
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from unscheduled_sources import ledger
from unscheduled_sources.base import Fetcher, Output, RawFile, Unit
from unscheduled_sources.locks import content_digest


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def gleif_matches(body: dict[str, Any], name: str) -> list[str]:
    """Legal names of the LEI records whose legal name contains the searched name."""
    wanted = name.casefold()
    names = []
    for record in body.get("data") or []:
        legal = (((record.get("attributes") or {}).get("entity") or {}).get("legalName") or {}).get("name")
        if legal and wanted in str(legal).casefold():
            names.append(str(legal))
    return sorted(set(names))


def edgar_matches(body: dict[str, Any], name: str) -> list[str]:
    wanted = name.casefold()
    return sorted(
        {str(v.get("title")) for v in body.values() if wanted in str(v.get("title", "")).casefold()}
    )


class Registries(Fetcher):
    source = "registries"
    tables: ClassVar[tuple[str, ...]] = ()
    refusal_is_result = True

    def units(self) -> Iterator[Unit]:
        day = self.ctx.today.isoformat()
        for name in self.cfg["names"]:
            for mode in ("legalName", "fulltext"):
                yield Unit(
                    f"gleif-{mode}-{slug(name)}-{day}",
                    f"gleif {mode} {name} {day}",
                    {"kind": "gleif", "mode": mode, "name": name},
                )
        yield Unit(f"edgar-{day}", f"edgar company_tickers {day}", {"kind": "edgar"})

    def fetch(self, unit: Unit) -> list[RawFile]:
        folder = self.raw_root / unit.name
        with self.ctx.http_factory(attempts=4) as http:
            if unit.meta["kind"] == "gleif":
                key = "filter[entity.legalName]" if unit.meta["mode"] == "legalName" else "filter[fulltext]"
                response = http.get(self.cfg["gleif"], params={key: unit.meta["name"], "page[size]": 100})
                path = folder / "answer.json.gz"
                path.parent.mkdir(parents=True, exist_ok=True)
                with gzip.GzipFile(path, "wb", mtime=0) as handle:
                    handle.write(response.content)
                sha, size = content_digest(path)
                meta = {"kind": "gleif", "name": unit.meta["name"]}
                return [
                    RawFile(
                        unit.name,
                        "answer.json.gz",
                        response.url,
                        path,
                        sha,
                        size,
                        response.fetched_at,
                        meta=meta,
                    )
                ]
            got = http.download(self.cfg["edgar"], folder / "company_tickers.json")
            return [
                RawFile(
                    unit.name,
                    "company_tickers.json",
                    got.url,
                    got.path,
                    got.sha256,
                    got.size,
                    got.fetched_at,
                    meta={"kind": "edgar"},
                )
            ]

    def parse(self, raws: list[RawFile]) -> Iterator[Output]:
        for raw in raws:
            if raw.meta.get("kind") == "gleif" or raw.file == "answer.json.gz":
                with gzip.open(raw.path, "rb") as handle:
                    body = json.loads(handle.read())
                name = str(raw.meta.get("name") or "")
                found = gleif_matches(body, name)
                raw.rows = len(body.get("data") or [])
                raw.meta["note"] = (
                    f"gleif answered {raw.rows} records, {len(found)} with the name in the legal name"
                )
            else:
                body = json.loads(raw.path.read_bytes())
                found = [m for n in self.cfg["names"] for m in edgar_matches(body, str(n))]
                raw.rows = len(body)
                raw.meta["note"] = (
                    f"edgar answered {raw.rows} companies, {len(found)} with the name in the title"
                )
        return iter(())

    def finish(self) -> None:
        return None


def name_check(locks_dir: Path) -> dict[str, dict[str, str]]:
    """The last answer of each registry query: its status and note, read back from the ledger."""
    latest: dict[str, dict[str, str]] = {}
    for row in ledger.rows(locks_dir, Registries.source):
        query = " ".join(row.window.split(" ")[:-1])
        latest[query] = {"status": row.status, "note": row.note or "", "window": row.window}
    return latest
