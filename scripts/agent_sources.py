"""The sources of the triage graph over the lake build's work database and the corpus, each answer as
known at the run time: what the agent evals of step 12 run on.

- description: the as-of engine over the CVE List record facts the corpus is labelled with.
- match: a finding of the six stand in products that names the CVE (product, package, installed
  version); else the first affected package of the newest advisory known by then that names it;
  else the product of its KEV entry.
- fixed versions: read from the affected section of that advisory's version known by then, the same
  text the verifier checks a citation against; with an installed version, the lowest fix above it.
- kev: the listing by then, with the name and version of the KEV text known by then.
- exploits: the first Metasploit module or Nuclei template seen by then.
- epss: the as-of engine over the lake's facts.
- predictions: none. The Phase 2 predictions were made in one batch in November 2026, after every
  listing the evals read, so none was known at a run time.
- retrieve: the configuration config/retrieval.yaml froze, through a search function the caller gives.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import polars as pl
from unscheduled_agent import verify
from unscheduled_agent.graph import Match
from unscheduled_agent.schemas import Evidence, ExploitSignal, FixedVersion, KevListing
from unscheduled_lake.engine import Engine
from unscheduled_retrieval import corpus

FIXED = re.compile(r"fixed in ([^\s;]+)")
Retrieve = Callable[[str, datetime, int], list[Evidence]]


def version_key(version: str) -> tuple[tuple[int, str], ...]:
    return tuple((int(p), "") if p.isdigit() else (-1, p) for p in re.split(r"[.\-+_]", version) if p)


class LakeSources:
    def __init__(self, work_db: Path, corpus_dir: Path, findings: Path, retrieve: Retrieve) -> None:
        self.con = corpus.connect(str(work_db))
        corpus.description_facts(self.con)
        self.descriptions = Engine(self.con, facts=corpus.DESCRIPTION_FACTS)
        self.facts = Engine(self.con)
        documents = pl.read_parquet(corpus_dir / "documents.parquet")
        self.docs = verify.FrameDocuments(documents)
        self.by_cve: dict[str, list[str]] = {}
        for r in documents.select("doc_id", "source", "cve_ids").unique().iter_rows(named=True):
            if r["source"] in ("ghsa", "osv"):
                for cve in r["cve_ids"] or []:
                    self.by_cve.setdefault(cve, []).append(r["doc_id"])
        self.findings = pl.read_parquet(findings)
        self.kev_events = {
            r["cve_id"]: r
            for r in self.con.sql("select cve_id, listed_at from silver.kev_events")
            .pl()
            .iter_rows(named=True)
        }
        self.exploit = {
            r["cve_id"]: r
            for r in self.con.sql(
                "select cve_id, metasploit_first_seen, nuclei_first_seen from silver.exploit_first_seen"
            )
            .pl()
            .iter_rows(named=True)
        }
        self.search = retrieve

    @property
    def documents(self) -> verify.Documents:
        return self.docs

    def _known(self, doc_id: str, at: datetime) -> verify.DocVersion | None:
        known = [
            v
            for v in self.docs.versions(doc_id)
            if v.known_from <= at and (v.withdrawn is None or v.withdrawn > at)
        ]
        return known[-1] if known else None

    def description(self, cve_id: str, at: datetime) -> str | None:
        facts = self.descriptions.asof([cve_id], at)
        found = facts.filter(pl.col("field") == "description").get_column("value").to_list()
        return str(found[0]) if found else None

    def _advisory(self, cve_id: str, at: datetime) -> verify.DocVersion | None:
        known = [v for d in sorted(self.by_cve.get(cve_id, [])) if (v := self._known(d, at)) is not None]
        return max(known, key=lambda v: (v.known_from, v.doc_id)) if known else None

    def match(self, cve_id: str, at: datetime) -> Match | None:
        rows = self.findings.filter(
            pl.col("cve_aliases").list.contains(cve_id) | pl.col("upstream_cves").list.contains(cve_id)
        ).sort(["product_id", "package"])
        if rows.height:
            r = rows.row(0, named=True)
            return {
                "product": r["product_id"],
                "component": r["package"],
                "ecosystem": r["ecosystem"],
                "installed_version": r["version"],
            }
        advisory = self._advisory(cve_id, at)
        if advisory is not None:
            first = (advisory.sections.get("affected") or "").split("\n")[0]
            if ":" in first:
                ecosystem, _, rest = first.partition("/")
                return {"component": rest.split(": ")[0], "ecosystem": ecosystem}
        kev = self.kev(cve_id, at)
        if kev is not None and kev.product:
            return {"component": kev.product}
        return None

    def fixed_versions(self, cve_id: str, match: Match | None, at: datetime) -> list[FixedVersion]:
        if not match or "ecosystem" not in match:
            return []
        prefix = f"{match['ecosystem']}/{match['component']}: "
        found: list[FixedVersion] = []
        for doc_id in sorted(self.by_cve.get(cve_id, [])):
            version = self._known(doc_id, at)
            if version is None:
                continue
            for line in (version.sections.get("affected") or "").split("\n"):
                if line.startswith(prefix):
                    for fixed in FIXED.findall(line):
                        found.append(FixedVersion(version=fixed, source=doc_id, doc_version=version.version))
        installed = match.get("installed_version")
        if installed:
            above = [f for f in found if version_key(f.version) > version_key(installed)]
            above.sort(key=lambda f: version_key(f.version))
            return above[:1]
        return found[:1]

    def predictions(self, cve_id: str, at: datetime) -> dict[str, Any]:
        return {}

    def kev(self, cve_id: str, at: datetime) -> KevListing | None:
        event = self.kev_events.get(cve_id)
        if event is None or event["listed_at"] is None or event["listed_at"] > at:
            return None
        text = self._known(f"kev:{cve_id}", at)
        entry = (text.sections.get("entry") or "") if text else ""
        name = entry.split("\n")[0] if entry else None
        product = next(
            (line.removeprefix("Product: ") for line in entry.split("\n") if line.startswith("Product: ")),
            None,
        )
        added = next(
            (
                line.removeprefix("Added to KEV on ")
                for line in entry.split("\n")
                if line.startswith("Added to KEV on ")
            ),
            None,
        )
        return KevListing(
            source=f"kev:{cve_id}",
            doc_version=text.version if text else None,
            listed_at=event["listed_at"],
            date_added=datetime.fromisoformat(added).date() if added else None,
            vulnerability_name=name,
            product=product,
        )

    def exploits(self, cve_id: str, at: datetime) -> list[ExploitSignal]:
        row = self.exploit.get(cve_id)
        if row is None:
            return []
        out = [
            ExploitSignal(source=name, first_seen=row[column])
            for name, column in (("metasploit", "metasploit_first_seen"), ("nuclei", "nuclei_first_seen"))
            if row[column] is not None and row[column] <= at
        ]
        return sorted(out, key=lambda s: s.first_seen)

    def epss(self, cve_id: str, at: datetime) -> float | None:
        facts = self.facts.asof([cve_id], at).filter(pl.col("field") == "epss")
        values = facts.get_column("value").to_list()
        return float(values[0]) if values else None

    def retrieve(self, query: str, at: datetime, k: int) -> list[Evidence]:
        return self.search(query, at, k)


def listings(work_db_con: Any) -> pl.DataFrame:
    """The KEV listings of the development and shadow windows, listed after their CVE was published."""
    frame: pl.DataFrame = work_db_con.sql(
        "select k.cve_id, k.listed_at, s.split_window as window, s.published "
        "from silver.kev_events as k join intermediate.int_cve_spine as s using (cve_id) "
        "where s.state = 'PUBLISHED' and s.split_window in ('development', 'shadow') and k.listed_at > s.published "
        "order by k.cve_id"
    ).pl()
    return frame


def summary(sources: LakeSources) -> str:
    return json.dumps({"documents": len(sources.docs.by_id), "kev": len(sources.kev_events)})
