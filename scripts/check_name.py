"""The fictional customer's name, checked against GLEIF and SEC EDGAR on the day.

uv run python scripts/check_name.py            # check, write results/name_check.json
uv run python scripts/check_name.py --verify   # exit 1 unless config/customer.yaml uses the chosen name

The candidates are tried in the order config/customer.yaml lists them (Velloran Systems, then Tessaly
Access, then Brannoch Systems). A candidate is taken when neither registry holds a name close to it:
GLEIF is asked for its full text search on the whole name and on the distinctive word and for its
fuzzy completions of the word, after a control search for a name it certainly holds; EDGAR's
company tickers file is read whole. A registry name matches when it holds the distinctive word, or a
word within one or two letters of it (difflib ratio 0.85 or more), so a near spelling counts as taken.

EDGAR's fair access policy asks automated clients to name themselves with a contact email. This
build sends a generic User-Agent that names the project and never an email; when EDGAR refuses
that, the refusal is recorded with its status and page title, and the check relies on GLEIF.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import httpx
import yaml

GLEIF = "https://api.gleif.org/api/v1/lei-records"
GLEIF_FUZZY = "https://api.gleif.org/api/v1/fuzzycompletions"
CONTROL = "Siemens"  # a name GLEIF certainly holds: a search that finds nothing for it is broken
EDGAR = "https://www.sec.gov/files/company_tickers.json"
USER_AGENT = "unscheduled-name-check/0.1 (+https://github.com/mekala27-45/unscheduled)"
CUSTOMER = ROOT / "config" / "customer.yaml"
RESULT = ROOT / "results" / "name_check.json"
THRESHOLD = 0.85
LEGAL_WORDS = {
    "systems",
    "system",
    "access",
    "gmbh",
    "ltd",
    "limited",
    "inc",
    "sa",
    "nv",
    "bv",
    "ag",
    "plc",
    "llc",
}


class AllNamesTaken(RuntimeError):
    """Every candidate in config/customer.yaml matched a registry name."""


@dataclass(frozen=True)
class Candidate:
    name: str
    token: str  # the distinctive word: the one a registry name must not hold


def candidates(customer: dict[str, Any]) -> list[Candidate]:
    out: list[Candidate] = []
    for name in customer["name_candidates"]:
        words = [w for w in re.findall(r"[a-z]+", str(name).lower()) if w not in LEGAL_WORDS]
        if not words:
            raise ValueError(f"{name!r} has no distinctive word to check")
        out.append(Candidate(str(name), words[0]))
    return out


def words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def close(token: str, name: str) -> bool:
    return any(
        w == token or difflib.SequenceMatcher(None, w, token).ratio() >= THRESHOLD for w in words(name)
    )


def gleif_names(record: dict[str, Any]) -> list[str]:
    entity = (record.get("attributes") or {}).get("entity") or {}
    names = [str((entity.get("legalName") or {}).get("name") or "")]
    for key in ("otherNames", "transliteratedOtherNames"):
        names.extend(str(n.get("name") or "") for n in entity.get(key) or [])
    return [n for n in names if n]


def check_gleif(candidate: Candidate, get: Callable[..., httpx.Response]) -> dict[str, Any]:
    queries: list[dict[str, Any]] = []
    matches: list[dict[str, str]] = []
    for text in dict.fromkeys([candidate.name, candidate.token]):
        response = get(GLEIF, params={"filter[fulltext]": text, "page[size]": 100})
        entry: dict[str, Any] = {"filter[fulltext]": text, "http_status": response.status_code}
        if response.status_code != 200:
            entry["error"] = response.text[:200]
            queries.append(entry)
            continue
        data = response.json()
        records = data.get("data") or []
        entry["records"] = len(records)
        entry["total"] = ((data.get("meta") or {}).get("pagination") or {}).get("total", len(records))
        queries.append(entry)
        for record in records:
            for name in gleif_names(record):
                if close(candidate.token, name):
                    matches.append({"lei": str(record.get("id", "")), "name": name})
    fuzzy = get(GLEIF_FUZZY, params={"field": "entity.legalName", "q": candidate.token})
    near: list[str] = []
    if fuzzy.status_code == 200:
        near = [str((d.get("attributes") or {}).get("value", "")) for d in fuzzy.json().get("data") or []]
        matches.extend({"lei": "", "name": n} for n in near if close(candidate.token, n))
    # Near names that are not close are counted, not kept: some are the trading names of people.
    best = max(
        (difflib.SequenceMatcher(None, w, candidate.token).ratio() for n in near for w in words(n)),
        default=0.0,
    )
    queries.append(
        {
            "fuzzycompletions": candidate.token,
            "http_status": fuzzy.status_code,
            "near_names": len(near),
            "closest_word_ratio": round(best, 3),
        }
    )
    answered = all(q["http_status"] == 200 for q in queries)
    return {
        "status": "answered" if answered else "error",
        "queries": queries,
        "matches": sorted({(m["lei"], m["name"]): m for m in matches}.values(), key=lambda m: m["name"]),
    }


def control(get: Callable[..., httpx.Response]) -> dict[str, Any]:
    """The same full text search for a name GLEIF holds, so an empty answer means no match, not a fault."""
    response = get(GLEIF, params={"filter[fulltext]": CONTROL, "page[size]": 1})
    total = 0
    if response.status_code == 200:
        total = int(((response.json().get("meta") or {}).get("pagination") or {}).get("total", 0))
    if total == 0:
        raise RuntimeError(f"GLEIF found nothing for the control name {CONTROL!r}; the search is not working")
    return {"filter[fulltext]": CONTROL, "http_status": response.status_code, "total": total}


def page_title(text: str) -> str:
    found = re.search(r"<title>(.*?)</title>", text, re.S | re.I)
    return " ".join(found.group(1).split()) if found else text[:120]


def check_edgar(candidate: Candidate, get: Callable[..., httpx.Response]) -> dict[str, Any]:
    response = get(EDGAR)
    if response.status_code != 200:
        return {
            "status": "refused",
            "http_status": response.status_code,
            "page_title": page_title(response.text),
            "note": "EDGAR refused a client that names the project and no email; GLEIF decides",
            "matches": [],
        }
    data = response.json()
    rows: Iterable[dict[str, Any]] = data.values() if isinstance(data, dict) else data
    titles = [str(r.get("title", "")) for r in rows]
    matches = [{"title": t} for t in titles if close(candidate.token, t)]
    return {"status": "answered", "http_status": 200, "companies": len(titles), "matches": matches}


def run(customer: dict[str, Any], get: Callable[..., httpx.Response]) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    gleif_control = control(get)
    edgar_cache: dict[str, Any] | None = None
    chosen: str | None = None
    for candidate in candidates(customer):
        gleif = check_gleif(candidate, get)
        if edgar_cache is None or edgar_cache["status"] != "refused":
            edgar = check_edgar(candidate, get)
            edgar_cache = edgar
        else:
            edgar = {**edgar_cache, "note": "refused earlier in this run; not asked again"}
        if gleif["status"] != "answered":
            raise RuntimeError(f"GLEIF did not answer for {candidate.name}: {gleif['queries']}")
        taken = bool(gleif["matches"] or edgar["matches"])
        checked.append(
            {
                "name": candidate.name,
                "token": candidate.token,
                "gleif": gleif,
                "edgar": edgar,
                "verdict": "taken" if taken else "clear",
            }
        )
        if not taken:
            chosen = candidate.name
            break
    if chosen is None:
        raise AllNamesTaken("every candidate name matched a registry name")
    refused = any(c["edgar"]["status"] == "refused" for c in checked)
    return {
        "date_read": date.today().isoformat(),
        "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user_agent": USER_AGENT,
        "rule": (
            "Try the candidates in order; take the first that neither GLEIF nor EDGAR holds a name "
            f"close to (the distinctive word itself, or a word with a difflib ratio of {THRESHOLD} or "
            "more). An EDGAR refusal is recorded and GLEIF decides alone."
        ),
        "gleif_control": gleif_control,
        "candidates": checked,
        "chosen": chosen,
        "renamed": chosen != customer["name_candidates"][0],
        "edgar_refused": refused,
        "relied_on": ["gleif"] if refused else ["gleif", "edgar"],
    }


def load_customer() -> dict[str, Any]:
    with CUSTOMER.open(encoding="utf-8") as handle:
        data: dict[str, Any] = yaml.safe_load(handle)
    return data


def verify() -> int:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    name = load_customer()["name"]
    if name != result["chosen"]:
        print(f"name check: config/customer.yaml names {name!r}, the check chose {result['chosen']!r}")
        return 1
    print(f"name check: {name} is the chosen name ({result['date_read']})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        return verify()
    customer = load_customer()
    with httpx.Client(timeout=60, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as http:
        result = run(customer, http.get)
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    edgar = result["candidates"][-1]["edgar"]
    print(
        f"name check: {result['chosen']} chosen; EDGAR {edgar['status']}"
        + (
            f" ({edgar['http_status']}, {edgar.get('page_title', '')})"
            if edgar["status"] == "refused"
            else ""
        )
    )
    if result["renamed"]:
        print("name check: the first candidate was taken; record the rename in DECISIONS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
