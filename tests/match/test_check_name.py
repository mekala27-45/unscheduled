"""The fictional name, checked against GLEIF and EDGAR, with the fallbacks in order."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from scripts import check_name
from tests.match import helpers

CUSTOMER = {
    "name": "Velloran Systems",
    "name_candidates": ["Velloran Systems", "Tessaly Access", "Brannoch Systems"],
}


def lei(name: str) -> dict[str, Any]:
    return {
        "id": "529900T8BM49AURSDO55",
        "attributes": {"entity": {"legalName": {"name": name}, "otherNames": []}},
    }


def fake(
    gleif: Callable[[str], list[dict[str, Any]]], edgar: httpx.Response
) -> Callable[..., httpx.Response]:
    def get(url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        request = httpx.Request("GET", url)
        if url == check_name.EDGAR:
            return edgar
        if url == check_name.GLEIF_FUZZY:
            return httpx.Response(200, json={"data": []}, request=request)
        text = str((params or {}).get("filter[fulltext]", ""))
        if text == check_name.CONTROL:
            return httpx.Response(
                200, json={"data": [], "meta": {"pagination": {"total": 968}}}, request=request
            )
        records = gleif(text)
        return httpx.Response(
            200, json={"data": records, "meta": {"pagination": {"total": len(records)}}}, request=request
        )

    return get


REFUSED = httpx.Response(403, text="<html><title>SEC.gov | Request Rate Threshold Exceeded</title></html>")
ANSWERED = httpx.Response(200, json={"0": {"cik_str": 1, "ticker": "VELO", "title": "VELORAN SYSTEMS CORP"}})


def test_a_name_no_registry_holds_is_taken_and_an_edgar_refusal_is_recorded() -> None:
    result = check_name.run(CUSTOMER, fake(lambda text: [], REFUSED))
    assert result["chosen"] == "Velloran Systems" and not result["renamed"]
    assert result["edgar_refused"] and result["relied_on"] == ["gleif"]
    assert result["candidates"][0]["edgar"]["page_title"] == "SEC.gov | Request Rate Threshold Exceeded"


def test_a_gleif_match_moves_to_the_next_name() -> None:
    result = check_name.run(
        CUSTOMER, fake(lambda text: [lei("VELLORAN SYSTEMS BV")] if "ell" in text.lower() else [], REFUSED)
    )
    assert [c["verdict"] for c in result["candidates"]] == ["taken", "clear"]
    assert result["chosen"] == "Tessaly Access" and result["renamed"]


def test_a_near_spelling_on_edgar_counts_as_taken() -> None:
    result = check_name.run(CUSTOMER, fake(lambda text: [], ANSWERED))
    assert result["candidates"][0]["verdict"] == "taken"
    assert result["candidates"][0]["edgar"]["matches"] == [{"title": "VELORAN SYSTEMS CORP"}]


def test_all_names_taken_stops_the_build() -> None:
    with pytest.raises(check_name.AllNamesTaken):
        check_name.run(CUSTOMER, fake(lambda text: [lei(f"{text} HOLDING")], REFUSED))


def test_a_search_that_finds_nothing_for_the_control_is_not_trusted() -> None:
    def broken(url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        return httpx.Response(200, json={"data": [], "meta": {"pagination": {"total": 0}}})

    with pytest.raises(RuntimeError, match="control"):
        check_name.run(CUSTOMER, broken)


def test_the_distinctive_word_skips_the_legal_words() -> None:
    assert [c.token for c in check_name.candidates(CUSTOMER)] == ["velloran", "tessaly", "brannoch"]


def test_the_customer_file_uses_the_name_the_check_chose() -> None:
    result = json.loads((helpers.ROOT / "results" / "name_check.json").read_text(encoding="utf-8"))
    assert check_name.load_customer()["name"] == result["chosen"]
    assert result["candidates"][-1]["verdict"] == "clear"
    assert "@" not in result["user_agent"], "the User-Agent names the project, never an email"
