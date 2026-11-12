"""The vector check: what parses, what the base is, and which stored scores agree (rule Q02)."""

from __future__ import annotations

from unscheduled_lake.cvss import band, check, scores_agree

VULDB_STYLE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P"


def test_a_threat_metric_gives_two_scores_and_either_agrees() -> None:
    result = check("4.0", VULDB_STYLE)
    assert result.parses
    assert result.base_vector == VULDB_STYLE.removesuffix("/E:P")
    assert result.vector_score is not None and result.base_score is not None
    assert result.vector_score < result.base_score
    assert scores_agree(result.base_score, result.vector_score, result.base_score)
    assert scores_agree(result.vector_score, result.vector_score, result.base_score)
    assert not scores_agree(9.9, result.vector_score, result.base_score)


def test_a_cvss3_base_score_ignores_the_environmental_metrics() -> None:
    written = "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:L/CR:H/IR:H/AR:H"
    result = check("3.0", written)
    assert result.parses
    assert result.base_score == result.vector_score == 5.9
    assert not scores_agree(7.1, result.vector_score, result.base_score)


def test_a_vector_that_does_not_parse_is_reported_not_repaired() -> None:
    result = check("3.1", "CVSS:3.1/AV:X/AC:L")
    assert not result.parses
    assert result.error
    assert result.base_score is None


def test_an_absent_score_agrees_and_the_bands_follow_the_specification() -> None:
    assert scores_agree(None, 5.0)
    assert scores_agree(5.0, None)
    assert band(0.0) == "None"
    assert band(3.9) == "Low"
    assert band(9.0) == "Critical"
    assert band(6.9, "2.0") == "Medium"
