"""The statement that appears on every surface.

Written once here. Every page of the site, every API response, every rendered document and the
README read it from this module or from its exported copy, and a gate checks each surface for it
verbatim.
"""

from __future__ import annotations

PROJECT = "unscheduled"

STATEMENT = (
    "unscheduled is a portfolio demonstration. Its customer is fictional, and public open source "
    "repositories stand in for the products of that customer. It is not affiliated with NIST, the NVD, "
    "CISA, FIRST, MITRE, ENISA or any vendor named in the data, and its values are not official "
    "scores. It is not for security, legal or regulatory decisions. It never files a report and never "
    "applies a patch: a person approves every plan and files every report. This product uses data from "
    "the NVD API but is not endorsed or certified by the NVD."
)

NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."

GHSA_ATTRIBUTION = (
    "Advisory data from the GitHub Advisory Database, licensed under CC BY 4.0 "
    "(https://github.com/github/advisory-database)."
)


def statement_markdown() -> str:
    return f"> {STATEMENT}"


def statement_payload() -> dict[str, str]:
    return {"statement": STATEMENT}


def contains_statement(text: str) -> bool:
    flat = " ".join(text.split())
    return " ".join(STATEMENT.split()) in flat
