"""The unscheduled API. In step one it is a health stub so the Vercel import happens in the first hour.

Every response carries the statement. The data routes arrive at step nine, with the sync from the
release into Neon (section 12 of the Phase 1 prompt).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from unscheduled_core.statements import GHSA_ATTRIBUTION, NVD_NOTICE, STATEMENT

VERSION = "0.1.0.dev0"

app = FastAPI(
    title="unscheduled",
    version=VERSION,
    summary="Triage for the CVEs the NVD no longer analyzes.",
    description=STATEMENT,
)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": VERSION, "database": "not yet connected", "statement": STATEMENT}


@app.get("/v1/meta")
def meta() -> dict[str, Any]:
    return {
        "version": VERSION,
        "statement": STATEMENT,
        "nvd_notice": NVD_NOTICE,
        "attribution": [GHSA_ATTRIBUTION],
        "locks": {},
    }
