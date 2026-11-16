"""The forty development drafts Ajay labels for the judge (evaluation/phase3_plan.yaml, judge).

The drafts are a committed file, evaluation/judge/drafts.json, drawn by scripts/draw_judge_drafts.py
from the development evals, half from the floor and half from the models, each without the
configuration that wrote it: evaluation/judge_key.json holds that, outside the folder the API image
copies, and only the scorer opens it. A label says whether a draft is usable, with a short reason.
It is recorded in judge_label only with the approver's token, as a decision is, and only on the hash
of the draft as the file holds it; labels are only ever added, and the newest label of a draft is
the one that counts. Until the development evals have run, the file does not exist and there is
nothing to label.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from unscheduled_agent import approvals

from unscheduled_api.problems import ProblemError

DRAFTS = Path("evaluation") / "judge" / "drafts.json"
WAITING = (
    "the forty drafts come with the development evals of step 12; until they run there is nothing to label"
)
NO_TOKEN = "a label needs the approver's token; nothing was recorded"
OTHER_HASH = "the hash is not the hash of this draft as it stands; nothing was recorded"


def drafts(root: Path) -> list[dict[str, Any]]:
    """The drafts to label, in the order of the file; none before the development evals."""
    path = root / DRAFTS
    if not path.exists():
        return []
    found = json.loads(path.read_text(encoding="utf-8"))
    return [dict(d) for d in found.get("drafts") or []]


def _latest(conn: sa.Connection, schema: str) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        sa.text(
            "select distinct on (draft_id) draft_id, sha256, usable, reason, labelled_by, labelled_at "
            f'from "{schema}".judge_label order by draft_id, labelled_at desc, id desc'
        )
    ).mappings()
    return {str(r["draft_id"]): dict(r) for r in rows}


def _item(draft: dict[str, Any], label: dict[str, Any] | None) -> dict[str, Any]:
    counts = label is not None and label["sha256"] == draft["sha256"]
    return {
        "draft_id": draft["draft_id"],
        "kind": draft["kind"],
        "cve_id": draft["cve_id"],
        "as_of": draft["as_of"],
        "sha256": draft["sha256"],
        "draft": draft["draft"],
        "label": (
            {
                "usable": bool(label["usable"]),
                "reason": str(label["reason"]),
                "by": str(label["labelled_by"]),
                "at": label["labelled_at"],
            }
            if counts and label is not None
            else None
        ),
    }


def listing(conn: sa.Connection, schema: str, root: Path) -> dict[str, Any]:
    """Every draft to label with the label that counts, if any."""
    found = drafts(root)
    latest = _latest(conn, schema) if found else {}
    items = [_item(d, latest.get(d["draft_id"])) for d in found]
    return {
        "drafts": items,
        "labelled": sum(1 for i in items if i["label"] is not None),
        "total": len(items),
        "note": None if found else WAITING,
    }


def record(
    conn: sa.Connection,
    schema: str,
    root: Path,
    *,
    draft_id: str,
    sha256: str,
    usable: bool,
    reason: str,
    by: str,
    token: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """A label on one draft, named by its hash, and the counts after it. Without the token, or on another
    hash, nothing is kept."""
    if not approvals.token_ok(token):
        raise ProblemError("label-refused", NO_TOKEN)
    found = {d["draft_id"]: d for d in drafts(root)}
    draft = found.get(draft_id)
    if draft is None:
        raise ProblemError(
            "not-found", f"there is no draft {draft_id} to label", context={"draft_id": draft_id}
        )
    if draft["sha256"] != sha256:
        raise ProblemError("label-refused", OTHER_HASH)
    conn.execute(
        sa.text(
            f'insert into "{schema}".judge_label (draft_id, sha256, usable, reason, labelled_by, labelled_at) '
            "values (:draft_id, :sha256, :usable, :reason, :by, :at)"
        ),
        {
            "draft_id": draft_id,
            "sha256": sha256,
            "usable": usable,
            "reason": reason,
            "by": by,
            "at": now or datetime.now(UTC),
        },
    )
    found_now = listing(conn, schema, root)
    item = next(i for i in found_now["drafts"] if i["draft_id"] == draft_id)
    return {"draft": item, "labelled": found_now["labelled"], "total": found_now["total"]}
