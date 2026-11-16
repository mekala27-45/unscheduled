"""The prompts as versioned files, and the context each drafting node packs for a model.

A prompt is a file under prompts/: a header between two lines of three dashes (its id, version,
node, schema, the token limit of its answer and the token budget of its context), then the text the
model reads. Every call records the version and the sha256 of the whole file, and
config/agent_points.yaml freezes both before the shadow window is recorded, so a change to a prompt
after that is a new version and a new development record.

Context packing, the same for every node: the typed state first, then the retrieved chunks in rank
order, each fenced between an UNTRUSTED START line and an UNTRUSTED END line with its chunk id, its
document and version and the time it became known, until the budget is spent. A chunk that would
pass the budget is left out whole and counted, never cut. Any line of a chunk that imitates a fence
is defused before it is fenced, so a chunk cannot close its own fence. The budget is counted in
estimated tokens, four bytes of UTF-8 a token, because every provider counts with its own tokenizer.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from unscheduled_core import paths

from unscheduled_agent.router import Prompt
from unscheduled_agent.schemas import Facts

START = "UNTRUSTED START"
END = "UNTRUSTED END"
_FENCE = re.compile(r"UNTRUSTED\s+(START|END)", re.IGNORECASE)
_HEADER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)


def folder(root: Path | None = None) -> Path:
    return (root or paths.root()) / "prompts"


def load(prompt_id: str, root: Path | None = None) -> Prompt:
    path = folder(root) / f"{prompt_id}.md"
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    match = _HEADER.match(text)
    if match is None:
        raise ValueError(f"{path}: a prompt file starts with a header between two --- lines")
    header = yaml.safe_load(match.group(1))
    if str(header.get("id")) != prompt_id:
        raise ValueError(f"{path}: the header names {header.get('id')!r}, not {prompt_id!r}")
    return Prompt(
        id=prompt_id,
        version=str(header["version"]),
        text=text[match.end() :].strip() + "\n",
        file_sha256=hashlib.sha256(raw).hexdigest(),
        max_tokens=int(header["max_tokens"]),
        context_tokens=int(header["context_tokens"]),
    )


def versions(root: Path | None = None) -> dict[str, dict[str, str]]:
    """Every prompt with its version and file hash, as config/agent_points.yaml freezes them."""
    out: dict[str, dict[str, str]] = {}
    for path in sorted(folder(root).glob("*.md")):
        prompt = load(path.stem, root)
        out[prompt.id] = {"version": prompt.version, "sha256": prompt.sha256}
    return out


def estimate(text: str) -> int:
    return -(-len(text.encode("utf-8")) // 4)


def defuse(text: str) -> str:
    return _FENCE.sub(lambda m: f"untrusted-{m.group(1).lower()}", text)


def fence(chunk_id: str, doc_id: str, version: str, known_from: str, text: str) -> str:
    label = f"chunk {chunk_id} from {doc_id} version {version}, known from {known_from}"
    return f"{START} {label}\n{defuse(text)}\n{END} {chunk_id}"


@dataclass(frozen=True)
class Packed:
    inputs: dict[str, Any]
    included: list[str]
    left_out: list[str]
    tokens: int


def pack(facts: Facts, budget: int, examples: list[dict[str, Any]] | None = None) -> Packed:
    """The inputs of one drafting call: the typed state, then fenced evidence in rank order."""
    state = facts.model_dump(mode="json", exclude={"evidence"})
    used = estimate(str(state)) + sum(estimate(str(e)) for e in examples or [])
    fenced: list[str] = []
    included: list[str] = []
    left_out: list[str] = []
    for item in sorted(facts.evidence, key=lambda e: -e.score):
        block = fence(item.chunk_id, item.doc_id, item.version, item.known_from.isoformat(), item.text)
        cost = estimate(block)
        if used + cost > budget:
            left_out.append(item.chunk_id)
            continue
        fenced.append(block)
        included.append(item.chunk_id)
        used += cost
    inputs: dict[str, Any] = {"typed_state": state, "evidence": fenced}
    if examples:
        inputs["examples"] = examples
    return Packed(inputs, included, left_out, used)


def header(prompt_id: str, root: Path | None = None) -> dict[str, Any]:
    text = (folder(root) / f"{prompt_id}.md").read_text(encoding="utf-8")
    match = _HEADER.match(text)
    return dict(yaml.safe_load(match.group(1))) if match else {}
