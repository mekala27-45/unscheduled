"""The defenses against text that tries to steer the agent, each one counted on its own (C6).

1. Normalization: untrusted text is NFKC normalized and stripped of the characters that hide text from
   a person while a model still reads it (bidirectional overrides, zero width characters, tag
   characters) and of markup that hides text (HTML comments, tags, the target of a markdown image or
   link), before it is fenced.
2. Fencing: prompts.fence puts every chunk between UNTRUSTED START and UNTRUSTED END lines it cannot
   close (step 7).
3. The injection signal: a rule set that marks a chunk that reads as an instruction to a tool or an
   assistant; with a Groq key, llama-prompt-guard-2 scores the chunk as well. A marked chunk is kept
   out of a model's context and counted. It is one signal and never the only one: a chunk it misses
   still meets the fence, the schema and the verifier.
4. The tool allowlist: each node of the graph may read only the sources its role needs (ALLOWLIST);
   a call outside it is refused and counted. A model calls no tool at all: it returns one object of
   its schema.
5. The schema: a draft that does not validate is retried once and then left to the next provider.
6. The verifier: no claim reaches a person unless its citation holds it (verify.py).
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from unscheduled_agent.graph import Match, Sources
from unscheduled_agent.schemas import Evidence, ExploitSignal, FixedVersion, KevListing
from unscheduled_agent.verify import Documents

HIDDEN = re.compile("[​‌‍⁠﻿‪‫‬‭‮⁦⁧⁨⁩\U000e0000-\U000e007f]")
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
TAG = re.compile(r"</?[A-Za-z][^>]*>")
IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
DATA_URL = re.compile(r"\b(?:data|javascript):[^\s)]+", re.IGNORECASE)

# Narrow on purpose: advisory text says apply the patch and names tokens all the time, so a rule
# fires only on the shape of an instruction to an assistant or a tool, never on a topic.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "addresses an assistant",
        re.compile(r"\b(?:assistant|ai model|language model|llm|automated (?:triage )?tools?)\s*[,:]", re.I),
    ),
    (
        "asks to ignore instructions",
        re.compile(r"\b(?:ignore|disregard|forget)\b.{0,40}\b(?:instructions?|rules|prompt)\b", re.I),
    ),
    ("asks to call a tool", re.compile(r"\b(?:call|invoke)\b.{0,30}\b(?:tool|function)\b", re.I)),
    (
        "asks to approve or file",
        re.compile(r"\b(?:approve|submit|file)\b.{0,40}\b(?:plan|warning|run|draft|now)\b", re.I),
    ),
    ("asks to apply a plan", re.compile(r"\bapply\b.{0,20}\b(?:plan|draft)\b", re.I)),
    (
        "asks to skip a step",
        re.compile(
            r"\b(?:skip (?:the|this|verification|the patch plan)|bypass the|do not (?:wait|verify|check))\b",
            re.I,
        ),
    ),
    (
        "asks for secrets",
        re.compile(
            r"\b(?:values?|contents?|print|reveal|include|show)\b.{0,40}\b(?:api[_ ]?keys?|database_url|environment variables?|secrets?|passwords?)\b",
            re.I,
        ),
    ),
    (
        "asks for the prompt",
        re.compile(r"\b(?:system prompt|your (?:instructions|prompt)|text of your instructions)\b", re.I),
    ),
    (
        "asks to change a recorded value",
        re.compile(
            r"\b(?:record|mark|set|change)\b\s+(?:its|the|this)?\s*(?:severity|cvss|score|cwe|published date)\s+(?:as|to)\b",
            re.I,
        ),
    ),
    (
        "claims a person agreed",
        re.compile(r"\b(?:reviewer|maintainer|admin)\b.{0,20}\b(?:agreed|approved|confirmed)\b", re.I),
    ),
)

# The sources each node of the graph may read.
ALLOWLIST: dict[str, frozenset[str]] = {
    "intake": frozenset({"description"}),
    "match": frozenset({"match", "fixed_versions"}),
    "fill": frozenset({"predictions"}),
    "rank": frozenset({"kev", "exploits", "epss"}),
    "retrieve": frozenset({"retrieve"}),
    "plan": frozenset(),
    "verify": frozenset({"documents"}),
    "warn": frozenset(),
    "verify_warning": frozenset({"documents"}),
}


@dataclass(frozen=True)
class Normalized:
    text: str
    removed: dict[str, int]


def normalize(text: str) -> Normalized:
    removed: Counter[str] = Counter()
    out = unicodedata.normalize("NFKC", text)
    if out != text:
        removed["nfkc"] += 1
    for name, pattern, keep in (
        ("hidden characters", HIDDEN, ""),
        ("html comments", COMMENT, " "),
        ("markdown images", IMAGE, r"\1"),
        ("markdown links", LINK, r"\1"),
        ("html tags", TAG, " "),
        ("script urls", DATA_URL, "[link removed]"),
    ):
        out, n = pattern.subn(keep, out)
        if n:
            removed[name] += n
    return Normalized(re.sub(r"[ \t]{2,}", " ", out), dict(removed))


def signals(text: str) -> list[str]:
    """The rules a text meets; any one marks it as a possible instruction."""
    return [name for name, pattern in RULES if pattern.search(text)]


class ToolRefused(PermissionError):
    """A node asked for a source outside its allowlist."""


@dataclass
class Guard:
    """The sources of a run behind the defenses: normalization and the injection signal on everything
    retrieved, and the allowlist on every call, with a count of what each defense did."""

    sources: Sources
    node: str = "intake"
    calls: list[tuple[str, str]] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)
    counts: Counter[str] = field(default_factory=Counter)
    marked: list[dict[str, Any]] = field(default_factory=list)

    def _allow(self, name: str) -> None:
        self.calls.append((self.node, name))
        if name not in ALLOWLIST.get(self.node, frozenset()):
            self.refused.append((self.node, name))
            self.counts["allowlist"] += 1
            raise ToolRefused(f"node {self.node} may not read {name}")

    @property
    def documents(self) -> Documents:
        self._allow("documents")
        return self.sources.documents

    def description(self, cve_id: str, at: datetime) -> str | None:
        self._allow("description")
        found = self.sources.description(cve_id, at)
        return normalize(found).text if found else found

    def match(self, cve_id: str, at: datetime) -> Match | None:
        self._allow("match")
        return self.sources.match(cve_id, at)

    def fixed_versions(self, cve_id: str, match: Match | None, at: datetime) -> list[FixedVersion]:
        self._allow("fixed_versions")
        return self.sources.fixed_versions(cve_id, match, at)

    def predictions(self, cve_id: str, at: datetime) -> dict[str, Any]:
        self._allow("predictions")
        return self.sources.predictions(cve_id, at)

    def kev(self, cve_id: str, at: datetime) -> KevListing | None:
        self._allow("kev")
        return self.sources.kev(cve_id, at)

    def exploits(self, cve_id: str, at: datetime) -> list[ExploitSignal]:
        self._allow("exploits")
        return self.sources.exploits(cve_id, at)

    def epss(self, cve_id: str, at: datetime) -> float | None:
        self._allow("epss")
        return self.sources.epss(cve_id, at)

    def retrieve(self, query: str, at: datetime, k: int) -> list[Evidence]:
        self._allow("retrieve")
        kept: list[Evidence] = []
        for item in self.sources.retrieve(query, at, k):
            clean = normalize(item.text)
            for name, n in clean.removed.items():
                self.counts[f"normalize: {name}"] += n
            found = signals(clean.text)
            if found:
                self.counts["injection signal"] += 1
                self.marked.append({"chunk_id": item.chunk_id, "doc_id": item.doc_id, "rules": found})
                continue
            kept.append(item.model_copy(update={"text": clean.text}))
        return kept
