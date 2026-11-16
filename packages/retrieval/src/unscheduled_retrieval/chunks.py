"""Chunks: a document cut by section, then by paragraph, each piece at most max_tokens long.

The pieces of a section are its paragraphs; a paragraph that does not fit alone is cut at sentence
ends, and a sentence that does not fit alone at word boundaries. Pieces are then packed in order
while they fit, across the sections of one document and never across two, so a KEV entry with four
short sections is one chunk and not four (the room plan measured four chunks a KEV entry without
packing, ADR 0011). A chunk keeps where each of its sections starts and ends in its text, so the
text of every section comes back exactly from the chunks, and a citation names a section, not a
chunk.

Sections a search should not match are not chunked: the references of an advisory and the notes of
a KEV entry are lists of links (1,494 of the 1,781 KEV notes of catalog 2026.11.13 are links and
nothing else, the rest links with the label of a directive), kept with the document for the
citations that name them.

Every chunk keeps its document, the moment its document became known and a digest of what it says,
so the same document always gives the same chunks.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from unscheduled_core.hashing import canonical_json, sha256_text

from unscheduled_retrieval.documents import Document

MAX_TOKENS = 256
NOT_CHUNKED = frozenset({"references", "notes"})
JOINER = "\n\n"
_PARAGRAPHS = re.compile(r"\n\s*\n")
_SENTENCES = re.compile(r"(?<=[.!?])\s+(?=\S)")


@dataclass(frozen=True)
class Span:
    """Where a piece of a section sits in a chunk's text: characters start to end."""

    section: str
    start: int
    end: int


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    doc_id: str
    source: str
    ordinal: int
    text: str
    spans: tuple[Span, ...]
    tokens: int
    known_from: str
    digest: str

    @property
    def sections(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(s.section for s in self.spans))


def _pack(pieces: list[str], count: Callable[[str], int], limit: int, joiner: str) -> Iterator[str]:
    current = ""
    for piece in pieces:
        candidate = f"{current}{joiner}{piece}" if current else piece
        if count(candidate) <= limit:
            current = candidate
            continue
        if current:
            yield current
        current = piece
    if current:
        yield current


def _fit(paragraph: str, count: Callable[[str], int], limit: int) -> Iterator[str]:
    """A paragraph as pieces that fit: whole, else cut at sentence ends, else at word boundaries. A
    single word longer than the limit stays whole; the model truncates it and the verifier reads
    the source."""
    if count(paragraph) <= limit:
        yield paragraph
        return
    for sentence in _pack(_SENTENCES.split(paragraph), count, limit, " "):
        if count(sentence) <= limit:
            yield sentence
        else:
            yield from _pack(sentence.split(), count, limit, " ")


def pieces(doc: Document, count: Callable[[str], int], max_tokens: int) -> list[tuple[str, str]]:
    """Every piece of every chunked section, in order, with the section it comes from."""
    out: list[tuple[str, str]] = []
    for section in doc.sections:
        if section.name in NOT_CHUNKED:
            continue
        for paragraph in (p.strip() for p in _PARAGRAPHS.split(section.text)):
            if paragraph:
                out.extend((section.name, piece) for piece in _fit(paragraph, count, max_tokens))
    return out


def chunk_document(doc: Document, count: Callable[[str], int], max_tokens: int = MAX_TOKENS) -> list[Chunk]:
    chunks: list[Chunk] = []
    group: list[tuple[str, str]] = []

    def close() -> None:
        if not group:
            return
        spans: list[Span] = []
        text = ""
        for section, piece in group:
            start = len(text) + (len(JOINER) if text else 0)
            text = f"{text}{JOINER}{piece}" if text else piece
            spans.append(Span(section, start, start + len(piece)))
        ordinal = len(chunks)
        digest = sha256_text(text)
        key = canonical_json([doc.doc_id, doc.version, ordinal, digest])
        chunks.append(
            Chunk(
                chunk_id=sha256_text(key)[:16],
                doc_id=doc.doc_id,
                source=doc.source,
                ordinal=ordinal,
                text=text,
                spans=tuple(spans),
                tokens=count(text),
                known_from=doc.known_from,
                digest=digest,
            )
        )
        group.clear()

    for section, piece in pieces(doc, count, max_tokens):
        candidate = JOINER.join([p for _, p in group] + [piece])
        if group and count(candidate) > max_tokens:
            close()
        group.append((section, piece))
    close()
    return chunks


def section_text(chunks: list[Chunk], section: str) -> str:
    """The text of one section, put back together from the chunks of its document."""
    parts = [
        c.text[s.start : s.end]
        for c in sorted(chunks, key=lambda c: c.ordinal)
        for s in c.spans
        if s.section == section
    ]
    return JOINER.join(parts)
