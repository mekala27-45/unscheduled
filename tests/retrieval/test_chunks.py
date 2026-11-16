"""Documents cut into sections and chunks: every chunk fits, every section comes back exactly from
the chunks, short sections share a chunk, links are not chunked, and the same document always gives
the same chunk ids.

The tests count tokens as words so the limits are easy to read; the build counts them with the
tokenizer of the pinned embedding model.
"""

from __future__ import annotations

from unscheduled_retrieval.chunks import chunk_document, section_text
from unscheduled_retrieval.documents import clean, from_cwe, from_kev, from_osv


def words(text: str) -> int:
    return len(text.split())


ADVISORY = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "modified": "2026-10-02T10:00:00Z",
    "published": "2026-10-01T09:00:00Z",
    "aliases": ["CVE-2026-1111", "PYSEC-2026-1"],
    "summary": "Path traversal in example-lib",
    "details": "First paragraph says the archive extractor trusts names.\n\n"
    + " ".join(f"word{i}." for i in range(30))
    + "\n\nLast paragraph names the fix.",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "example-lib"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.1"}]}],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "example-cli"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}]}],
        },
    ],
    "references": [{"type": "ADVISORY", "url": "https://example.test/a"}, {"type": "WEB"}],
}
KEV = {
    "cveID": "CVE-2026-1111",
    "vendorProject": "Example",
    "product": "Lib",
    "vulnerabilityName": "Example Lib Path Traversal",
    "dateAdded": "2026-10-20",
    "shortDescription": "Example Lib lets an archive write outside its folder.",
    "requiredAction": "Apply the vendor fix.",
    "notes": "",
    "knownRansomwareCampaignUse": "Unknown",
}


def test_an_osv_record_becomes_named_sections_with_its_cves() -> None:
    doc = from_osv(ADVISORY, source="ghsa", known_from="2026-10-02T10:05:00Z")
    assert doc.doc_id == "ghsa:GHSA-aaaa-bbbb-cccc" and doc.cve_ids == ("CVE-2026-1111",)
    sections = {s.name: s.text for s in doc.sections}
    assert list(sections) == ["summary", "details", "affected", "references"]
    assert (
        sections["affected"]
        == "PyPI/example-lib: from 0 fixed in 2.4.1\nPyPI/example-cli: from 1.0 with no fix"
    )
    assert sections["references"] == "ADVISORY: https://example.test/a"


def test_every_chunk_fits_and_every_section_comes_back_exactly() -> None:
    doc = from_osv(ADVISORY, source="ghsa", known_from="2026-10-02T10:05:00Z")
    chunks = chunk_document(doc, words, max_tokens=12)
    assert all(c.tokens <= 12 for c in chunks)
    assert [c.ordinal for c in chunks] == list(range(len(chunks)))
    for section in doc.sections:
        if section.name == "references":
            continue
        back = section_text(chunks, section.name)
        assert back.split() == section.text.split()
    assert all(c.known_from == "2026-10-02T10:05:00Z" and c.doc_id == doc.doc_id for c in chunks)


def test_the_links_of_an_advisory_are_not_chunked() -> None:
    doc = from_osv(ADVISORY, source="ghsa", known_from="t")
    chunks = chunk_document(doc, words, max_tokens=256)
    assert all("references" not in c.sections for c in chunks)
    assert not any("https://example.test/a" in c.text for c in chunks)


def test_the_links_of_a_kev_entry_are_not_chunked() -> None:
    doc = from_kev(
        {**KEV, "notes": "https://vendor.test/advisory ; https://nvd.test/CVE-2026-1111"},
        catalog_version="2026.10.20",
        known_from="t",
    )
    assert "notes" in [s.name for s in doc.sections]
    chunks = chunk_document(doc, words, max_tokens=256)
    assert all("notes" not in c.sections and "https://" not in c.text for c in chunks)


def test_short_sections_share_one_chunk_and_keep_their_place() -> None:
    doc = from_kev(KEV, catalog_version="2026.10.20", known_from="2026-10-20T15:00:00Z")
    chunks = chunk_document(doc, words, max_tokens=256)
    assert len(chunks) == 1 and chunks[0].sections == ("entry", "description", "required_action")
    for span in chunks[0].spans:
        assert chunks[0].text[span.start : span.end] == {s.name: s.text for s in doc.sections}[span.section]


def test_the_same_document_gives_the_same_chunk_ids_and_a_new_version_new_ones() -> None:
    first = chunk_document(from_osv(ADVISORY, source="ghsa", known_from="t1"), words, max_tokens=12)
    again = chunk_document(from_osv(ADVISORY, source="ghsa", known_from="t1"), words, max_tokens=12)
    assert [c.chunk_id for c in first] == [c.chunk_id for c in again]
    assert len({c.chunk_id for c in first}) == len(first)
    newer = chunk_document(
        from_osv({**ADVISORY, "modified": "2026-10-09T00:00:00Z"}, source="ghsa", known_from="t2"),
        words,
        max_tokens=12,
    )
    assert not {c.chunk_id for c in first} & {c.chunk_id for c in newer}
    assert [c.digest for c in first] == [c.digest for c in newer]


def test_a_kev_entry_and_a_cwe_entry_become_documents() -> None:
    kev = from_kev(KEV, catalog_version="2026.10.20", known_from="2026-10-20T15:00:00Z")
    assert kev.doc_id == "kev:CVE-2026-1111"
    assert [s.name for s in kev.sections] == ["entry", "description", "required_action"]
    cwe = from_cwe(
        {
            "cwe_id": "CWE-22",
            "name": "Path Traversal",
            "description": "The product uses input to build a path.",
        },
        catalog_version="5.0",
        known_from="2026-10-28T00:00:00Z",
    )
    assert cwe.doc_id == "cwe:CWE-22" and [s.name for s in cwe.sections] == ["description"]


def test_clean_keeps_the_words_and_one_blank_line() -> None:
    assert clean("a  b\t c\r\n\r\n\r\n\r\nd ") == "a b c\n\nd"
    assert clean(None) == ""
