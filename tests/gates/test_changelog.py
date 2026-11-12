"""The changelog groups each section's commits by conventional type, in a fixed order."""

from __future__ import annotations

from scripts import changelog
from scripts.changelog import Commit, Section


def test_render_groups_by_type_and_keeps_the_scope() -> None:
    text = changelog.render(
        [
            Section(
                "v0.2.0",
                None,
                (
                    Commit("aaa1111", "docs: the quickstart"),
                    Commit("bbb2222", "feat(api): every CVE with its history, live"),
                    Commit("ccc3333", "fix(web): the ruler on a phone"),
                ),
            ),
            Section("v0.1.0", "2026-11-12", (Commit("ddd4444", "a subject with no type"),)),
        ]
    )
    assert text.startswith("# Changelog\n")
    assert "## v0.2.0\n" in text and "## v0.1.0, 2026-11-12\n" in text
    added, fixed, documents = text.index("### Added"), text.index("### Fixed"), text.index("### Documents")
    assert added < fixed < documents
    assert "- api: every CVE with its history, live (bbb2222)" in text
    assert "### Other\n\n- a subject with no type (ddd4444)" in text


def test_an_empty_section_list_is_only_the_heading() -> None:
    assert changelog.render([]).splitlines()[0] == "# Changelog"
