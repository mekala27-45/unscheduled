"""The token gate: colors and faces only through the token block."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_tokens


def test_token_gate_passes_styles_that_use_tokens(tmp_path: Path) -> None:
    f = tmp_path / "a.css"
    f.write_text(
        ".panel { color: var(--fg); background: color-mix(in oklch, var(--bg) 90%, transparent);"
        " font-family: var(--font-body); }\n",
        encoding="utf-8",
    )
    assert check_tokens.check(tmp_path, [f]) == 1


@pytest.mark.parametrize(
    "line",
    [
        ".a { color: #1f6feb; }",
        ".a { background: rgb(12, 40, 90); }",
        ".a { border-color: oklch(0.62 0.19 259); }",
        ".a { font-family: Inter, sans-serif; }",
        "const s = { fontFamily: 'Inter' };",
        '<div className="bg-[#0a0a0a]" />',
    ],
)
def test_token_gate_catches_a_literal(tmp_path: Path, line: str) -> None:
    f = tmp_path / "a.tsx"
    f.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="token gate failed"):
        check_tokens.check(tmp_path, [f])


def test_token_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        check_tokens.check(tmp_path, [])
