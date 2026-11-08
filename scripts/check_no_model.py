"""Phase 1 has no prediction model and no language model: fail on any import that would bring one.

The one fitted model in this phase is the Q8 domain classifier, a scikit-learn logistic regression
that measures shift and is never shown as a value for a CVE. Deep learning, embedding and model
provider libraries are refused anywhere under packages/ or scripts/ until Phase 2 lifts the gate.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REFUSED = (
    "torch",
    "transformers",
    "sentence_transformers",
    "onnxruntime",
    "vllm",
    "openai",
    "anthropic",
    "langchain",
    "langgraph",
    "google.genai",
    "groq",
    "litellm",
)
IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", re.M)


def refused_imports(text: str) -> list[str]:
    found = []
    for module in IMPORT.findall(text):
        top = module.split(".")[0]
        if top in REFUSED or module in REFUSED:
            found.append(module)
    return found


def check(root: Path, files: list[Path] | None = None) -> int:
    if files is None:
        files = sorted(
            p
            for base in ("packages", "scripts")
            for p in (root / base).rglob("*.py")
            if ".venv" not in p.parts and p.name != Path(__file__).name
        )
    if not files:
        raise ValueError("the no model gate found no files to scan")
    problems = [
        f"{p.relative_to(root)}: {sorted(set(found))}"
        for p in files
        if (found := refused_imports(p.read_text(encoding="utf-8")))
    ]
    if problems:
        raise ValueError("no model gate failed (Phase 1 has no model):\n" + "\n".join(problems))
    return len(files)


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"no model gate: {count} files, no model library imported")
