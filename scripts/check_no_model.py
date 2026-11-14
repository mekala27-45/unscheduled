"""No language model anywhere, and model libraries only where Phase 2 trains or serves them.

Phase 1 refused every model library. Phase 2 lifts that in two places and nowhere else: the deep
learning and embedding libraries may be imported only under packages/models and kaggle/, where the
models are trained, and the ONNX runtime only under packages/models and packages/api, where they
are served. Every model provider client and agent framework stays refused everywhere until Phase 3,
so no language model runs and nothing generates text in this phase.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Refused in every file until Phase 3 lifts them.
EVERYWHERE = (
    "vllm",
    "openai",
    "anthropic",
    "langchain",
    "langgraph",
    "google.genai",
    "groq",
    "litellm",
)
# Allowed only under these folders, relative to the repository root.
SCOPED: dict[str, tuple[str, ...]] = {
    "torch": ("packages/models", "kaggle"),
    "transformers": ("packages/models", "kaggle"),
    "sentence_transformers": ("packages/models", "kaggle"),
    "optimum": ("packages/models", "kaggle"),
    "onnxruntime": ("packages/models", "packages/api"),
}
SCANNED = ("packages", "scripts", "kaggle")
IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", re.M)


def refused_imports(text: str, where: str = "") -> list[str]:
    """The imports in a file that its place in the repository does not allow."""
    found = []
    for module in IMPORT.findall(text):
        top = module.split(".")[0]
        refused_here = top in EVERYWHERE or module in EVERYWHERE
        out_of_place = top in SCOPED and not any(
            where == folder or where.startswith(folder + "/") for folder in SCOPED[top]
        )
        if refused_here or out_of_place:
            found.append(module)
    return found


def check(root: Path, files: list[Path] | None = None) -> int:
    if files is None:
        files = sorted(
            p
            for base in SCANNED
            if (root / base).exists()
            for p in (root / base).rglob("*.py")
            if ".venv" not in p.parts and p.name != Path(__file__).name
        )
    if not files:
        raise ValueError("the model gate found no files to scan")
    problems = []
    for p in files:
        if not p.exists():
            continue
        where = p.resolve().relative_to(root.resolve()).as_posix() if p.is_absolute() else p.as_posix()
        found = refused_imports(p.read_text(encoding="utf-8"), where)
        if found:
            problems.append(f"{where}: {sorted(set(found))}")
    if problems:
        raise ValueError(
            "model gate failed (no language model anywhere; model libraries only where Phase 2 "
            "trains or serves):\n" + "\n".join(problems)
        )
    return len(files)


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"model gate: {count} files, no language model, model libraries only where allowed")
