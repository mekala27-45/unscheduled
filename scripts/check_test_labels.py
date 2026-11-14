"""Only the scorer opens the test labels: fail on any other reference to the test label file.

The training sets put the test labels in files of their own, TEST_LABELS and TEST_PRODUCT_LABELS in
packages/models/src/unscheduled_models/sets.py, and unscheduled_models.sets opens them only when the
caller unseals them. This gate fails when any other Python file under packages, scripts or
kaggle names that file or unseals the labels, so the test window is judged once, by
scripts/score_test.py (evaluation/phase2_plan.yaml, test_scoring).
"""

from __future__ import annotations

from pathlib import Path

PATTERNS = ("TEST_LABELS", "test_labels", "TEST_PRODUCT_LABELS", "test_product_labels", "unsealed=True")
ALLOWED = (
    "packages/models/src/unscheduled_models/sets.py",
    "scripts/score_test.py",
    "scripts/check_test_labels.py",
)
SCANNED = ("packages", "scripts", "kaggle")


def check(root: Path, files: list[Path] | None = None) -> int:
    if files is None:
        files = sorted(
            p
            for base in SCANNED
            if (root / base).exists()
            for p in (root / base).rglob("*.py")
            if ".venv" not in p.parts
        )
    if not files:
        raise ValueError("the test label gate found no files to scan")
    problems = []
    for path in files:
        where = path.resolve().relative_to(root.resolve()).as_posix()
        if where in ALLOWED:
            continue
        text = path.read_text(encoding="utf-8")
        found = [p for p in PATTERNS if p in text]
        if found:
            problems.append(f"{where}: {', '.join(found)}")
    if problems:
        raise ValueError(
            "test label gate failed (only scripts/score_test.py opens them):\n" + "\n".join(problems)
        )
    return len(files)


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"test label gate: {count} files, the test labels opened only by the scorer")
