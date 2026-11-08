"""Hash the registered plan: criteria, splits, labels, samples, budgets and the Phase 1 plan.

    python scripts/register.py           # write evaluation/registration.json (once)
    python scripts/register.py --check   # fail if any registered file changed since

The hash is taken before any test CVE is scored. A later change is a change request, recorded in
DECISIONS.md with both verdicts, never a silent edit.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTERED = (
    "config/criteria.yaml",
    "config/splits.yaml",
    "config/labels.yaml",
    "config/samples.yaml",
    "config/budgets.yaml",
    "evaluation/phase1_plan.yaml",
)
OUT = ROOT / "evaluation" / "registration.json"


def digests(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in REGISTERED:
        path = root / rel
        if not path.exists():
            raise FileNotFoundError(f"cannot register: {rel} does not exist yet")
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def combined(files: dict[str, str]) -> str:
    joined = "\n".join(f"{k} {v}" for k, v in sorted(files.items()))
    return hashlib.sha256(joined.encode()).hexdigest()


def main(check: bool) -> int:
    files = digests(ROOT)
    if check:
        if not OUT.exists():
            print("registration: not registered yet")
            return 1
        saved = json.loads(OUT.read_text(encoding="utf-8"))
        changed = sorted(k for k, v in files.items() if saved["files"].get(k) != v)
        if changed:
            print("registration: changed since the hash: " + ", ".join(changed))
            return 1
        print(f"registration: {len(files)} files match hash {saved['hash'][:12]}")
        return 0
    if OUT.exists():
        print("registration: already registered; a change is a change request in DECISIONS.md")
        return 1
    digest = combined(files)
    record: dict[str, object] = {
        "registered_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "hash": digest,
        "files": files,
        "note": "registered before any test CVE was scored by anything",
    }
    OUT.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"registration: hashed {len(files)} files as {digest[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
