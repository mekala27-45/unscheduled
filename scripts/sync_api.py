"""Ask the live API to load the newest serving release, one chunk per call, until it answers done.

    python scripts/sync_api.py                       # https://unscheduled-api.vercel.app
    python scripts/sync_api.py --base http://127.0.0.1:8000 --max-calls 50

The sync takes no input: the API decides what to load from the newest serving release of this
repository and checks every digest itself (ADR 0007), so this client only knocks and reads the
answer. It paces itself under the API's limit, waits as told on a 429 or a busy answer, and stops at
done or current. Every answer is written to results/live/sync.json, with no secret anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://unscheduled-api.vercel.app"
AGENT = "unscheduled-sync/0.1 (+https://github.com/mekala27-45/unscheduled)"
PACE_S = 2.5  # the API allows 30 calls a minute; this stays under it


def call(base: str) -> tuple[int, dict[str, Any], float | None]:
    request = urllib.request.Request(
        f"{base}/internal/sync", method="POST", data=b"", headers={"User-Agent": AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return int(response.status), json.loads(response.read()), None
    except urllib.error.HTTPError as error:
        body = error.read()
        retry = error.headers.get("Retry-After")
        try:
            payload: dict[str, Any] = json.loads(body)
        except json.JSONDecodeError:
            payload = {"detail": body.decode("utf-8", errors="replace")[:300]}
        return int(error.code), payload, float(retry) if retry and retry.isdigit() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default=BASE)
    parser.add_argument("--max-calls", type=int, default=400)
    args = parser.parse_args(argv)
    answers: list[dict[str, Any]] = []
    final = "stopped"
    started = time.monotonic()
    for n in range(1, args.max_calls + 1):
        status, body, retry = call(args.base)
        record = {
            "call": n,
            "http": status,
            "status": body.get("status"),
            "step": body.get("step"),
            "chunk": body.get("chunk"),
            "chunks_done": body.get("chunks_done"),
            "chunks_total": body.get("chunks_total"),
            "storage_bytes": body.get("storage_bytes"),
            "target": body.get("target"),
            "detail": body.get("detail") if status >= 400 else None,
            "type": body.get("type") if status >= 400 else None,
        }
        answers.append(record)
        print(
            f"sync {n}: {status} {body.get('status') or body.get('type')} "
            f"{body.get('step') or ''} {body.get('chunks_done')}/{body.get('chunks_total')}",
            flush=True,
        )
        if status == 200 and body.get("status") in {"done", "current"}:
            final = str(body["status"])
            break
        if status in {429, 409, 503} or (status >= 400 and "busy" in str(body.get("type", ""))):
            time.sleep(retry if retry is not None else 15.0)
            continue
        if status >= 400:
            final = f"refused: {body.get('type') or status}"
            break
        time.sleep(PACE_S)
    out = {
        "base": args.base,
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
        "calls": len(answers),
        "final": final,
        "answers": answers,
    }
    path = ROOT / "results" / "live" / "sync.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(f"sync: {final} after {len(answers)} calls")
    return 0 if final in {"done", "current"} else 1


if __name__ == "__main__":
    sys.exit(main())
