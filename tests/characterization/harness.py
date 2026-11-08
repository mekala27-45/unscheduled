"""Run the legacy script the way cron runs it, on files in a temporary directory, and capture all it does.

The script runs as a separate process from the repository's Python in isolated mode, with a copy of
the handed-over config whose feed URL, output directory and mail server are pointed at the test:
a file:// directory of sample feeds (or an empty one, which is what a retired feed looks like),
and the local SMTP sink. Nothing reaches the network. What it wrote and what it mailed are
normalized only where they carry the day the test ran.
"""

from __future__ import annotations

import configparser
import email
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from email.message import Message as EmailMessage
from pathlib import Path

from tests.characterization import convert
from tests.characterization.smtp_sink import Message, SmtpSink

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "customer" / "legacy" / "vuln_report.py"
CONFIG = ROOT / "customer" / "legacy" / "vuln_report.ini"
GOLDEN = Path(__file__).resolve().parent / "golden"
REFERENCE_DAY = date(2026, 11, 7)  # the day the NVD sample was read


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    csv_name: str
    csv_bytes: bytes
    mail: str
    attachment: bytes


def write_config(tmp: Path, base_url: str, years: list[str] | None, port: int) -> Path:
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG, encoding="utf-8")
    cfg["feeds"]["base_url"] = base_url
    if years is not None:
        cfg["feeds"]["years"] = ",".join(years)
    cfg["output"]["directory"] = str(tmp / "reports")
    cfg["mail"]["smtp_host"] = "127.0.0.1"
    cfg["mail"]["smtp_port"] = str(port)
    path = tmp / "vuln_report.ini"
    with path.open("w", encoding="utf-8") as handle:
        cfg.write(handle)
    return path


def sample_feeds(tmp: Path) -> tuple[str, list[str]]:
    records = convert.load_sample()
    feeds = tmp / "feeds"
    convert.write(feeds, records, REFERENCE_DAY)
    return feeds.as_uri() + "/", convert.years(records)


def retired_feeds(tmp: Path) -> str:
    """A feed location that answers nothing, as the retired 1.1 feeds do."""
    empty = tmp / "retired"
    empty.mkdir()
    return empty.as_uri() + "/"


def _day_tokens(text: str) -> str:
    text = re.sub(r"\b\d{2}/\d{2}/\d{4}\b", "<day>", text)
    return re.sub(r"vuln_report_\d{8}\.csv", "vuln_report_<day>.csv", text)


def normalize_mail(message: Message) -> tuple[str, bytes]:
    parsed: EmailMessage = email.message_from_bytes(message.data)
    lines = [
        f"envelope from: {message.sender}",
        f"envelope to: {', '.join(message.recipients)}",
        f"Subject: {_day_tokens(str(parsed['Subject']))}",
        f"From: {parsed['From']}",
        f"To: {parsed['To']}",
        f"Content-Type: {parsed.get_content_type()}",
    ]
    attachment = b""
    for index, part in enumerate(parsed.walk()):
        if part.is_multipart():
            continue
        disposition = part.get("Content-Disposition", "")
        payload = part.get_payload(decode=True)
        body = payload if isinstance(payload, bytes) else b""
        if "attachment" in disposition:
            attachment = body
            lines.append(
                f"part {index}: {part.get_content_type()}, attachment "
                f"{_day_tokens(str(part.get_filename()))}, {part.get('Content-Transfer-Encoding')}"
            )
            lines.append(f"attachment sha256: {hashlib.sha256(body).hexdigest()}")
        else:
            lines.append(f"part {index}: {part.get_content_type()}; charset={part.get_content_charset()}")
            lines.append(body.decode(part.get_content_charset() or "utf-8").rstrip("\n"))
    return "\n".join(lines) + "\n", attachment


def run(tmp: Path, base_url: str, years: list[str] | None) -> Run:
    with SmtpSink() as sink:
        config = write_config(tmp, base_url, years, sink.port)
        done = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "-c", str(config)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        messages = sink.messages
    reports = sorted((tmp / "reports").glob("vuln_report_*.csv"))
    if len(reports) != 1 or len(messages) != 1:
        raise AssertionError(
            f"expected one report and one mail, got {len(reports)} and {len(messages)}: {done.stderr[-2000:]}"
        )
    mail, attachment = normalize_mail(messages[0])
    stdout = _day_tokens(done.stdout.replace(str(tmp / "reports"), "<reports>"))
    return Run(
        done.returncode, stdout, _day_tokens(reports[0].name), reports[0].read_bytes(), mail, attachment
    )


def golden(name: str) -> bytes:
    return (GOLDEN / name).read_bytes()
