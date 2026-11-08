"""A local SMTP sink that keeps every message it is sent, so the legacy script's mail can be pinned.

It speaks just enough SMTP for smtplib (EHLO or HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT) on
127.0.0.1 and an ephemeral port, and delivers nothing anywhere.
"""

from __future__ import annotations

import socketserver
import threading
from dataclasses import dataclass, field
from types import TracebackType


@dataclass
class Message:
    sender: str
    recipients: list[str]
    data: bytes


@dataclass
class Mailbox:
    messages: list[Message] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


def _address(line: str) -> str:
    _, _, rest = line.partition(":")
    return rest.strip().strip("<>").split()[0] if rest.strip() else ""


class _Handler(socketserver.StreamRequestHandler):
    mailbox: Mailbox

    def _send(self, text: str) -> None:
        self.wfile.write((text + "\r\n").encode("ascii"))

    def handle(self) -> None:
        self._send("220 sink ESMTP")
        sender, recipients = "", []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            verb = line[:4].upper()
            if verb in ("EHLO", "HELO"):
                self._send("250 sink")
            elif verb == "MAIL":
                sender, recipients = _address(line), []
                self._send("250 ok")
            elif verb == "RCPT":
                recipients.append(_address(line))
                self._send("250 ok")
            elif verb == "DATA":
                self._send("354 end with <CRLF>.<CRLF>")
                lines: list[bytes] = []
                while True:
                    chunk = self.rfile.readline()
                    if not chunk or chunk in (b".\r\n", b".\n"):
                        break
                    lines.append(chunk[1:] if chunk.startswith(b"..") else chunk)
                with self.mailbox.lock:
                    self.mailbox.messages.append(Message(sender, list(recipients), b"".join(lines)))
                self._send("250 queued")
            elif verb in ("RSET", "NOOP"):
                self._send("250 ok")
            elif verb == "QUIT":
                self._send("221 bye")
                return
            else:
                self._send("502 not implemented")


class SmtpSink:
    def __init__(self) -> None:
        self.mailbox = Mailbox()
        handler = type("Handler", (_Handler,), {"mailbox": self.mailbox})
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> SmtpSink:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def messages(self) -> list[Message]:
        with self.mailbox.lock:
            return list(self.mailbox.messages)
