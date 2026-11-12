"""Structured logs: one JSON object per line, ids and digests only.

Never a token, never a connection string, never an uploaded SBOM, never a client address in clear.
A request line carries the method, the route template, the status, the time taken and the first
eight hex digits of the hashed client when the route computed one.
"""

from __future__ import annotations

import logging
import sys

import structlog

_configured = False


def configure(level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    _configured = True
