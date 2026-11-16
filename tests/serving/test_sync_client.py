"""The lake asks the live API whether it reads the corpus before a bundle carries corpus files."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

from scripts import sync_api


@contextmanager
def api(paths: dict[str, object] | None, status: int = 200) -> Iterator[str]:
    """A local stand in for the API that serves one schema, or an error."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = json.dumps({"openapi": "3.1.0", "paths": paths or {}}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_an_api_with_the_search_reads_the_corpus() -> None:
    with api({"/health": {}, "/v1/search": {}}) as base:
        assert sync_api.reads_corpus(base)
        assert sync_api.main(["--base", base, "--reads-corpus"]) == 0


def test_an_api_that_predates_the_corpus_gets_a_bundle_without_it() -> None:
    with api({"/health": {}, "/v1/cves": {}}) as base:
        assert not sync_api.reads_corpus(base)
        assert sync_api.main(["--base", base, "--reads-corpus"]) == 1


def test_an_api_that_cannot_answer_reads_nothing() -> None:
    with api(None, status=503) as base:
        assert not sync_api.reads_corpus(base)
    assert not sync_api.reads_corpus("http://127.0.0.1:9")
