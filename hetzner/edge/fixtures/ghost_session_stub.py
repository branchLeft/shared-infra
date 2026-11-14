"""A stand-in for two Ghost sites, for test_trusted_session_replay.py only.

It answers Ghost's "who am I" endpoint the way Ghost does for each kind of
session the edge may be shown, and records every such call it receives so the
test can see what the edge sent. Every other path answers 200 JSON with the
number of body bytes it read, except a path containing `/missing-`, which
answers 404, so a client can raise the 404s a probe raises.

The session it accepts on a host is `staff-<host>`, and only when the request's
Origin or Referer is that host's own origin, as Ghost checks it. Two other
answers stand for the ways a verifier can answer 2xx without a staff session:
any request carrying an Authorization header is accepted (Ghost accepts an
Admin API key), and the cookie value `staff-html` gets a 2xx HTML page.
"""

from __future__ import annotations

import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

VERIFY_PATH = "/ghost/api/admin/users/me/"
COOKIE = "ghost-admin-api-session"
RECORDS = pathlib.Path("/records/verifications.jsonl")
PORTS = (2368, 2369)
LOCK = threading.Lock()


def session_of(cookie_header: str) -> str | None:
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            return value
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- the stdlib's name
        sys.stderr.write("stub: " + (format % args) + "\n")

    def _answer(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._answer(status, json.dumps(payload).encode(), "application/json; charset=utf-8")

    def _read_body(self) -> int:
        length = int(self.headers.get("Content-Length") or 0)
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 20))
            if not chunk:
                break
            remaining -= len(chunk)
        return length - remaining

    def _verify(self, query: str) -> None:
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        session = session_of(self.headers.get("Cookie") or "")
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        body = self._read_body()
        record = {
            "host": host,
            "method": self.command,
            "query": query,
            "session": session,
            "authorization": self.headers.get("Authorization") is not None,
            "content_length": self.headers.get("Content-Length"),
            "body_bytes": body,
        }
        with LOCK, RECORDS.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        if self.headers.get("Authorization") is not None:
            self._json(200, {"users": [{"id": "integration"}]})
        elif session == "staff-html":
            self._answer(200, b"<!doctype html><title>signin</title>", "text/html; charset=utf-8")
        elif session == "ghost-error":
            self._json(500, {"errors": [{"type": "InternalServerError"}]})
        elif session == f"staff-{host}" and origin.startswith(f"https://{host}"):
            self._json(200, {"users": [{"id": "staff", "email": "staff@example.invalid"}]})
        else:
            self._json(403, {"errors": [{"type": "NoPermissionError"}]})

    def _handle(self) -> None:
        url = urllib.parse.urlsplit(self.path)
        if url.path == VERIFY_PATH and self.command == "GET":
            self._verify(url.query)
            return
        received = self._read_body()
        if "/missing-" in url.path:
            self._json(404, {"errors": [{"type": "NotFoundError"}]})
            return
        self._json(200, {"path": url.path, "received": received})

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle


def main() -> None:
    RECORDS.parent.mkdir(parents=True, exist_ok=True)
    RECORDS.touch()
    servers = [http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in PORTS]  # noqa: S104 -- a test network
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
