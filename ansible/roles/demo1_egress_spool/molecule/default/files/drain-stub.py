"""Test stand-in for the spool's drain endpoint, run by standin-drain-stub.service.

It is a real HTTP listener on the host side of the published port, so the role's
listener read and its call with no token meet a real socket. It is not the
mailgun-shim and proves nothing about it. STUB_BIND says the address it listens
on, and STUB_OPEN=1 makes it answer the drain path without a token, which is the
fault the role's call must catch.
"""

import http.server
import os


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/drain":
            self.send_response(404)
        elif os.environ.get("STUB_OPEN") == "1":
            self.send_response(200)
        else:
            self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


bind = os.environ.get("STUB_BIND", "127.0.0.1")
port = int(os.environ.get("STUB_PORT", "8095"))
http.server.HTTPServer((bind, port), Handler).serve_forever()
