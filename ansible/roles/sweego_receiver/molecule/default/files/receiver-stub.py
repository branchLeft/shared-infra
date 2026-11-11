#!/usr/bin/python3 -I
"""Test stand-in for the receiver's two listeners, started by the stand-in docker.

It proves wiring only: that something listens on the two published addresses and that the drain
listener answers a call with no token with 401. It is not the receiver.
"""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Public(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self) -> None:  # noqa: N802 -- the name http.server calls
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class Drain(Public):
    status = 401


def serve(address: str, port: int, handler: type[Public]) -> None:
    ThreadingHTTPServer((address, port), handler).serve_forever()


def main() -> int:
    address, public_port, drain_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    for port, handler in ((public_port, Public), (drain_port, Drain)):
        threading.Thread(target=serve, args=(address, port, handler), daemon=True).start()
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
