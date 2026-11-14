"""A browser stand-in for test_trusted_session_replay.py, run in its own container.

It runs on the test network with the source address the test gives it, so the
edge sees each case's requests from that case's address. It reads a JSON list
of requests from the file named by its one argument, sends each over TLS to the
edge with the request's host as the server name, and prints one JSON list of
results: the status and the start of each body. The edge's certificate is
Caddy's own test CA, so it is not verified.
"""

from __future__ import annotations

import http.client
import json
import pathlib
import socket
import ssl
import sys

EDGE_ADDRESS = sys.argv[2] if len(sys.argv) > 2 else "edge"


def send(spec: dict[str, object]) -> dict[str, object]:
    host = str(spec["host"])
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((EDGE_ADDRESS, 443), timeout=60)
    connection = http.client.HTTPConnection(host, 443, timeout=60)
    connection.sock = context.wrap_socket(raw, server_hostname=host)
    try:
        size = int(str(spec.get("body_bytes", 0)))
        body = b"\0" * size if size else None
        given = spec.get("headers") or {}
        if not isinstance(given, dict):
            raise TypeError("headers must be an object")
        headers = {str(name): str(value) for name, value in given.items()}
        connection.request(str(spec["method"]), str(spec["path"]), body=body, headers=headers)
        response = connection.getresponse()
        text = response.read()[:2000].decode("utf-8", "replace")
        return {"status": response.status, "body": text}
    except OSError as error:
        return {"status": 0, "body": f"{type(error).__name__}: {error}"}
    finally:
        connection.close()


def main() -> None:
    specs = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps([send(spec) for spec in specs]))


if __name__ == "__main__":
    main()
