#!/usr/bin/env python3
"""Tests for probe-edge-block.py, against a local stand-in for the edge."""

from __future__ import annotations

import importlib.util
import pathlib
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import ModuleType

_SPEC = importlib.util.spec_from_file_location(
    "probe_edge_block", pathlib.Path(__file__).resolve().parent / "probe-edge-block.py"
)
assert _SPEC is not None and _SPEC.loader is not None
probe_mod: ModuleType = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(probe_mod)


class _Stub(BaseHTTPRequestHandler):
    """Answers every GET with the status set on its server, and records the User-Agent."""

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        server = self.server
        server.seen_agents.append(self.headers.get("User-Agent", ""))  # type: ignore[attr-defined]
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/somewhere")
            self.end_headers()
            return
        self.send_response(server.status)  # type: ignore[attr-defined]
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class _Edge:
    def __init__(self, status: int) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), _Stub)
        self.server.status = status  # type: ignore[attr-defined]
        self.server.seen_agents = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_Edge":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"


class ClassifyTest(unittest.TestCase):
    def test_403_is_blocked(self) -> None:
        self.assertEqual(probe_mod.classify(403), "blocked")

    def test_2xx_is_allowed(self) -> None:
        self.assertEqual(probe_mod.classify(204), "allowed")
        self.assertEqual(probe_mod.classify(200), "allowed")

    def test_other_statuses_and_no_answer_are_other(self) -> None:
        for status in (301, 404, 429, 500, 502):
            self.assertEqual(probe_mod.classify(status), "other", status)
        self.assertEqual(probe_mod.classify(None), "other")

    def test_exit_codes(self) -> None:
        self.assertEqual(probe_mod.exit_code_for("blocked"), 0)
        self.assertEqual(probe_mod.exit_code_for("allowed"), 1)
        self.assertEqual(probe_mod.exit_code_for("other"), 2)


class BuildUrlTest(unittest.TestCase):
    def test_builds_https_url(self) -> None:
        self.assertEqual(probe_mod.build_url("blog.example.test", "/.env"), "https://blog.example.test/.env")

    def test_rejects_url_as_host(self) -> None:
        with self.assertRaises(ValueError):
            probe_mod.build_url("https://blog.example.test", "/.env")
        with self.assertRaises(ValueError):
            probe_mod.build_url("blog.example.test:8443", "/.env")

    def test_rejects_empty_host_and_path_without_slash(self) -> None:
        with self.assertRaises(ValueError):
            probe_mod.build_url("", "/.env")
        with self.assertRaises(ValueError):
            probe_mod.build_url("blog.example.test", ".env")


class ProbeTest(unittest.TestCase):
    def test_reports_blocked_on_403(self) -> None:
        with _Edge(403) as edge:
            status = probe_mod.probe(edge.base + "/.env")
            self.assertEqual(status, 403)
            self.assertEqual(probe_mod.classify(status), "blocked")

    def test_reports_allowed_on_204(self) -> None:
        with _Edge(204) as edge:
            status = probe_mod.probe(edge.base + "/.env")
            self.assertEqual(probe_mod.classify(status), "allowed")

    def test_sends_one_request_with_the_probe_user_agent(self) -> None:
        with _Edge(403) as edge:
            probe_mod.probe(edge.base + "/.env")
            self.assertEqual(edge.server.seen_agents, [probe_mod.USER_AGENT])  # type: ignore[attr-defined]

    def test_does_not_follow_redirects(self) -> None:
        with _Edge(403) as edge:
            status = probe_mod.probe(edge.base + "/redirect")
            self.assertEqual(status, 302)
            self.assertEqual(len(edge.server.seen_agents), 1)  # type: ignore[attr-defined]

    def test_no_answer_is_none(self) -> None:
        self.assertIsNone(probe_mod.probe("http://127.0.0.1:1/.env"))


if __name__ == "__main__":
    unittest.main()
