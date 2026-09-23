#!/usr/bin/env python3
"""Tests for probe-project-isolation, against a real HTTP server on loopback.

The fake speaks the Cloud API's shapes -- paginated `servers` and `firewalls`
lists, `GET /firewalls/{id}`, `{"error": {"code": ...}}` bodies -- and scopes
every answer to the project whose token made the request, the property under
test. Each test bends one piece of that scoping and asserts the probe notices.
Requests go through the probe's real `urllib` path; nothing is mocked below it.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


probe = _load("probe_project_isolation", HERE / "probe-project-isolation.py")

TOKENS = {name: f"secret-token-for-{name}-{'x' * 20}" for name in probe.PROJECTS}
PAGE_SIZE = 2


class FakeHetzner:
    """Seven projects. `visible_to` decides which projects a token's reads reach."""

    def __init__(self):
        self.firewalls: dict[str, dict[int, str]] = {}
        self.servers: dict[str, dict[int, str]] = {}
        next_id = 1000
        for name, servers in probe.PROJECTS.items():
            # A decoy firewall before the marker pushes it past page one.
            self.firewalls[name] = {next_id: f"{name}-decoy-a", next_id + 1: f"{name}-decoy-b"}
            self.firewalls[name][next_id + 2] = probe.marker(name)
            self.servers[name] = {next_id + 10 + i: server for i, server in enumerate(servers)}
            next_id += 100
        self.token_project = {token: name for name, token in TOKENS.items()}
        self.list_leaks: dict[str, set[str]] = {}
        self.server_leaks: dict[str, set[str]] = {}
        self.id_leaks: dict[str, set[str]] = {}
        self.not_found_code = "not_found"
        self.wrong_name_for_id: set[int] = set()

    def reach(self, project: str, leaks: dict[str, set[str]]) -> list[str]:
        return [project, *sorted(leaks.get(project, set()))]


class Handler(BaseHTTPRequestHandler):
    fake: FakeHetzner

    def log_message(self, *args):
        pass

    def reply(self, status: int, body: dict):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        fake = self.fake
        auth = self.headers.get("Authorization", "")
        project = fake.token_project.get(auth.removeprefix("Bearer "))
        if project is None:
            return self.reply(401, {"error": {"code": "unauthorized", "message": "x"}})
        url = urllib.parse.urlparse(self.path)
        server_match = re.fullmatch(r"/v1/servers/(\d+)", url.path)
        if server_match:
            wanted = int(server_match.group(1))
            for owner in fake.reach(project, fake.id_leaks):
                if wanted in fake.servers[owner]:
                    name = fake.servers[owner][wanted]
                    return self.reply(200, {"server": {"id": wanted, "name": name}})
            return self.reply(404, {"error": {"code": "not_found", "message": "x"}})
        match = re.fullmatch(r"/v1/firewalls/(\d+)", url.path)
        if match:
            wanted = int(match.group(1))
            for owner in fake.reach(project, fake.id_leaks):
                if wanted in fake.firewalls[owner]:
                    name = fake.firewalls[owner][wanted]
                    if wanted in fake.wrong_name_for_id:
                        name = "something-else"
                    return self.reply(200, {"firewall": {"id": wanted, "name": name}})
            return self.reply(404, {"error": {"code": fake.not_found_code, "message": "x"}})
        collection = url.path.removeprefix("/v1/")
        if collection not in ("servers", "firewalls"):
            return self.reply(404, {"error": {"code": "not_found", "message": "x"}})
        source = fake.servers if collection == "servers" else fake.firewalls
        leaks = {k: set(v) for k, v in fake.list_leaks.items()}
        if collection == "servers":
            for k, v in fake.server_leaks.items():
                leaks.setdefault(k, set()).update(v)
        items = [
            {"id": item_id, "name": name}
            for owner in fake.reach(project, leaks)
            for item_id, name in source[owner].items()
        ]
        page = int(urllib.parse.parse_qs(url.query).get("page", ["1"])[0])
        chunk = items[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
        more = page * PAGE_SIZE < len(items)
        return self.reply(
            200,
            {
                collection: chunk,
                "meta": {"pagination": {"page": page, "next_page": page + 1 if more else None}},
            },
        )


class ProbeTestCase(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHetzner()
        handler = type("BoundHandler", (Handler,), {"fake": self.fake})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.api = probe.Api(f"http://127.0.0.1:{self.server.server_address[1]}/v1")
        self.environ = {probe.token_env(name): token for name, token in TOKENS.items()}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def run_probe(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        code = probe.run(list(argv), self.environ, self.api, out=out)
        return code, out.getvalue()


class IsolatedEstate(ProbeTestCase):
    def test_passes_when_every_token_sees_only_its_own_project(self):
        code, out = self.run_probe()
        self.assertEqual(code, 0, out)
        self.assertTrue(out.rstrip().endswith("PASS"), out)
        self.assertEqual(out.count("ok "), 49, out)

    def test_every_own_cell_is_a_200_and_every_other_a_404(self):
        views = probe.observe(self.api, TOKENS)
        result = probe.evaluate(self.api, TOKENS, views)
        self.assertEqual(len(result.cells), 49)
        for cell in result.cells:
            expected = 200 if cell.row == cell.column else 404
            self.assertEqual(cell.by_id_status, expected, cell)

    def test_finds_a_marker_that_is_not_on_the_first_page(self):
        views = probe.observe(self.api, {"dns": TOKENS["dns"]})
        self.assertIn(probe.marker("dns"), views["dns"].firewalls)

    def test_never_prints_a_token(self):
        for argv in ((), ("--control-swap", "tenants=demos")):
            _, out = self.run_probe(*argv)
            for token in TOKENS.values():
                self.assertNotIn(token, out)

    def test_demo_dns_env_var_uses_an_underscore_not_the_project_names_hyphen(self):
        # A shell variable name can't contain '-'. `probe.PROJECTS` and
        # `--control-swap` still use the hyphenated project name; only the
        # environment lookup is translated.
        self.assertEqual(probe.token_env("demo-dns"), "HCLOUD_PROBE_TOKEN_DEMO_DNS")
        self.assertIn("HCLOUD_PROBE_TOKEN_DEMO_DNS", self.environ)


class ControlCase(ProbeTestCase):
    def test_swap_reports_fail_and_the_control_passes(self):
        code, out = self.run_probe("--control-swap", "tenants=demos")
        self.assertEqual(code, 0, out)
        self.assertIn("\nFAIL\n", out)
        self.assertIn("CONTROL OK", out)
        self.assertIn("tenants token vs demos project: REACHES ACROSS", out)

    def test_every_swap_is_detected(self):
        for row in probe.PROJECTS:
            for source in probe.PROJECTS:
                if row == source:
                    continue
                code, out = self.run_probe("--control-swap", f"{row}={source}")
                self.assertEqual(code, 0, f"{row}={source}\n{out}")

    def test_a_control_that_passes_is_reported_broken(self):
        original = probe.evaluate
        probe.evaluate = lambda api, tokens, views: probe.Result()
        try:
            code, out = self.run_probe("--control-swap", "tenants=demos")
        finally:
            probe.evaluate = original
        self.assertEqual(code, 1)
        self.assertIn("CONTROL BROKEN", out)

    def test_a_fail_without_the_reach_does_not_count_as_a_working_control(self):
        # The swapped row fails on its missing own marker, but the cell that
        # matters -- tenants token against demos -- reads clean.
        failing = probe.Result(
            cells=[probe.Cell("tenants", "demos", False, 404, True, "refused")],
            problems=["tenants: its token does not list project-marker-tenants"],
        )
        original = probe.evaluate
        probe.evaluate = lambda api, tokens, views: failing
        try:
            code, out = self.run_probe("--control-swap", "tenants=demos")
        finally:
            probe.evaluate = original
        self.assertIn("\nFAIL\n", out)
        self.assertEqual(code, 1)
        self.assertIn("CONTROL BROKEN", out)

    def test_rejects_a_malformed_swap(self):
        for value in ("tenants", "tenants=tenants", "nope=demos", "tenants=nope"):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                self.run_probe("--control-swap", value)


class Leaks(ProbeTestCase):
    def test_fails_when_a_token_lists_another_project(self):
        self.fake.list_leaks = {"tenants": {"demos"}}
        code, out = self.run_probe()
        self.assertEqual(code, 1, out)
        self.assertIn("tenants token vs demos project: REACHES ACROSS", out)

    def test_fails_when_only_a_server_leaks(self):
        self.fake.server_leaks = {"dns": {"mail"}}
        code, out = self.run_probe()
        self.assertEqual(code, 1, out)
        self.assertIn("dns token vs mail project: REACHES ACROSS", out)

    def test_fails_when_a_token_fetches_another_project_by_id(self):
        self.fake.id_leaks = {"org": {"tenants"}}
        code, out = self.run_probe()
        self.assertEqual(code, 1, out)
        self.assertIn("org token vs tenants project: REACHES ACROSS", out)

    def test_fails_when_a_project_has_no_marker(self):
        self.fake.firewalls["demos"] = {1: "unrelated"}
        code, out = self.run_probe()
        self.assertEqual(code, 1, out)
        self.assertIn("demos: its token does not list project-marker-demos", out)
        self.assertIn("no demos marker id to test against", out)

    def test_fails_when_the_own_fetch_returns_a_different_firewall(self):
        marker_id = next(
            i for i, n in self.fake.firewalls["org"].items() if n == probe.marker("org")
        )
        self.fake.wrong_name_for_id = {marker_id}
        code, out = self.run_probe()
        self.assertEqual(code, 1, out)
        self.assertIn("org token vs org project: OWN PROJECT NOT SEEN", out)


class RequiredServers(ProbeTestCase):
    def test_fails_when_the_mail_token_cannot_see_mx1(self):
        self.fake.servers["mail"] = {}
        code, out = self.run_probe()
        self.assertEqual(code, 1, out)
        self.assertIn("mail token vs mail project: OWN PROJECT NOT SEEN: mx1", out)

    def test_fails_when_edge1_cannot_be_fetched_by_id(self):
        edge1 = next(i for i, n in self.fake.servers["org"].items() if n == "edge1")
        self.fake.servers["org"][edge1 + 50] = self.fake.servers["org"].pop(edge1)
        original = probe.Api.list_names

        def stale_ids(api, token, collection):
            names = original(api, token, collection)
            if collection == "servers" and "edge1" in names:
                names["edge1"] = edge1
            return names

        probe.Api.list_names = stale_ids
        try:
            code, out = self.run_probe()
        finally:
            probe.Api.list_names = original
        self.assertEqual(code, 1, out)
        self.assertIn("org token vs org project: OWN PROJECT NOT SEEN: edge1", out)

    def test_only_mail_and_org_have_required_servers(self):
        self.assertEqual(probe.REQUIRED_SERVERS, {"mail": ("mx1",), "org": ("edge1",)})
        for project, servers in probe.REQUIRED_SERVERS.items():
            for server in servers:
                self.assertIn(server, probe.PROJECTS[project])


class CannotRun(ProbeTestCase):
    def test_a_missing_token_is_an_error_not_a_result(self):
        del self.environ[probe.token_env("dns")]
        code, out = self.run_probe()
        self.assertEqual(code, 2)
        self.assertIn("HCLOUD_PROBE_TOKEN_DNS", out)

    def test_the_same_token_twice_is_an_error(self):
        self.environ[probe.token_env("demos")] = TOKENS["tenants"]
        code, out = self.run_probe()
        self.assertEqual(code, 2)
        self.assertIn("tenants and demos were given the same token", out)

    def test_a_refused_token_is_an_error(self):
        self.environ[probe.token_env("mail")] = "not-a-real-token"
        code, out = self.run_probe()
        self.assertEqual(code, 2)
        self.assertIn("HTTP 401 unauthorized", out)

    def test_a_404_without_not_found_is_an_error(self):
        self.fake.not_found_code = "something_else"
        code, out = self.run_probe()
        self.assertEqual(code, 2, out)

    def test_an_unreachable_api_is_an_error(self):
        self.api = probe.Api("http://127.0.0.1:9/v1", timeout=2)
        code, out = self.run_probe()
        self.assertEqual(code, 2)
        self.assertIn("transport error", out)


class TableMatchesProjectsTs(unittest.TestCase):
    """The probe carries its own copy of `projects.ts`; the two must not drift."""

    def test_same_projects_servers_and_markers(self):
        source = (HERE.parent / "projects.ts").read_text()
        # The object key is a bare identifier for most entries but a quoted
        # string for `'demo-dns'`, since a hyphen is not a valid identifier
        # character; the project name itself can carry a hyphen either way.
        entries = re.findall(
            r"(?:\w+|'[\w-]+'):\s*project\(\s*'([\w-]+)',\s*'[^']*',\s*\[([^\]]*)\]",
            source,
            flags=re.S,
        )
        parsed = {name: tuple(re.findall(r"'([^']+)'", servers)) for name, servers in entries}
        self.assertEqual(parsed, probe.PROJECTS)
        self.assertIn(f"MARKER_PREFIX = '{probe.MARKER_PREFIX}'", source)


if __name__ == "__main__":
    unittest.main()
