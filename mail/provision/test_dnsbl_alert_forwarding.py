#!/usr/bin/env python3
"""Tests for check_dnsbl_blocklist.py's alert forwarding to a Healthchecks.io
check. The control cases run the real urllib network stack against a
throwaway HTTP server on 127.0.0.1 inside the test process -- nothing about
the HTTP layer is mocked -- and use the file's own fake-resolver seam for the
DNS side. Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
from __future__ import annotations

import contextlib
import http.server
import io
import json
import logging
import os
import socket
import tempfile
import threading
import unittest
from dataclasses import dataclass
from unittest import mock

import check_dnsbl_blocklist as dnsbl

TARGET = "198.51.100.7"
# Stands in for the secret part of a ping URL. No test may ever see it in a
# log line, a stream, or an exception message.
PATH_TOKEN = "EXAMPLE-NOT-A-REAL-CHECK-0000"
SECRET_PATH = f"/{PATH_TOKEN}"


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    body: str
    content_type: str | None


class PingServer:
    """A real HTTP server on an ephemeral loopback port, recording every
    request it receives. `status` is what it answers; `redirect_to` turns the
    answer into a redirect; `stall` makes it hold the connection open past any
    client timeout."""

    def __init__(self, *, status: int = 200, redirect_to: str | None = None, stall: bool = False) -> None:
        self.requests: list[RecordedRequest] = []
        self._release = threading.Event()
        recorded = self.requests
        release = self._release

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                recorded.append(RecordedRequest(self.command, self.path, body, self.headers.get("Content-Type")))
                if stall:
                    release.wait(5)
                    return
                self.send_response(302 if redirect_to else status)
                if redirect_to:
                    self.send_header("Location", redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = _handle
            do_POST = _handle

            def log_message(self, format: str, *args: object) -> None:
                pass

        class QuietServer(http.server.ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

        self._server = QuietServer(("127.0.0.1", 0), Handler)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    def url(self, path: str = SECRET_PATH) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def __enter__(self) -> PingServer:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._release.set()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5)


def refused_port() -> int:
    """A loopback port with nothing listening on it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def resolver_listing_everything(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
    return dnsbl.ResolutionOutcome(ok=True, addresses=("127.0.0.2",))


def resolver_listing_nothing(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
    if hostname.startswith("2.0.0.127."):
        return dnsbl.ResolutionOutcome(ok=True, addresses=("127.0.0.2",))
    return dnsbl.ResolutionOutcome(ok=True, addresses=())


class _CollectingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []
        self._formatter = logging.Formatter("%(levelname)s %(message)s")

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self._formatter.format(record))


@dataclass(frozen=True)
class RunOutcome:
    exit_code: int
    log_lines: list[str]
    streams: str

    @property
    def log_text(self) -> str:
        return "\n".join(self.log_lines)


class MainRunTestCase(unittest.TestCase):
    """Runs main() against a fake resolver with every ambient input pinned:
    no real state file, no real env file, no inherited ping URL."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = self._tmp.name
        self.state_path = os.path.join(self.tmp_path, "state.json")
        self.env_file_path = os.path.join(self.tmp_path, "absent.env")

        environment = mock.patch.dict(os.environ, {"DNSBL_ENV_FILE": self.env_file_path})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("DNSBL_PING_URL", None)
        for name, value in (("TARGET_IP", TARGET), ("STATE_PATH", self.state_path)):
            patcher = mock.patch.object(dnsbl, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.logger = logging.getLogger("dnsbl-check")
        self.handler = _CollectingHandler()
        saved = (self.logger.handlers[:], self.logger.level, self.logger.propagate)
        self.logger.handlers[:] = [self.handler]
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        def restore() -> None:
            self.logger.handlers[:], self.logger.level, self.logger.propagate = saved

        self.addCleanup(restore)
        configure = mock.patch.object(dnsbl, "_configure_logging", return_value=self.logger)
        configure.start()
        self.addCleanup(configure.stop)

    def allow_plain_http(self) -> None:
        patcher = mock.patch.object(dnsbl, "ACCEPTED_PING_SCHEMES", frozenset({"https", "http"}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self, resolver, argv: list[str] | None = None) -> RunOutcome:
        self.handler.lines.clear()
        streams = io.StringIO()
        with mock.patch.object(dnsbl, "resolve_a_records", resolver):
            with contextlib.redirect_stdout(streams), contextlib.redirect_stderr(streams):
                exit_code = dnsbl.main([] if argv is None else argv)
        return RunOutcome(exit_code, list(self.handler.lines), streams.getvalue())

    def assert_url_not_leaked(self, outcome: RunOutcome, server: PingServer | None = None) -> None:
        everything = outcome.log_text + "\n" + outcome.streams
        self.assertNotIn(PATH_TOKEN, everything)
        if server is not None:
            self.assertNotIn(f"127.0.0.1:{server.port}", everything)
            self.assertNotIn(str(server.port), everything)

    def saved_state(self) -> dict[str, str]:
        with open(self.state_path, encoding="utf-8") as handle:
            return json.load(handle)


class ControlCaseTests(MainRunTestCase):
    """The control: a listed target must produce a /fail request that carries
    the NEW LISTING line, and a clean run must produce a bare-path request,
    over the real network stack."""

    def test_a_listing_pings_fail_with_the_new_listing_lines_as_the_body(self) -> None:
        self.allow_plain_http()
        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(resolver_listing_everything)

        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(len(server.requests), 1)
        request = server.requests[0]
        self.assertTrue(request.path.endswith("/fail"), request.path)
        self.assertEqual(request.path, f"{SECRET_PATH}/fail")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.content_type, "text/plain; charset=utf-8")
        self.assertIn("NEW LISTING: Spamhaus ZEN (zen.spamhaus.org)", request.body)
        self.assertIn(f"dnsbl check for {TARGET}: 5 of 5 list(s) need attention", request.body)
        self.assert_url_not_leaked(outcome, server)

    def test_a_clean_run_pings_the_bare_url_and_never_fail(self) -> None:
        self.allow_plain_http()
        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(resolver_listing_nothing)

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual([request.path for request in server.requests], [SECRET_PATH])
        self.assertFalse(any("/fail" in request.path for request in server.requests))
        self.assert_url_not_leaked(outcome, server)

    def test_inconclusive_findings_also_ping_fail(self) -> None:
        self.allow_plain_http()

        def dead_resolver(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
            return dnsbl.ResolutionOutcome(ok=False, error="timed out")

        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(dead_resolver)

        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(server.requests[0].path, f"{SECRET_PATH}/fail")
        self.assertIn("CHECK INCONCLUSIVE", server.requests[0].body)

    def test_a_query_string_on_the_url_survives_and_fail_is_added_to_the_path(self) -> None:
        self.allow_plain_http()
        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url(f"{SECRET_PATH}/?create=1")
            self.run_main(resolver_listing_everything)

        self.assertEqual(server.requests[0].path, f"{SECRET_PATH}/fail?create=1")

    def test_the_ping_happens_after_the_findings_are_logged_and_the_state_saved(self) -> None:
        self.allow_plain_http()
        observed: dict[str, object] = {}

        def inspect_at_ping_time(url: str, body: str, failed: bool) -> None:
            observed["state_saved"] = os.path.exists(self.state_path)
            observed["findings_logged"] = [line for line in self.handler.lines if "NEW LISTING" in line]

        os.environ["DNSBL_PING_URL"] = "http://127.0.0.1:1/unused"
        with mock.patch.object(dnsbl, "send_ping", inspect_at_ping_time):
            self.run_main(resolver_listing_everything)

        self.assertTrue(observed["state_saved"])
        self.assertEqual(len(observed["findings_logged"]), 5)


class CrashPathTests(MainRunTestCase):
    def test_a_crash_pings_fail_with_a_short_fixed_body_and_still_exits_one(self) -> None:
        self.allow_plain_http()

        def crashing_resolver(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
            raise RuntimeError("simulated crash")

        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(crashing_resolver)

        self.assertEqual(outcome.exit_code, 1)
        self.assertIn("dnsbl check crashed before completing", outcome.log_text)
        self.assertEqual(len(server.requests), 1)
        self.assertEqual(server.requests[0].path, f"{SECRET_PATH}/fail")
        self.assertEqual(server.requests[0].body, "dnsbl check crashed before completing")
        self.assertNotIn("simulated crash", server.requests[0].body)
        self.assert_url_not_leaked(outcome, server)

    def test_a_crash_while_resolving_the_target_also_pings_fail(self) -> None:
        self.allow_plain_http()
        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            with mock.patch.object(dnsbl, "TARGET_IP", ""):
                with mock.patch.object(dnsbl, "resolve_target_address", side_effect=socket.gaierror("no host")):
                    outcome = self.run_main(resolver_listing_nothing)

        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(server.requests[0].path, f"{SECRET_PATH}/fail")

    def test_a_failing_ping_on_the_crash_path_cannot_escape_the_handler(self) -> None:
        self.allow_plain_http()

        def crashing_resolver(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
            raise RuntimeError("simulated crash")

        os.environ["DNSBL_PING_URL"] = f"http://127.0.0.1:{refused_port()}{SECRET_PATH}"
        outcome = self.run_main(crashing_resolver)

        self.assertEqual(outcome.exit_code, 1)
        self.assertIn("alert forwarding failed", outcome.log_text)
        self.assert_url_not_leaked(outcome)


class CorruptStateTests(MainRunTestCase):
    def test_a_corrupt_state_file_is_logged_and_the_run_still_reports_the_same_way(self) -> None:
        self.allow_plain_http()
        with open(self.state_path, "w", encoding="utf-8") as handle:
            handle.write("{not json")

        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            listed = self.run_main(resolver_listing_everything)
            with open(self.state_path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            clean = self.run_main(resolver_listing_nothing)

        self.assertIn("state file", listed.log_text)
        self.assertIn("unreadable", listed.log_text)
        self.assertEqual((listed.exit_code, clean.exit_code), (1, 0))
        self.assertEqual([request.path for request in server.requests], [f"{SECRET_PATH}/fail", SECRET_PATH])
        self.assertIn("NEW LISTING", server.requests[0].body)
        self.assertEqual(self.saved_state()["spamhaus_zen"], "not_listed")


class ForwarderContainmentTests(MainRunTestCase):
    """Failure of the forwarder must change nothing about the check itself,
    and must never put the URL anywhere."""

    def assert_check_unaffected(self, outcome: RunOutcome, expected_exit: int, expected_verdict: str) -> None:
        self.assertEqual(outcome.exit_code, expected_exit)
        self.assertEqual(self.saved_state()["spamhaus_zen"], expected_verdict)
        self.assertIn("ERROR dnsbl alert forwarding failed", outcome.log_text)

    def test_connection_refused_leaves_exit_code_state_and_findings_intact(self) -> None:
        self.allow_plain_http()
        os.environ["DNSBL_PING_URL"] = f"http://127.0.0.1:{refused_port()}{SECRET_PATH}"
        listed = self.run_main(resolver_listing_everything)
        clean = self.run_main(resolver_listing_nothing)

        self.assert_check_unaffected(clean, 0, "not_listed")
        self.assertIn("ConnectionRefusedError", clean.log_text)
        self.assertEqual(len([line for line in listed.log_lines if line.startswith("ERROR NEW LISTING")]), 5)
        self.assertEqual(listed.exit_code, 1)
        self.assert_url_not_leaked(listed)
        self.assert_url_not_leaked(clean)

    def test_a_timeout_leaves_exit_code_and_state_intact_and_is_bounded(self) -> None:
        self.allow_plain_http()
        with mock.patch.object(dnsbl, "PING_TIMEOUT_SECONDS", 0.3):
            with PingServer(stall=True) as server:
                os.environ["DNSBL_PING_URL"] = server.url()
                outcome = self.run_main(resolver_listing_everything)

        self.assert_check_unaffected(outcome, 1, "listed")
        self.assertEqual(len(server.requests), 1)
        self.assert_url_not_leaked(outcome, server)

    def test_an_http_error_status_leaves_exit_code_and_state_intact(self) -> None:
        self.allow_plain_http()
        with PingServer(status=500) as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(resolver_listing_nothing)

        self.assert_check_unaffected(outcome, 0, "not_listed")
        self.assertIn("HTTP 500", outcome.log_text)
        self.assert_url_not_leaked(outcome, server)

    def test_a_redirect_is_refused_not_followed(self) -> None:
        self.allow_plain_http()
        with PingServer() as target:
            with PingServer(redirect_to=target.url("/elsewhere")) as redirector:
                os.environ["DNSBL_PING_URL"] = redirector.url()
                outcome = self.run_main(resolver_listing_everything)

        self.assertEqual(len(redirector.requests), 1)
        self.assertEqual(target.requests, [])
        self.assert_check_unaffected(outcome, 1, "listed")
        self.assert_url_not_leaked(outcome, redirector)

    def test_proxy_environment_variables_are_ignored(self) -> None:
        self.allow_plain_http()
        dead_proxy = f"http://127.0.0.1:{refused_port()}"
        with mock.patch.dict(os.environ, {"http_proxy": dead_proxy, "HTTP_PROXY": dead_proxy}):
            with PingServer() as server:
                os.environ["DNSBL_PING_URL"] = server.url()
                outcome = self.run_main(resolver_listing_nothing)

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(len(server.requests), 1)

    def test_an_unexpected_exception_from_the_sender_is_contained_and_never_echoed(self) -> None:
        self.allow_plain_http()
        url = f"http://127.0.0.1:1{SECRET_PATH}"
        os.environ["DNSBL_PING_URL"] = url
        with mock.patch.object(dnsbl, "send_ping", side_effect=RuntimeError(f"exploded talking to {url}")):
            outcome = self.run_main(resolver_listing_everything)

        self.assert_check_unaffected(outcome, 1, "listed")
        self.assertIn("RuntimeError", outcome.log_text)
        self.assertNotIn("exploded", outcome.log_text)
        self.assert_url_not_leaked(outcome)

    def test_a_malformed_url_that_passes_the_scheme_check_is_contained(self) -> None:
        self.allow_plain_http()
        os.environ["DNSBL_PING_URL"] = f"http://127.0.0.1:99999{SECRET_PATH}"
        outcome = self.run_main(resolver_listing_nothing)

        self.assertEqual(outcome.exit_code, 0)
        self.assertIn("alert forwarding failed", outcome.log_text)
        self.assert_url_not_leaked(outcome)

    def test_the_timeout_constant_is_at_most_ten_seconds(self) -> None:
        self.assertLessEqual(dnsbl.PING_TIMEOUT_SECONDS, 10)


class NotConfiguredTests(MainRunTestCase):
    def assert_one_not_configured_error(self, outcome: RunOutcome) -> None:
        matching = [line for line in outcome.log_lines if "alert forwarding is not configured" in line]
        self.assertEqual(len(matching), 1, outcome.log_lines)
        self.assertTrue(matching[0].startswith("ERROR "))

    def test_unset_url_logs_one_error_per_run_and_changes_no_exit_code(self) -> None:
        listed = self.run_main(resolver_listing_everything)
        clean = self.run_main(resolver_listing_nothing)

        self.assert_one_not_configured_error(listed)
        self.assert_one_not_configured_error(clean)
        self.assertEqual((listed.exit_code, clean.exit_code), (1, 0))

    def test_a_crash_with_no_url_also_logs_not_configured_and_exits_one(self) -> None:
        def crashing_resolver(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
            raise RuntimeError("simulated crash")

        outcome = self.run_main(crashing_resolver)

        self.assertEqual(outcome.exit_code, 1)
        self.assert_one_not_configured_error(outcome)

    def test_production_accepts_https_only(self) -> None:
        self.assertEqual(dnsbl.ACCEPTED_PING_SCHEMES, frozenset({"https"}))

    def test_a_plain_http_url_is_refused_as_not_configured_and_nothing_is_sent(self) -> None:
        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(resolver_listing_everything)

        self.assertEqual(server.requests, [])
        self.assertEqual(outcome.exit_code, 1)
        self.assert_one_not_configured_error(outcome)
        self.assert_url_not_leaked(outcome, server)

    def test_other_wrong_urls_are_refused_without_echoing_them(self) -> None:
        for wrong in (
            f"ftp://example.invalid{SECRET_PATH}",
            f"file:///etc/{PATH_TOKEN}",
            f"https://{SECRET_PATH}",
            f"//example.invalid{SECRET_PATH}",
            PATH_TOKEN,
            f"https://example.invalid{SECRET_PATH} extra",
        ):
            with self.subTest(wrong=wrong):
                os.environ["DNSBL_PING_URL"] = wrong
                outcome = self.run_main(resolver_listing_nothing)
                self.assertEqual(outcome.exit_code, 0)
                self.assert_one_not_configured_error(outcome)
                self.assert_url_not_leaked(outcome)

    def test_an_empty_variable_counts_as_unset(self) -> None:
        os.environ["DNSBL_PING_URL"] = ""
        outcome = self.run_main(resolver_listing_nothing)
        self.assert_one_not_configured_error(outcome)


class StatusTests(MainRunTestCase):
    def test_status_queries_nothing_and_pings_nothing(self) -> None:
        self.allow_plain_http()

        def forbidden_resolver(hostname: str, timeout: int) -> dnsbl.ResolutionOutcome:
            raise AssertionError("--status must not query DNS")

        with open(self.state_path, "w", encoding="utf-8") as handle:
            json.dump({"spamhaus_zen": "listed"}, handle)
        with PingServer() as server:
            os.environ["DNSBL_PING_URL"] = server.url()
            outcome = self.run_main(forbidden_resolver, ["--status"])

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(server.requests, [])
        self.assertEqual(outcome.log_lines, [])
        self.assertIn("Spamhaus ZEN\tlisted", outcome.streams)


class EnvFileTests(MainRunTestCase):
    def write_env_file(self, content: str, mode: int = 0o600, name: str = "dnsbl-check.env") -> str:
        path = os.path.join(self.tmp_path, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, mode)
        return path

    def test_the_file_supplies_the_url_when_the_variable_is_unset(self) -> None:
        self.allow_plain_http()
        with PingServer() as server:
            os.environ["DNSBL_ENV_FILE"] = self.write_env_file(
                "# comment\n\n  OTHER_KEY = ignored  \n"
                f"  DNSBL_PING_URL = {server.url()}  \nDNSBL_PING_URL_EXTRA=ignored\n"
            )
            outcome = self.run_main(resolver_listing_nothing)

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual([request.path for request in server.requests], [SECRET_PATH])

    def test_the_variable_wins_over_the_file(self) -> None:
        self.allow_plain_http()
        with PingServer() as from_variable, PingServer() as from_file:
            os.environ["DNSBL_PING_URL"] = from_variable.url("/from-variable")
            os.environ["DNSBL_ENV_FILE"] = self.write_env_file(f"DNSBL_PING_URL={from_file.url('/from-file')}\n")
            self.run_main(resolver_listing_nothing)

        self.assertEqual(len(from_variable.requests), 1)
        self.assertEqual(from_file.requests, [])

    def test_matching_quotes_are_stripped_and_nothing_is_expanded(self) -> None:
        path = self.write_env_file('DNSBL_PING_URL="https://example.invalid/$HOME"\n')
        self.assertEqual(dnsbl.read_env_file_value(path, "DNSBL_PING_URL"), "https://example.invalid/$HOME")

    def test_a_missing_file_is_just_unset(self) -> None:
        self.assertIsNone(dnsbl.read_env_file_value(self.env_file_path, "DNSBL_PING_URL"))
        self.assertIsNone(dnsbl.resolve_ping_url({"DNSBL_ENV_FILE": self.env_file_path}))

    def test_a_file_without_the_key_is_just_unset(self) -> None:
        path = self.write_env_file("OTHER=1\n")
        self.assertIsNone(dnsbl.read_env_file_value(path, "DNSBL_PING_URL"))

    def test_a_symbolic_link_is_refused(self) -> None:
        real = self.write_env_file(f"DNSBL_PING_URL=https://example.invalid{SECRET_PATH}\n", name="real.env")
        link = os.path.join(self.tmp_path, "link.env")
        os.symlink(real, link)
        with self.assertRaises(dnsbl.PingConfigurationError) as raised:
            dnsbl.read_env_file_value(link, "DNSBL_PING_URL")
        self.assertIn("symbolic link", str(raised.exception))

    def test_a_fifo_is_refused_without_hanging(self) -> None:
        fifo = os.path.join(self.tmp_path, "fifo.env")
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(dnsbl.PingConfigurationError) as raised:
            dnsbl.read_env_file_value(fifo, "DNSBL_PING_URL")
        self.assertIn("not a regular file", str(raised.exception))

    def test_a_directory_is_refused(self) -> None:
        directory = os.path.join(self.tmp_path, "directory.env")
        os.mkdir(directory, 0o700)
        with self.assertRaises(dnsbl.PingConfigurationError) as raised:
            dnsbl.read_env_file_value(directory, "DNSBL_PING_URL")
        self.assertIn("not a regular file", str(raised.exception))

    def test_a_file_readable_by_group_or_other_is_refused(self) -> None:
        for mode in (0o640, 0o604, 0o644, 0o660):
            with self.subTest(mode=oct(mode)):
                path = self.write_env_file(f"DNSBL_PING_URL=https://example.invalid{SECRET_PATH}\n", mode)
                with self.assertRaises(dnsbl.PingConfigurationError) as raised:
                    dnsbl.read_env_file_value(path, "DNSBL_PING_URL")
                self.assertIn("readable by group or other", str(raised.exception))

    def test_a_file_owned_by_someone_else_is_refused(self) -> None:
        path = self.write_env_file("DNSBL_PING_URL=https://example.invalid/x\n")
        with mock.patch.object(dnsbl.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(dnsbl.PingConfigurationError) as raised:
                dnsbl.read_env_file_value(path, "DNSBL_PING_URL")
        self.assertIn("not owned by the running user", str(raised.exception))

    def test_an_oversize_file_is_refused(self) -> None:
        path = self.write_env_file("# " + "x" * (dnsbl.ENV_FILE_MAX_BYTES + 1) + "\nDNSBL_PING_URL=https://example.invalid/x\n")
        with self.assertRaises(dnsbl.PingConfigurationError) as raised:
            dnsbl.read_env_file_value(path, "DNSBL_PING_URL")
        self.assertIn("larger than", str(raised.exception))

    def test_a_file_that_is_not_text_is_refused(self) -> None:
        path = os.path.join(self.tmp_path, "binary.env")
        with open(path, "wb") as handle:
            handle.write(b"DNSBL_PING_URL=\xff\xfe\n")
        os.chmod(path, 0o600)
        with self.assertRaises(dnsbl.PingConfigurationError):
            dnsbl.read_env_file_value(path, "DNSBL_PING_URL")

    def test_an_unreadable_file_is_refused(self) -> None:
        path = self.write_env_file("DNSBL_PING_URL=https://example.invalid/x\n")
        with mock.patch.object(dnsbl.os, "open", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(dnsbl.PingConfigurationError) as raised:
                dnsbl.read_env_file_value(path, "DNSBL_PING_URL")
        self.assertIn("cannot be opened", str(raised.exception))

    def test_a_refused_file_logs_not_configured_without_its_contents_and_sends_nothing(self) -> None:
        self.allow_plain_http()
        with PingServer() as server:
            os.environ["DNSBL_ENV_FILE"] = self.write_env_file(
                f"DNSBL_PING_URL={server.url()}\n", mode=0o644
            )
            outcome = self.run_main(resolver_listing_everything)

        self.assertEqual(server.requests, [])
        self.assertEqual(outcome.exit_code, 1)
        matching = [line for line in outcome.log_lines if "alert forwarding is not configured" in line]
        self.assertEqual(len(matching), 1)
        self.assertIn("readable by group or other", matching[0])
        self.assert_url_not_leaked(outcome, server)


class BodyTruncationTests(unittest.TestCase):
    def test_a_long_body_is_cut_to_the_limit_on_a_character_boundary(self) -> None:
        body = "é" * dnsbl.PING_BODY_LIMIT_BYTES
        truncated = dnsbl.truncate_ping_body(body)
        self.assertLessEqual(len(truncated), dnsbl.PING_BODY_LIMIT_BYTES)
        truncated.decode("utf-8")

    def test_a_short_body_is_unchanged(self) -> None:
        self.assertEqual(dnsbl.truncate_ping_body("short"), b"short")


if __name__ == "__main__":
    unittest.main()
