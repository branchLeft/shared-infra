#!/usr/bin/env python3
"""Unit tests for list_and_clear_blocked_ips.py's selection logic -- no
network access, no live server needed. Run with: python3 -m unittest
discover -s mail/provision -p 'test_*.py' -v
"""
import base64
import http.client
import io
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

import list_and_clear_blocked_ips as lc
from list_and_clear_blocked_ips import select_ids_to_clear

# Documentation-range addresses (RFC 5737). A blocked-IP list is a record of
# somebody else's host, so a real one never becomes a committed fixture.
OPERATOR_IP = "198.51.100.7"
SCANNER_IP = "198.51.100.42"
ABUSE_IP = "198.51.100.99"
UNBLOCKED_IP = "198.51.100.100"

BLOCKED = [
    {"id": "b1", "address": OPERATOR_IP, "reason": "portScanning"},
    {"id": "b2", "address": SCANNER_IP, "reason": "portScanning"},
    {"id": "b3", "address": ABUSE_IP, "reason": "abuseDetected"},
]


class SelectIdsToClearTests(unittest.TestCase):
    def test_all_selects_every_id(self):
        self.assertCountEqual(select_ids_to_clear(BLOCKED, [], [], True), ["b1", "b2", "b3"])

    def test_single_ip_selects_only_its_id(self):
        self.assertEqual(select_ids_to_clear(BLOCKED, [OPERATOR_IP], [], False), ["b1"])

    def test_multiple_ips_select_their_ids_only(self):
        # The scenario this design exists for: a genuine scanner (b2) stays
        # blocked while an operator's own false-positive (b1) is cleared --
        # selecting by explicit address, never by "all".
        result = select_ids_to_clear(BLOCKED, [OPERATOR_IP], [], False)
        self.assertEqual(result, ["b1"])
        self.assertNotIn("b2", result)

    def test_neither_all_nor_ip_nor_reason_is_refused(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [], [], False)

    def test_all_and_ip_together_is_refused(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [OPERATOR_IP], [], True)

    def test_all_and_reason_together_is_refused(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [], ["portScanning"], True)

    def test_ip_not_currently_blocked_is_refused_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, ["1.2.3.4"], [], False)

    def test_all_on_empty_blocked_list_selects_nothing(self):
        self.assertEqual(select_ids_to_clear([], [], [], True), [])

    def test_reason_selects_every_matching_entry(self):
        # The accumulated-portScanning case this flag exists for: both
        # entries sharing that reason are selected in one command, the
        # unrelated abuseDetected entry (b3) is left alone.
        result = select_ids_to_clear(BLOCKED, [], ["portScanning"], False)
        self.assertCountEqual(result, ["b1", "b2"])
        self.assertNotIn("b3", result)

    def test_reason_matching_nothing_is_refused_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [], ["typoedReason"], False)

    def test_ip_and_reason_together_is_a_union(self):
        # b3 (abuseDetected) selected by --reason, plus OPERATOR_IP (b1,
        # portScanning) selected explicitly by --ip -- neither selector
        # excludes the other's match.
        result = select_ids_to_clear(BLOCKED, [OPERATOR_IP], ["abuseDetected"], False)
        self.assertCountEqual(result, ["b1", "b3"])

    def test_valid_ip_does_not_mask_a_typoed_reason(self):
        # The exact masking bug this fix closes: a valid --ip matching
        # something must not let a typo'd --reason matching nothing pass
        # silently, since the union used to only check combined emptiness.
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [OPERATOR_IP], ["typoedReasonXYZ"], False)

    def test_valid_reason_does_not_mask_a_typoed_ip(self):
        # Mirror case: a valid --reason matching something must not let a
        # typo'd --ip pass silently either.
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [UNBLOCKED_IP], ["portScanning"], False)


SECRET_VALUE = "TEST_SECRET_VALUE"
UNREACHABLE_BASE_URL = "http://127.0.0.1:1"
SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "list_and_clear_blocked_ips.py")
FORBIDDEN_SERVER_BLAME = ("restarting", "reach", "not answering")


def _write_credentials_file(test: unittest.TestCase) -> str:
    temp_directory = tempfile.TemporaryDirectory()
    test.addCleanup(temp_directory.cleanup)
    path = os.path.join(temp_directory.name, "stalwart-admin-credentials")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"testadmin:{SECRET_VALUE}\n")
    return path


class RunReportsFailureAsOneLineTests(unittest.TestCase):
    """run() turns a failed API call into one stderr line and exit status 1,
    classified by what the failure says about the server: no answer (network),
    an answer with an error status (HTTP), or a local problem such as a missing
    file or binary. Each test fails inside the real _jmap_call by faking only
    urlopen, so the Authorization header is built before the failure.
    """

    def setUp(self):
        self.credentials_path = _write_credentials_file(self)
        for name, value in (("CREDENTIALS_PATH", self.credentials_path), ("BASE_URL", UNREACHABLE_BASE_URL)):
            patcher = mock.patch.object(lc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        argv_patcher = mock.patch.object(sys, "argv", ["list_and_clear_blocked_ips.py", "--list-only"])
        argv_patcher.start()
        self.addCleanup(argv_patcher.stop)

    def _run_with_urlopen_raising(self, exc: BaseException) -> tuple[int, str]:
        with mock.patch("urllib.request.urlopen", side_effect=exc):
            with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                status = lc.run()
        return status, stderr.getvalue()

    def test_network_failures_print_one_line_naming_the_endpoint_and_exit_1(self):
        direct = [
            ConnectionResetError(104, "connection reset by peer"),
            ConnectionRefusedError(111, "connection refused"),
            ConnectionAbortedError(103, "connection aborted"),
            BrokenPipeError(32, "broken pipe"),
            TimeoutError("timed out"),
        ]
        gaierror = socket.gaierror(-2, "Name or service not known")
        cases = [
            *direct,
            http.client.RemoteDisconnected("Remote end closed connection without response"),
            http.client.IncompleteRead(b"partial", 10),
            gaierror,
            *[urllib.error.URLError(inner) for inner in (*direct, gaierror)],
        ]
        for exc in cases:
            with self.subTest(exception=repr(exc)):
                status, output = self._run_with_urlopen_raising(exc)

                self.assertEqual(status, 1)
                self.assertEqual(len(output.splitlines()), 1, output)
                self.assertIn(UNREACHABLE_BASE_URL, output)
                self.assertIn("restarting", output)
                inner = exc.reason if isinstance(exc, urllib.error.URLError) else exc
                self.assertIn(type(inner).__name__, output)

    def test_an_http_error_status_says_the_server_answered(self):
        exc = urllib.error.HTTPError(f"{UNREACHABLE_BASE_URL}/jmap", 401, "Unauthorized", {}, None)

        status, output = self._run_with_urlopen_raising(exc)

        self.assertEqual(status, 1)
        self.assertEqual(len(output.splitlines()), 1, output)
        self.assertIn("401", output)
        self.assertIn(UNREACHABLE_BASE_URL, output)
        for forbidden in FORBIDDEN_SERVER_BLAME:
            self.assertNotIn(forbidden, output)

    def test_a_local_file_error_is_not_blamed_on_the_server(self):
        temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temp_directory.cleanup)
        cases = {
            "missing credentials file": ("FileNotFoundError", os.path.join(temp_directory.name, "absent")),
            "credentials path is a directory": ("IsADirectoryError", temp_directory.name),
        }
        for name, (class_name, credentials_path) in cases.items():
            with self.subTest(case=name):
                with mock.patch.object(lc, "CREDENTIALS_PATH", credentials_path):
                    with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        status = lc.run()
                output = stderr.getvalue()

                self.assertEqual(status, 1)
                self.assertEqual(len(output.splitlines()), 1, output)
                self.assertIn(class_name, output)
                self.assertIn(credentials_path, output)
                for forbidden in FORBIDDEN_SERVER_BLAME:
                    self.assertNotIn(forbidden, output)

    def test_the_line_is_one_line_even_if_the_exception_text_has_a_newline(self):
        status, output = self._run_with_urlopen_raising(ConnectionResetError("reset\nby\npeer"))

        self.assertEqual(status, 1)
        self.assertEqual(len(output.splitlines()), 1, output)
        self.assertIn("reset by peer", output)

    def test_the_credential_never_appears_in_the_line(self):
        _, output = self._run_with_urlopen_raising(ConnectionResetError(104, "connection reset by peer"))

        encoded = base64.b64encode(f"testadmin:{SECRET_VALUE}".encode()).decode()
        self.assertNotIn(SECRET_VALUE, output)
        self.assertNotIn(encoded, output)
        self.assertNotIn("Authorization", output)

    def test_other_failures_keep_propagating(self):
        with mock.patch.object(lc, "main", side_effect=RuntimeError("x:BlockedIp/get failed")):
            with self.assertRaises(RuntimeError):
                lc.run()

    def test_a_successful_main_returns_its_status_unchanged(self):
        with mock.patch.object(lc, "main", return_value=0):
            self.assertEqual(lc.run(), 0)


class ReloadFailureAfterDestroyTests(unittest.TestCase):
    """The destroy removes the entries from the registry, but the block is
    enforced from a cache that only the reload clears; a failed reload must
    say so instead of advising a re-run, which would report nothing to clear.
    """

    BLOCKED_LIST = {
        "list": [
            {"id": "b1", "address": "198.51.100.7", "reason": "portScanning", "createdAt": "2026-01-01T00:00:00Z"}
        ]
    }

    def setUp(self):
        self.credentials_path = _write_credentials_file(self)
        for name, value in (("CREDENTIALS_PATH", self.credentials_path), ("BASE_URL", UNREACHABLE_BASE_URL)):
            patcher = mock.patch.object(lc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        argv_patcher = mock.patch.object(sys, "argv", ["list_and_clear_blocked_ips.py", "--ip", "198.51.100.7"])
        argv_patcher.start()
        self.addCleanup(argv_patcher.stop)

    def _run_with_reload_raising(self, exc: BaseException) -> tuple[int, str, mock.Mock]:
        with mock.patch.object(lc, "_jmap_call", side_effect=[self.BLOCKED_LIST, {}, exc]) as jmap_call:
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    status = lc.run()
        return status, stderr.getvalue(), jmap_call

    def _assert_one_line_about_the_unreloaded_block(self, status: int, output: str, class_name: str) -> None:
        self.assertEqual(status, 1)
        self.assertEqual(len(output.splitlines()), 1, output)
        self.assertIn("already deleted", output)
        self.assertIn("not reloaded", output)
        self.assertIn(class_name, output)
        self.assertNotIn("run it again", output)
        self.assertNotIn(SECRET_VALUE, output)

    def test_a_reload_failure_after_the_destroy_says_the_entries_are_already_deleted(self):
        status, output, jmap_call = self._run_with_reload_raising(ConnectionResetError(104, "reset"))

        self.assertEqual(jmap_call.call_count, 3)
        self._assert_one_line_about_the_unreloaded_block(status, output, "ConnectionResetError")
        self.assertIn("reset", output)

    def test_a_reload_http_error_after_the_destroy_says_the_entries_are_already_deleted(self):
        exc = urllib.error.HTTPError(f"{UNREACHABLE_BASE_URL}/jmap", 500, "Internal Server Error", {}, None)

        status, output, _ = self._run_with_reload_raising(exc)

        self._assert_one_line_about_the_unreloaded_block(status, output, "HTTPError")
        self.assertIn("500", output)

    def test_a_failed_destroy_still_gets_the_generic_advice(self):
        with mock.patch.object(
            lc, "_jmap_call", side_effect=[self.BLOCKED_LIST, ConnectionResetError(104, "reset")]
        ):
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    status = lc.run()
        output = stderr.getvalue()

        self.assertEqual(status, 1)
        self.assertEqual(len(output.splitlines()), 1, output)
        self.assertIn("run it again", output)
        self.assertNotIn("already deleted", output)

    def test_a_reload_runtime_error_keeps_propagating(self):
        with mock.patch.object(
            lc, "_jmap_call", side_effect=[self.BLOCKED_LIST, {}, RuntimeError("x:Action/set failed")]
        ):
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaises(RuntimeError):
                    lc.run()


class RealRunEndToEndTests(unittest.TestCase):
    def _run_script(self, environment_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, SCRIPT_PATH, "--list-only"],
            env=dict(os.environ, **environment_overrides),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_a_missing_credentials_file_is_reported_as_one_line_in_a_real_run(self):
        temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temp_directory.cleanup)
        missing_path = os.path.join(temp_directory.name, "absent-credentials")

        completed = self._run_script({"STALWART_CREDENTIALS_PATH": missing_path})

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(completed.stderr.splitlines()), 1, completed.stderr)
        self.assertIn("FileNotFoundError", completed.stderr)
        self.assertIn(missing_path, completed.stderr)
        self.assertNotIn("restarting", completed.stderr)


class ConnectionResetEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.credentials_path = _write_credentials_file(self)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.listener.settimeout(0.2)
        self.stop_accepting = threading.Event()
        thread = threading.Thread(target=self._accept_and_reset_until_stopped, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.stop_accepting.set)

    def _accept_and_reset_until_stopped(self) -> None:
        while not self.stop_accepting.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            connection.close()

    def test_a_real_connection_reset_is_reported_as_one_line(self):
        port = self.listener.getsockname()[1]
        environment = dict(
            os.environ,
            STALWART_BASE_URL=f"http://127.0.0.1:{port}",
            STALWART_CREDENTIALS_PATH=self.credentials_path,
        )

        completed = subprocess.run(
            [sys.executable, SCRIPT_PATH, "--list-only"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(completed.stderr.splitlines()), 1, completed.stderr)
        self.assertIn("restarting", completed.stderr)


if __name__ == "__main__":
    unittest.main()
