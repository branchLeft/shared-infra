"""Unit tests for the program that asks whether Stalwart is still in bootstrap mode.

The program is run against a real HTTP server on a loopback port that these tests start, so each
test says what the program asked, what it sent and what it printed. The one property that
matters is that only a clear "not in bootstrap mode" exits 0: a doubt of any kind must not.
"""

import base64
import contextlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import check_stalwart_bootstrap_mode as probe

PROGRAM = Path(__file__).resolve().parents[2] / "files" / "check_stalwart_bootstrap_mode.py"
USER = "admin"
SECRET = "SECRETVALUE-9a1:with-a-colon"  # noqa: S105 - a throwaway for this test only


@contextlib.contextmanager
def _server(status: int, body: bytes) -> Iterator[tuple[str, list[str]]]:
    """Serve one fixed answer on a loopback port; yield its base URL and the requests it saw."""
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - the name the server calls
            seen.append(f"{self.path} {self.headers.get('Authorization', '')}")
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _answer(permissions: object) -> bytes:
    return json.dumps({"permissions": permissions}).encode()


def _run(base_url: str, credentials: str | None = f"{USER}:{SECRET}\n") -> tuple[int, str]:
    """Run the program in this process with a credential file; return its status and output."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, "credentials")
        if credentials is not None:
            path.write_text(credentials, encoding="utf-8")
        environment = {"STALWART_CREDENTIALS_PATH": str(path), "STALWART_BASE_URL": base_url}
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            status = probe.run(environment)
    return status, printed.getvalue()


class ModeTests(unittest.TestCase):
    def test_only_the_bootstrap_permission_is_bootstrap_mode(self) -> None:
        self.assertTrue(probe.is_bootstrap_mode({"permissions": ["a", "sysBootstrapUpdate"]}))
        self.assertFalse(probe.is_bootstrap_mode({"permissions": []}))
        self.assertFalse(probe.is_bootstrap_mode({"permissions": ["sysBootstrapUpdateX", "a"]}))

    def test_an_answer_with_no_permissions_is_not_bootstrap_mode_as_the_program_reads_it(
        self,
    ) -> None:
        self.assertFalse(probe.is_bootstrap_mode({}))

    def test_an_answer_of_the_wrong_shape_cannot_be_told(self) -> None:
        answers: tuple[object, ...] = (
            None,
            [],
            "sysBootstrapUpdate",
            7,
            {"permissions": "sysBootstrapUpdate"},
            {"permissions": {"sysBootstrapUpdate": True}},
            {"permissions": [1, "sysBootstrapUpdate"]},
            {"permissions": None},
        )
        for answer in answers:
            with self.assertRaises(probe.CannotTellError, msg=repr(answer)):
                probe.is_bootstrap_mode(answer)


class CredentialTests(unittest.TestCase):
    def _read(self, text: str) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials")
            path.write_text(text, encoding="utf-8")
            return probe.read_credentials(str(path))

    def test_the_file_is_split_at_the_first_colon_and_trimmed(self) -> None:
        self.assertEqual(self._read(f"{USER}:{SECRET}\n"), (USER, SECRET))

    def test_a_file_that_is_not_user_and_secret_is_refused_without_naming_its_content(self) -> None:
        for text in ("", "\n", "nocolon-SECRETVALUE", ":SECRETVALUE", "admin:"):
            with self.assertRaises(probe.CannotTellError, msg=repr(text)) as raised:
                self._read(text)
            self.assertNotIn("SECRETVALUE", str(raised.exception))


class RunTests(unittest.TestCase):
    def test_a_server_not_in_bootstrap_mode_exits_0_and_the_credential_is_sent_as_basic_auth(
        self,
    ) -> None:
        with _server(200, _answer(["authenticate"])) as (url, seen):
            status, output = _run(url)
        self.assertEqual(status, 0)
        self.assertIn("not in bootstrap mode", output)
        self.assertEqual(len(seen), 1)
        path, _, header = seen[0].partition(" ")
        self.assertEqual(path, "/api/account")
        token = base64.b64encode(f"{USER}:{SECRET}".encode()).decode()
        self.assertEqual(header, f"Basic {token}")

    def test_a_server_in_bootstrap_mode_exits_3(self) -> None:
        with _server(200, _answer(["authenticate", "sysBootstrapUpdate"])) as (url, seen):
            status, output = _run(url)
        self.assertEqual(status, 3)
        self.assertIn("REFUSED, nothing written: Stalwart is in bootstrap mode", output)
        self.assertEqual(len(seen), 1)

    def test_every_doubt_exits_2_never_0(self) -> None:
        for status_code, body in (
            (500, b"{}"),
            (401, _answer([])),
            (200, b"not json"),
            (200, b""),
            (200, b'["sysBootstrapUpdate"]'),
            (200, _answer("sysBootstrapUpdate")),
        ):
            with _server(status_code, body) as (url, _):
                status, output = _run(url)
            self.assertEqual(status, 2, f"{status_code} {body!r}")
            self.assertIn("REFUSED, nothing written: could not tell", output)

    def test_no_file_a_bad_file_no_listener_and_a_non_loopback_address_exit_2(self) -> None:
        with _server(200, _answer([])) as (url, seen):
            self.assertEqual(_run(url, credentials=None)[0], 2)
            self.assertEqual(_run(url, credentials="nocolon")[0], 2)
            self.assertEqual(seen, [], "a file that cannot be read makes no request")
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        self.assertEqual(_run(f"http://127.0.0.1:{port}")[0], 2)
        with _server(200, _answer([])) as (url, seen):
            for address in (url.replace("127.0.0.1", "localhost"), "https://127.0.0.1:1", ""):
                self.assertEqual(_run(address)[0], 2, address)
            self.assertEqual(seen, [], "an address that is not loopback gets no request")

    def test_nothing_it_prints_holds_the_credential_or_the_answer(self) -> None:
        for status_code, body in ((200, _answer(["sysBootstrapUpdate"])), (500, b"BODYSECRET")):
            with _server(status_code, body) as (url, _):
                _, output = _run(url)
            for needle in (SECRET, "SECRETVALUE", "BODYSECRET", "authenticate"):
                self.assertNotIn(needle, output)

    def test_run_as_the_host_runs_it_the_status_and_one_line_are_the_whole_output(self) -> None:
        self.assertEqual(
            PROGRAM.read_text(encoding="utf-8").splitlines()[0], "#!/usr/bin/python3 -I"
        )
        with (
            _server(200, _answer(["sysBootstrapUpdate"])) as (url, _),
            tempfile.TemporaryDirectory() as d,
        ):
            path = Path(d, "credentials")
            path.write_text(f"{USER}:{SECRET}\n", encoding="utf-8")
            done = subprocess.run(  # noqa: S603 - this interpreter, over the program under test
                [sys.executable, "-I", str(PROGRAM)],
                env={"STALWART_CREDENTIALS_PATH": str(path), "STALWART_BASE_URL": url},
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(done.returncode, 3)
        self.assertEqual(done.stderr, "")
        self.assertEqual(len(done.stdout.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
