"""Unit tests for the abuse-report page program, run with no network and no Stalwart.

A fake answers Stalwart's JMAP and the pager, records every request, and can be told to refuse,
so each test says what was asked of whom and what was written.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import yaml

PROGRAM = Path(__file__).resolve().parents[2] / "files" / "branchleft_abuse_page.py"
_spec = importlib.util.spec_from_file_location("branchleft_abuse_page", PROGRAM)
if _spec is None or _spec.loader is None:
    raise ImportError(str(PROGRAM))
page = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = page
_spec.loader.exec_module(page)

TOKEN = "tk_" + "m" * 29
ADMIN = ("admin", "admin-secret-for-tests")
DOMAIN_ID = "d1"
ACCOUNT_ID = "a-abuse"


def body_of(request: urllib.request.Request) -> bytes:
    data = request.data
    if not isinstance(data, bytes):
        raise TypeError("the request had no body")
    return data


class FakeWorld:
    """Stalwart and the pager in one callable, with the mailbox's ids newest first."""

    def __init__(self, ids: list[str]) -> None:
        self.ids = ids
        self.requests: list[urllib.request.Request] = []
        self.pager_status = 200
        self.pager_body = b'{"id":"msg1","event":"message"}'
        self.pager_error = False
        self.methods: list[str] = []
        self.domains: list[dict[str, str]] = [{"id": DOMAIN_ID, "name": "branchleft.co.uk"}]
        self.accounts: list[dict[str, str]] = [
            {"id": ACCOUNT_ID, "name": "abuse", "domainId": DOMAIN_ID},
            {"id": "a-rob", "name": "rob", "domainId": DOMAIN_ID},
        ]
        self.refuse_method: str | None = None

    def pages(self) -> list[urllib.request.Request]:
        return [r for r in self.requests if r.full_url == page.NTFY_TOPIC_URL]

    def __call__(self, request: urllib.request.Request) -> tuple[int, bytes]:
        self.requests.append(request)
        if request.full_url == page.NTFY_TOPIC_URL:
            if self.pager_error:
                raise page.AbusePageError("request")
            return self.pager_status, self.pager_body
        if request.full_url != f"{page.STALWART_URL}/jmap":
            raise AssertionError(request.full_url)
        call = page.as_list(
            page.as_list(page.as_mapping(json.loads(body_of(request)))["methodCalls"])[0]
        )
        method = str(call[0])
        self.methods.append(method)
        if method == self.refuse_method:
            return 200, json.dumps({"methodResponses": [["error", {"type": "x"}, "0"]]}).encode()
        results = {
            "x:Domain/get": {"list": self.domains},
            "x:Account/get": {"list": self.accounts},
            "Email/query": {"accountId": ACCOUNT_ID, "ids": self.ids},
        }
        return 200, json.dumps({"methodResponses": [[method, results[method], "0"]]}).encode()


class Rig(unittest.TestCase):
    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.state = holder.name
        self.world = FakeWorld(["m3", "m2", "m1"])
        self.log: list[str] = []

    def poll(self) -> int:
        code: int = page.run_once(
            self.world, ADMIN, TOKEN, self.state, self.log.append, os.geteuid()
        )
        return code

    def query_request(self) -> bytes:
        return [
            body
            for body in (body_of(r) for r in self.world.requests if r.data)
            if b"Email/query" in body
        ][0]

    def saved(self) -> object:
        return json.loads((Path(self.state) / "seen.json").read_text())


class NewIdsTests(unittest.TestCase):
    def test_a_first_run_has_no_new_ids_so_old_mail_is_not_paged(self) -> None:
        self.assertEqual([], page.new_ids(["m2", "m1"], page.Seen(None)))

    def test_an_id_not_seen_before_is_new_and_a_removed_one_is_not(self) -> None:
        self.assertEqual(["m4"], page.new_ids(["m4", "m2"], page.Seen(("m3", "m2", "m1"))))
        self.assertEqual([], page.new_ids(["m2"], page.Seen(("m3", "m2", "m1"))))

    def test_a_damaged_state_counts_every_id_as_new(self) -> None:
        self.assertEqual(["m2", "m1"], page.new_ids(["m2", "m1"], page.Seen(())))


class PollTests(Rig):
    def test_the_first_run_records_the_mailbox_and_does_not_page(self) -> None:
        self.assertEqual(0, self.poll())
        self.assertEqual([], self.world.pages())
        self.assertEqual({"ids": ["m3", "m2", "m1"]}, self.saved())
        self.assertIn("baseline", self.log[0])

    def test_a_run_with_nothing_new_does_not_page(self) -> None:
        self.poll()
        self.assertEqual(0, self.poll())
        self.assertEqual([], self.world.pages())

    def test_a_new_message_pages_once_with_the_fixed_notice(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        self.assertEqual(0, self.poll())
        pages = self.world.pages()
        self.assertEqual(1, len(pages))
        self.assertEqual("POST", pages[0].get_method())
        self.assertEqual(page.PAGE_MESSAGE.encode(), pages[0].data)
        self.assertEqual(page.PAGE_TITLE, pages[0].get_header("Title"))
        self.assertEqual(f"Bearer {TOKEN}", pages[0].get_header("Authorization"))
        self.assertEqual({"ids": ["m4", "m3", "m2", "m1"]}, self.saved())

    def test_a_burst_of_messages_pages_once(self) -> None:
        self.poll()
        self.world.ids = ["m7", "m6", "m5", "m4", *self.world.ids]
        self.poll()
        self.assertEqual(1, len(self.world.pages()))

    def test_the_same_message_is_not_paged_twice(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        self.poll()
        self.poll()
        self.assertEqual(1, len(self.world.pages()))

    def test_the_notice_names_no_sender_no_text_and_no_tenant(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        self.poll()
        notice = self.world.pages()[0]
        everything = repr((notice.full_url, notice.data, notice.header_items()))
        self.assertEqual("abuse", self.world.accounts[0]["name"])
        for forbidden in ("@", "tenant", "From", "Subject", "m4"):
            self.assertNotIn(forbidden, everything.replace("Authorization", ""))
        self.assertTrue(page.PAGE_TITLE.isupper() and page.PAGE_MESSAGE.isupper())

    def test_nothing_of_a_message_is_asked_for_only_its_id(self) -> None:
        self.poll()
        self.assertEqual(["x:Domain/get", "x:Account/get", "Email/query"], self.world.methods)
        query = self.query_request()
        self.assertNotIn(b"properties", query)
        self.assertNotIn(b"Email/get", query)

    def test_the_account_is_found_by_name_on_the_mail_domain_only(self) -> None:
        self.world.accounts = [
            {"id": "other", "name": "abuse", "domainId": "elsewhere"},
            {"id": ACCOUNT_ID, "name": "abuse", "domainId": DOMAIN_ID},
        ]
        self.poll()
        query = self.query_request()
        self.assertIn(ACCOUNT_ID.encode(), query)
        self.assertNotIn(b"other", query)

    def test_a_refused_page_leaves_the_state_so_the_next_run_tries_again(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        self.world.pager_status = 403
        with self.assertRaises(page.AbusePageError):
            self.poll()
        self.assertEqual({"ids": ["m3", "m2", "m1"]}, self.saved())
        self.world.pager_status = 200
        self.assertEqual(0, self.poll())
        self.assertEqual(2, len(self.world.pages()))
        self.assertEqual({"ids": ["m4", "m3", "m2", "m1"]}, self.saved())

    def test_a_200_that_is_not_an_ntfy_message_is_not_a_page(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        for body in (b"<html>ok</html>", b"{}", b'{"id": ""}', b"[]"):
            self.world.pager_body = body
            with self.assertRaises(page.AbusePageError, msg=body):
                self.poll()
        self.assertEqual({"ids": ["m3", "m2", "m1"]}, self.saved())

    def test_an_unreachable_pager_is_a_failure_with_the_state_kept(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        self.world.pager_error = True
        with self.assertRaises(page.AbusePageError):
            self.poll()
        self.assertEqual({"ids": ["m3", "m2", "m1"]}, self.saved())

    def test_a_damaged_state_file_pages_for_what_the_mailbox_holds(self) -> None:
        (Path(self.state) / "seen.json").write_text("not json")
        os.chmod(Path(self.state) / "seen.json", 0o600)
        with mock.patch.object(page, "read_private_file", side_effect=page.AbusePageError("x")):
            self.assertEqual(0, self.poll())
        self.assertEqual(1, len(self.world.pages()))

    def test_a_page_sent_but_a_state_that_will_not_write_is_reported_by_its_exit_code(self) -> None:
        self.poll()
        self.world.ids = ["m4", *self.world.ids]
        with mock.patch.object(page, "write_seen", side_effect=page.AbusePageError("state-write")):
            self.assertEqual(page.EXIT_PAGED_STATE_LOST, self.poll())
        self.assertEqual(1, len(self.world.pages()))

    def test_an_error_from_stalwart_stops_the_run_before_any_page(self) -> None:
        for method in ("x:Domain/get", "x:Account/get", "Email/query"):
            world = FakeWorld(["m1"])
            world.refuse_method = method
            with self.assertRaises(page.AbusePageError, msg=method):
                page.run_once(world, ADMIN, TOKEN, self.state, self.log.append, os.geteuid())
            self.assertEqual([], world.pages())

    def test_a_missing_or_doubled_domain_or_account_stops_the_run(self) -> None:
        cases: list[tuple[str, list[dict[str, str]]]] = [
            ("domains", []),
            (
                "domains",
                [{"id": "1", "name": "branchleft.co.uk"}, {"id": "2", "name": "branchleft.co.uk"}],
            ),
            ("accounts", []),
            ("accounts", [{"id": "1", "name": "rob", "domainId": DOMAIN_ID}]),
        ]
        for attribute, value in cases:
            world = FakeWorld(["m1"])
            setattr(world, attribute, value)
            with self.assertRaises(page.AbusePageError, msg=f"{attribute} {value}"):
                page.run_once(world, ADMIN, TOKEN, self.state, self.log.append, os.geteuid())

    def test_a_message_id_of_an_odd_shape_is_refused(self) -> None:
        self.world.ids = ["m1", "../etc"]
        with self.assertRaises(page.AbusePageError):
            self.poll()


class FileTests(unittest.TestCase):
    @contextlib.contextmanager
    def as_root(self) -> Iterator[None]:
        real = os.fstat

        def fake(descriptor: int) -> os.stat_result:
            info = real(descriptor)
            return os.stat_result(
                (info.st_mode, info.st_ino, info.st_dev, 1, 0, 0, info.st_size, 0, 0, 0)
            )

        with mock.patch.object(os, "fstat", fake):
            yield

    def make(self, text: str, mode: int = 0o600) -> str:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        path = Path(holder.name) / "file"
        path.write_text(text)
        path.chmod(mode)
        return str(path)

    def test_a_root_owned_closed_regular_file_is_read(self) -> None:
        with self.as_root():
            self.assertEqual("hello", page.read_private_file(self.make("hello")))

    def test_a_file_open_to_group_or_others_is_refused(self) -> None:
        for mode in (0o640, 0o604, 0o644, 0o660):
            with self.as_root(), self.assertRaises(page.AbusePageError, msg=oct(mode)):
                page.read_private_file(self.make("hello", mode))

    def test_a_file_that_is_not_root_s_is_refused(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the test would own the file as root")
        with self.assertRaises(page.AbusePageError):
            page.read_private_file(self.make("hello"))

    def test_a_link_and_a_directory_and_a_missing_file_are_refused(self) -> None:
        path = self.make("hello")
        link = path + ".link"
        os.symlink(path, link)
        with self.as_root():
            for candidate in (link, os.path.dirname(path), path + ".none"):
                with self.assertRaises(page.AbusePageError, msg=candidate):
                    page.read_private_file(candidate)

    def test_a_file_that_is_not_text_or_is_too_large_is_refused(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        binary = Path(holder.name) / "binary"
        binary.write_bytes(b"\xff\xfe")
        binary.chmod(0o600)
        big = Path(holder.name) / "big"
        big.write_bytes(b"a" * (page.FILE_MAX_BYTES + 1))
        big.chmod(0o600)
        with self.as_root():
            for path in (binary, big):
                with self.assertRaises(page.AbusePageError, msg=str(path)):
                    page.read_private_file(str(path))

    def test_the_state_file_is_written_closed_to_root_and_leaves_no_temporary(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        page.write_seen(holder.name, ["m2", "m1"])
        written = Path(holder.name) / "seen.json"
        self.assertEqual(0o600, stat.S_IMODE(written.stat().st_mode))
        self.assertEqual([written], list(Path(holder.name).iterdir()))

    def test_a_state_directory_that_cannot_be_written_is_a_failure(self) -> None:
        with self.assertRaises(page.AbusePageError):
            page.write_seen("/nonexistent-directory-for-the-test", ["m1"])


class TokenTests(unittest.TestCase):
    def test_one_well_formed_token_is_read(self) -> None:
        self.assertEqual(TOKEN, page.parse_token(f"{page.TOKEN_KEY}={TOKEN}\n"))

    def test_none_two_or_a_malformed_token_is_refused(self) -> None:
        for text in (
            "",
            f"OTHER={TOKEN}\n",
            f"{page.TOKEN_KEY}={TOKEN}\n{page.TOKEN_KEY}={TOKEN}\n",
            f"{page.TOKEN_KEY}=tk_short\n",
            f"{page.TOKEN_KEY}=\n",
            f"{page.TOKEN_KEY}=tk_{'M' * 29}\n",
        ):
            with self.assertRaises(page.AbusePageError, msg=text):
                page.parse_token(text)

    def test_a_refusal_never_holds_the_token(self) -> None:
        with self.assertRaises(page.AbusePageError) as caught:
            page.parse_token(f"{page.TOKEN_KEY}={TOKEN}x\n")
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_the_administrator_credential_is_user_colon_secret(self) -> None:
        self.assertEqual(("admin", "se:cret"), page.parse_admin_credentials("admin:se:cret\n"))
        for text in ("", "admin", "admin:", ":secret", "a:b\nc"):
            with self.assertRaises(page.AbusePageError, msg=text):
                page.parse_admin_credentials(text)


class ConstantsAndMainTests(Rig):
    def test_the_pager_url_is_the_abuse_topic_and_not_the_page_topic(self) -> None:
        self.assertTrue(page.NTFY_TOPIC_URL.startswith("https://"))
        self.assertTrue(page.NTFY_TOPIC_URL.endswith("/branchleft-abuse"))
        self.assertNotIn("branchleft-pages", page.NTFY_TOPIC_URL)

    def test_a_redirect_is_never_followed(self) -> None:
        handler = page.RefuseRedirects()
        request = urllib.request.Request(page.NTFY_TOPIC_URL)  # noqa: S310
        self.assertIsNone(
            handler.redirect_request(request, io.BytesIO(), 302, "Found", mock.Mock(), "http://x/")
        )

    def test_check_only_succeeds_and_an_unknown_argument_is_refused(self) -> None:
        self.assertEqual(0, page.main(["--check"]))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, page.main([]))
            self.assertEqual(2, page.main(["run", "extra"]))

    def test_run_reads_the_two_private_files_and_pages_without_printing_a_secret(self) -> None:
        files = {
            page.ADMIN_CREDENTIALS_PATH: f"{ADMIN[0]}:{ADMIN[1]}\n",
            page.TOKEN_FILE_PATH: f"{page.TOKEN_KEY}={TOKEN}\n",
        }
        real = page.read_private_file

        def reader(path: str, owner_uid: int = 0) -> str:
            # The two files are root's on a host; the state file here is the test's own.
            return files[path] if path in files else str(real(path, os.geteuid()))

        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(page, "read_private_file", side_effect=reader),
            mock.patch.object(page, "STATE_DIR", self.state),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            self.assertEqual(0, page.main(["run"], self.world))
            self.world.ids = ["m4", *self.world.ids]
            self.assertEqual(0, page.main(["run"], self.world))
        self.assertEqual(1, len(self.world.pages()))
        for secret in (TOKEN, ADMIN[1]):
            self.assertNotIn(secret, out.getvalue() + err.getvalue())

    def test_run_with_a_file_missing_fails_with_a_fixed_message(self) -> None:
        err = io.StringIO()
        with (
            mock.patch.object(
                page, "read_private_file", side_effect=page.AbusePageError("file-open")
            ),
            contextlib.redirect_stderr(err),
        ):
            self.assertEqual(1, page.main(["run"], self.world))
        self.assertIn("cannot be opened", err.getvalue())
        self.assertEqual([], self.world.requests)


class RolePinsTests(unittest.TestCase):
    """The program, the units and the role's constants name the same paths."""

    ROLE = Path(__file__).resolve().parents[2]

    def constants(self) -> dict[str, str]:
        loaded = yaml.safe_load((self.ROLE / "vars" / "main.yml").read_text())
        return {str(key): str(value) for key, value in page.as_mapping(loaded).items()}

    def unit(self, name: str) -> str:
        return (self.ROLE / "files" / name).read_text()

    def test_the_program_and_the_role_agree_on_every_path_and_the_key(self) -> None:
        constants = self.constants()
        self.assertEqual(constants["mx1_abuse_page_env_file"], page.TOKEN_FILE_PATH)
        self.assertEqual(constants["mx1_abuse_page_env_key"], page.TOKEN_KEY)
        self.assertEqual(constants["mx1_abuse_page_state_dir"], page.STATE_DIR)
        self.assertEqual(
            constants["mx1_abuse_page_program_path"],
            f"{constants['mx1_abuse_page_program_dir']}/{constants['mx1_abuse_page_program_name']}",
        )

    def test_the_service_runs_the_installed_program_on_the_token_file_and_one_write_path(
        self,
    ) -> None:
        constants = self.constants()
        service = self.unit(constants["mx1_abuse_page_service_unit"])
        self.assertIn(
            f"ExecStart=/usr/bin/python3 -I {constants['mx1_abuse_page_program_path']} run", service
        )
        self.assertIn(f"ConditionPathExists={page.TOKEN_FILE_PATH}", service)
        self.assertIn(f"ReadWritePaths={page.STATE_DIR}", service)
        self.assertEqual(1, service.count("ReadWritePaths="))
        for line in ("ProtectSystem=strict", "NoNewPrivileges=yes", "ProtectHome=read-only"):
            self.assertIn(line, service)

    def test_the_timer_polls_every_minute_and_names_no_other_unit(self) -> None:
        timer = self.unit(self.constants()["mx1_abuse_page_timer_unit"])
        self.assertIn("OnUnitActiveSec=1min", timer)
        self.assertNotIn("Unit=", timer)

    def test_the_program_holds_no_host_name_address_or_credential(self) -> None:
        text = PROGRAM.read_text()
        for forbidden in ("tk_" + "a", "@branchleft", "password", "Bearer tk"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
