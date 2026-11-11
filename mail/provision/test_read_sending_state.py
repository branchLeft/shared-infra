#!/usr/bin/env python3
"""Unit tests for read_sending_state.py -- no network, no live server.
The JMAP reply is a fake; the credential and key strings are fakes too, so
the tests can assert they never reach stdout or stderr.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

import read_sending_state as rss
from read_sending_state import READ_CALLS, ReadError, assert_read_only

FAKE_SECRET = "FAKE-ADMIN-SECRET-7f3a"
FAKE_PRIVATE_KEY = "FAKE-PRIVATE-KEY-MARKER-91c2"
FAKE_PUBLIC_KEY = "FAKE-PUBLIC-KEY-MARKER-b04e"


def _domain(domain_id, name):
    return {"id": domain_id, "name": name, "dkimManagement": {"@type": "Manual"}}


def _key(domain_id, selector, stage="active"):
    return {
        "id": f"k-{domain_id}-{selector}",
        "domainId": domain_id,
        "selector": selector,
        "stage": stage,
        "@type": "Dkim1RsaSha256",
        "publicKey": FAKE_PUBLIC_KEY,
        "privateKey": {"@type": "Text", "secret": FAKE_PRIVATE_KEY},
    }


def _account(domain_id, name):
    return {"id": f"a-{name}", "name": name, "domainId": domain_id}


def _reply(domains, keys, accounts):
    return [
        ["x:Domain/get", {"list": domains}, "domains"],
        ["x:DkimSignature/get", {"list": keys}, "keys"],
        ["x:Account/get", {"list": accounts}, "accounts"],
    ]


def _run(reply, secret=FAKE_SECRET, jmap=None):
    """Runs main() against a fake reply. Returns (exit code, stdout, stderr)."""
    if jmap is None:

        def jmap(auth, calls):
            assert calls == READ_CALLS
            if isinstance(reply, BaseException):
                raise reply
            return reply

    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(rss, "_load_credentials", return_value=("admin", secret)),
        mock.patch.object(rss, "_jmap", jmap),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = rss.main()
    return code, out.getvalue(), err.getvalue()


class ReadTests(unittest.TestCase):
    def test_normal_read_prints_sorted_lines_and_role_summaries(self):
        reply = _reply(
            [_domain("a", "branchleft.co.uk"), _domain("b", "demo.example")],
            [_key("a", "bl"), _key("b", "bl")],
            [_account("a", "rob"), _account("a", "complaints"), _account("a", "abuse")],
        )
        code, out, err = _run(reply)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            out.splitlines(),
            [
                "dkim branchleft.co.uk bl active",
                "dkim demo.example bl active",
                "domain branchleft.co.uk",
                "domain demo.example",
                "mailbox abuse@branchleft.co.uk",
                "mailbox complaints@branchleft.co.uk",
                "mailbox rob@branchleft.co.uk",
                "postmaster: absent",
                "abuse: present as mailbox",
                "complaints: present as mailbox",
                "aliases: not read (only mailbox accounts were read, so postmaster absent means no mailbox, not no alias)",
            ],
        )

    def test_domain_without_a_dkim_key_gets_a_domain_line_and_no_dkim_line(self):
        reply = _reply([_domain("a", "demo.example")], [], [])
        code, out, _ = _run(reply)
        self.assertEqual(code, 0)
        self.assertIn("domain demo.example", out.splitlines())
        self.assertFalse(
            [line for line in out.splitlines() if line.startswith("dkim ")]
        )

    def test_missing_postmaster_is_reported_absent_and_others_still_read(self):
        reply = _reply(
            [_domain("a", "branchleft.co.uk")],
            [],
            [_account("a", "abuse"), _account("a", "complaints")],
        )
        code, out, _ = _run(reply)
        self.assertEqual(code, 0)
        self.assertIn("postmaster: absent", out.splitlines())
        self.assertIn("abuse: present as mailbox", out.splitlines())

    def test_missing_complaints_is_reported_absent(self):
        reply = _reply(
            [_domain("a", "branchleft.co.uk")], [], [_account("a", "postmaster")]
        )
        _, out, _ = _run(reply)
        self.assertIn("complaints: absent", out.splitlines())
        self.assertIn("postmaster: present as mailbox", out.splitlines())

    def test_error_response_prints_one_line_and_exits_1(self):
        reply = [["error", {"type": "forbidden"}, "domains"]]
        code, out, err = _run(reply)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err, "read_sending_state: the Stalwart API refused the read (forbidden)\n"
        )

    def test_error_type_with_odd_characters_is_not_echoed(self):
        reply = [["error", {"type": f"bad {FAKE_SECRET}"}, "domains"]]
        code, _, err = _run(reply)
        self.assertEqual(code, 1)
        self.assertNotIn(FAKE_SECRET, err)
        self.assertIn("(unknown)", err)

    def test_key_material_and_credential_never_reach_stdout_or_stderr(self):
        reply = _reply(
            [_domain("a", "branchleft.co.uk")],
            [_key("a", "bl")],
            [_account("a", "rob")],
        )
        code, out, err = _run(reply)
        self.assertEqual(code, 0)
        for text in (out, err):
            self.assertNotIn(FAKE_SECRET, text)
            self.assertNotIn(FAKE_PRIVATE_KEY, text)
            self.assertNotIn(FAKE_PUBLIC_KEY, text)

    def test_unexpected_exception_text_is_not_printed(self):
        def jmap(auth, calls):
            raise RuntimeError(
                f"boom {FAKE_SECRET} http://admin:{FAKE_SECRET}@127.0.0.1:8080"
            )

        code, out, err = _run(None, jmap=jmap)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(
            err, "read_sending_state: unexpected RuntimeError, nothing printed\n"
        )

    def test_http_error_prints_status_only(self):
        exc = urllib.error.HTTPError(
            "http://127.0.0.1:8080/jmap", 401, "Unauthorized", {}, None
        )
        code, _, err = _run(exc)
        self.assertEqual(code, 1)
        self.assertEqual(
            err, "read_sending_state: the Stalwart API answered HTTP 401\n"
        )

    def test_unreachable_api_prints_fixed_reason(self):
        code, _, err = _run(urllib.error.URLError("connection refused"))
        self.assertEqual(code, 1)
        self.assertEqual(
            err, "read_sending_state: could not reach the Stalwart API on loopback\n"
        )

    def test_dkim_key_naming_an_unread_domain_is_refused(self):
        reply = _reply([_domain("a", "branchleft.co.uk")], [_key("zzz", "bl")], [])
        code, out, err = _run(reply)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("names a domain that was not read", err)

    def test_malformed_credential_file_is_refused_without_its_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write(FAKE_SECRET)
            with mock.patch.object(rss, "CREDENTIALS_PATH", path):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    with self.assertRaises(ReadError) as ctx:
                        rss._load_credentials()
        self.assertEqual(str(ctx.exception), "the admin credential file is malformed")
        self.assertNotIn(FAKE_SECRET, str(ctx.exception))

    def test_missing_credential_file_is_refused(self):
        with mock.patch.object(rss, "CREDENTIALS_PATH", "/nonexistent/creds-for-test"):
            with self.assertRaises(ReadError) as ctx:
                rss._load_credentials()
        self.assertEqual(
            str(ctx.exception), "the admin credential file is missing or unreadable"
        )


class ReadOnlyTests(unittest.TestCase):
    def test_read_calls_are_all_gets(self):
        for call in READ_CALLS:
            self.assertTrue(call[0].endswith("/get"), call[0])
        assert_read_only(READ_CALLS)

    def test_write_methods_are_refused(self):
        for method in (
            "x:Domain/set",
            "x:Account/create",
            "x:DkimSignature/destroy",
            "x:Account/set",
        ):
            with self.subTest(method=method):
                with self.assertRaises(ReadError):
                    assert_read_only([[method, {}, "c"]])

    def test_jmap_refuses_a_write_before_sending_anything(self):
        calls = [["x:Account/set", {"create": {}}, "c"]]
        with mock.patch.object(rss.urllib.request, "urlopen") as urlopen:
            with self.assertRaises(ReadError):
                rss._jmap(("admin", FAKE_SECRET), calls)
        urlopen.assert_not_called()

    def test_jmap_sends_one_request_with_only_the_read_calls(self):
        reply = {"methodResponses": _reply([], [], [])}
        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value.read.return_value = json.dumps(reply).encode()
        with mock.patch.object(
            rss.urllib.request, "urlopen", return_value=fake_resp
        ) as urlopen:
            responses = rss._jmap(("admin", FAKE_SECRET), READ_CALLS)
        self.assertEqual(urlopen.call_count, 1)
        sent = urlopen.call_args[0][0]
        self.assertEqual(sent.full_url, "http://127.0.0.1:8080/jmap")
        self.assertIn(b'"x:Domain/get"', sent.data)
        self.assertEqual(len(responses), 3)

    def test_output_lines_are_only_the_allowed_types(self):
        reply = _reply(
            [_domain("a", "branchleft.co.uk")],
            [_key("a", "bl")],
            [_account("a", "rob"), _account("a", "postmaster")],
        )
        _, out, _ = _run(reply)
        allowed = (
            "domain ",
            "dkim ",
            "mailbox ",
            "postmaster: ",
            "abuse: ",
            "complaints: ",
            "aliases: not read",
        )
        for line in out.splitlines():
            self.assertTrue(line.startswith(allowed), line)


if __name__ == "__main__":
    unittest.main()
