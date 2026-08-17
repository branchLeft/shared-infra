#!/usr/bin/env python3
"""Unit tests for render_shim_env.py. The parsing and composition functions
are pure and get full coverage with no network and no real filesystem state
(find_credential_secret takes text directly, render_env_file takes a secret
directly); write_env_file_atomic and main() are exercised against a real
temp directory since their entire job is a real filesystem write --
mocking that away would leave the atomicity and permission guarantees
unverified.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
from __future__ import annotations

import io
import os
import stat
import tempfile
import unittest
from unittest import mock

import render_shim_env as rse
from render_shim_env import (
    CREDENTIAL_LABEL,
    find_credential_secret,
    render_env_file,
    write_env_file_atomic,
)


class FindCredentialSecretTests(unittest.TestCase):
    def test_missing_label_returns_none(self):
        self.assertIsNone(find_credential_secret("some-other-label:x\n", "blog-shim-bulk-submission"))

    def test_matching_label_returns_its_secret(self):
        text = "blog-ghost-smtp:not-this-one\nblog-shim-bulk-submission:the-secret-value\n"
        self.assertEqual(
            find_credential_secret(text, "blog-shim-bulk-submission"), "the-secret-value"
        )

    def test_empty_text_returns_none(self):
        self.assertIsNone(find_credential_secret("", "blog-shim-bulk-submission"))

    def test_blank_lines_are_skipped(self):
        text = "\n\nblog-shim-bulk-submission:the-secret-value\n"
        self.assertEqual(
            find_credential_secret(text, "blog-shim-bulk-submission"), "the-secret-value"
        )

    def test_a_secret_containing_a_colon_is_preserved_whole(self):
        text = "blog-shim-bulk-submission:has:a:colon\n"
        self.assertEqual(find_credential_secret(text, "blog-shim-bulk-submission"), "has:a:colon")

    def test_malformed_line_raises_runtime_error_not_value_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            find_credential_secret("this-line-has-no-colon\n", "blog-shim-bulk-submission")
        self.assertNotIsInstance(ctx.exception, ValueError)
        self.assertIn("malformed", str(ctx.exception))

    def test_malformed_line_error_names_the_given_path_and_line_number(self):
        text = "blog-ghost-smtp:fine\nno-colon-here\n"
        with self.assertRaises(RuntimeError) as ctx:
            find_credential_secret(text, "blog-shim-bulk-submission", path="/some/path")
        self.assertIn("/some/path", str(ctx.exception))
        self.assertIn("2", str(ctx.exception))

    def test_first_match_wins_when_a_label_appears_twice(self):
        # Shouldn't happen in practice (the provisioner only ever appends),
        # but the scan is defined to stop at the first match, not the last.
        text = "blog-shim-bulk-submission:first\nblog-shim-bulk-submission:second\n"
        self.assertEqual(find_credential_secret(text, "blog-shim-bulk-submission"), "first")


class RenderEnvFileTests(unittest.TestCase):
    def test_includes_all_required_keys(self):
        contents = render_env_file("the-secret")
        for key in (
            "PORT=",
            "SHIM_DB_PATH=",
            "SHIM_THROTTLE_PATH=",
            "SMTP_HOST=",
            "SMTP_PORT=",
            "SMTP_SECURE=",
            "SMTP_USER=",
            "SMTP_PASS=",
        ):
            self.assertIn(key, contents)

    def test_smtp_host_is_the_public_hostname_not_loopback(self):
        # nodemailer's STARTTLS cert check has to match the name Stalwart's
        # own certificate presents -- see the module docstring.
        contents = render_env_file("the-secret")
        self.assertIn("SMTP_HOST=mx1.branchleft.co.uk", contents)
        self.assertNotIn("127.0.0.1", contents)
        self.assertNotIn("localhost", contents)

    def test_smtp_secure_is_false_for_starttls_on_587(self):
        contents = render_env_file("the-secret")
        self.assertIn("SMTP_SECURE=false", contents)
        self.assertIn("SMTP_PORT=587", contents)

    def test_smtp_user_is_blog_at_branchleft(self):
        contents = render_env_file("the-secret")
        self.assertIn("SMTP_USER=blog@branchleft.co.uk", contents)

    def test_secret_appears_exactly_once_as_smtp_pass(self):
        contents = render_env_file("distinctive-secret-value")
        self.assertEqual(contents.count("distinctive-secret-value"), 1)
        self.assertIn("SMTP_PASS=distinctive-secret-value", contents)

    def test_ends_with_a_single_trailing_newline(self):
        contents = render_env_file("the-secret")
        self.assertTrue(contents.endswith("\n"))
        self.assertFalse(contents.endswith("\n\n"))


class WriteEnvFileAtomicTests(unittest.TestCase):
    def test_writes_the_given_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "env")
            write_env_file_atomic(path, "PORT=8080\n")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "PORT=8080\n")

    def test_file_mode_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "env")
            write_env_file_atomic(path, "PORT=8080\n")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_overwrites_an_existing_file_completely_not_appending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "env")
            with open(path, "w", encoding="utf-8") as f:
                f.write("STALE=leftover-from-a-previous-render\n")
            write_env_file_atomic(path, "PORT=8080\n")
            with open(path, encoding="utf-8") as f:
                contents = f.read()
            self.assertEqual(contents, "PORT=8080\n")
            self.assertNotIn("STALE", contents)

    def test_no_leftover_temp_file_after_a_successful_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "env")
            write_env_file_atomic(path, "PORT=8080\n")
            self.assertEqual(os.listdir(tmp), ["env"])

    def test_leftover_temp_file_is_cleaned_up_if_the_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "env")
            with mock.patch("os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    write_env_file_atomic(path, "PORT=8080\n")
            self.assertEqual(os.listdir(tmp), [])
            self.assertFalse(os.path.exists(path))


class MainOrchestrationTests(unittest.TestCase):
    """main()'s control flow against a real temp directory -- covers the
    "run 62 first" failure modes and the happy path, without touching
    /root or /etc/mailgun-shim.
    """

    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        self.stderr = stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)

    def test_missing_credentials_file_fails_loudly_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "does-not-exist")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                result = rse.main()

            self.assertEqual(result, 1)
            self.assertFalse(os.path.exists(env_path))
            self.assertIn("run 62-provision-shim-submission-credential.sh first", self.stderr.getvalue())

    def test_credentials_file_present_but_label_missing_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            with open(creds_path, "w", encoding="utf-8") as f:
                f.write("blog-ghost-smtp:unrelated-secret\n")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                result = rse.main()

            self.assertEqual(result, 1)
            self.assertFalse(os.path.exists(env_path))
            self.assertIn("run 62-provision-shim-submission-credential.sh first", self.stderr.getvalue())

    def test_happy_path_writes_env_file_and_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            with open(creds_path, "w", encoding="utf-8") as f:
                f.write(f"{CREDENTIAL_LABEL}:a-real-secret\n")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                result = rse.main()

            self.assertEqual(result, 0)
            with open(env_path, encoding="utf-8") as f:
                contents = f.read()
            self.assertIn("SMTP_PASS=a-real-secret", contents)
            self.assertEqual(stat.S_IMODE(os.stat(env_path).st_mode), 0o600)

    def test_secret_is_never_printed_to_stdout_or_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            with open(creds_path, "w", encoding="utf-8") as f:
                f.write(f"{CREDENTIAL_LABEL}:a-very-distinctive-secret-token\n")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                rse.main()

            self.assertNotIn("a-very-distinctive-secret-token", self.stdout.getvalue())
            self.assertNotIn("a-very-distinctive-secret-token", self.stderr.getvalue())

    def test_malformed_credentials_file_fails_loudly_via_the_shared_error_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            with open(creds_path, "w", encoding="utf-8") as f:
                f.write("no-colon-on-this-line\n")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                result = rse.main()

            self.assertEqual(result, 1)
            self.assertFalse(os.path.exists(env_path))
            self.assertIn("malformed", self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
