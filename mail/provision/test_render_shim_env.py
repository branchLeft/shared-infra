#!/usr/bin/env python3
"""Unit tests for render_shim_env.py. The parsing, composition and
token-provisioning functions are pure (or, for generate_drain_token, have
their one impure call isolated to a single call site) and get full coverage
with no network and minimal real filesystem state; write_env_file_atomic,
append_credential_atomic and main() are exercised against a real temp
directory since their entire job is a real filesystem write -- mocking that
away would leave the atomicity and permission guarantees unverified.
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
    DRAIN_TOKEN_LABEL,
    append_credential_atomic,
    ensure_drain_token,
    find_credential_secret,
    render_env_file,
    write_env_file_atomic,
)


class FindCredentialSecretTests(unittest.TestCase):
    def test_missing_label_returns_none(self):
        self.assertIsNone(find_credential_secret("some-other-label:x\n", "shim-drain-token"))

    def test_matching_label_returns_its_secret(self):
        text = "blog-ghost-smtp:not-this-one\nshim-drain-token:the-secret-value\n"
        self.assertEqual(find_credential_secret(text, "shim-drain-token"), "the-secret-value")

    def test_empty_text_returns_none(self):
        self.assertIsNone(find_credential_secret("", "shim-drain-token"))

    def test_blank_lines_are_skipped(self):
        text = "\n\nshim-drain-token:the-secret-value\n"
        self.assertEqual(find_credential_secret(text, "shim-drain-token"), "the-secret-value")

    def test_a_secret_containing_a_colon_is_preserved_whole(self):
        text = "shim-drain-token:has:a:colon\n"
        self.assertEqual(find_credential_secret(text, "shim-drain-token"), "has:a:colon")

    def test_malformed_line_raises_runtime_error_not_value_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            find_credential_secret("this-line-has-no-colon\n", "shim-drain-token")
        self.assertNotIsInstance(ctx.exception, ValueError)
        self.assertIn("malformed", str(ctx.exception))

    def test_malformed_line_error_names_the_given_path_and_line_number(self):
        text = "blog-ghost-smtp:fine\nno-colon-here\n"
        with self.assertRaises(RuntimeError) as ctx:
            find_credential_secret(text, "shim-drain-token", path="/some/path")
        self.assertIn("/some/path", str(ctx.exception))
        self.assertIn("2", str(ctx.exception))

    def test_first_match_wins_when_a_label_appears_twice(self):
        # Shouldn't happen in practice (append_credential_atomic only ever
        # appends, and ensure_drain_token checks before it does), but the
        # scan is defined to stop at the first match, not the last.
        text = "shim-drain-token:first\nshim-drain-token:second\n"
        self.assertEqual(find_credential_secret(text, "shim-drain-token"), "first")


class AppendCredentialAtomicTests(unittest.TestCase):
    def test_creates_the_file_at_mode_0600_if_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "does-not-exist-yet")
            append_credential_atomic(path, "shim-drain-token", "a-secret")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "shim-drain-token:a-secret\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_appends_without_disturbing_an_existing_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("blog-ghost-smtp:unrelated-secret\n")
            append_credential_atomic(path, "shim-drain-token", "a-secret")
            with open(path, encoding="utf-8") as f:
                contents = f.read()
            self.assertEqual(
                contents, "blog-ghost-smtp:unrelated-secret\nshim-drain-token:a-secret\n"
            )


class EnsureDrainTokenTests(unittest.TestCase):
    def test_missing_file_generates_and_records_a_fresh_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "does-not-exist")
            with mock.patch.object(rse, "generate_drain_token", return_value="freshly-generated"):
                token = ensure_drain_token(path, "shim-drain-token")

            self.assertEqual(token, "freshly-generated")
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "shim-drain-token:freshly-generated\n")

    def test_existing_token_is_returned_unchanged_and_nothing_is_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("shim-drain-token:already-here\n")
            with mock.patch.object(rse, "generate_drain_token") as mock_generate:
                token = ensure_drain_token(path, "shim-drain-token")

            self.assertEqual(token, "already-here")
            mock_generate.assert_not_called()
            with open(path, encoding="utf-8") as f:
                # unchanged -- ensure_drain_token never rewrites an existing line
                self.assertEqual(f.read(), "shim-drain-token:already-here\n")

    def test_a_second_run_against_a_freshly_generated_token_is_a_no_op(self):
        # The idempotency property re-rendering depends on: run once against
        # an empty file, then again against what the first run left behind.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            first = ensure_drain_token(path, "shim-drain-token")
            second = ensure_drain_token(path, "shim-drain-token")
            self.assertEqual(first, second)
            with open(path, encoding="utf-8") as f:
                # exactly one line -- the second run did not append again
                self.assertEqual(len(f.readlines()), 1)

    def test_malformed_existing_file_fails_loudly_not_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("no-colon-on-this-line\n")
            with self.assertRaises(RuntimeError) as ctx:
                ensure_drain_token(path, "shim-drain-token")
            self.assertIn("malformed", str(ctx.exception))


class RenderEnvFileTests(unittest.TestCase):
    def test_includes_exactly_the_keys_the_shim_reads_with_no_safe_default(self):
        contents = render_env_file("the-token")
        for key in ("PORT=", "SHIM_DB_PATH=", "SHIM_THROTTLE_PATH=", "SHIM_DRAIN_TOKEN="):
            self.assertIn(key, contents)

    def test_no_longer_emits_the_retired_outbound_delivery_variables(self):
        # The shim's own outbound delivery (worker.ts/smtp.ts) is gone;
        # config.ts no longer reads any of these. Sabotage: reinstate one of
        # these lines in render_env_file and this test goes red -- it is not
        # merely absent from the "includes" list above, it is asserted gone.
        contents = render_env_file("the-token")
        for retired_key in ("SMTP_HOST=", "SMTP_PORT=", "SMTP_SECURE=", "SMTP_USER=", "SMTP_PASS="):
            self.assertNotIn(retired_key, contents)

    def test_port_matches_shim_compose_ymls_container_side_mapping(self):
        contents = render_env_file("the-token")
        self.assertIn("PORT=8080", contents)

    def test_drain_token_appears_exactly_once_as_shim_drain_token(self):
        contents = render_env_file("distinctive-drain-token-value")
        self.assertEqual(contents.count("distinctive-drain-token-value"), 1)
        self.assertIn("SHIM_DRAIN_TOKEN=distinctive-drain-token-value", contents)

    def test_ends_with_a_single_trailing_newline(self):
        contents = render_env_file("the-token")
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
    """main()'s control flow against a real temp directory -- the happy
    path on both a fresh host (no credentials file yet) and a re-run
    (token already recorded), and the no-print guarantee end to end.
    """

    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        self.stderr = stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)

    def test_fresh_host_generates_a_token_writes_the_env_file_and_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "does-not-exist-yet")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                result = rse.main()

            self.assertEqual(result, 0)
            self.assertTrue(os.path.exists(creds_path))
            with open(env_path, encoding="utf-8") as f:
                contents = f.read()
            self.assertRegex(contents, r"SHIM_DRAIN_TOKEN=\S+")
            self.assertEqual(stat.S_IMODE(os.stat(env_path).st_mode), 0o600)

    def test_a_second_run_reuses_the_same_token_the_first_run_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                rse.main()
                with open(env_path, encoding="utf-8") as f:
                    first_contents = f.read()

                rse.main()
                with open(env_path, encoding="utf-8") as f:
                    second_contents = f.read()

            self.assertEqual(first_contents, second_contents)
            with open(creds_path, encoding="utf-8") as f:
                # exactly one shim-drain-token line across both runs
                self.assertEqual(
                    sum(1 for line in f if line.startswith(f"{DRAIN_TOKEN_LABEL}:")), 1
                )

    def test_happy_path_with_a_pre_recorded_token_writes_it_verbatim(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            with open(creds_path, "w", encoding="utf-8") as f:
                f.write(f"{DRAIN_TOKEN_LABEL}:a-real-token\n")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                result = rse.main()

            self.assertEqual(result, 0)
            with open(env_path, encoding="utf-8") as f:
                contents = f.read()
            self.assertIn("SHIM_DRAIN_TOKEN=a-real-token", contents)
            self.assertEqual(stat.S_IMODE(os.stat(env_path).st_mode), 0o600)

    def test_token_is_never_printed_to_stdout_or_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            with open(creds_path, "w", encoding="utf-8") as f:
                f.write(f"{DRAIN_TOKEN_LABEL}:a-very-distinctive-drain-token-value\n")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                rse.main()

            self.assertNotIn("a-very-distinctive-drain-token-value", self.stdout.getvalue())
            self.assertNotIn("a-very-distinctive-drain-token-value", self.stderr.getvalue())

    def test_a_freshly_generated_token_is_also_never_printed(self):
        # Sabotage-relevant distinction from the case above: this covers
        # the generate-on-first-use path specifically, not only the
        # already-recorded path.
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "does-not-exist-yet")
            env_path = os.path.join(tmp, "env")
            with mock.patch.multiple(
                rse, SERVICE_CREDENTIALS_PATH=creds_path, SHIM_ENV_PATH=env_path
            ):
                rse.main()
                with open(creds_path, encoding="utf-8") as f:
                    recorded_line = f.read().strip()
            generated_token = recorded_line.split(":", 1)[1]

            self.assertNotIn(generated_token, self.stdout.getvalue())
            self.assertNotIn(generated_token, self.stderr.getvalue())

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
