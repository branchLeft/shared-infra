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
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

import render_shim_env as rse
from render_shim_env import (
    ContractError,
    append_credential_atomic,
    contract_for_compose,
    digest_in_compose,
    ensure_drain_token,
    find_credential_secret,
    load_table,
    render_env_file,
    validate_table,
    write_env_file_atomic,
)

PINNED_DIGEST = "sha256:37c60999cd3bad612f5f1d4947ddf88716e138b17ddf9dd29a23964b88b7c21d"
OTHER_DIGEST = "sha256:" + "b" * 64
SMTP_LABEL = "blog-shim-bulk-submission"
DRAIN_LABEL = "shim-drain-token"


def compose_with(digest: str) -> str:
    return (
        "services:\n  mailgun-shim:\n"
        f"    image: ghcr.io/branchleft/mailgun-shim@{digest}\n"
        "  caddy:\n    image: caddy:2-alpine@sha256:" + "c" * 64 + "\n"
    )


# The environment the image pinned at PINNED_DIGEST was run with before the drain handover
# replaced it (git show 9cf0f01^:mail/provision/render_shim_env.py): the contract must keep
# producing exactly this, byte for byte.
SMTP_DELIVERY_ENV = (
    "PORT=8080\n"
    "SHIM_DB_PATH=/data/shim.db\n"
    "SHIM_THROTTLE_PATH=/data/throttle.json\n"
    "SMTP_HOST=mx1.branchleft.co.uk\n"
    "SMTP_PORT=587\n"
    "SMTP_SECURE=false\n"
    "SMTP_USER=blog@branchleft.co.uk\n"
    "SMTP_PASS=the-secret\n"
)
DRAIN_ENV = (
    "PORT=8080\n"
    "SHIM_DB_PATH=/data/shim.db\n"
    "SHIM_THROTTLE_PATH=/data/throttle.json\n"
    "SHIM_DRAIN_TOKEN=the-secret\n"
)


def real_table() -> dict:
    return load_table(rse.CONTRACTS_PATH)


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
    def test_smtp_delivery_renders_the_pre_drain_environment_byte_for_byte(self):
        contract = real_table()["contracts"]["smtp-delivery"]
        self.assertEqual(SMTP_DELIVERY_ENV, render_env_file(contract, "the-secret"))

    def test_drain_renders_the_drain_only_environment_byte_for_byte(self):
        contract = real_table()["contracts"]["drain"]
        self.assertEqual(DRAIN_ENV, render_env_file(contract, "the-secret"))

    def test_the_drain_environment_carries_no_smtp_variable(self):
        # Sabotage: reinstate an SMTP_ line in the drain contract and this goes red. The drain
        # image reads none of them, and a stray credential line is a leak for nothing.
        contents = render_env_file(real_table()["contracts"]["drain"], "the-secret")
        self.assertNotIn("SMTP_", contents)

    def test_the_smtp_environment_carries_no_drain_token(self):
        contents = render_env_file(real_table()["contracts"]["smtp-delivery"], "the-secret")
        self.assertNotIn("SHIM_DRAIN_TOKEN", contents)

    def test_the_secret_appears_exactly_once(self):
        for name, contract in real_table()["contracts"].items():
            with self.subTest(contract=name):
                contents = render_env_file(contract, "distinctive-secret-value")
                self.assertEqual(contents.count("distinctive-secret-value"), 1)

    def test_every_contract_ends_with_a_single_trailing_newline(self):
        for name, contract in real_table()["contracts"].items():
            with self.subTest(contract=name):
                contents = render_env_file(contract, "the-secret")
                self.assertTrue(contents.endswith("\n"))
                self.assertFalse(contents.endswith("\n\n"))

    def test_port_matches_shim_compose_ymls_container_side_mapping(self):
        for name, contract in real_table()["contracts"].items():
            with self.subTest(contract=name):
                self.assertIn("PORT=8080", render_env_file(contract, "the-secret"))


class ContractTableTests(unittest.TestCase):
    def test_the_real_table_is_valid_and_the_pinned_digest_is_smtp_delivery(self):
        table = real_table()
        self.assertEqual("smtp-delivery", table["digests"][PINNED_DIGEST])
        self.assertEqual(SMTP_LABEL, table["contracts"]["smtp-delivery"]["secret_label"])
        self.assertFalse(table["contracts"]["smtp-delivery"]["mint"])

    def test_the_drain_contract_has_no_digest_until_a_drain_image_is_pinned(self):
        table = real_table()
        self.assertEqual(DRAIN_LABEL, table["contracts"]["drain"]["secret_label"])
        self.assertTrue(table["contracts"]["drain"]["mint"])
        self.assertNotIn("drain", table["digests"].values())

    def test_the_digest_pinned_in_the_compose_file_has_a_contract(self):
        with open(os.path.join(rse.PROVISION_DIR, "shim-compose.yml"), encoding="utf-8") as f:
            compose_text = f.read()
        contract = contract_for_compose(compose_text, real_table())
        self.assertEqual(SMTP_LABEL, contract["secret_label"])

    def test_a_malformed_table_is_refused(self):
        good = real_table()
        bad_tables = {
            "extra key": dict(good, extra={}),
            "no placeholder": {
                "contracts": {"c": {"secret_label": "l", "mint": False, "env_lines": ["A=1"]}},
                "digests": {},
            },
            "two placeholders": {
                "contracts": {
                    "c": {"secret_label": "l", "mint": False, "env_lines": ["A={secret}", "B={secret}"]}
                },
                "digests": {},
            },
            "mint not a bool": {
                "contracts": {"c": {"secret_label": "l", "mint": "no", "env_lines": ["A={secret}"]}},
                "digests": {},
            },
            "digest names no contract": {"contracts": good["contracts"], "digests": {PINNED_DIGEST: "nope"}},
            "digest is a tag": {"contracts": good["contracts"], "digests": {"latest": "drain"}},
        }
        for case, table in bad_tables.items():
            with self.subTest(case=case), self.assertRaises(ContractError):
                validate_table(table)

    def test_an_unreadable_table_is_refused_without_naming_its_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "table.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            with self.assertRaises(ContractError):
                load_table(path)
            with self.assertRaises(ContractError):
                load_table(os.path.join(tmp, "absent.json"))


class ContractForComposeTests(unittest.TestCase):
    def test_a_listed_digest_selects_its_contract(self):
        contract = contract_for_compose(compose_with(PINNED_DIGEST), real_table())
        self.assertEqual(SMTP_LABEL, contract["secret_label"])

    def test_an_unlisted_digest_is_refused_naming_the_digest_and_the_table(self):
        with self.assertRaises(ContractError) as ctx:
            contract_for_compose(compose_with(OTHER_DIGEST), real_table(), "compose.yml", "table.json")
        self.assertIn(OTHER_DIGEST, str(ctx.exception))
        self.assertIn("table.json", str(ctx.exception))

    def test_a_tag_pinned_shim_image_is_refused(self):
        text = "services:\n  s:\n    image: ghcr.io/branchleft/mailgun-shim:latest\n"
        with self.assertRaises(ContractError):
            contract_for_compose(text, real_table())

    def test_a_placeholder_digest_is_refused(self):
        text = "services:\n  s:\n    image: ghcr.io/branchleft/mailgun-shim@sha256:IMAGE_DIGEST_PLACEHOLDER\n"
        with self.assertRaises(ContractError):
            contract_for_compose(text, real_table())

    def test_no_shim_image_line_is_refused(self):
        with self.assertRaises(ContractError):
            digest_in_compose("services:\n  c:\n    image: caddy:2-alpine\n")

    def test_two_shim_image_lines_are_refused(self):
        text = compose_with(PINNED_DIGEST) + compose_with(OTHER_DIGEST)
        with self.assertRaises(ContractError):
            digest_in_compose(text)

    def test_a_commented_image_line_does_not_select_a_contract(self):
        text = compose_with(OTHER_DIGEST) + f"# image: ghcr.io/branchleft/mailgun-shim@{PINNED_DIGEST}\n"
        with self.assertRaises(ContractError):
            contract_for_compose(text, real_table())


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
    """main()'s control flow against a real temp directory: each contract's happy path, the
    fail-closed refusals, the credentials file left byte-unchanged for mint=false, and the
    no-print guarantee end to end.
    """

    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        self.stderr = stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.creds_path = os.path.join(self.tmp, "creds")
        self.env_path = os.path.join(self.tmp, "env")
        self.compose_path = os.path.join(self.tmp, "shim-compose.yml")
        self.write_compose(PINNED_DIGEST)

    def write_compose(self, digest):
        with open(self.compose_path, "w", encoding="utf-8") as f:
            f.write(compose_with(digest))

    def write_creds(self, text):
        with open(self.creds_path, "w", encoding="utf-8") as f:
            f.write(text)

    def read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    def run_main(self, **extra):
        paths = dict(
            SERVICE_CREDENTIALS_PATH=self.creds_path,
            SHIM_ENV_PATH=self.env_path,
            SHIM_COMPOSE_PATH=self.compose_path,
        )
        with mock.patch.multiple(rse, **{**paths, **extra}):
            return rse.main()

    def table_with_drain_digest(self):
        table = real_table()
        table["digests"][OTHER_DIGEST] = "drain"
        path = os.path.join(self.tmp, "table.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(table, f)
        return path

    def test_the_pinned_digest_renders_the_smtp_environment_from_the_recorded_credential(self):
        self.write_creds(f"other-label:unrelated\n{SMTP_LABEL}:the-secret\n")
        self.assertEqual(0, self.run_main())
        self.assertEqual(SMTP_DELIVERY_ENV, self.read(self.env_path))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.env_path).st_mode))

    def test_smtp_delivery_leaves_the_credentials_file_byte_unchanged(self):
        # The pre-fix main() would have minted a shim-drain-token here and appended it to the
        # host's credentials file. A mint=false contract must never write that file.
        self.write_creds(f"other-label:unrelated\n{SMTP_LABEL}:the-secret\n")
        before = self.read(self.creds_path)
        self.run_main()
        self.run_main()
        self.assertEqual(before, self.read(self.creds_path))
        self.assertNotIn(DRAIN_LABEL, self.read(self.creds_path))

    def test_smtp_delivery_with_no_recorded_credential_refuses_and_writes_nothing(self):
        self.write_creds("other-label:unrelated\n")
        before = self.read(self.creds_path)
        self.assertEqual(1, self.run_main())
        self.assertFalse(os.path.exists(self.env_path))
        self.assertEqual(before, self.read(self.creds_path))
        self.assertIn(SMTP_LABEL, self.stderr.getvalue())

    def test_smtp_delivery_with_no_credentials_file_refuses_and_creates_none(self):
        self.assertEqual(1, self.run_main())
        self.assertFalse(os.path.exists(self.env_path))
        self.assertFalse(os.path.exists(self.creds_path))

    def test_a_digest_the_table_does_not_list_refuses_and_writes_nothing(self):
        # Sabotage: make contract_for_compose fall back to a contract on an unknown digest
        # and this goes red. The failure it guards is a guessed environment for an image
        # nobody described.
        self.write_compose(OTHER_DIGEST)
        self.write_creds(f"{SMTP_LABEL}:the-secret\n")
        before = self.read(self.creds_path)
        self.assertEqual(1, self.run_main())
        self.assertFalse(os.path.exists(self.env_path))
        self.assertEqual(before, self.read(self.creds_path))
        self.assertIn(OTHER_DIGEST, self.stderr.getvalue())
        self.assertIn("shim-env-contracts.json", self.stderr.getvalue())

    def test_a_refusal_does_not_replace_an_env_file_already_there(self):
        self.write_compose(OTHER_DIGEST)
        self.write_creds(f"{SMTP_LABEL}:the-secret\n")
        with open(self.env_path, "w", encoding="utf-8") as f:
            f.write("LIVE=untouched\n")
        self.assertEqual(1, self.run_main())
        self.assertEqual("LIVE=untouched\n", self.read(self.env_path))

    def test_a_missing_table_refuses(self):
        self.write_creds(f"{SMTP_LABEL}:the-secret\n")
        self.assertEqual(1, self.run_main(CONTRACTS_PATH=os.path.join(self.tmp, "absent.json")))
        self.assertFalse(os.path.exists(self.env_path))

    def test_an_unreadable_compose_file_refuses(self):
        self.write_creds(f"{SMTP_LABEL}:the-secret\n")
        self.assertEqual(1, self.run_main(SHIM_COMPOSE_PATH=os.path.join(self.tmp, "absent.yml")))
        self.assertFalse(os.path.exists(self.env_path))

    def test_a_drain_digest_on_a_fresh_host_generates_a_token_and_records_it(self):
        self.write_compose(OTHER_DIGEST)
        self.assertEqual(0, self.run_main(CONTRACTS_PATH=self.table_with_drain_digest()))
        self.assertRegex(self.read(self.env_path), r"SHIM_DRAIN_TOKEN=\S+")
        self.assertEqual(1, sum(1 for line in self.read(self.creds_path).splitlines() if line.startswith(f"{DRAIN_LABEL}:")))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.env_path).st_mode))

    def test_a_second_drain_run_reuses_the_token_the_first_generated(self):
        self.write_compose(OTHER_DIGEST)
        table = self.table_with_drain_digest()
        self.run_main(CONTRACTS_PATH=table)
        first = self.read(self.env_path)
        self.run_main(CONTRACTS_PATH=table)
        self.assertEqual(first, self.read(self.env_path))
        self.assertEqual(1, sum(1 for line in self.read(self.creds_path).splitlines() if line.startswith(f"{DRAIN_LABEL}:")))

    def test_a_drain_digest_with_a_recorded_token_writes_it_verbatim(self):
        self.write_compose(OTHER_DIGEST)
        self.write_creds(f"{DRAIN_LABEL}:a-real-token\n")
        self.assertEqual(0, self.run_main(CONTRACTS_PATH=self.table_with_drain_digest()))
        self.assertIn("SHIM_DRAIN_TOKEN=a-real-token", self.read(self.env_path))

    def test_the_secret_is_never_printed_to_stdout_or_stderr(self):
        self.write_creds(f"{SMTP_LABEL}:a-very-distinctive-secret-value\n")
        self.run_main()
        self.assertNotIn("a-very-distinctive-secret-value", self.stdout.getvalue())
        self.assertNotIn("a-very-distinctive-secret-value", self.stderr.getvalue())

    def test_a_freshly_generated_drain_token_is_also_never_printed(self):
        self.write_compose(OTHER_DIGEST)
        self.run_main(CONTRACTS_PATH=self.table_with_drain_digest())
        generated = self.read(self.creds_path).strip().split(":", 1)[1]
        self.assertNotIn(generated, self.stdout.getvalue())
        self.assertNotIn(generated, self.stderr.getvalue())

    def test_a_refusal_never_prints_the_secret(self):
        self.write_compose(OTHER_DIGEST)
        self.write_creds(f"{SMTP_LABEL}:a-very-distinctive-secret-value\n")
        self.run_main()
        self.assertNotIn("a-very-distinctive-secret-value", self.stdout.getvalue())
        self.assertNotIn("a-very-distinctive-secret-value", self.stderr.getvalue())

    def test_malformed_credentials_file_fails_loudly_via_the_shared_error_path(self):
        self.write_creds("no-colon-on-this-line\n")
        self.assertEqual(1, self.run_main())
        self.assertFalse(os.path.exists(self.env_path))
        self.assertIn("malformed", self.stderr.getvalue())

    def test_an_empty_recorded_smtp_secret_is_refused_and_writes_nothing(self):
        # The role refuses an empty secret, and so must this script: a rendered SMTP_PASS=
        # line starts the shim with a blank password.
        self.write_creds(f"other-label:unrelated\n{SMTP_LABEL}:\n")
        before = self.read(self.creds_path)
        self.assertEqual(1, self.run_main())
        self.assertFalse(os.path.exists(self.env_path))
        self.assertEqual(before, self.read(self.creds_path))
        self.assertIn(SMTP_LABEL, self.stderr.getvalue())

    def test_an_empty_recorded_drain_token_is_refused_and_not_rendered(self):
        self.write_compose(OTHER_DIGEST)
        self.write_creds(f"{DRAIN_LABEL}:\n")
        before = self.read(self.creds_path)
        self.assertEqual(1, self.run_main(CONTRACTS_PATH=self.table_with_drain_digest()))
        self.assertFalse(os.path.exists(self.env_path))
        self.assertEqual(before, self.read(self.creds_path))
        self.assertIn(DRAIN_LABEL, self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
