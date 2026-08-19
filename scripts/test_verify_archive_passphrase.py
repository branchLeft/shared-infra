#!/usr/bin/env python3
"""Unit tests for verify-archive-passphrase.

The claim this script makes is "the escrowed passphrase still opens this
archive", and it is checked immediately before an irreversible key
destruction. The failure that matters is therefore a **false PASS** -- a run
that reports success without having decrypted anything, or one that decrypted
against a passphrase the operator did not supply. Most of what follows is
aimed at that shape rather than at the happy path.

The second failure that matters is a decrypted value reaching a terminal.
Pulumi emits one on exactly one path -- a correct passphrase over a corrupt
archive, where the JSON parse error quotes a character of the plaintext -- so
there is a test that this script's own output never carries what Pulumi wrote.

`pulumi` itself is stubbed everywhere below. These tests therefore prove the
orchestration, the classification and the environment handling; they do not
prove that `pulumi stack init` validates a salt or that `pulumi stack import`
decrypts, which are properties of Pulumi observed by running it and recorded
in the runbook section this script belongs to.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "verify-archive-passphrase.py"
    spec = importlib.util.spec_from_file_location("verify_archive_passphrase", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = _load_module()


# Obviously fake throughout. Nothing here is, or resembles, a real salt,
# ciphertext or passphrase from any stack.
FAKE_SALT = "v1:FAKESALTAAAA=:v1:FAKENONCEAAAAAAA:FAKEWRAPPEDKNOWNPLAINTEXT=="
FAKE_CIPHERTEXT = "v1:FAKENONCEBBBBBB:FAKECIPHERTEXTVALUE="
FAKE_PASSPHRASE = "not-a-real-passphrase"


def archive_document(
    *,
    provider: str = "passphrase",
    salt: str | None = FAKE_SALT,
    resources: list | None = None,
) -> dict:
    providers: dict = {"type": provider, "state": {}}
    if provider == "passphrase":
        if salt is not None:
            providers["state"]["salt"] = salt
    else:
        providers["state"] = {"url": "gcpkms://projects/FAKE/x", "encryptedkey": "FAKE"}
    if resources is None:
        resources = [
            {
                "urn": "urn:pulumi:production::branchleft-mail::pulumi:pulumi:Stack::branchleft-mail-production",
                "custom": False,
                "type": "pulumi:pulumi:Stack",
                "outputs": {
                    "thing": {
                        "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
                        "ciphertext": FAKE_CIPHERTEXT,
                    }
                },
            }
        ]
    return {
        "version": 3,
        "deployment": {
            "manifest": {"time": "2026-08-18T00:00:00Z", "version": "v3.255.0"},
            "secrets_providers": providers,
            "resources": resources,
        },
    }


@contextlib.contextmanager
def temp_archive(document) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "archive.json")
        with open(path, "w", encoding="utf-8") as fh:
            if isinstance(document, str):
                fh.write(document)
            else:
                json.dump(document, fh)
        yield path


class FakePulumi:
    """Stands in for the `pulumi` binary.

    `whoami` answers with whatever backend the environment selected, so a test
    can make Pulumi report a *different* backend and prove the script refuses
    to continue -- the guard that keeps this off live state.
    """

    def __init__(self, *, init=(0, ""), imp=(0, ""), whoami_backend=None, raises=None):
        self.init = init
        self.imp = imp
        self.whoami_backend = whoami_backend
        self.raises = raises
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def __call__(self, args, *, cwd, env, capture_stdout=False):
        if self.raises is not None:
            raise self.raises
        self.calls.append((tuple(args), dict(env)))
        if args[1] == "whoami":
            backend = self.whoami_backend or env["PULUMI_BACKEND_URL"]
            return 0, f"User: nobody\nBackend URL: {backend}\nToken type: personal\n", ""
        if tuple(args[1:3]) == ("stack", "init"):
            rc, err = self.init
            return rc, "", err
        if tuple(args[1:3]) == ("stack", "import"):
            rc, err = self.imp
            return rc, "", err
        raise AssertionError(f"unexpected pulumi invocation: {args}")

    def subcommands(self) -> list[tuple[str, ...]]:
        return [tuple(args[1:3]) for args, _ in self.calls]


@contextlib.contextmanager
def stubbed(fake: FakePulumi):
    original = verify.run_pulumi
    verify.run_pulumi = fake
    try:
        yield fake
    finally:
        verify.run_pulumi = original


class ExitCodeTests(unittest.TestCase):
    def test_every_outcome_has_its_own_code(self):
        # The defect this guards is the one the committed-secret guard shipped
        # with: an unreadable file and a real finding sharing exit 1, so the
        # caller could not tell "it says no" from "it could not look".
        codes = [
            verify.EXIT_PASS,
            verify.EXIT_FAIL,
            verify.EXIT_USAGE,
            verify.EXIT_ARCHIVE,
            verify.EXIT_INCONCLUSIVE,
        ]
        self.assertEqual(len(set(codes)), len(codes))

    def test_pass_is_zero_and_nothing_else_is(self):
        self.assertEqual(verify.EXIT_PASS, 0)
        for code in (verify.EXIT_FAIL, verify.EXIT_USAGE, verify.EXIT_ARCHIVE, verify.EXIT_INCONCLUSIVE):
            self.assertNotEqual(code, 0)

    def test_a_single_failure_dominates_a_batch_of_passes(self):
        self.assertEqual(
            verify.verdict_exit_code([verify.EXIT_PASS, verify.EXIT_PASS, verify.EXIT_FAIL]),
            verify.EXIT_FAIL,
        )

    def test_severity_order_is_fail_then_archive_then_inconclusive(self):
        self.assertEqual(
            verify.verdict_exit_code([verify.EXIT_ARCHIVE, verify.EXIT_INCONCLUSIVE]),
            verify.EXIT_ARCHIVE,
        )
        self.assertEqual(
            verify.verdict_exit_code([verify.EXIT_INCONCLUSIVE, verify.EXIT_PASS]),
            verify.EXIT_INCONCLUSIVE,
        )
        self.assertEqual(verify.verdict_exit_code([verify.EXIT_PASS]), verify.EXIT_PASS)

    def test_no_archives_is_not_silently_a_pass_of_something(self):
        self.assertEqual(verify.verdict_exit_code([]), verify.EXIT_PASS)


class CountKeyTests(unittest.TestCase):
    def test_counts_nested_keys_in_dicts_and_lists(self):
        doc = {"a": {"ciphertext": "x"}, "b": [{"ciphertext": "y"}, {"c": {"ciphertext": "z"}}]}
        self.assertEqual(verify.count_key(doc, "ciphertext"), 3)

    def test_a_matching_value_is_not_a_matching_key(self):
        self.assertEqual(verify.count_key({"a": "ciphertext"}, "ciphertext"), 0)

    def test_absent_key_counts_zero(self):
        self.assertEqual(verify.count_key({"a": 1}, "ciphertext"), 0)


class NamesFromUrnTests(unittest.TestCase):
    def test_reads_stack_then_project(self):
        urn = "urn:pulumi:production::branchleft-mail::pulumi:pulumi:Stack::branchleft-mail-production"
        self.assertEqual(verify.names_from_urn(urn), ("branchleft-mail", "production"))

    def test_a_non_urn_falls_back(self):
        self.assertEqual(
            verify.names_from_urn("not-a-urn"), (verify.FALLBACK_PROJECT, verify.FALLBACK_STACK)
        )

    def test_absent_urn_falls_back(self):
        self.assertEqual(
            verify.names_from_urn(None), (verify.FALLBACK_PROJECT, verify.FALLBACK_STACK)
        )

    def test_a_name_that_is_not_a_legal_pulumi_name_falls_back(self):
        # Straight into `pulumi stack init` otherwise, where a shell-special or
        # path-traversing name is not something to find out about at the last
        # reversible moment before a key destruction.
        urn = "urn:pulumi:../../etc::proj::pulumi:pulumi:Stack::x"
        self.assertEqual(
            verify.names_from_urn(urn), (verify.FALLBACK_PROJECT, verify.FALLBACK_STACK)
        )


class InspectArchiveTests(unittest.TestCase):
    def test_reads_a_post_wrap_archive(self):
        with temp_archive(archive_document()) as path:
            info = verify.inspect_archive(path)
        self.assertEqual(info["salt"], FAKE_SALT)
        self.assertEqual(info["resources"], 1)
        self.assertEqual(info["ciphertext"], 1)
        self.assertEqual(info["names"], ("branchleft-mail", "production"))

    def test_a_kms_wrapped_pre_wrap_archive_is_refused(self):
        # Four of these sit in the same bucket and prefix as the six that
        # matter. No passphrase opens one, so a passphrase verdict over one
        # would be meaningless -- and mistaking it for evidence is exactly the
        # confusion the archive record warns about.
        with temp_archive(archive_document(provider="cloud")) as path:
            with self.assertRaises(verify.ArchiveError) as caught:
                verify.inspect_archive(path)
        self.assertIn("passphrase", str(caught.exception))

    def test_a_passphrase_provider_with_no_salt_is_refused(self):
        with temp_archive(archive_document(salt=None)) as path:
            with self.assertRaises(verify.ArchiveError):
                verify.inspect_archive(path)

    def test_an_unwrapped_export_is_refused(self):
        # `plaintext` keys mean the export was taken with --show-secrets. It is
        # not protected by anything, so it is not evidence about a passphrase.
        doc = archive_document()
        doc["deployment"]["resources"][0]["outputs"]["thing"] = {
            "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
            "plaintext": '"FAKE"',
        }
        with temp_archive(doc) as path:
            with self.assertRaises(verify.ArchiveError) as caught:
                verify.inspect_archive(path)
        self.assertIn("unwrapped", str(caught.exception))

    def test_malformed_json_is_refused(self):
        with temp_archive('{"version": 3, "deployment": {"secrets_pro') as path:
            with self.assertRaises(verify.ArchiveError) as caught:
                verify.inspect_archive(path)
        self.assertIn("not valid JSON", str(caught.exception))

    def test_json_that_is_not_a_stack_export_is_refused(self):
        with temp_archive({"hello": "world"}) as path:
            with self.assertRaises(verify.ArchiveError):
                verify.inspect_archive(path)

    def test_a_missing_file_is_refused(self):
        with self.assertRaises(verify.ArchiveError) as caught:
            verify.inspect_archive("/nonexistent/archive.json")
        self.assertIn("cannot read", str(caught.exception))

    def test_an_empty_deployment_reports_no_ciphertext(self):
        with temp_archive(archive_document(resources=[])) as path:
            info = verify.inspect_archive(path)
        self.assertEqual(info["ciphertext"], 0)
        self.assertEqual(info["names"], (verify.FALLBACK_PROJECT, verify.FALLBACK_STACK))


class ChildEnvTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)

    def test_the_plain_passphrase_variable_is_removed(self):
        # It outranks the _FILE form, so an operator with it exported would
        # have the whole verification run against their ambient value and pass.
        os.environ["PULUMI_CONFIG_PASSPHRASE"] = "ambient-value-that-must-not-be-used"
        env = verify.child_env(home="/tmp/h", backend_url="file:///tmp/s", passphrase_file="/tmp/p")
        self.assertNotIn("PULUMI_CONFIG_PASSPHRASE", env)
        self.assertEqual(env["PULUMI_CONFIG_PASSPHRASE_FILE"], "/tmp/p")

    def test_a_service_token_is_removed(self):
        os.environ["PULUMI_ACCESS_TOKEN"] = "pul-FAKE"
        env = verify.child_env(home="/tmp/h", backend_url="file:///tmp/s", passphrase_file="/tmp/p")
        self.assertNotIn("PULUMI_ACCESS_TOKEN", env)

    def test_an_ambient_backend_is_overridden(self):
        # A placeholder bucket name rather than either of this estate's. The
        # Pulumi secrets audit next door flags any file naming a real backend
        # as a site where one is selected, and a fixture asserting a backend is
        # *refused* is not such a site.
        os.environ["PULUMI_BACKEND_URL"] = "gs://example-bucket-not-this-estate"
        env = verify.child_env(home="/tmp/h", backend_url="file:///tmp/s", passphrase_file="/tmp/p")
        self.assertEqual(env["PULUMI_BACKEND_URL"], "file:///tmp/s")

    def test_a_non_file_backend_is_refused(self):
        with self.assertRaises(verify.PreflightError):
            verify.child_env(
                home="/tmp/h",
                backend_url="gs://example-bucket-not-this-estate",
                passphrase_file="/tmp/p",
            )

    def test_the_update_check_is_disabled(self):
        env = verify.child_env(home="/tmp/h", backend_url="file:///tmp/s", passphrase_file="/tmp/p")
        self.assertEqual(env["PULUMI_SKIP_UPDATE_CHECK"], "true")


class ClassifyFailureTests(unittest.TestCase):
    def test_incorrect_passphrase(self):
        self.assertEqual(
            verify.classify_failure("error: could not create secrets manager: incorrect passphrase"),
            "passphrase",
        )

    def test_failed_to_decrypt(self):
        self.assertEqual(
            verify.classify_failure("error: could not deserialize deployment: failed to decrypt: x"),
            "passphrase",
        )

    def test_authentication_failure_is_its_own_kind(self):
        self.assertEqual(
            verify.classify_failure(
                "error: could not deserialize deployment: cipher: message authentication failed"
            ),
            "authentication",
        )

    def test_a_bare_deserialisation_error_is_an_archive_problem(self):
        self.assertEqual(
            verify.classify_failure("error: could not deserialize deployment: unexpected end"),
            "deployment",
        )

    def test_an_unrecognised_failure_is_not_guessed_at(self):
        # Degrading to `unknown` -- and from there to INCONCLUSIVE -- is what
        # keeps a reworded Pulumi error from becoming a false PASS.
        self.assertEqual(verify.classify_failure("error: no such host"), "unknown")


class VerifyArchiveTests(unittest.TestCase):
    def _info(self, **overrides):
        info = {
            "salt": FAKE_SALT,
            "resources": 4,
            "ciphertext": 6,
            "names": ("branchleft-mail", "production"),
        }
        info.update(overrides)
        return info

    def test_both_stages_clean_is_a_pass(self):
        fake = FakePulumi()
        with stubbed(fake):
            outcome, detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertEqual(outcome, verify.EXIT_PASS)
        self.assertIn("opens this archive", detail)
        self.assertEqual(
            fake.subcommands(),
            [("whoami", "--verbose"), ("stack", "init"), ("stack", "import")],
        )

    def test_a_salt_mismatch_fails(self):
        fake = FakePulumi(init=(255, "error: could not create secrets manager for new stack: incorrect passphrase"))
        with stubbed(fake):
            outcome, detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertEqual(outcome, verify.EXIT_FAIL)
        self.assertIn("salt", detail)

    def test_a_ciphertext_that_does_not_decrypt_fails(self):
        fake = FakePulumi(imp=(255, "error: could not deserialize deployment: failed to decrypt: incorrect passphrase"))
        with stubbed(fake):
            outcome, detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertEqual(outcome, verify.EXIT_FAIL)
        self.assertIn("decrypt", detail)

    def test_an_authentication_failure_fails_closed(self):
        fake = FakePulumi(imp=(255, "error: could not deserialize deployment: cipher: message authentication failed"))
        with stubbed(fake):
            outcome, detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertEqual(outcome, verify.EXIT_FAIL)
        self.assertIn("corrupted archive", detail)

    def test_a_corrupt_archive_is_not_reported_as_a_wrong_passphrase(self):
        fake = FakePulumi(imp=(255, "error: could not deserialize deployment: unexpected end of JSON input"))
        with stubbed(fake):
            outcome, _detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertEqual(outcome, verify.EXIT_ARCHIVE)

    def test_an_unrecognised_pulumi_failure_is_inconclusive_not_a_verdict(self):
        fake = FakePulumi(imp=(255, "error: the disk is full"))
        with stubbed(fake):
            outcome, _detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertEqual(outcome, verify.EXIT_INCONCLUSIVE)

    def test_pulumi_never_sees_a_decrypted_value_in_this_scripts_output(self):
        # The one path where Pulumi's own stderr carries plaintext: a correct
        # passphrase over a corrupt archive, where the parse error quotes the
        # first character of what was decrypted. Nothing Pulumi wrote may
        # appear in what this script returns.
        leak = "error: could not deserialize deployment: invalid character 'S' looking for beginning of value"
        fake = FakePulumi(imp=(255, leak))
        with stubbed(fake):
            _outcome, detail = verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        self.assertNotIn("invalid character", detail)
        self.assertNotIn("'S'", detail)

    def test_an_archive_with_no_encrypted_values_proves_nothing(self):
        fake = FakePulumi()
        with stubbed(fake):
            outcome, detail = verify.verify_archive(
                "/tmp/a.json", self._info(ciphertext=0), "/tmp/p", pulumi="pulumi"
            )
        self.assertEqual(outcome, verify.EXIT_INCONCLUSIVE)
        self.assertIn("proves nothing", detail)
        # And it must not have reached Pulumi at all: a clean run over an
        # archive holding nothing encrypted is precisely the false PASS.
        self.assertEqual(fake.calls, [])

    def test_it_refuses_a_backend_that_is_not_the_scratch_one(self):
        fake = FakePulumi(whoami_backend="gs://example-bucket-not-this-estate")
        with stubbed(fake):
            with self.assertRaises(verify.PreflightError):
                verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")

    def test_relative_paths_are_made_absolute_before_pulumi_sees_them(self):
        # Every invocation runs with its cwd inside the scratch project, so a
        # relative archive path or passphrase file would resolve against the
        # wrong directory.
        fake = FakePulumi()
        with stubbed(fake):
            verify.verify_archive("archive.json", self._info(), "pp", pulumi="pulumi")
        args, env = fake.calls[-1]
        self.assertIn(os.path.abspath("archive.json"), args)
        self.assertEqual(env["PULUMI_CONFIG_PASSPHRASE_FILE"], os.path.abspath("pp"))

    def test_the_import_is_forced_and_reads_the_archive_in_place(self):
        fake = FakePulumi()
        with stubbed(fake):
            verify.verify_archive("/srv/archive.json", self._info(), "/tmp/p", pulumi="pulumi")
        args, env = fake.calls[-1]
        self.assertIn("--force", args)
        self.assertIn("/srv/archive.json", args)
        self.assertEqual(env["PULUMI_CONFIG_PASSPHRASE_FILE"], "/tmp/p")

    def test_every_invocation_addresses_a_file_backend_under_a_scratch_directory(self):
        fake = FakePulumi()
        with stubbed(fake):
            verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        for _args, env in fake.calls:
            self.assertTrue(env["PULUMI_BACKEND_URL"].startswith("file://"))
            self.assertIn("pulumi-archive-verify-", env["PULUMI_BACKEND_URL"])
            self.assertIn("pulumi-archive-verify-", env["PULUMI_HOME"])

    def test_the_scratch_directory_is_removed_even_when_the_run_blows_up(self):
        fake = FakePulumi(raises=RuntimeError("boom"))
        before = set(pathlib.Path(tempfile.gettempdir()).glob("pulumi-archive-verify-*"))
        with stubbed(fake):
            with self.assertRaises(RuntimeError):
                verify.verify_archive("/tmp/a.json", self._info(), "/tmp/p", pulumi="pulumi")
        after = set(pathlib.Path(tempfile.gettempdir()).glob("pulumi-archive-verify-*"))
        self.assertEqual(after - before, set())


class MainTests(unittest.TestCase):
    """`main` end to end with `pulumi` stubbed.

    `--pulumi` is pointed at this interpreter so the binary check passes; the
    stub means it is never executed.
    """

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = verify.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_an_empty_passphrase_file_is_a_usage_error_not_a_failed_verification(self):
        # The zsh trap in the migration runbook -- `read -rs -p` leaves the
        # variable empty and the file zero-length -- must not come back as
        # "your escrowed passphrase does not work".
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, "pp")
            open(empty, "w").close()
            with temp_archive(archive_document()) as archive:
                code, _out, err = self._run(
                    ["--passphrase-file", empty, "--pulumi", sys.executable, archive]
                )
        self.assertEqual(code, verify.EXIT_USAGE)
        self.assertIn("empty", err)

    def test_a_whitespace_only_passphrase_file_is_a_usage_error(self):
        # Pulumi strips a trailing newline from the file, so a file holding
        # only one is an empty passphrase to Pulumi -- which it reports as an
        # incorrect passphrase. That must not surface as "your escrowed
        # passphrase does not work".
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pp")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n")
            with temp_archive(archive_document()) as archive:
                code, _out, err = self._run(
                    ["--passphrase-file", path, "--pulumi", sys.executable, archive]
                )
        self.assertEqual(code, verify.EXIT_USAGE)
        self.assertIn("empty", err)

    def test_a_passphrase_file_that_is_not_text_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pp")
            with open(path, "wb") as fh:
                fh.write(b"\xff\xfe\x00binary")
            with temp_archive(archive_document()) as archive:
                code, _out, _err = self._run(
                    ["--passphrase-file", path, "--pulumi", sys.executable, archive]
                )
        self.assertEqual(code, verify.EXIT_USAGE)

    def test_a_missing_passphrase_file_is_a_usage_error(self):
        with temp_archive(archive_document()) as archive:
            code, _out, _err = self._run(
                ["--passphrase-file", "/nonexistent/pp", "--pulumi", sys.executable, archive]
            )
        self.assertEqual(code, verify.EXIT_USAGE)

    def test_a_missing_pulumi_binary_is_a_usage_error(self):
        with temp_archive(archive_document()) as archive:
            code, _out, err = self._run(
                ["--passphrase-file", "/nonexistent/pp", "--pulumi", "/nonexistent/pulumi", archive]
            )
        self.assertEqual(code, verify.EXIT_USAGE)
        self.assertIn("nothing was verified", err)

    def _with_passphrase(self, fake, archives, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "pp")
            with open(pp, "w", encoding="utf-8") as fh:
                fh.write(FAKE_PASSPHRASE)
            with stubbed(fake):
                return self._run(
                    ["--passphrase-file", pp, "--pulumi", sys.executable, *extra, *archives]
                )

    def test_a_clean_run_passes(self):
        with temp_archive(archive_document()) as archive:
            code, out, _err = self._with_passphrase(FakePulumi(), [archive])
        self.assertEqual(code, verify.EXIT_PASS)
        self.assertIn("PASS", out)
        self.assertIn("all 1 archive open", out)

    def test_one_bad_archive_among_good_ones_still_blocks(self):
        fake = FakePulumi(imp=(255, "error: could not deserialize deployment: failed to decrypt: x"))
        with temp_archive(archive_document()) as a, temp_archive(archive_document()) as b:
            code, out, _err = self._with_passphrase(fake, [a, b])
        self.assertEqual(code, verify.EXIT_FAIL)
        self.assertIn("must not be destroyed", out)

    def test_a_pre_wrap_archive_reports_archive_not_failure(self):
        with temp_archive(archive_document(provider="cloud")) as archive:
            code, out, _err = self._with_passphrase(FakePulumi(), [archive])
        self.assertEqual(code, verify.EXIT_ARCHIVE)
        self.assertIn("ARCHIVE", out)

    def test_nothing_pulumi_wrote_reaches_stdout(self):
        leak = "error: could not deserialize deployment: invalid character 'S' looking for beginning of value"
        with temp_archive(archive_document()) as archive:
            code, out, err = self._with_passphrase(FakePulumi(imp=(255, leak)), [archive])
        self.assertEqual(code, verify.EXIT_ARCHIVE)
        self.assertNotIn("invalid character", out + err)
        self.assertNotIn("'S'", out + err)

    def test_the_passphrase_is_never_echoed(self):
        with temp_archive(archive_document()) as archive:
            _code, out, err = self._with_passphrase(FakePulumi(), [archive])
        self.assertNotIn(FAKE_PASSPHRASE, out + err)

    def test_the_salt_is_never_echoed(self):
        # A salt is not a secret on its own, but it is half of what derives the
        # key and the archive record is explicit that it must stay out of a
        # terminal scrollback.
        with temp_archive(archive_document()) as archive:
            _code, out, err = self._with_passphrase(FakePulumi(), [archive])
        self.assertNotIn(FAKE_SALT, out + err)

    def test_json_output_carries_the_outcome_and_its_code(self):
        with temp_archive(archive_document()) as archive:
            code, out, _err = self._with_passphrase(FakePulumi(), [archive], extra=["--json"])
        payload = json.loads(out)
        self.assertEqual(code, verify.EXIT_PASS)
        self.assertEqual(payload[0]["outcome"], "PASS")
        self.assertEqual(payload[0]["exit_code"], verify.EXIT_PASS)

    def test_the_passphrase_cannot_be_given_as_an_argument(self):
        # It would be visible in the process table and in shell history. There
        # is deliberately no such flag, and its absence is worth a test so it
        # is not added back as a convenience.
        self.assertNotIn("--passphrase\n", verify.__doc__ or "")
        with self.assertRaises(SystemExit):
            self._run(["--passphrase", FAKE_PASSPHRASE, "/tmp/a.json"])


if __name__ == "__main__":
    unittest.main()
