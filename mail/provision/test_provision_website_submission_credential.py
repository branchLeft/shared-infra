#!/usr/bin/env python3
"""Unit tests for provision_website_submission_credential.py. Pure diff
functions get full coverage (no network access, no live server needed); the
orchestration in main() is exercised against a mocked JMAP layer, same split
as test_provision_mailboxes.py's ReconcileAccountsOrderingTests.
EnvironmentParameterizationTests covers SEND_AS_LOCAL/CREDENTIAL_LABEL/
APP_PASSWORD_DESCRIPTION themselves being environment-variable-driven -- the
mechanism that lets this one script provision both the website's and the
blog's submission credentials.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
import importlib
import io
import os
import tempfile
import unittest
from unittest import mock

import provision_website_submission_credential as pwsc
from provision_website_submission_credential import (
    APP_PASSWORD_DESCRIPTION,
    CREDENTIAL_LABEL,
    DISABLED_PERMISSIONS,
    SEND_AS_LOCAL,
    build_app_password_create_args,
    plan_app_password_action,
)


class BuildAppPasswordCreateArgsTests(unittest.TestCase):
    def test_sets_the_given_description(self):
        args = build_app_password_create_args("some-description", ("imapAuthenticate",))

        self.assertEqual(args["description"], "some-description")

    def test_permissions_use_the_disable_variant(self):
        # Disable, not Replace -- Replace would drop every permission not
        # explicitly listed, breaking SMTP submission itself. Disable only
        # subtracts the named permissions from the account's own effective
        # set, leaving submission (Permission::Authenticate) untouched.
        args = build_app_password_create_args("d", ("imapAuthenticate",))

        self.assertEqual(args["permissions"]["@type"], "Disable")

    def test_permissions_is_an_object_keyed_by_permission_name_not_a_list(self):
        # Map<Permission> (the schema type backing this field) serializes
        # as {"name": true, ...}, not a JSON array -- same family of gotcha
        # as provision_mailboxes.py's credentials field, different shape.
        args = build_app_password_create_args("d", ("imapAuthenticate", "imapAppend"))

        self.assertEqual(
            args["permissions"]["permissions"],
            {"imapAuthenticate": True, "imapAppend": True},
        )

    def test_empty_disabled_permissions_yields_an_empty_permissions_object(self):
        args = build_app_password_create_args("d", ())

        self.assertEqual(args["permissions"]["permissions"], {})


class ModuleConstantsTests(unittest.TestCase):
    def test_disables_imap_authenticate(self):
        # The specific permission IMAP's own LOGIN/AUTHENTICATE handlers
        # assert before anything else runs -- disabling it blocks IMAP
        # login outright, not just access to one mailbox's contents.
        self.assertIn("imapAuthenticate", DISABLED_PERMISSIONS)

    def test_send_as_local_is_info_not_a_new_account(self):
        # This credential attaches to the *existing* info@ mailbox rather
        # than a new account -- see the module docstring for why a
        # separate account can't claim info@ as a send-as alias (the
        # global email-uniqueness index collision).
        self.assertEqual(SEND_AS_LOCAL, "info")

    def test_description_does_not_look_like_a_real_mailbox_local_part(self):
        # It's a free-text label, not an address -- but it shouldn't read
        # as one to a future reader either.
        self.assertNotIn("@", APP_PASSWORD_DESCRIPTION)


class EnvironmentParameterizationTests(unittest.TestCase):
    """SEND_AS_LOCAL/CREDENTIAL_LABEL/APP_PASSWORD_DESCRIPTION are read via
    os.environ.get at import time (same pattern this module already uses for
    BASE_URL/MAIL_DOMAIN/etc), so overriding them requires reimporting the
    module under the patched environment -- mock.patch.object on the already
    -imported module wouldn't exercise the os.environ.get call itself.
    Reloads back to the unpatched environment in a finally so these don't
    leak a blog-flavoured module into every other test in this file.
    """

    def _reload_under_env(self, **env_overrides):
        with mock.patch.dict(os.environ, env_overrides):
            return importlib.reload(pwsc)

    def tearDown(self):
        # Restore the module-level constants to their unpatched defaults
        # regardless of what the test body did, so later tests (and other
        # test modules sharing the same process) see the real defaults.
        importlib.reload(pwsc)

    def test_send_as_local_defaults_to_info_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SEND_AS_LOCAL", None)
            reloaded = importlib.reload(pwsc)
        self.assertEqual(reloaded.SEND_AS_LOCAL, "info")

    def test_send_as_local_honors_an_override(self):
        reloaded = self._reload_under_env(SEND_AS_LOCAL="blog")
        self.assertEqual(reloaded.SEND_AS_LOCAL, "blog")

    def test_credential_label_honors_an_override(self):
        reloaded = self._reload_under_env(CREDENTIAL_LABEL="blog-ghost-smtp")
        self.assertEqual(reloaded.CREDENTIAL_LABEL, "blog-ghost-smtp")

    def test_app_password_description_honors_an_override(self):
        reloaded = self._reload_under_env(
            APP_PASSWORD_DESCRIPTION="blog-ghost-transactional-submission"
        )
        self.assertEqual(
            reloaded.APP_PASSWORD_DESCRIPTION, "blog-ghost-transactional-submission"
        )

    def test_overriding_one_variable_leaves_the_others_at_their_defaults(self):
        # A wrapper script that only sets SEND_AS_LOCAL (a mistake -- the
        # three are meant to be set together) shouldn't silently mix a new
        # send-as address with the website's own label/description.
        reloaded = self._reload_under_env(SEND_AS_LOCAL="blog")
        self.assertEqual(reloaded.CREDENTIAL_LABEL, "info-website-submission")
        self.assertEqual(
            reloaded.APP_PASSWORD_DESCRIPTION, "website-contact-form-submission"
        )

    def test_disabled_permissions_is_not_environment_driven(self):
        # Both credentials this script provisions disable IMAP the same
        # way -- unlike the three identity fields, this isn't meant to vary
        # per invocation, so it stays a plain module constant.
        reloaded = self._reload_under_env(SEND_AS_LOCAL="blog")
        self.assertEqual(reloaded.DISABLED_PERMISSIONS, ("imapAuthenticate",))


class PlanAppPasswordActionTests(unittest.TestCase):
    def test_nothing_remote_is_a_create(self):
        self.assertEqual(plan_app_password_action(existing_remotely=False, recorded_locally=False), "create")

    def test_nothing_remote_but_something_recorded_locally_is_still_a_create(self):
        # A stale local record from some unrelated prior state (e.g. a
        # hand-edited file) doesn't stop a genuinely missing credential
        # from being created -- remote state is authoritative for
        # existence.
        self.assertEqual(plan_app_password_action(existing_remotely=False, recorded_locally=True), "create")

    def test_exists_remotely_and_recorded_locally_is_a_no_op(self):
        self.assertEqual(plan_app_password_action(existing_remotely=True, recorded_locally=True), "none")

    def test_exists_remotely_but_not_recorded_locally_is_orphaned(self):
        # The credential-loss-analogous scenario: Stalwart applied the
        # create but the response (and the one-time plaintext secret in
        # it) never reached this script -- unlike provision_mailboxes.py's
        # fix, there's no secret to persist-before-create here (the server
        # generates it), so this state can only be detected, not prevented.
        self.assertEqual(plan_app_password_action(existing_remotely=True, recorded_locally=False), "orphaned")


class LoadRecordedSecretTests(unittest.TestCase):
    """Direct coverage of the real line-parsing logic -- previously only
    exercised indirectly through full-function mocking in
    MainOrchestrationTests, which never actually ran a real split(":", 1)
    against real file content. Mirrors provision_mailboxes.py's
    LoadRecordedSecretsTests in shape.
    """

    def test_missing_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", os.path.join(tmp, "nope")):
                self.assertIsNone(pwsc._load_recorded_secret())

    def test_matching_label_returns_its_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{CREDENTIAL_LABEL}:the-secret-value\n")
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", path):
                self.assertEqual(pwsc._load_recorded_secret(), "the-secret-value")

    def test_non_matching_label_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("some-other-label:some-other-secret\n")
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", path):
                self.assertIsNone(pwsc._load_recorded_secret())

    def test_a_secret_containing_a_colon_is_preserved_whole(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{CREDENTIAL_LABEL}:has:a:colon\n")
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", path):
                self.assertEqual(pwsc._load_recorded_secret(), "has:a:colon")

    def test_blank_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"\n\n{CREDENTIAL_LABEL}:the-secret-value\n")
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", path):
                self.assertEqual(pwsc._load_recorded_secret(), "the-secret-value")

    def test_malformed_line_with_no_colon_raises_a_clear_runtime_error_not_a_valueerror(self):
        # The exact gap this round's review found: a disk-full mid-append
        # or a hand-edited file could leave a line with no ':' at all --
        # label, secret = line.split(":", 1) would previously raise an
        # unhandled ValueError on unpacking a single-element list, caught
        # nowhere, surfacing as a raw traceback instead of the clean
        # designed-for error path every other failure mode in this script
        # uses.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("this-line-has-no-colon-in-it\n")
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", path):
                with self.assertRaises(RuntimeError) as ctx:
                    pwsc._load_recorded_secret()
                self.assertNotIsInstance(ctx.exception, ValueError)
                self.assertIn("malformed", str(ctx.exception))

    def test_malformed_line_error_message_includes_the_path_and_line_number(self):
        # A well-formed but non-matching first line so scanning actually
        # reaches line 2 before hitting the malformed one -- a match on
        # line 1 would return early and never see it.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("some-other-label:some-other-secret\nno-colon-here\n")
            with mock.patch.object(pwsc, "SERVICE_CREDENTIALS_PATH", path):
                with self.assertRaises(RuntimeError) as ctx:
                    pwsc._load_recorded_secret()
                self.assertIn(path, str(ctx.exception))
                self.assertIn("2", str(ctx.exception))


class MainOrchestrationTests(unittest.TestCase):
    """main()'s call sequence and the three plan_app_password_action
    branches, against a fully mocked JMAP layer -- no network.
    """

    ADMIN_AUTH = ("admin", "admin-secret-not-real")

    def setUp(self):
        patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        patcher.start()
        self.addCleanup(patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)

    def _patched(self, **overrides):
        defaults = dict(
            _load_admin_credentials=mock.DEFAULT,
            _get_domain_id=mock.DEFAULT,
            _get_account_id=mock.DEFAULT,
            _app_password_exists=mock.DEFAULT,
            _load_recorded_secret=mock.DEFAULT,
            _create_app_password=mock.DEFAULT,
            _record_secret=mock.DEFAULT,
        )
        defaults.update(overrides)
        return mock.patch.multiple(pwsc, **defaults)

    def test_create_path_records_the_returned_secret_and_returns_zero(self):
        with self._patched(
            _load_admin_credentials=mock.DEFAULT,
        ) as mocks:
            mocks["_load_admin_credentials"].return_value = self.ADMIN_AUTH
            mocks["_get_domain_id"].return_value = "d1"
            mocks["_get_account_id"].return_value = "acct-info"
            mocks["_app_password_exists"].return_value = False
            mocks["_load_recorded_secret"].return_value = None
            mocks["_create_app_password"].return_value = "brand-new-app-password"

            result = pwsc.main()

            self.assertEqual(result, 0)
            mocks["_create_app_password"].assert_called_once()
            # the account id resolved for info@ is what gets used, not a
            # hardcoded/guessed one
            call_args = mocks["_create_app_password"].call_args.args
            self.assertEqual(call_args[1], "acct-info")
            mocks["_record_secret"].assert_called_once_with("brand-new-app-password")

    def test_already_provisioned_path_makes_no_create_or_record_calls(self):
        with self._patched() as mocks:
            mocks["_load_admin_credentials"].return_value = self.ADMIN_AUTH
            mocks["_get_domain_id"].return_value = "d1"
            mocks["_get_account_id"].return_value = "acct-info"
            mocks["_app_password_exists"].return_value = True
            mocks["_load_recorded_secret"].return_value = "already-on-disk"

            result = pwsc.main()

            self.assertEqual(result, 0)
            mocks["_create_app_password"].assert_not_called()
            mocks["_record_secret"].assert_not_called()

    def test_orphaned_path_returns_nonzero_and_makes_no_create_or_record_calls(self):
        with self._patched() as mocks:
            mocks["_load_admin_credentials"].return_value = self.ADMIN_AUTH
            mocks["_get_domain_id"].return_value = "d1"
            mocks["_get_account_id"].return_value = "acct-info"
            mocks["_app_password_exists"].return_value = True
            mocks["_load_recorded_secret"].return_value = None

            result = pwsc.main()

            self.assertEqual(result, 1)
            mocks["_create_app_password"].assert_not_called()
            mocks["_record_secret"].assert_not_called()

    def test_account_lookup_uses_the_domain_id_from_get_domain_id(self):
        with self._patched() as mocks:
            mocks["_load_admin_credentials"].return_value = self.ADMIN_AUTH
            mocks["_get_domain_id"].return_value = "the-resolved-domain-id"
            mocks["_get_account_id"].return_value = "acct-info"
            mocks["_app_password_exists"].return_value = True
            mocks["_load_recorded_secret"].return_value = "x"

            pwsc.main()

            mocks["_get_account_id"].assert_called_once_with(
                self.ADMIN_AUTH, "info", "the-resolved-domain-id"
            )


if __name__ == "__main__":
    unittest.main()
