#!/usr/bin/env python3
"""Unit tests for provision_zitadel_submission_credential.py and
check_zitadel_sender_scope.py.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
import contextlib
import copy
import io
import os
import pathlib
import re
import tempfile
import unittest
from unittest import mock

import check_zitadel_sender_scope as check
import provision_zitadel_submission_credential as pz

ADDRESS = "noreply@publicpress.co.uk"
SECRET = "s3cr3t-value-that-must-never-be-printed"


class AddressTests(unittest.TestCase):
    def test_the_committed_address_is_the_one_the_sign_in_service_sends_as(self):
        self.assertEqual(pz.account_address(), ADDRESS)

    def test_the_committed_domain_is_not_the_main_domain_or_under_it(self):
        self.assertNotEqual(pz.ACCOUNT_DOMAIN, pz.MAIN_DOMAIN)
        self.assertFalse(pz.ACCOUNT_DOMAIN.endswith("." + pz.MAIN_DOMAIN))

    def test_the_main_domain_and_its_subdomains_are_refused(self):
        for domain in ("branchleft.co.uk", "mail.branchleft.co.uk"):
            with self.assertRaises(pz.Refused):
                pz.account_address("noreply", domain)

    def test_a_quote_or_upper_case_is_refused(self):
        for local, domain in (("no'reply", "publicpress.co.uk"), ("NoReply", "publicpress.co.uk"),
                              ("noreply", "PublicPress.co.uk"), ("noreply", "publicpress")):
            with self.assertRaises(pz.Refused):
                pz.account_address(local, domain)


class CheckMustMatchSenderTests(unittest.TestCase):
    def test_the_shipped_default_passes(self):
        pz.check_must_match_sender({"match": {}, "else": "true"}, ADDRESS)
        pz.check_must_match_sender(None, ADDRESS)

    def test_another_accounts_branch_is_left_alone(self):
        pz.check_must_match_sender(
            {"match": {"0": {"if": "authenticated_as == 'collector@trypublicpress.co.uk'", "then": "false"}},
             "else": "true"},
            ADDRESS,
        )

    def test_a_fallback_of_false_is_refused(self):
        with self.assertRaises(pz.Refused):
            pz.check_must_match_sender({"match": {}, "else": "false"}, ADDRESS)

    def test_a_branch_for_this_account_is_refused(self):
        with self.assertRaises(pz.Refused):
            pz.check_must_match_sender(
                {"match": {"0": {"if": f"authenticated_as == '{ADDRESS}'", "then": "false"}}, "else": "true"},
                ADDRESS,
            )

    def test_an_unexpected_shape_is_refused(self):
        with self.assertRaises(pz.Refused):
            pz.check_must_match_sender("false", ADDRESS)


class BuildTests(unittest.TestCase):
    def test_the_account_has_no_password_of_its_own(self):
        args = pz.build_account_create_args("noreply", "d1")

        self.assertNotIn("credentials", args)
        self.assertEqual(args["@type"], "User")
        self.assertEqual((args["name"], args["domainId"]), ("noreply", "d1"))

    def test_the_credential_replaces_permissions_with_authenticate_and_send_only(self):
        args = pz.build_app_password_create_args(pz.APP_PASSWORD_DESCRIPTION, pz.CREDENTIAL_PERMISSIONS)

        self.assertEqual(args["permissions"]["@type"], "Replace")
        self.assertEqual(args["permissions"]["permissions"], {"authenticate": True, "emailSend": True})

    def test_an_empty_permission_list_is_refused(self):
        with self.assertRaises(pz.Refused):
            pz.build_app_password_create_args("d", ())

    def test_no_mailbox_protocol_permission_is_granted(self):
        for name in pz.CREDENTIAL_PERMISSIONS:
            self.assertFalse(name.startswith(("imap", "pop3", "jmap", "dav")), name)


class PlanCredentialTests(unittest.TestCase):
    def test_fresh(self):
        self.assertEqual(pz.plan_credential(False, False, False), "create")

    def test_reconciled(self):
        self.assertEqual(pz.plan_credential(True, True, True), "none")

    def test_orphaned(self):
        self.assertEqual(pz.plan_credential(True, True, False), "orphaned")

    def test_a_stale_local_record_is_refused(self):
        with self.assertRaises(pz.Refused):
            pz.plan_credential(True, False, True)


class RemoveRecordedSecretTests(unittest.TestCase):
    def test_removes_only_its_label_and_keeps_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("a:1\nzitadel-smtp:2\nb:3\n")
            self.assertTrue(pz.remove_recorded_secret(path, "zitadel-smtp"))
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), "a:1\nb:3\n")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertFalse(pz.remove_recorded_secret(path, "zitadel-smtp"))

    def test_a_missing_file_removes_nothing(self):
        self.assertFalse(pz.remove_recorded_secret("/nonexistent/creds", "x"))


class FakeStalwart:
    """In-memory stand-in for the x:* methods main() calls, recording writes."""

    def __init__(self, domains=("branchleft.co.uk", "publicpress.co.uk")):
        self.domains = [{"id": f"d{i}", "name": name} for i, name in enumerate(domains)]
        self.accounts = []
        self.app_passwords = {}
        self.must_match = {"match": {}, "else": "true"}
        self.writes = []

    def __call__(self, auth, method, args):
        object_type, verb = method[2:].split("/")
        if verb == "get":
            if object_type == "Domain":
                return {"list": copy.deepcopy(self.domains)}
            if object_type == "Account":
                return {"list": copy.deepcopy(self.accounts)}
            if object_type == "AppPassword":
                return {"list": copy.deepcopy(self.app_passwords.get(args["accountId"], []))}
            if object_type == "MtaStageAuth":
                return {"list": [{"id": "singleton", "mustMatchSender": copy.deepcopy(self.must_match)}]}
            raise AssertionError(f"unexpected read of {object_type}")
        self.writes.append(object_type)
        if object_type == "Account":
            created = args["create"]["c"]
            self.accounts.append({"id": "a1", "name": created["name"], "domainId": created["domainId"]})
            return {"created": {"c": {"id": "a1"}}}
        if object_type == "AppPassword" and "destroy" in args:
            entries = self.app_passwords.get(args["accountId"], [])
            self.app_passwords[args["accountId"]] = [e for e in entries if e["id"] not in args["destroy"]]
            return {"destroyed": list(args["destroy"])}
        if object_type == "AppPassword":
            entries = self.app_passwords.setdefault(args["accountId"], [])
            entries.append({"id": f"p{len(entries)}", "description": args["create"]["s"]["description"]})
            return {"created": {"s": {"secret": SECRET}}}
        raise AssertionError(f"unexpected write to {object_type}")


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.creds = os.path.join(self.tmp.name, "service-credentials")
        self.fake = FakeStalwart()
        self.tty = True
        for patcher in (
            mock.patch.object(pz, "SERVICE_CREDENTIALS_PATH", self.creds),
            mock.patch.object(pz.configure_stalwart, "_jmap_call", self.fake),
            mock.patch.object(pz.configure_stalwart, "_load_credentials", return_value=("admin", "x")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_main(self, *argv, tty=None):
        out, err = io.StringIO(), io.StringIO()
        out.isatty = lambda: self.tty if tty is None else tty
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pz.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_reads_and_plans_but_writes_nothing(self):
        code, out, _ = self.run_main("--dry-run")

        self.assertEqual(code, 0)
        self.assertEqual(self.fake.writes, [])
        self.assertFalse(os.path.exists(self.creds))
        self.assertIn(
            "DRY RUN, nothing written; would create the account noreply@publicpress.co.uk; "
            "create the app password",
            out,
        )

    def test_dry_run_still_refuses(self):
        self.fake.must_match = {"match": {}, "else": "false"}

        with self.assertRaises(pz.Refused):
            self.run_main("--dry-run")

    def test_fresh_server_creates_the_account_then_the_credential_and_nothing_else(self):
        code, _, _ = self.run_main()

        self.assertEqual(code, 0)
        self.assertEqual(self.fake.writes, ["Account", "AppPassword"])

    def test_the_secret_is_recorded_under_the_label_with_owner_only_mode(self):
        self.run_main()

        with open(self.creds, encoding="utf-8") as f:
            self.assertEqual(f.read(), f"zitadel-smtp:{SECRET}\n")
        self.assertEqual(os.stat(self.creds).st_mode & 0o777, 0o600)

    def test_the_secret_is_shown_once_on_a_terminal_with_the_entry_name(self):
        _, out, err = self.run_main()

        self.assertEqual(out.count(SECRET), 1)
        self.assertIn(pz.PASSWORD_MANAGER_ENTRY, out)
        self.assertNotIn(SECRET, err)

    def test_the_secret_is_never_printed_when_stdout_is_not_a_terminal(self):
        code, out, err = self.run_main(tty=False)

        self.assertEqual(code, 0)
        self.assertNotIn(SECRET, out + err)
        self.assertIn("NOT printed", out)
        with open(self.creds, encoding="utf-8") as f:
            self.assertIn(SECRET, f.read())

    def test_second_run_is_read_only_and_never_shows_the_secret_again(self):
        self.run_main()
        self.fake.writes.clear()

        code, out, err = self.run_main()

        self.assertEqual(code, 0)
        self.assertEqual(self.fake.writes, [])
        self.assertIn("already provisioned", out)
        self.assertNotIn(SECRET, out + err)

    def test_a_missing_domain_stops_everything_before_any_write(self):
        self.fake.domains = [{"id": "d0", "name": "branchleft.co.uk"}]

        with self.assertRaises(pz.Refused) as caught:
            self.run_main()
        self.assertEqual(self.fake.writes, [])
        self.assertIn("provision_sending_domain.py", str(caught.exception))

    def test_a_relaxed_exact_address_rule_stops_everything_before_any_write(self):
        self.fake.must_match = {"match": {}, "else": "false"}

        with self.assertRaises(pz.Refused):
            self.run_main()
        self.assertEqual(self.fake.writes, [])

    def test_the_collectors_branch_does_not_stop_it(self):
        self.fake.must_match = {
            "match": {"0": {"if": "authenticated_as == 'collector@trypublicpress.co.uk'", "then": "false"}},
            "else": "true",
        }

        code, _, _ = self.run_main()

        self.assertEqual(code, 0)

    def test_it_writes_no_server_wide_setting(self):
        self.run_main()

        self.assertEqual(set(self.fake.writes), {"Account", "AppPassword"})

    def test_an_orphaned_credential_exits_non_zero_without_writing(self):
        self.fake.accounts.append({"id": "a1", "name": "noreply", "domainId": "d1"})
        self.fake.app_passwords["a1"] = [{"id": "p0", "description": pz.APP_PASSWORD_DESCRIPTION}]

        code, _, err = self.run_main()

        self.assertEqual(code, 1)
        self.assertEqual(self.fake.writes, [])
        self.assertIn("--revoke", err)

    def test_a_stale_local_record_stops_before_any_write(self):
        with open(self.creds, "w", encoding="utf-8") as f:
            f.write("zitadel-smtp:old\n")

        with self.assertRaises(pz.Refused):
            self.run_main()
        self.assertEqual(self.fake.writes, [])

    def test_revoke_destroys_the_credential_and_its_record_and_keeps_the_account(self):
        self.run_main()

        code, out, _ = self.run_main("--revoke")

        self.assertEqual(code, 0)
        self.assertIn("destroyed 1 app password", out)
        self.assertEqual(self.fake.app_passwords["a1"], [])
        self.assertEqual(len(self.fake.accounts), 1)
        with open(self.creds, encoding="utf-8") as f:
            self.assertEqual(f.read(), "")

    def test_revoke_then_provision_mints_a_fresh_credential(self):
        self.run_main()
        self.run_main("--revoke")

        _, out, _ = self.run_main()

        self.assertEqual(out.count(SECRET), 1)

    def test_a_failed_account_create_raises_rather_than_recording_a_secret(self):
        real = self.fake.__call__

        def failing(auth, method, args):
            if method == "x:Account/set":
                return {"notCreated": {"c": {"type": "invalidProperties"}}}
            return real(auth, method, args)

        with mock.patch.object(pz.configure_stalwart, "_jmap_call", failing):
            with self.assertRaises(RuntimeError):
                self.run_main()
        self.assertFalse(os.path.exists(self.creds))


class WrapperTests(unittest.TestCase):
    wrapper = pathlib.Path(__file__).with_name("68-provision-zitadel-submission-credential.sh")

    def test_the_wrapper_sets_the_label_the_script_and_tests_agree_on(self):
        text = self.wrapper.read_text(encoding="utf-8")

        self.assertIn("CREDENTIAL_LABEL=zitadel-smtp", text)
        self.assertEqual(pz.CREDENTIAL_LABEL, "zitadel-smtp")

    def test_the_wrapper_forwards_its_arguments(self):
        self.assertIn('"$@"', self.wrapper.read_text(encoding="utf-8"))

    def test_the_wrapper_and_scripts_are_executable(self):
        for name in (self.wrapper.name, "provision_zitadel_submission_credential.py", "check_zitadel_sender_scope.py"):
            path = self.wrapper.with_name(name)
            self.assertTrue(os.access(path, os.X_OK), name)

    def test_it_is_not_in_run_all(self):
        run_all = self.wrapper.with_name("run-all.sh").read_text(encoding="utf-8")

        self.assertNotIn("68-provision-zitadel", run_all)


class VerdictTests(unittest.TestCase):
    def test_pass(self):
        passed, _ = check.verdict(250, 250, (553, 553))
        self.assertTrue(passed)

    def test_a_failed_control_fails_even_if_every_refusal_is_right(self):
        passed, text = check.verdict(535, 0, (553, 553))
        self.assertFalse(passed)
        self.assertIn("control failed", text)
        passed, _ = check.verdict(250, 550, (553, 553))
        self.assertFalse(passed)

    def test_an_accepted_other_sender_is_an_open_scope(self):
        passed, text = check.verdict(250, 250, (553, 250))
        self.assertFalse(passed)
        self.assertIn("scope is open", text)

    def test_a_deferral_is_not_a_refusal(self):
        passed, _ = check.verdict(250, 250, (553, 451))
        self.assertFalse(passed)

    def test_both_other_senders_are_probed_and_neither_is_the_accounts_own(self):
        self.assertEqual(len(check.REFUSE_SENDERS), 2)
        self.assertNotIn(ADDRESS, check.REFUSE_SENDERS)
        self.assertIn(pz.MAIN_DOMAIN, check.REFUSE_SENDERS[1])
        self.assertTrue(check.REFUSE_SENDERS[0].endswith("@" + pz.ACCOUNT_DOMAIN))

    def test_the_check_sends_no_message_body(self):
        source = pathlib.Path(check.__file__).read_text(encoding="utf-8")

        self.assertNotRegex(source, re.compile(r"\.data\(|\.sendmail\(|send_message"))


class RunTests(unittest.TestCase):
    def smtp(self, mail_codes):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.mail.side_effect = [(c, b"x") for c in mail_codes]
        client.rcpt.return_value = (250, b"ok")
        return client

    def run_check(self, client):
        with mock.patch.object(check.smtplib, "SMTP", return_value=client), \
                contextlib.redirect_stdout(io.StringIO()):
            return check.run(SECRET)

    def test_passes_when_only_the_accounts_own_address_is_accepted(self):
        client = self.smtp([250, 553, 553])

        self.assertEqual(self.run_check(client), 0)
        client.starttls.assert_called_once()
        client.login.assert_called_once_with(ADDRESS, SECRET)
        client.data.assert_not_called()

    def test_fails_when_the_main_domain_sender_is_accepted(self):
        self.assertEqual(self.run_check(self.smtp([250, 553, 250])), 1)

    def test_starttls_happens_before_login(self):
        client = self.smtp([250, 553, 553])
        self.run_check(client)
        names = [call[0] for call in client.method_calls if call[0] in ("starttls", "login")]

        self.assertEqual(names, ["starttls", "login"])


if __name__ == "__main__":
    unittest.main()
