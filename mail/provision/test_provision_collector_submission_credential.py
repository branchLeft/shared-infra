#!/usr/bin/env python3
"""Unit tests for provision_collector_submission_credential.py.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
import contextlib
import copy
import io
import os
import tempfile
import unittest
from unittest import mock

import provision_collector_submission_credential as pc

ADDRESS = "collector@trypublicpress.co.uk"
SECRET = "s3cr3t-value-that-must-never-be-printed"


class MainDomainNeverAllowedTests(unittest.TestCase):
    """The control the containment design rests on: the committed sending set
    must never include the main domain or anything under it."""

    def test_committed_sending_domains_pass_validation(self):
        pc.validate_sending_domains(pc.COLLECTOR_SENDING_DOMAINS)

    def test_committed_sending_domains_exclude_the_main_domain_and_its_subdomains(self):
        for domain in pc.COLLECTOR_SENDING_DOMAINS:
            self.assertNotEqual(domain, pc.MAIN_DOMAIN)
            self.assertFalse(domain.endswith("." + pc.MAIN_DOMAIN), domain)

    def test_rendered_expression_never_names_the_main_domain(self):
        expression = pc.build_is_sender_allowed(pc.collector_address(), pc.COLLECTOR_SENDING_DOMAINS)

        self.assertNotIn(pc.MAIN_DOMAIN, expression["match"]["0"]["then"])

    def test_main_domain_is_refused(self):
        with self.assertRaises(pc.Refused):
            pc.validate_sending_domains(("trypublicpress.co.uk", "branchleft.co.uk"))

    def test_subdomain_of_the_main_domain_is_refused(self):
        with self.assertRaises(pc.Refused):
            pc.validate_sending_domains(("demo.branchleft.co.uk",))

    def test_build_refuses_the_main_domain_too(self):
        with self.assertRaises(pc.Refused):
            pc.build_is_sender_allowed(ADDRESS, ("branchleft.co.uk",))

    def test_main_refuses_before_any_api_call_if_the_set_includes_the_main_domain(self):
        with mock.patch.object(pc, "COLLECTOR_SENDING_DOMAINS", ("branchleft.co.uk",)), \
                mock.patch.object(pc.configure_stalwart, "_load_credentials") as load, \
                mock.patch.object(pc.configure_stalwart, "_jmap_call") as call:
            with self.assertRaises(pc.Refused):
                pc.main()
        load.assert_not_called()
        call.assert_not_called()


class ValidateSendingDomainsTests(unittest.TestCase):
    def test_lookalike_that_merely_ends_with_the_main_name_is_allowed(self):
        pc.validate_sending_domains(("notbranchleft.co.uk",))

    def test_rejects_empty(self):
        with self.assertRaises(pc.Refused):
            pc.validate_sending_domains(())

    def test_rejects_upper_case(self):
        with self.assertRaises(pc.Refused):
            pc.validate_sending_domains(("TryPublicPress.co.uk",))

    def test_rejects_a_quote_that_would_break_out_of_the_expression(self):
        with self.assertRaises(pc.Refused):
            pc.validate_sending_domains(("x.co.uk' || true || '",))

    def test_rejects_duplicates(self):
        with self.assertRaises(pc.Refused):
            pc.validate_sending_domains(("a.co.uk", "a.co.uk"))

    def test_collector_address_rejects_a_quote(self):
        with self.assertRaises(pc.Refused):
            pc.collector_address("coll'ector", "trypublicpress.co.uk")


class ExpressionBuilderTests(unittest.TestCase):
    def test_is_sender_allowed_selects_only_the_collector(self):
        expression = pc.build_is_sender_allowed(ADDRESS, ("a.co.uk",))

        self.assertEqual(expression["match"]["0"]["if"], f"authenticated_as == '{ADDRESS}'")
        self.assertEqual(expression["match"]["0"]["then"], "sender_domain == 'a.co.uk'")

    def test_is_sender_allowed_keeps_stalwarts_default_for_everyone_else(self):
        expression = pc.build_is_sender_allowed(ADDRESS, ("a.co.uk",))

        self.assertEqual(
            expression["else"],
            "!is_empty(authenticated_as) || !key_exists('spam-block', sender_domain)",
        )

    def test_several_domains_are_ored(self):
        expression = pc.build_is_sender_allowed(ADDRESS, ("a.co.uk", "b.org"))

        self.assertEqual(
            expression["match"]["0"]["then"],
            "sender_domain == 'a.co.uk' || sender_domain == 'b.org'",
        )

    def test_must_match_sender_is_relaxed_for_the_collector_only(self):
        expression = pc.build_must_match_sender(ADDRESS)

        self.assertEqual(expression["match"]["0"], {"if": f"authenticated_as == '{ADDRESS}'", "then": "false"})
        self.assertEqual(expression["else"], "true")

    def test_both_expressions_select_the_same_sessions(self):
        self.assertEqual(
            pc.build_is_sender_allowed(ADDRESS, ("a.co.uk",))["match"]["0"]["if"],
            pc.build_must_match_sender(ADDRESS)["match"]["0"]["if"],
        )


class PlanExpressionTests(unittest.TestCase):
    target = pc.build_is_sender_allowed(ADDRESS, ("a.co.uk",))
    default = pc.DEFAULT_IS_SENDER_ALLOWED

    def plan(self, current):
        return pc.plan_expression(current, self.target, self.default, "field")

    def test_already_reconciled_is_a_no_op(self):
        self.assertIsNone(self.plan(copy.deepcopy(self.target)))

    def test_whitespace_differences_are_not_a_change(self):
        current = copy.deepcopy(self.target)
        current["else"] = "  " + current["else"].replace(" || ", "  ||  ")

        self.assertIsNone(self.plan(current))

    def test_unset_field_is_written(self):
        self.assertEqual(self.plan(None), self.target)

    def test_default_with_no_match_key_is_written(self):
        self.assertEqual(self.plan({"else": self.default}), self.target)

    def test_default_with_empty_match_is_written(self):
        self.assertEqual(self.plan({"match": {}, "else": self.default}), self.target)

    def test_own_earlier_output_with_another_domain_list_is_updated(self):
        earlier = pc.build_is_sender_allowed(ADDRESS, ("old.co.uk",))

        self.assertEqual(self.plan(earlier), self.target)

    def test_a_foreign_match_branch_is_refused(self):
        with self.assertRaises(pc.Refused):
            self.plan({"match": {"0": {"if": "authenticated_as == 'x@y.z'", "then": "true"}}, "else": self.default})

    def test_an_extra_branch_beside_ours_is_refused(self):
        current = copy.deepcopy(self.target)
        current["match"]["1"] = {"if": "true", "then": "true"}

        with self.assertRaises(pc.Refused):
            self.plan(current)

    def test_a_changed_default_is_refused(self):
        with self.assertRaises(pc.Refused):
            self.plan({"match": {}, "else": "true"})

    def test_an_unexpected_shape_is_refused(self):
        with self.assertRaises(pc.Refused):
            self.plan("true")

    def test_a_list_shaped_match_is_read_the_same_as_a_keyed_one(self):
        current = copy.deepcopy(self.target)
        current["match"] = [current["match"]["0"]]

        self.assertIsNone(self.plan(current))


class RecordedSecretTests(unittest.TestCase):
    def test_a_malformed_line_fails_with_a_reason_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("no-separator-here\n")
            with mock.patch.object(pc, "SERVICE_CREDENTIALS_PATH", path):
                with self.assertRaisesRegex(RuntimeError, "malformed"):
                    pc._load_recorded_secret()

    def test_another_label_is_not_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\nblog-ghost-smtp:other\ncollector-smtp:mine\n")
            with mock.patch.object(pc, "SERVICE_CREDENTIALS_PATH", path):
                self.assertEqual(pc._load_recorded_secret(), "mine")


class MailStageHookTests(unittest.TestCase):
    def test_defaults_pass(self):
        pc.check_mail_stage_hooks({"rewrite": {"else": "false"}, "script": {"match": {}, "else": "false"}})

    def test_absent_fields_pass(self):
        pc.check_mail_stage_hooks({})

    def test_a_rewrite_is_refused(self):
        with self.assertRaises(pc.Refused):
            pc.check_mail_stage_hooks({"rewrite": {"else": "'x@y.z'"}})

    def test_a_conditional_script_is_refused(self):
        with self.assertRaises(pc.Refused):
            pc.check_mail_stage_hooks({"script": {"match": {"0": {"if": "true", "then": "'s'"}}, "else": "false"}})


class CreateArgsTests(unittest.TestCase):
    def test_app_password_replaces_permissions_with_exactly_submission(self):
        args = pc.build_app_password_create_args("d", pc.CREDENTIAL_PERMISSIONS)

        self.assertEqual(args["permissions"]["@type"], "Replace")
        self.assertEqual(args["permissions"]["permissions"], {"authenticate": True, "emailSend": True})

    def test_an_empty_replace_list_is_refused(self):
        with self.assertRaises(pc.Refused):
            pc.build_app_password_create_args("d", ())

    def test_account_has_no_password_of_its_own(self):
        args = pc.build_account_create_args("collector", "d1")

        self.assertNotIn("credentials", args)
        self.assertEqual(args["@type"], "User")


class PlanCredentialTests(unittest.TestCase):
    def test_fresh(self):
        self.assertEqual(pc.plan_credential(False, False, False), "create")

    def test_reconciled(self):
        self.assertEqual(pc.plan_credential(True, True, True), "none")

    def test_orphaned(self):
        self.assertEqual(pc.plan_credential(True, True, False), "orphaned")

    def test_a_stale_local_record_is_refused(self):
        with self.assertRaises(pc.Refused):
            pc.plan_credential(True, False, True)


class FakeStalwart:
    """In-memory stand-in for the x:* methods main() calls, recording writes."""

    def __init__(self, domains=("branchleft.co.uk", "trypublicpress.co.uk")):
        self.domains = [{"id": f"d{i}", "name": name} for i, name in enumerate(domains)]
        self.accounts = []
        self.app_passwords = {}
        self.singletons = {
            "MtaStageMail": {"id": "singleton", "isSenderAllowed": {"match": {}, "else": pc.DEFAULT_IS_SENDER_ALLOWED},
                             "rewrite": {"match": {}, "else": "false"}, "script": {"match": {}, "else": "false"}},
            "MtaStageAuth": {"id": "singleton", "mustMatchSender": {"match": {}, "else": "true"}},
        }
        self.writes = []
        self.drop_writes_to = None

    def __call__(self, auth, method, args):
        object_type, verb = method[2:].split("/")
        if verb == "get":
            if object_type == "Domain":
                return {"list": copy.deepcopy(self.domains)}
            if object_type == "Account":
                return {"list": copy.deepcopy(self.accounts)}
            if object_type == "AppPassword":
                return {"list": copy.deepcopy(self.app_passwords.get(args["accountId"], []))}
            return {"list": [copy.deepcopy(self.singletons[object_type])]}
        self.writes.append(object_type)
        if object_type == "Account":
            created = args["create"]["c"]
            self.accounts.append({"id": "a1", "name": created["name"], "domainId": created["domainId"]})
            return {"created": {"c": {"id": "a1"}}}
        if object_type == "AppPassword":
            self.app_passwords.setdefault(args["accountId"], []).append(
                {"description": args["create"]["s"]["description"]}
            )
            return {"created": {"s": {"secret": SECRET}}}
        if object_type != self.drop_writes_to:
            self.singletons[object_type].update(copy.deepcopy(args["update"]["singleton"]))
        return {"updated": {"singleton": None}}


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.creds = os.path.join(self.tmp.name, "service-credentials")
        self.fake = FakeStalwart()
        self.restart = mock.MagicMock()
        for patcher in (
            mock.patch.object(pc, "SERVICE_CREDENTIALS_PATH", self.creds),
            mock.patch.object(pc.configure_stalwart, "_jmap_call", self.fake),
            mock.patch.object(pc.configure_stalwart, "_load_credentials", return_value=("admin", "x")),
            mock.patch.object(pc.configure_stalwart, "_wait_for_stalwart_ready"),
            mock.patch.object(pc.subprocess, "run", self.restart),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_main(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pc.main()
        return code, out.getvalue() + err.getvalue()

    def test_fresh_server_writes_the_domain_check_before_relaxing_the_exact_match(self):
        code, _ = self.run_main()

        self.assertEqual(code, 0)
        self.assertEqual(self.fake.writes, ["MtaStageMail", "MtaStageAuth", "Account", "AppPassword"])

    def test_fresh_server_records_the_secret_under_the_label_and_never_prints_it(self):
        _, output = self.run_main()

        with open(self.creds, encoding="utf-8") as f:
            self.assertEqual(f.read(), f"collector-smtp:{SECRET}\n")
        self.assertEqual(os.stat(self.creds).st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET, output)

    def test_fresh_server_restarts_stalwart(self):
        self.run_main()

        self.restart.assert_called_once_with(["docker", "restart", "stalwart"], check=True, capture_output=True)

    def test_second_run_is_read_only_and_does_not_restart(self):
        self.run_main()
        self.fake.writes.clear()
        self.restart.reset_mock()

        code, output = self.run_main()

        self.assertEqual(code, 0)
        self.assertEqual(self.fake.writes, [])
        self.restart.assert_not_called()
        self.assertIn("already provisioned", output)

    def test_a_hand_edited_expression_stops_everything_before_any_write(self):
        self.fake.singletons["MtaStageAuth"]["mustMatchSender"] = {"match": {}, "else": "false"}

        with self.assertRaises(pc.Refused):
            self.run_main()
        self.assertEqual(self.fake.writes, [])

    def test_a_set_rewrite_stops_everything_before_any_write(self):
        self.fake.singletons["MtaStageMail"]["rewrite"] = {"match": {}, "else": "'x@y.z'"}

        with self.assertRaises(pc.Refused):
            self.run_main()
        self.assertEqual(self.fake.writes, [])

    def test_a_missing_sending_domain_stops_everything_before_any_write(self):
        self.fake.domains = [{"id": "d0", "name": "branchleft.co.uk"}]

        with self.assertRaises(pc.Refused):
            self.run_main()
        self.assertEqual(self.fake.writes, [])

    def test_an_orphaned_credential_exits_non_zero_without_writing(self):
        self.fake.accounts.append({"id": "a1", "name": "collector", "domainId": "d1"})
        self.fake.app_passwords["a1"] = [{"description": pc.APP_PASSWORD_DESCRIPTION}]

        code, _ = self.run_main()

        self.assertEqual(code, 1)
        self.assertEqual(self.fake.writes, [])

    def test_a_read_back_that_differs_from_what_was_written_fails_loudly(self):
        self.fake.drop_writes_to = "MtaStageAuth"

        with self.assertRaises(RuntimeError):
            self.run_main()


if __name__ == "__main__":
    unittest.main()
