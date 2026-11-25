#!/usr/bin/env python3
"""Unit tests for provision_diagnostic_credential.py.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
import contextlib
import io
import os
import pathlib
import re
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from unittest import mock

import configure_stalwart
import provision_diagnostic_credential as pd

SECRET = "diag-secret-value-that-must-never-be-printed"
NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
AUTH = ("admin", "pw")


class FakeStalwart:
    """The admin-side objects the script reads and writes, and a probe that
    answers as the real server would for a key holding `granted` permissions."""

    def __init__(self, domain=True):
        self.domains = [{"id": "d1", "name": pd.ACCOUNT_DOMAIN}] if domain else []
        self.roles = []
        self.accounts = []
        self.keys = []
        self.calls = []
        self.next_id = 0

    def new_id(self, prefix):
        self.next_id += 1
        return f"{prefix}{self.next_id}"

    def jmap(self, auth, method, args):
        self.calls.append((method, args))
        if method == "x:Domain/get":
            return {"list": self.domains}
        if method == "x:Role/get":
            return {"list": self.roles}
        if method == "x:Account/get":
            return {"list": self.accounts}
        if method == "x:ApiKey/get":
            return {"list": [{"id": k["id"], "description": k["description"]} for k in self.keys]}
        if method == "x:Role/set":
            created = {}
            for ref, obj in args.get("create", {}).items():
                rid = self.new_id("r")
                self.roles.append({"id": rid, **obj})
                created[ref] = {"id": rid}
            return {"created": created}
        if method == "x:Account/set":
            created = {}
            for ref, obj in args.get("create", {}).items():
                aid = self.new_id("a")
                self.accounts.append({"id": aid, **obj})
                created[ref] = {"id": aid}
            return {"created": created}
        if method == "x:ApiKey/set":
            created = {}
            for ref, obj in args.get("create", {}).items():
                kid = self.new_id("k")
                self.keys.append({"id": kid, **obj})
                created[ref] = {"id": kid, "secret": SECRET}
            for kid in args.get("destroy", []):
                self.keys = [k for k in self.keys if k["id"] != kid]
            return {"created": created}
        raise AssertionError(f"unexpected call {method}")

    def writes(self):
        return [m for m, _ in self.calls if m.endswith("/set")]


def good_probe(token, method, args):
    """A server that gives the key exactly the intended scope."""
    if re.match(r"^x:[A-Za-z]+/query$", method) and method[2:].split("/")[0] in pd.READ_OBJECTS:
        return "allowed"
    return "forbidden"


class Harness(unittest.TestCase):
    def setUp(self):
        self.fake = FakeStalwart()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.creds = os.path.join(self.dir.name, "service-credentials")
        for patcher in (
            mock.patch.object(pd, "SERVICE_CREDENTIALS_PATH", self.creds),
            mock.patch.object(configure_stalwart, "_jmap_call", self.fake.jmap),
            mock.patch.object(configure_stalwart, "_load_credentials", lambda: AUTH),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_main(self, argv=None, probe=good_probe):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = pd.main(argv or [], probe=probe, now=NOW)
            except pd.Refused as exc:
                err.write(f"REFUSED: {exc}")
                code = 1
        return code, out.getvalue(), err.getvalue()

    def recorded(self):
        if not os.path.exists(self.creds):
            return ""
        return pathlib.Path(self.creds).read_text()


class PermissionSetTests(unittest.TestCase):
    def test_the_set_is_authenticate_plus_get_and_query_of_the_listed_objects_only(self):
        expected = {"authenticate"} | {f"sys{o}{v}" for o in pd.READ_OBJECTS for v in ("Get", "Query")}
        self.assertEqual(expected, set(pd.PERMISSIONS))
        self.assertEqual(len(pd.PERMISSIONS), len(set(pd.PERMISSIONS)))

    def test_no_permission_can_write_act_impersonate_or_read_a_message_body(self):
        banned = ("Create", "Update", "Destroy", "action", "task", "impersonate", "fetchAnyBlob",
                  "jmap", "email", "imap", "Account", "ApiKey", "AppPassword", "Role", "Credential")
        for name in pd.PERMISSIONS:
            for word in banned:
                self.assertNotIn(word, name, name)

    def test_no_enterprise_only_object_is_listed(self):
        self.assertNotIn("Metric", pd.READ_OBJECTS)
        self.assertNotIn("Trace", pd.READ_OBJECTS)

    def test_the_key_holds_exactly_the_role_set_and_expires(self):
        args = pd.build_api_key_create_args(NOW)
        self.assertEqual("Replace", args["permissions"]["@type"])
        self.assertEqual(set(pd.PERMISSIONS), set(args["permissions"]["permissions"]))
        self.assertEqual("2027-05-23T12:00:00Z", args["expiresAt"])
        self.assertEqual({}, args["allowedIps"])

    def test_the_role_extends_and_disables_nothing(self):
        args = pd.build_role_create_args()
        self.assertEqual({}, args["roleIds"])
        self.assertEqual({}, args["disabledPermissions"])

    def test_the_account_has_a_custom_role_and_no_password(self):
        args = pd.build_account_create_args("d1", "r1")
        self.assertEqual({"@type": "Custom", "roleIds": {"r1": True}}, args["roles"])
        self.assertNotIn("credentials", args)

    def test_every_denied_probe_is_a_write_or_a_read_of_something_outside_the_scope(self):
        for method, args in pd.DENIED_PROBES:
            obj = method[2:].split("/")[0]
            if not method.endswith("/set"):
                self.assertNotIn(obj, pd.READ_OBJECTS)
            else:
                # Harmless even if the server wrongly allowed it: an id that does not exist.
                self.assertIn("none", repr(args))


class ClassifyTests(unittest.TestCase):
    def test_a_result_is_allowed(self):
        self.assertEqual("allowed", pd.classify(200, {"methodResponses": [["x:Log/query", {"ids": []}, "0"]]}))

    def test_a_forbidden_method_error_is_forbidden(self):
        body = {"methodResponses": [["error", {"type": "forbidden"}, "0"]]}
        self.assertEqual("forbidden", pd.classify(200, body))

    def test_http_403_is_forbidden_and_401_is_not(self):
        self.assertEqual("forbidden", pd.classify(403, None))
        self.assertTrue(pd.classify(401, None).startswith("other"))

    def test_anything_else_is_other(self):
        for status, body in (
            (200, {"methodResponses": [["error", {"type": "unknownMethod"}, "0"]]}),
            (200, {"methodResponses": [["x:Domain/set", {"notDestroyed": {"none": {"type": "notFound"}}}, "0"]]}),
            (200, {"methodResponses": []}),
            (200, {"methodResponses": [["a", {}, "0"], ["b", {}, "1"]]}),
            (200, []),
            (500, None),
        ):
            self.assertTrue(pd.classify(status, body).startswith("other"), (status, body))


class VerifyScopeTests(unittest.TestCase):
    def test_the_intended_scope_has_no_problems(self):
        self.assertEqual([], pd.verify_scope(good_probe, "t"))

    def test_a_key_that_can_not_read_an_object_is_a_problem(self):
        problems = pd.verify_scope(lambda t, m, a: "forbidden", "t")
        self.assertEqual(len(pd.READ_OBJECTS), len(problems))

    def test_log_query_refused_only_for_want_of_a_file_tracer_still_proves_the_permission(self):
        # mx1 runs the Stdout tracer, so Log/query answers invalidArguments after
        # the permission gate has passed. That is a key that holds sysLogQuery.
        def probe(token, method, a):
            if method == "x:Log/query":
                return "other: method error 'invalidArguments'"
            return good_probe(token, method, a)

        self.assertEqual([], pd.verify_scope(probe, "t"))

    def test_invalid_arguments_is_accepted_for_no_object_but_log(self):
        def probe(token, method, a):
            if method == "x:QueuedMessage/query":
                return "other: method error 'invalidArguments'"
            return good_probe(token, method, a)

        problems = pd.verify_scope(probe, "t")
        self.assertEqual(1, len(problems))
        self.assertIn("x:QueuedMessage/query", problems[0])

    def test_a_forbidden_log_query_is_still_a_problem(self):
        def probe(token, method, a):
            if method == "x:Log/query":
                return "forbidden"
            return good_probe(token, method, a)

        problems = pd.verify_scope(probe, "t")
        self.assertEqual(["x:Log/query should be allowed: forbidden"], problems)

    def test_every_denied_probe_that_is_allowed_is_reported(self):
        for method, args in pd.DENIED_PROBES:
            def probe(token, called, a, method=method):
                return "allowed" if called == method else good_probe(token, called, a)

            problems = pd.verify_scope(probe, "t")
            self.assertEqual(1, len(problems), method)
            self.assertIn(method, problems[0])

    def test_an_inconclusive_answer_for_a_denied_probe_is_a_problem(self):
        def probe(token, method, args):
            return "other: method error 'notFound'" if method == "x:Domain/set" else good_probe(token, method, args)

        self.assertEqual(1, len(pd.verify_scope(probe, "t")))


class CheckTests(unittest.TestCase):
    def good_role(self):
        return {"id": "r1", "enabledPermissions": {p: True for p in pd.PERMISSIONS},
                "disabledPermissions": {}, "roleIds": {}}

    def test_the_role_this_script_wrote_passes(self):
        pd.check_role(self.good_role())

    def test_an_added_or_missing_permission_is_refused(self):
        wider = self.good_role()
        wider["enabledPermissions"]["sysDomainUpdate"] = True
        narrower = self.good_role()
        del narrower["enabledPermissions"]["sysLogGet"]
        for role in (wider, narrower):
            with self.assertRaises(pd.Refused):
                pd.check_role(role)

    def test_a_role_that_extends_another_is_refused(self):
        role = self.good_role()
        role["roleIds"] = {"admin": True}
        with self.assertRaises(pd.Refused):
            pd.check_role(role)

    def test_an_account_with_another_role_a_password_or_own_permissions_is_refused(self):
        good = {"roles": {"@type": "Custom", "roleIds": {"r1": True}}, "permissions": {"@type": "Inherit"}}
        pd.check_account(good, "r1")
        for bad in (
            {**good, "roles": {"@type": "Admin"}},
            {**good, "roles": {"@type": "Custom", "roleIds": {"r1": True, "r2": True}}},
            {**good, "permissions": {"@type": "Merge", "enabledPermissions": {"sysAccountUpdate": True}}},
            {**good, "credentials": [{"@type": "Password"}]},
        ):
            with self.assertRaises(pd.Refused):
                pd.check_account(bad, "r1")


class MainTests(Harness):
    def test_a_fresh_run_creates_role_account_and_key_and_proves_the_scope(self):
        code, out, err = self.run_main()
        self.assertEqual((0, ""), (code, err), out + err)
        self.assertEqual(1, len(self.fake.roles))
        self.assertEqual(1, len(self.fake.accounts))
        self.assertEqual(1, len(self.fake.keys))
        self.assertIn("scope proven", out)
        self.assertEqual(f"{pd.CREDENTIAL_LABEL}:{SECRET}\n", self.recorded())
        self.assertEqual(0o600, os.stat(self.creds).st_mode & 0o777)

    def test_the_secret_is_never_printed(self):
        _, out, err = self.run_main()
        self.assertNotIn(SECRET, out + err)

    def test_a_second_run_changes_nothing_and_proves_the_recorded_key(self):
        self.run_main()
        before = self.fake.writes()
        seen = []

        def probe(token, method, args):
            seen.append(token)
            return good_probe(token, method, args)

        code, out, _ = self.run_main(probe=probe)
        self.assertEqual(0, code)
        self.assertEqual(before, self.fake.writes())
        self.assertEqual({SECRET}, set(seen))
        self.assertEqual(f"{pd.CREDENTIAL_LABEL}:{SECRET}\n", self.recorded())

    def test_a_key_that_can_do_more_than_intended_is_destroyed_and_unrecorded(self):
        def probe(token, method, args):
            return "allowed" if method == "x:Domain/set" else good_probe(token, method, args)

        code, out, err = self.run_main(probe=probe)
        self.assertEqual(1, code)
        self.assertEqual([], self.fake.keys)
        self.assertEqual("", self.recorded())
        self.assertIn("FAILED", err)
        self.assertIn("x:Domain/set should be forbidden", err)

    def test_a_scope_proof_that_raises_destroys_the_fresh_key_and_reraises(self):
        def probe(token, method, args):
            raise urllib.error.URLError("connection refused")

        with self.assertRaises(urllib.error.URLError):
            self.run_main(probe=probe)
        self.assertEqual([], self.fake.keys)
        self.assertEqual("", self.recorded())

    def test_an_existing_key_that_fails_the_proof_is_reported_and_left_for_revoke(self):
        self.run_main()
        code, _, err = self.run_main(probe=lambda t, m, a: "allowed")
        self.assertEqual(1, code)
        self.assertEqual(1, len(self.fake.keys))
        self.assertIn("run --revoke", err)

    def test_dry_run_reads_and_writes_nothing(self):
        code, out, _ = self.run_main(["--dry-run"], probe=lambda *a: self.fail("probed in a dry run"))
        self.assertEqual(0, code)
        self.assertEqual([], self.fake.writes())
        self.assertFalse(os.path.exists(self.creds))
        self.assertIn("DRY RUN", out)

    def test_a_missing_main_domain_refuses_before_any_write(self):
        self.fake.domains = []
        code, _, err = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("REFUSED", err)
        self.assertEqual([], self.fake.writes())

    def test_a_role_this_script_did_not_write_refuses_before_any_write(self):
        self.fake.roles.append({"id": "r9", "description": pd.ROLE_DESCRIPTION,
                                "enabledPermissions": {"sysDomainUpdate": True},
                                "disabledPermissions": {}, "roleIds": {}})
        code, _, err = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("REFUSED", err)
        self.assertEqual([], self.fake.writes())

    def test_a_stale_record_with_no_key_refuses(self):
        pathlib.Path(self.creds).write_text(f"{pd.CREDENTIAL_LABEL}:old\n")
        code, _, err = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("stale", err)
        self.assertEqual([], self.fake.writes())

    def test_a_key_with_no_record_is_reported_not_recreated(self):
        self.run_main()
        os.remove(self.creds)
        code, _, err = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("cannot be recovered", err)
        self.assertEqual(1, len(self.fake.keys))

    def test_a_response_with_no_secret_destroys_the_key(self):
        original = self.fake.jmap

        def no_secret(auth, method, args):
            result = original(auth, method, args)
            if method == "x:ApiKey/set" and "create" in args:
                result["created"]["k"].pop("secret")
            return result

        with mock.patch.object(configure_stalwart, "_jmap_call", no_secret):
            code, _, err = self.run_main()
        self.assertEqual(1, code)
        self.assertEqual([], self.fake.keys)
        self.assertEqual("", self.recorded())
        self.assertIn("did not return", err)

    def test_revoke_destroys_the_key_and_the_record_and_keeps_other_labels(self):
        self.run_main()
        with open(self.creds, "a") as f:
            f.write("other-label:keep\n")
        code, out, _ = self.run_main(["--revoke"])
        self.assertEqual(0, code)
        self.assertEqual([], self.fake.keys)
        self.assertEqual("other-label:keep\n", self.recorded())
        self.assertIn("destroyed 1", out)


class PinTests(unittest.TestCase):
    def test_the_scope_was_written_against_the_pinned_stalwart_version(self):
        compose = (pathlib.Path(__file__).parent / "docker-compose.yml").read_text()
        self.assertIn(f"stalwartlabs/stalwart:{pd.VERIFIED_STALWART_VERSION}@sha256:", compose)


if __name__ == "__main__":
    unittest.main()
