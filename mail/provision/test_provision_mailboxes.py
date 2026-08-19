#!/usr/bin/env python3
"""Unit tests for provision_mailboxes.py. Most of these cover the pure diff
functions (no network access, no live server needed); a smaller set uses
unittest.mock to exercise the credential resolve/persist ordering and
main()'s orchestration against a fake JMAP layer -- see the module-level
comment on ReconcileAccountsOrderingTests for why that split, not full
parity with the pure-function coverage, was judged sufficient here.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
import io
import os
import tempfile
import unittest
from unittest import mock

import provision_mailboxes as pm
from provision_mailboxes import (
    FORWARD_TARGET,
    MAILBOXES,
    ROLE_ADDRESSES,
    build_account_create_args,
    missing_mailboxes,
    plan_sieve_action,
    resolve_mailbox_secret,
    sieve_script_contents,
)


class MailboxesAndRoleAddressesTests(unittest.TestCase):
    def test_rob_is_a_mailbox_but_not_a_role_address(self):
        self.assertIn("rob", MAILBOXES)
        self.assertNotIn("rob", ROLE_ADDRESSES)

    def test_every_role_address_is_also_a_mailbox(self):
        for role in ROLE_ADDRESSES:
            self.assertIn(role, MAILBOXES)

    def test_exactly_eight_mailboxes_seven_role_addresses(self):
        self.assertEqual(len(MAILBOXES), 8)
        self.assertEqual(len(ROLE_ADDRESSES), 7)

    def test_forward_target_is_rob_at_the_mail_domain(self):
        self.assertEqual(FORWARD_TARGET, "rob@branchleft.co.uk")


class SieveScriptContentsTests(unittest.TestCase):
    def test_uses_copy_modifier_not_a_plain_redirect(self):
        # The distinction that matters here: a plain `redirect`
        # (no :copy) suppresses the implicit keep, so the role mailbox would
        # never see its own mail -- :copy is what keeps both deliveries.
        script = sieve_script_contents("rob@branchleft.co.uk")
        self.assertIn(':copy "rob@branchleft.co.uk"', script)
        self.assertNotIn('redirect "rob@branchleft.co.uk"', script)

    def test_declares_the_copy_extension(self):
        script = sieve_script_contents("rob@branchleft.co.uk")
        self.assertIn('require ["copy"]', script)

    def test_is_parameterised_on_the_forward_target(self):
        script = sieve_script_contents("someone-else@example.com")
        self.assertIn("someone-else@example.com", script)
        self.assertNotIn("rob@branchleft.co.uk", script)


class BuildAccountCreateArgsTests(unittest.TestCase):
    def test_sets_type_user_and_the_given_name_and_domain(self):
        args = build_account_create_args("contact", "d1", "hunter2-but-actually-random")

        self.assertEqual(args["@type"], "User")
        self.assertEqual(args["name"], "contact")
        self.assertEqual(args["domainId"], "d1")

    def test_credentials_is_an_index_keyed_object_not_a_json_array(self):
        # registry::types::list::List<T> (the schema type backing
        # UserAccount.credentials) serializes as {"0": ..., "1": ...}, not
        # a JSON array -- confirmed from Stalwart's own source. Getting
        # this wrong is exactly the by-analogy mistake this story's brief
        # warned against, so it's pinned here explicitly.
        args = build_account_create_args("contact", "d1", "s3cr3t")

        self.assertIsInstance(args["credentials"], dict)
        self.assertIn("0", args["credentials"])
        self.assertEqual(args["credentials"]["0"]["@type"], "Password")
        self.assertEqual(args["credentials"]["0"]["secret"], "s3cr3t")

    def test_only_one_credential_is_set(self):
        args = build_account_create_args("contact", "d1", "s3cr3t")

        self.assertEqual(len(args["credentials"]), 1)

    def test_no_roles_or_permissions_are_set(self):
        # Deliberately absent, not just unset -- Stalwart's own
        # UserAccount::default() already resolves to UserRoles::User and
        # Permissions::Inherit (a plain, non-admin mailbox), confirmed from
        # source. Setting them here would be redundant, and duplicating the
        # default in two places is exactly the kind of drift this story's
        # source-verification requirement exists to avoid.
        args = build_account_create_args("contact", "d1", "s3cr3t")

        self.assertNotIn("roles", args)
        self.assertNotIn("permissions", args)


class MissingMailboxesTests(unittest.TestCase):
    def test_all_missing_when_none_exist(self):
        result = missing_mailboxes(MAILBOXES, set())

        self.assertEqual(result, list(MAILBOXES))

    def test_none_missing_when_all_exist(self):
        result = missing_mailboxes(MAILBOXES, set(MAILBOXES))

        self.assertEqual(result, [])

    def test_only_the_absent_ones_are_returned_in_order(self):
        existing = {"rob", "sales"}

        result = missing_mailboxes(MAILBOXES, existing)

        self.assertEqual(result, ["contact", "info", "complaints", "abuse", "blog", "acme"])

    def test_unrelated_existing_accounts_are_ignored(self):
        # e.g. the Stalwart admin bootstrap account, or some other domain's
        # mailbox that happens to share a local part -- the caller is
        # expected to have already filtered `existing_names` to this
        # domain, but this function shouldn't behave surprisingly either
        # way since it only ever looks *up* names in the set, never treats
        # its size as meaningful.
        existing = {"rob", "admin", "postmaster"}

        result = missing_mailboxes(MAILBOXES, existing)

        self.assertEqual(result, ["contact", "info", "sales", "complaints", "abuse", "blog", "acme"])


class PlanSieveActionTests(unittest.TestCase):
    TARGET = 'require ["copy"];\nredirect :copy "rob@branchleft.co.uk";\n'

    def test_no_existing_script_is_a_create(self):
        self.assertEqual(plan_sieve_action(None, self.TARGET), "create")

    def test_matching_content_already_active_is_a_no_op(self):
        existing = {"id": "s1", "isActive": True, "contents": self.TARGET}

        self.assertEqual(plan_sieve_action(existing, self.TARGET), "none")

    def test_matching_content_but_inactive_is_an_activate(self):
        # The exact scenario an operator manually deactivating a script (or
        # activating a different one) via the webadmin would leave behind --
        # must be caught and fixed, not treated as "close enough".
        existing = {"id": "s1", "isActive": False, "contents": self.TARGET}

        self.assertEqual(plan_sieve_action(existing, self.TARGET), "activate")

    def test_drifted_content_is_an_update_even_if_active(self):
        # e.g. someone hand-edited the forward target, or an older version
        # of this script wrote a plain `redirect` without :copy.
        existing = {
            "id": "s1",
            "isActive": True,
            "contents": 'redirect "someone-else@branchleft.co.uk";\n',
        }

        self.assertEqual(plan_sieve_action(existing, self.TARGET), "update")

    def test_drifted_content_and_inactive_is_still_an_update_not_an_activate(self):
        # Content correctness takes priority -- reactivating stale content
        # would leave the wrong script live.
        existing = {
            "id": "s1",
            "isActive": False,
            "contents": "redirect \"nowhere@example.com\";\n",
        }

        self.assertEqual(plan_sieve_action(existing, self.TARGET), "update")


class ResolveMailboxSecretTests(unittest.TestCase):
    """The crux of the credential-loss-on-partial-failure fix: a secret
    already on disk for a mailbox must be reused, never silently replaced
    with a freshly generated one that wouldn't match what Stalwart may
    already have been told (see _reconcile_accounts's docstring).
    """

    def test_reuses_a_recorded_secret_instead_of_generating_a_new_one(self):
        recorded = {"contact": "already-on-disk-from-a-previous-attempt"}
        generate_calls = []

        def generate():
            generate_calls.append(1)
            return "should-never-be-used"

        secret = resolve_mailbox_secret("contact", recorded, generate)

        self.assertEqual(secret, "already-on-disk-from-a-previous-attempt")
        self.assertEqual(generate_calls, [])

    def test_generates_a_fresh_secret_when_none_is_recorded(self):
        secret = resolve_mailbox_secret("info", {}, lambda: "freshly-generated")

        self.assertEqual(secret, "freshly-generated")

    def test_only_the_matching_local_parts_recorded_secret_is_returned(self):
        recorded = {"sales": "sales-secret", "info": "info-secret"}

        self.assertEqual(resolve_mailbox_secret("sales", recorded, lambda: "new"), "sales-secret")
        self.assertEqual(resolve_mailbox_secret("complaints", recorded, lambda: "new"), "new")


class LoadRecordedSecretsTests(unittest.TestCase):
    def test_missing_file_is_an_empty_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(pm, "MAILBOX_CREDENTIALS_PATH", os.path.join(tmp, "nope")):
                self.assertEqual(pm._load_recorded_secrets(), {})

    def test_parses_one_local_colon_secret_pair_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("rob:secret-one\ncontact:secret-two\n")
            with mock.patch.object(pm, "MAILBOX_CREDENTIALS_PATH", path):
                self.assertEqual(
                    pm._load_recorded_secrets(), {"rob": "secret-one", "contact": "secret-two"}
                )

    def test_a_secret_containing_a_colon_is_preserved_whole(self):
        # secrets.token_urlsafe never emits ':', but a hand-edited or
        # differently-generated value might -- split(":", 1) is what makes
        # that safe.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("rob:has:a:colon\n")
            with mock.patch.object(pm, "MAILBOX_CREDENTIALS_PATH", path):
                self.assertEqual(pm._load_recorded_secrets(), {"rob": "has:a:colon"})

    def test_blank_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            with open(path, "w", encoding="utf-8") as f:
                f.write("rob:secret-one\n\n\ncontact:secret-two\n")
            with mock.patch.object(pm, "MAILBOX_CREDENTIALS_PATH", path):
                self.assertEqual(
                    pm._load_recorded_secrets(), {"rob": "secret-one", "contact": "secret-two"}
                )


class ReconcileAccountsOrderingTests(unittest.TestCase):
    """_reconcile_accounts is the orchestration this round's review found a
    real bug in (secret persisted after, not before, the network write that
    uses it) -- these tests exercise it against a fake JMAP layer
    (unittest.mock, no live call) to pin the fix: record-before-create, and
    reuse-on-retry for a secret a previous partial run already recorded.

    Deliberately not covered here or elsewhere: the raw HTTP/JMAP mechanics
    in _request/_jmap_call/_upload_blob/_download_blob/_get_sieve_script.
    That layer is a thin, mechanical wrapper around urllib (build a request,
    add an auth header, parse JSON) with no branching logic of its own to
    get wrong -- configure_stalwart.py's existing test suite draws the same
    line (its _request/_jmap_call are equally untested), and this PR's own
    live validation against mx1 already exercised every JMAP call this
    script makes end to end. The risk this review surfaced was in the
    orchestration logic around that layer, which is what these tests cover.
    """

    ADMIN_AUTH = ("admin", "admin-secret-not-real")
    DOMAIN_ID = "d1"

    def setUp(self):
        # _reconcile_accounts prints a status line per mailbox -- silence it
        # so test output stays readable; the prints themselves are the
        # untested, non-branching stdlib-only I/O layer described above.
        patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_secret_is_recorded_before_the_create_call_uses_it(self):
        call_order = []

        def fake_record(local, secret):
            call_order.append(("record", local, secret))

        def fake_create(auth, local, create_args):
            call_order.append(("create", local, create_args["credentials"]["0"]["secret"]))
            return f"id-{local}"

        with mock.patch.object(pm, "_get_existing_account_names", return_value={}), \
             mock.patch.object(pm, "_load_recorded_secrets", return_value={}), \
             mock.patch.object(pm, "_record_mailbox_secret", side_effect=fake_record), \
             mock.patch.object(pm, "_create_account", side_effect=fake_create), \
             mock.patch.object(pm.secrets, "token_urlsafe", return_value="brand-new-secret"):
            account_ids = pm._reconcile_accounts(self.ADMIN_AUTH, self.DOMAIN_ID)

        by_local: dict[str, dict[str, str]] = {}
        order_within_local: dict[str, list[str]] = {}
        for kind, local, secret in call_order:
            by_local.setdefault(local, {})[kind] = secret
            order_within_local.setdefault(local, []).append(kind)

        for local in MAILBOXES:
            self.assertEqual(order_within_local[local], ["record", "create"])
            # the exact same secret that was written to disk is the one sent
            # in the create call -- not a second, independently-generated one
            self.assertEqual(by_local[local]["record"], by_local[local]["create"])
            self.assertEqual(account_ids[local], f"id-{local}")

    def test_secret_is_persisted_even_if_the_create_call_then_fails(self):
        # The exact scenario this fix closes: the create call raises (lost
        # response, crashed process, etc.) -- the secret must already be on
        # disk by that point, not lost with it.
        recorded_calls = []

        def fake_record(local, secret):
            recorded_calls.append((local, secret))

        def fake_create(auth, local, create_args):
            raise RuntimeError("simulated: response never arrived")

        with mock.patch.object(pm, "_get_existing_account_names", return_value={}), \
             mock.patch.object(pm, "_load_recorded_secrets", return_value={}), \
             mock.patch.object(pm, "_record_mailbox_secret", side_effect=fake_record), \
             mock.patch.object(pm, "_create_account", side_effect=fake_create), \
             mock.patch.object(pm.secrets, "token_urlsafe", return_value="s"):
            with self.assertRaises(RuntimeError):
                pm._reconcile_accounts(self.ADMIN_AUTH, self.DOMAIN_ID)

        # the first mailbox in MAILBOXES order was attempted, and its secret
        # reached disk before the (failing) create call ran
        self.assertEqual(recorded_calls, [(MAILBOXES[0], "s")])

    def test_a_secret_already_on_disk_is_reused_not_regenerated_and_not_rewritten(self):
        # The specific case the review asked to be pinned: secret file
        # already has an entry for this mailbox, the account doesn't exist
        # yet (e.g. a create-then-crash-then-retry). "rob" has a recorded
        # secret; the rest of MAILBOXES don't.
        record_calls = []

        def fake_record(local, secret):
            record_calls.append((local, secret))

        create_secrets = {}

        def fake_create(auth, local, create_args):
            create_secrets[local] = create_args["credentials"]["0"]["secret"]
            return f"id-{local}"

        generated = []

        def fake_generate(*_args, **_kwargs):
            # side_effect for secrets.token_urlsafe(32) -- must accept the
            # positional length argument it's actually called with.
            value = f"freshly-generated-{len(generated)}"
            generated.append(value)
            return value

        with mock.patch.object(pm, "_get_existing_account_names", return_value={}), \
             mock.patch.object(
                 pm, "_load_recorded_secrets", return_value={"rob": "already-on-disk"}
             ), \
             mock.patch.object(pm, "_record_mailbox_secret", side_effect=fake_record), \
             mock.patch.object(pm, "_create_account", side_effect=fake_create), \
             mock.patch.object(pm.secrets, "token_urlsafe", side_effect=fake_generate):
            pm._reconcile_accounts(self.ADMIN_AUTH, self.DOMAIN_ID)

        # rob's already-recorded secret was sent as-is, and never re-recorded
        self.assertEqual(create_secrets["rob"], "already-on-disk")
        self.assertNotIn("rob", [local for local, _ in record_calls])

        # the rest, without a recorded secret, each got a freshly generated
        # one, which was recorded exactly once
        for local in MAILBOXES:
            if local == "rob":
                continue
            self.assertEqual(create_secrets[local], generated[generated.index(create_secrets[local])])
            self.assertIn((local, create_secrets[local]), record_calls)
        self.assertEqual(len(generated), len(MAILBOXES) - 1)

    def test_no_missing_mailboxes_makes_no_secret_or_create_calls(self):
        with mock.patch.object(
            pm, "_get_existing_account_names", return_value=dict.fromkeys(MAILBOXES, "existing-id")
        ), mock.patch.object(pm, "_load_recorded_secrets", return_value={}), mock.patch.object(
            pm, "_record_mailbox_secret"
        ) as record_mock, mock.patch.object(pm, "_create_account") as create_mock:
            account_ids = pm._reconcile_accounts(self.ADMIN_AUTH, self.DOMAIN_ID)

        record_mock.assert_not_called()
        create_mock.assert_not_called()
        self.assertEqual(set(account_ids), set(MAILBOXES))


class MainOrchestrationTests(unittest.TestCase):
    """main()'s call order and error propagation, against a fully faked
    module surface -- no network, no filesystem.
    """

    def setUp(self):
        patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_calls_each_stage_in_order_and_returns_zero(self):
        calls = []

        def fake_load_admin_credentials():
            calls.append("load_admin_credentials")
            return ("admin", "secret")

        def fake_get_domain_id(auth, domain_name):
            calls.append("get_domain_id")
            return "d1"

        def fake_reconcile_accounts(auth, domain_id):
            calls.append("reconcile_accounts")
            return {local: f"id-{local}" for local in MAILBOXES}

        def fake_reconcile_role_sieve_script(auth, local, account_id):
            calls.append(f"reconcile_sieve:{local}")
            return False

        with mock.patch.object(pm, "_load_admin_credentials", side_effect=fake_load_admin_credentials), \
             mock.patch.object(pm, "_get_domain_id", side_effect=fake_get_domain_id), \
             mock.patch.object(pm, "_reconcile_accounts", side_effect=fake_reconcile_accounts), \
             mock.patch.object(
                 pm, "_reconcile_role_sieve_script", side_effect=fake_reconcile_role_sieve_script
             ):
            result = pm.main()

        self.assertEqual(result, 0)
        self.assertEqual(
            calls,
            ["load_admin_credentials", "get_domain_id", "reconcile_accounts"]
            + [f"reconcile_sieve:{local}" for local in ROLE_ADDRESSES],
        )

    def test_a_failure_reconciling_accounts_propagates_and_skips_sieve_scripts(self):
        sieve_mock_calls = []

        with mock.patch.object(pm, "_load_admin_credentials", return_value=("admin", "s")), \
             mock.patch.object(pm, "_get_domain_id", return_value="d1"), \
             mock.patch.object(
                 pm, "_reconcile_accounts", side_effect=RuntimeError("simulated failure")
             ), \
             mock.patch.object(
                 pm,
                 "_reconcile_role_sieve_script",
                 side_effect=lambda *a: sieve_mock_calls.append(a),
             ):
            with self.assertRaises(RuntimeError):
                pm.main()

        self.assertEqual(sieve_mock_calls, [])


if __name__ == "__main__":
    unittest.main()
