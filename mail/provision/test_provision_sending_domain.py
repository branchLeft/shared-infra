#!/usr/bin/env python3
"""Unit tests for provision_sending_domain.py -- no network, no live server.
The reconcile tests run against an in-memory stand-in for Stalwart's
registry that applies the script's own /set calls, so "a second run changes
nothing" is checked against state the first run actually produced.
"""
import contextlib
import copy
import io
import itertools
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import urllib.error
from unittest import mock

import provision_sending_domain as psd
from provision_sending_domain import (
    DMARC_VALUE,
    KEY_TYPE,
    Plan,
    Refused,
    build_set_calls,
    dns_records,
    find_key,
    format_zone,
    plan_sending_domain,
    validate_domain,
    validate_selector,
)

FAKE_PEM = "-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY-MARKER\n-----END PRIVATE KEY-----\n"


def _domain(domain_id, name, management="Manual"):
    return {"id": domain_id, "name": name, "dkimManagement": {"@type": management}}


def _key(key_id, domain_id, selector, stage="active", key_type=KEY_TYPE, public_key="PUBKEY"):
    return {
        "id": key_id,
        "domainId": domain_id,
        "selector": selector,
        "stage": stage,
        "@type": key_type,
        "publicKey": public_key,
        "privateKey": {"@type": "Text", "secret": "****"},
    }


class FakeStalwart:
    """Applies x:Domain/set and x:DkimSignature/set creates to in-memory
    lists, resolving `#creation-id` references the way the server does, and
    records every method call so a test can see exactly what was written."""

    def __init__(self, domains=None, keys=None):
        self.domains = copy.deepcopy(domains or [])
        self.keys = copy.deepcopy(keys or [])
        self.calls = []
        self._next = itertools.count(100)

    def writes(self):
        return [c for c in self.calls if c[0].endswith("/set")]

    def __call__(self, auth, calls):
        created_ids = {}
        responses = []
        for method, args, call_id in calls:
            self.calls.append((method, copy.deepcopy(args)))
            if method == "x:Domain/get":
                responses.append([method, {"list": copy.deepcopy(self.domains)}, call_id])
            elif method == "x:DkimSignature/get":
                redacted = [{**k, "privateKey": {"@type": "Text", "secret": "****"}} for k in self.keys]
                responses.append([method, {"list": redacted}, call_id])
            elif method == "x:Domain/set":
                created = {}
                for cid, obj in args.get("create", {}).items():
                    new_id = f"d{next(self._next)}"
                    self.domains.append({"id": new_id, **obj})
                    created_ids[cid] = new_id
                    created[cid] = {"id": new_id}
                responses.append([method, {"created": created}, call_id])
            elif method == "x:DkimSignature/set":
                created = {}
                for cid, obj in args.get("create", {}).items():
                    domain_id = obj["domainId"]
                    if domain_id.startswith("#"):
                        domain_id = created_ids[domain_id[1:]]
                    new_id = f"k{next(self._next)}"
                    self.keys.append(
                        {
                            "id": new_id,
                            "domainId": domain_id,
                            "selector": obj["selector"],
                            "stage": "active",
                            "@type": obj["@type"],
                            "publicKey": f"PUB-{new_id}",
                        }
                    )
                    created[cid] = {"id": new_id}
                responses.append([method, {"created": created}, call_id])
            else:
                raise AssertionError(f"unexpected method {method}")
        return responses


@contextlib.contextmanager
def _against(fake, pem=FAKE_PEM):
    with mock.patch.object(psd, "_jmap", fake), mock.patch.object(
        psd, "_load_credentials", return_value=("admin", "x")
    ), mock.patch.object(psd, "generate_private_key", return_value=pem) as gen:
        yield gen


class PlanTests(unittest.TestCase):
    def test_absent_domain_is_planned_for_creation_with_a_key(self):
        plan = plan_sending_domain("demo.example", "bl", [_domain("a", "other.example")], [])
        self.assertEqual(plan, Plan(create_domain=True, create_key=True, domain_id=None))
        self.assertFalse(plan.is_noop)

    def test_present_domain_with_active_key_is_a_noop(self):
        plan = plan_sending_domain(
            "demo.example", "bl", [_domain("a", "demo.example")], [_key("k", "a", "bl")]
        )
        self.assertTrue(plan.is_noop)
        self.assertEqual(plan.domain_id, "a")

    def test_noop_ignores_the_domain_management_mode(self):
        # A key under our selector is ours whatever the domain's mode says.
        plan = plan_sending_domain(
            "demo.example", "bl", [_domain("a", "demo.example", "Automatic")], [_key("k", "a", "bl")]
        )
        self.assertTrue(plan.is_noop)

    def test_manual_domain_without_a_key_resumes_with_only_the_key(self):
        plan = plan_sending_domain("demo.example", "bl", [_domain("a", "demo.example")], [])
        self.assertEqual(plan, Plan(create_domain=False, create_key=True, domain_id="a"))

    def test_other_domains_keys_do_not_count(self):
        plan = plan_sending_domain(
            "demo.example",
            "bl",
            [_domain("a", "demo.example"), _domain("b", "main.example", "Automatic")],
            [_key("k1", "b", "bl"), _key("k2", "b", "v1-rsa-20260101")],
        )
        self.assertEqual(plan, Plan(create_domain=False, create_key=True, domain_id="a"))

    def test_domain_with_keys_under_other_selectors_is_refused(self):
        with self.assertRaisesRegex(Refused, "other selectors .*v1-ed25519.*v1-rsa"):
            plan_sending_domain(
                "main.example",
                "bl",
                [_domain("a", "main.example", "Automatic")],
                [_key("k1", "a", "v1-rsa-20260810"), _key("k2", "a", "v1-ed25519-20260810")],
            )

    def test_automatic_domain_without_keys_is_refused(self):
        with self.assertRaisesRegex(Refused, "dkimManagement 'Automatic'"):
            plan_sending_domain("demo.example", "bl", [_domain("a", "demo.example", "Automatic")], [])

    def test_domain_with_no_management_field_is_refused(self):
        with self.assertRaisesRegex(Refused, "dkimManagement None"):
            plan_sending_domain("demo.example", "bl", [{"id": "a", "name": "demo.example"}], [])

    def test_inactive_key_under_our_selector_is_refused_not_replaced(self):
        for stage in ("retiring", "retired", "pending"):
            with self.subTest(stage=stage), self.assertRaisesRegex(Refused, f"stage '{stage}'"):
                plan_sending_domain(
                    "demo.example", "bl", [_domain("a", "demo.example")], [_key("k", "a", "bl", stage)]
                )


class NeverTouchesExistingKeysTests(unittest.TestCase):
    """Over every combination of an existing domain's management mode and
    keys, the planner either refuses or produces calls that only create --
    and never a key for a domain that already has one."""

    def test_every_existing_state_is_refused_noop_or_create_only(self):
        modes = ("Manual", "Automatic", None)
        key_sets = (
            [],
            [_key("k1", "a", "bl")],
            [_key("k1", "a", "bl", "retired")],
            [_key("k1", "a", "other")],
            [_key("k1", "a", "bl"), _key("k2", "a", "other")],
        )
        for mode, keys in itertools.product(modes, key_sets):
            domain = {"id": "a", "name": "demo.example"}
            if mode is not None:
                domain["dkimManagement"] = {"@type": mode}
            with self.subTest(mode=mode, keys=[(k["selector"], k["stage"]) for k in keys]):
                try:
                    plan = plan_sending_domain("demo.example", "bl", [domain], keys)
                except Refused:
                    continue
                self.assertFalse(plan.create_domain)
                calls = build_set_calls("demo.example", "bl", plan, FAKE_PEM)
                for method, args, _ in calls:
                    self.assertEqual(set(args), {"create"}, "only creates are ever planned")
                    self.assertEqual(method, "x:DkimSignature/set")
                if plan.create_key:
                    self.assertEqual(keys, [], "a key is only added to a domain with none")


class BuildSetCallsTests(unittest.TestCase):
    def test_new_domain_and_key_go_in_one_request_linked_by_creation_id(self):
        calls = build_set_calls("demo.example", "bl", Plan(True, True, None), FAKE_PEM)
        self.assertEqual([c[0] for c in calls], ["x:Domain/set", "x:DkimSignature/set"])
        domain = calls[0][1]["create"]["domain"]
        self.assertEqual(domain, {"name": "demo.example", "dkimManagement": {"@type": "Manual"}})
        key = calls[1][1]["create"]["key"]
        self.assertEqual(key["domainId"], "#domain")
        self.assertEqual(key["@type"], "Dkim1RsaSha256")
        self.assertEqual(key["selector"], "bl")
        self.assertEqual(key["privateKey"], {"@type": "Text", "secret": FAKE_PEM})

    def test_resume_targets_the_existing_domain_id(self):
        calls = build_set_calls("demo.example", "bl", Plan(False, True, "a"), FAKE_PEM)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["create"]["key"]["domainId"], "a")

    def test_noop_plan_builds_nothing(self):
        self.assertEqual(build_set_calls("demo.example", "bl", Plan(False, False, "a"), FAKE_PEM), [])


class ReconcileTests(unittest.TestCase):
    def test_first_run_creates_second_run_writes_nothing_and_keeps_the_key(self):
        fake = FakeStalwart(domains=[_domain("main", "main.example", "Automatic")],
                            keys=[_key("m1", "main", "v1-rsa-20260810")])
        with _against(fake) as gen:
            plan, first = psd.reconcile("demo.example", "bl", dkim_only=False)
            self.assertFalse(plan.is_noop)
            self.assertEqual(gen.call_count, 1)
            state_after_first = (copy.deepcopy(fake.domains), copy.deepcopy(fake.keys))
            writes_after_first = len(fake.writes())

            plan2, second = psd.reconcile("demo.example", "bl", dkim_only=False)

        self.assertTrue(plan2.is_noop)
        self.assertEqual(gen.call_count, 1, "no key generated on the second run")
        self.assertEqual(len(fake.writes()), writes_after_first, "second run made a /set call")
        self.assertEqual((fake.domains, fake.keys), state_after_first)
        self.assertEqual(first, second, "the published record changed between runs")
        self.assertEqual(len([k for k in fake.keys if k["domainId"] != "main"]), 1)

    def test_first_run_leaves_every_other_domains_keys_alone(self):
        main_keys = [_key("m1", "main", "v1-rsa-20260810"), _key("m2", "main", "v1-ed25519-20260810")]
        fake = FakeStalwart(domains=[_domain("main", "main.example", "Automatic")], keys=main_keys)
        with _against(fake):
            psd.reconcile("demo.example", "bl", dkim_only=False)
        self.assertEqual([k for k in fake.keys if k["domainId"] == "main"], main_keys)

    def test_resume_after_a_half_finished_run(self):
        fake = FakeStalwart(domains=[_domain("a", "demo.example")])
        with _against(fake):
            plan, records = psd.reconcile("demo.example", "bl", dkim_only=True)
        self.assertFalse(plan.is_noop)
        self.assertEqual(len(fake.domains), 1)
        self.assertEqual([k["domainId"] for k in fake.keys], ["a"])
        self.assertEqual(records[0]["name"], "bl._domainkey.demo.example")

    def test_refusal_writes_nothing_and_generates_no_key(self):
        fake = FakeStalwart(domains=[_domain("a", "main.example", "Automatic")], keys=[_key("k", "a", "v1")])
        with _against(fake) as gen, self.assertRaises(Refused):
            psd.reconcile("main.example", "bl", dkim_only=False)
        self.assertEqual(fake.writes(), [])
        gen.assert_not_called()

    def test_a_tenant_domain_is_the_same_call(self):
        fake = FakeStalwart()
        with _against(fake):
            psd.reconcile("demo.example", "bl", dkim_only=False)
            plan, records = psd.reconcile("tenant.example", "bl", dkim_only=True)
        self.assertFalse(plan.is_noop)
        self.assertEqual([r["type"] for r in records], ["TXT"])
        self.assertEqual(sorted(d["name"] for d in fake.domains), ["demo.example", "tenant.example"])
        self.assertEqual(len({k["publicKey"] for k in fake.keys}), 2, "each domain has its own key")


class RecordTests(unittest.TestCase):
    def test_full_record_set(self):
        records = dns_records("demo.example", "bl", _key("k", "a", "bl"), "mx1.example", dkim_only=False)
        self.assertEqual(
            records,
            [
                {"name": "bl._domainkey.demo.example", "type": "TXT", "value": "v=DKIM1; k=rsa; h=sha256; p=PUBKEY"},
                {"name": "demo.example", "type": "MX", "value": "10 mx1.example."},
                {"name": "demo.example", "type": "TXT", "value": "v=spf1 mx -all"},
                {"name": "_dmarc.demo.example", "type": "TXT", "value": DMARC_VALUE},
            ],
        )

    def test_dkim_only(self):
        records = dns_records("t.example", "bl", _key("k", "a", "bl"), "mx1.example", dkim_only=True)
        self.assertEqual([r["name"] for r in records], ["bl._domainkey.t.example"])

    def test_ed25519_key_is_tagged_as_such(self):
        key = _key("k", "a", "bl", key_type="Dkim1Ed25519Sha256")
        self.assertIn("k=ed25519;", dns_records("t.example", "bl", key, "mx1.example", True)[0]["value"])

    def test_unknown_key_type_and_missing_public_key_are_refused(self):
        with self.assertRaisesRegex(Refused, "unrecognised"):
            dns_records("t.example", "bl", _key("k", "a", "bl", key_type="Arc"), "mx1.example", True)
        with self.assertRaisesRegex(Refused, "no public key"):
            dns_records("t.example", "bl", _key("k", "a", "bl", public_key=""), "mx1.example", True)

    def test_zone_output_splits_long_txt_at_255(self):
        value = "v=DKIM1; k=rsa; h=sha256; p=" + "A" * 392
        text = format_zone([{"name": "bl._domainkey.d.example", "type": "TXT", "value": value},
                            {"name": "d.example", "type": "MX", "value": "10 mx1.example."}])
        first, second = text.splitlines()
        strings = first.split(" IN TXT ", 1)[1].split('" "')
        self.assertEqual(len(strings), 2)
        self.assertEqual(len(strings[0].strip('"')), 255)
        self.assertEqual("".join(s.strip('"') for s in strings), value)
        self.assertEqual(second, "d.example. 3600 IN MX 10 mx1.example.")


class FindKeyTests(unittest.TestCase):
    def test_returns_the_active_key(self):
        key = _key("k", "a", "bl")
        self.assertIs(find_key("d.example", "bl", [_domain("a", "d.example")], [key]), key)

    def test_missing_domain_missing_key_and_inactive_key_all_fail(self):
        with self.assertRaisesRegex(RuntimeError, "does not exist"):
            find_key("d.example", "bl", [], [])
        with self.assertRaisesRegex(RuntimeError, "no 'bl' key"):
            find_key("d.example", "bl", [_domain("a", "d.example")], [_key("k", "a", "other")])
        with self.assertRaisesRegex(RuntimeError, "not active"):
            find_key("d.example", "bl", [_domain("a", "d.example")], [_key("k", "a", "bl", "retired")])


class ValidationTests(unittest.TestCase):
    def test_accepts_ordinary_names(self):
        for name in ("demo.example.com", "a-b.example.co.uk", "x1.io"):
            self.assertEqual(validate_domain(name), name)
        for selector in ("bl", "bl2", "s1.keys"):
            self.assertEqual(validate_selector(selector), selector)

    def test_rejects_bad_names(self):
        for name in ("Demo.example.com", "example", "-a.example.com", "a..example.com",
                     "a.example.com.", "a example.com", "a.example.c0m", "a" * 250 + ".com"):
            with self.subTest(name=name), self.assertRaises(Refused):
                validate_domain(name)
        for selector in ("", "-bl", "bl_", "b l", "bl."):
            with self.subTest(selector=selector), self.assertRaises(Refused):
                validate_selector(selector)


class KeyGenerationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_real_openssl_produces_a_2048_bit_pkcs8_rsa_key(self):
        pem = psd.generate_private_key()
        self.assertTrue(pem.startswith("-----BEGIN PRIVATE KEY-----"))
        out = subprocess.run(["openssl", "pkey", "-noout", "-text"], input=pem,
                             capture_output=True, text=True, check=True).stdout
        self.assertIn("2048 bit", out)

    def test_non_pkcs8_output_is_rejected(self):
        done = subprocess.CompletedProcess([], 0, stdout="garbage", stderr="")
        with mock.patch.object(psd.subprocess, "run", return_value=done):
            with self.assertRaisesRegex(RuntimeError, "no PKCS#8"):
                psd.generate_private_key()


class CredentialsTests(unittest.TestCase):
    def test_splits_username_from_secret_on_the_first_colon_only(self):
        # The secret itself may contain ':' -- split(":", 1) must not
        # truncate it.
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("admin:pass:word\n")
            with mock.patch.object(psd, "CREDENTIALS_PATH", path):
                self.assertEqual(psd._load_credentials(), ("admin", "pass:word"))
        finally:
            os.remove(path)


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class JmapTests(unittest.TestCase):
    def _respond(self, responses):
        body = json.dumps({"methodResponses": responses}).encode()
        return mock.patch.object(psd.urllib.request, "urlopen", return_value=_Response(body))

    def test_returns_responses_and_sends_basic_auth(self):
        with self._respond([["x:Domain/get", {"list": []}, "0"]]) as urlopen:
            out = psd._jmap(("u", "p"), [["x:Domain/get", {}, "0"]])
        self.assertEqual(out[0][1], {"list": []})
        request = urlopen.call_args[0][0]
        self.assertEqual(request.get_header("Authorization"), "Basic dTpw")
        self.assertEqual(json.loads(request.data)["methodCalls"], [["x:Domain/get", {}, "0"]])

    def test_method_error_raises(self):
        with self._respond([["error", {"type": "forbidden"}, "0"]]), self.assertRaisesRegex(RuntimeError, "forbidden"):
            psd._jmap(("u", "p"), [])

    def test_rejected_object_raises_even_when_the_call_succeeds(self):
        for key in ("notCreated", "notUpdated", "notDestroyed"):
            with self.subTest(key=key), self._respond([["x:Domain/set", {key: {"d": {"type": "x"}}}, "0"]]):
                with self.assertRaisesRegex(RuntimeError, key):
                    psd._jmap(("u", "p"), [])


class MainTests(unittest.TestCase):
    def _run(self, argv, fake):
        out, err = io.StringIO(), io.StringIO()
        with _against(fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = psd.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_create_then_noop_output_and_the_private_key_is_never_printed(self):
        fake = FakeStalwart()
        code, out, err = self._run(["demo.example"], fake)
        self.assertEqual(code, 0)
        self.assertIn("created the domain and its DKIM key", out)
        self.assertIn("bl._domainkey.demo.example. 3600 IN TXT", out)
        code, out2, _ = self._run(["demo.example"], fake)
        self.assertEqual(code, 0)
        self.assertIn("already present, no-op", out2)
        for text in (out, err, out2):
            self.assertNotIn("NOT-A-REAL-KEY-MARKER", text)
            self.assertNotIn("PRIVATE KEY", text)

    def test_resume_output_names_only_the_key(self):
        code, out, _ = self._run(["demo.example"], FakeStalwart(domains=[_domain("a", "demo.example")]))
        self.assertEqual(code, 0)
        self.assertIn("created its DKIM key", out)

    def test_json_output(self):
        code, out, _ = self._run(["demo.example", "--selector", "s2", "--dkim-only", "--json"], FakeStalwart())
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual((parsed["domain"], parsed["selector"], parsed["changed"]), ("demo.example", "s2", True))
        self.assertEqual([r["name"] for r in parsed["records"]], ["s2._domainkey.demo.example"])

    def test_refusal_exits_2(self):
        fake = FakeStalwart(domains=[_domain("a", "main.example", "Automatic")], keys=[_key("k", "a", "v1")])
        code, out, err = self._run(["main.example"], fake)
        self.assertEqual(code, 2)
        self.assertIn("refused, nothing written", err)
        self.assertEqual(out, "")

    def test_invalid_name_exits_2_before_any_call(self):
        fake = FakeStalwart()
        code, _, err = self._run(["Demo.Example"], fake)
        self.assertEqual(code, 2)
        self.assertEqual(fake.calls, [])

    def test_unreachable_api_exits_1(self):
        def unreachable(auth, calls):
            raise urllib.error.URLError("refused")

        code, _, err = self._run(["demo.example"], unreachable)
        self.assertEqual(code, 1)
        self.assertIn("could not reach", err)


if __name__ == "__main__":
    unittest.main()
