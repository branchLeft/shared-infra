#!/usr/bin/env python3
"""Unit tests for configure_stalwart.py's pure diff functions -- no network
access, no live server needed. Run with: python3 -m unittest discover -s
mail/provision -p 'test_*.py' -v
"""
import copy
import unittest

from configure_stalwart import (
    ACME_DIRECTORY,
    ALLOWED_IPS,
    HTTP_DENY_HTTPS_LISTENER,
    MANAGED_LISTENERS,
    SECURITY_TARGET,
    plan_acme_provider,
    plan_allowed_ips,
    plan_domain_sans,
    plan_http_change,
    plan_listener_changes,
    plan_security_change,
    plan_tracer_change,
)

_DAY_MS = 86400000


def _listener(name: str, listener_id: str, **overrides) -> dict:
    """A managed listener already matching its target spec, plus whatever
    fields the real API also returns that this script doesn't manage
    (present here to prove the diff ignores them)."""
    spec = dict(MANAGED_LISTENERS[name])
    spec.update(overrides)
    return {
        "id": listener_id,
        "name": name,
        "socketBacklog": 1024,
        "maxConnections": 8192,
        **spec,
    }


# Every managed listener, already fully reconciled -- the baseline for the
# no-drift tests and for composing individual-field-drift cases from.
RECONCILED_LISTENERS = [
    _listener("smtp", "l-smtp"),
    _listener("submissions", "l-submissions"),
    _listener("imaps", "l-imaps"),
    _listener("https", "l-https"),
    _listener("http", "l-http"),
    _listener("submission", "l-submission"),
]

# What Stalwart's own bootstrap wizard actually creates by default: no
# "submission" listener at all, "pop3s"/"sieve" present, but "https"
# already matches the target (protocol="http", required for ACME -- see
# MANAGED_LISTENERS's comment on why an earlier version of this script got
# that wrong). See mail/RUNBOOK-mx1-provision.md.
BOOTSTRAP_DEFAULT_LISTENERS = [
    _listener("smtp", "l-smtp"),
    _listener("submissions", "l-submissions"),
    _listener("imaps", "l-imaps"),
    _listener("http", "l-http"),
    _listener("https", "l-https"),
    {"id": "l-pop3s", "name": "pop3s", "bind": {"[::]:995": True}, "protocol": "pop3"},
    {"id": "l-sieve", "name": "sieve", "bind": {"[::]:4190": True}, "protocol": "manageSieve"},
]


class PlanListenerChangesFreshBootstrapTests(unittest.TestCase):
    def test_needs_new_submission_and_two_removals_but_no_https_change(self):
        plan = plan_listener_changes(BOOTSTRAP_DEFAULT_LISTENERS)

        self.assertNotIn("update", plan)
        self.assertEqual(plan["create"]["submission"]["bind"], {"[::]:587": True})
        self.assertCountEqual(plan["destroy"], ["l-pop3s", "l-sieve"])


class PlanListenerChangesNoDriftTests(unittest.TestCase):
    def test_fully_reconciled_state_is_a_no_op(self):
        self.assertEqual(plan_listener_changes(RECONCILED_LISTENERS), {})

    def test_extra_unmanaged_fields_on_a_reconciled_listener_are_ignored(self):
        listeners = copy.deepcopy(RECONCILED_LISTENERS)
        listeners[0]["socketBacklog"] = 99999
        listeners[0]["maxConnections"] = 1

        self.assertEqual(plan_listener_changes(listeners), {})


class PlanListenerChangesPerListenerDriftTests(unittest.TestCase):
    """Every managed listener, checked individually for drift on each field
    this script manages -- the exact gap the previous presence-only check
    for "submission" left open (a listener could exist with the wrong
    bind/protocol/useTls/tlsImplicit and never get fixed).
    """

    def _drifted(self, name: str, listener_id: str, **field_overrides) -> list[dict]:
        listeners = copy.deepcopy(RECONCILED_LISTENERS)
        for listener in listeners:
            if listener["name"] == name:
                listener.update(field_overrides)
        return listeners

    def test_smtp_bind_drift_is_detected_and_fixed(self):
        listeners = self._drifted("smtp", "l-smtp", bind={"[::]:2525": True})
        plan = plan_listener_changes(listeners)
        self.assertEqual(plan["update"], {"l-smtp": {"bind": {"[::]:25": True}}})

    def test_smtp_no_drift_is_a_no_op(self):
        listeners = self._drifted("smtp", "l-smtp")
        self.assertEqual(plan_listener_changes(listeners), {})

    def test_submissions_tls_implicit_drift_is_detected_and_fixed(self):
        listeners = self._drifted("submissions", "l-submissions", tlsImplicit=False)
        plan = plan_listener_changes(listeners)
        self.assertEqual(plan["update"], {"l-submissions": {"tlsImplicit": True}})

    def test_submissions_no_drift_is_a_no_op(self):
        listeners = self._drifted("submissions", "l-submissions")
        self.assertEqual(plan_listener_changes(listeners), {})

    def test_imaps_protocol_drift_is_detected_and_fixed(self):
        listeners = self._drifted("imaps", "l-imaps", protocol="pop3")
        plan = plan_listener_changes(listeners)
        self.assertEqual(plan["update"], {"l-imaps": {"protocol": "imap"}})

    def test_imaps_no_drift_is_a_no_op(self):
        listeners = self._drifted("imaps", "l-imaps")
        self.assertEqual(plan_listener_changes(listeners), {})

    def test_https_use_tls_drift_is_detected_and_fixed(self):
        # Distinct from the "protocol reverted to http" bootstrap-default
        # case already covered above -- this is a *different* field
        # drifting on the same listener.
        listeners = self._drifted("https", "l-https", useTls=False)
        plan = plan_listener_changes(listeners)
        self.assertEqual(plan["update"], {"l-https": {"useTls": True}})

    def test_https_no_drift_is_a_no_op(self):
        listeners = self._drifted("https", "l-https")
        self.assertEqual(plan_listener_changes(listeners), {})

    def test_http_bind_drift_to_loopback_is_detected_and_reverted(self):
        # The specific regression this script must never reintroduce: an
        # operator (or a future edit) rebinding "http" to 127.0.0.1 at the
        # Stalwart level breaks admin access entirely, because Docker's
        # port-forwarding reaches the container's bridge address, not its
        # loopback. The fix is to revert to `[::]:8080` and rely solely on
        # docker-compose.yml's `127.0.0.1:8080:8080` publish restriction.
        listeners = self._drifted("http", "l-http", bind={"127.0.0.1:8080": True})
        plan = plan_listener_changes(listeners)
        self.assertEqual(plan["update"], {"l-http": {"bind": {"[::]:8080": True}}})

    def test_http_no_drift_is_a_no_op(self):
        listeners = self._drifted("http", "l-http")
        self.assertEqual(plan_listener_changes(listeners), {})

    def test_submission_protocol_drift_is_detected_and_fixed(self):
        # The exact gap the review caught: this listener previously had no
        # field-level check at all, only a presence check.
        listeners = self._drifted("submission", "l-submission", protocol="imap", tlsImplicit=True)
        plan = plan_listener_changes(listeners)
        self.assertEqual(
            plan["update"], {"l-submission": {"protocol": "smtp", "tlsImplicit": False}}
        )

    def test_submission_no_drift_is_a_no_op(self):
        listeners = self._drifted("submission", "l-submission")
        self.assertEqual(plan_listener_changes(listeners), {})

    def test_missing_https_listener_is_not_recreated(self):
        # If an operator has already removed the https listener entirely,
        # this script must not try to invent one back -- it only edits an
        # existing listener's fields, never creates "https" from scratch.
        listeners = [l for l in copy.deepcopy(RECONCILED_LISTENERS) if l["name"] != "https"]

        plan = plan_listener_changes(listeners)

        self.assertNotIn("update", plan)
        self.assertNotIn("create", plan)

    def test_only_missing_submission_listener_is_created(self):
        listeners = [l for l in copy.deepcopy(RECONCILED_LISTENERS) if l["name"] != "submission"]

        plan = plan_listener_changes(listeners)

        self.assertNotIn("update", plan)
        self.assertNotIn("destroy", plan)
        self.assertEqual(plan["create"]["submission"]["bind"], {"[::]:587": True})


class PlanDomainSansTests(unittest.TestCase):
    def test_missing_san_is_added_alongside_existing_ones(self):
        domain = {
            "id": "d1",
            "name": "branchleft.co.uk",
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": "acme-1",
                "subjectAlternativeNames": {"other.branchleft.co.uk": True},
            },
        }

        plan = plan_domain_sans(domain, {"mx1.branchleft.co.uk"}, "acme-1")

        sans = plan["d1"]["certificateManagement"]["subjectAlternativeNames"]
        self.assertEqual(sans, {"other.branchleft.co.uk": True, "mx1.branchleft.co.uk": True})
        self.assertEqual(plan["d1"]["certificateManagement"]["acmeProviderId"], "acme-1")

    def test_already_present_san_is_a_no_op(self):
        domain = {
            "id": "d1",
            "name": "branchleft.co.uk",
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": "acme-1",
                "subjectAlternativeNames": {"mx1.branchleft.co.uk": True},
            },
        }

        self.assertIsNone(plan_domain_sans(domain, {"mx1.branchleft.co.uk"}, "acme-1"))

    def test_manual_certificate_management_is_left_alone(self):
        # A domain the operator has deliberately opted out of ACME for
        # must never be silently switched to Automatic by this script.
        domain = {
            "id": "d1",
            "name": "branchleft.co.uk",
            "certificateManagement": {"@type": "Manual"},
        }

        self.assertIsNone(plan_domain_sans(domain, {"mx1.branchleft.co.uk"}, "acme-1"))

    def test_no_resolved_provider_defers_the_update(self):
        # The provider was just created this same run and its id isn't
        # known yet by the time domains are being planned (shouldn't
        # normally happen given the reconciliation order in main(), but the
        # function itself must not point a domain at a provider id of
        # None).
        domain = {
            "id": "d1",
            "name": "branchleft.co.uk",
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": "acme-1",
                "subjectAlternativeNames": {},
            },
        }

        self.assertIsNone(plan_domain_sans(domain, {"mx1.branchleft.co.uk"}, None))

    def test_drifted_acme_provider_id_is_corrected(self):
        # The domain still has SANs correct but points at a stale/wrong
        # provider id (e.g. left over from manual staging-directory
        # testing) -- this must be corrected even with no SAN to add.
        domain = {
            "id": "d1",
            "name": "branchleft.co.uk",
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": "stale-staging-provider",
                "subjectAlternativeNames": {"mx1.branchleft.co.uk": True},
            },
        }

        plan = plan_domain_sans(domain, {"mx1.branchleft.co.uk"}, "acme-1")

        self.assertEqual(plan["d1"]["certificateManagement"]["acmeProviderId"], "acme-1")
        self.assertEqual(
            plan["d1"]["certificateManagement"]["subjectAlternativeNames"],
            {"mx1.branchleft.co.uk": True},
        )


class PlanHttpChangeTests(unittest.TestCase):
    def test_unmaterialized_singleton_is_created_with_the_deny_rule(self):
        plan = plan_http_change([])

        self.assertEqual(
            plan["create"]["singleton"]["allowedEndpoints"], HTTP_DENY_HTTPS_LISTENER
        )

    def test_wrong_rule_is_corrected(self):
        current = [{"id": "singleton", "allowedEndpoints": {"match": {}, "else": "200"}}]

        plan = plan_http_change(current)

        self.assertEqual(
            plan["update"]["singleton"]["allowedEndpoints"], HTTP_DENY_HTTPS_LISTENER
        )

    def test_correct_rule_is_a_no_op(self):
        current = [{"id": "singleton", "allowedEndpoints": HTTP_DENY_HTTPS_LISTENER}]

        self.assertEqual(plan_http_change(current), {})


class PlanAcmeProviderTests(unittest.TestCase):
    def test_missing_provider_is_created(self):
        args, provider_id = plan_acme_provider([])

        self.assertEqual(args["create"]["production"]["directory"], ACME_DIRECTORY)
        self.assertEqual(args["create"]["production"]["challengeType"], "TlsAlpn01")
        self.assertIsNone(provider_id)

    def test_drifted_challenge_type_is_corrected(self):
        # The exact regression this test guards: an operator or a future
        # Stalwart default picking http-01 (needs port 80, not open here)
        # instead of tls-alpn-01 must be caught and fixed, not left alone.
        providers = [
            {
                "id": "p1",
                "directory": ACME_DIRECTORY,
                "challengeType": "Http01",
                "contact": {"mailto:postmaster@branchleft.co.uk": True},
                "renewBefore": "R23",
                "maxRetries": 10,
                "reuseKey": False,
            }
        ]

        args, provider_id = plan_acme_provider(providers)

        self.assertEqual(args["update"]["p1"], {"challengeType": "TlsAlpn01"})
        self.assertEqual(provider_id, "p1")

    def test_drifted_contact_is_corrected(self):
        providers = [
            {
                "id": "p1",
                "directory": ACME_DIRECTORY,
                "challengeType": "TlsAlpn01",
                "contact": {"mailto:someone-else@branchleft.co.uk": True},
                "renewBefore": "R23",
                "maxRetries": 10,
                "reuseKey": False,
            }
        ]

        args, provider_id = plan_acme_provider(providers)

        self.assertEqual(
            args["update"]["p1"]["contact"], {"mailto:postmaster@branchleft.co.uk": True}
        )
        self.assertEqual(provider_id, "p1")

    def test_fully_reconciled_provider_is_a_no_op(self):
        providers = [
            {
                "id": "p1",
                "directory": ACME_DIRECTORY,
                "challengeType": "TlsAlpn01",
                "contact": {"mailto:postmaster@branchleft.co.uk": True},
                "renewBefore": "R23",
                "maxRetries": 10,
                "reuseKey": False,
            }
        ]

        args, provider_id = plan_acme_provider(providers)

        self.assertEqual(args, {})
        self.assertEqual(provider_id, "p1")

    def test_a_staging_provider_is_ignored_not_treated_as_the_managed_one(self):
        # A leftover manual staging-directory provider (created to prove
        # the ACME flow works before spending a production attempt) must
        # never be mistaken for the managed production provider -- matched
        # strictly by directory URL.
        providers = [
            {
                "id": "p-staging",
                "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
                "challengeType": "TlsAlpn01",
                "contact": {"mailto:postmaster@branchleft.co.uk": True},
                "renewBefore": "R23",
                "maxRetries": 10,
                "reuseKey": False,
            }
        ]

        args, provider_id = plan_acme_provider(providers)

        self.assertIn("create", args)
        self.assertIsNone(provider_id)


class PlanTracerChangeTests(unittest.TestCase):
    def test_log_tracer_is_switched_to_stdout(self):
        tracers = [{"id": "t1", "@type": "Log", "level": "info"}]

        plan = plan_tracer_change(tracers)

        self.assertEqual(plan["t1"]["@type"], "Stdout")
        self.assertEqual(plan["t1"]["level"], "info")

    def test_existing_stdout_tracer_is_a_no_op(self):
        tracers = [{"id": "t1", "@type": "Stdout", "level": "info"}]

        self.assertIsNone(plan_tracer_change(tracers))

    def test_no_tracers_configured_is_a_no_op(self):
        self.assertIsNone(plan_tracer_change([]))


class PlanSecurityChangeTests(unittest.TestCase):
    """SECURITY_TARGET already fully reconciled, plus an id -- the baseline
    for the no-drift test and for composing individual-field-drift cases.
    """

    RECONCILED_SECURITY = {"id": "singleton", **SECURITY_TARGET}

    def _drifted(self, **field_overrides) -> dict:
        current = dict(self.RECONCILED_SECURITY)
        current.update(field_overrides)
        return current

    def test_default_scan_ban_rate_is_disabled(self):
        # Stalwart's own shipped default -- the heuristic that misfired on
        # an ordinary mail client.
        current = self._drifted(scanBanRate={"count": 5, "period": 3600000})

        plan = plan_security_change(current, SECURITY_TARGET)

        self.assertEqual(plan, {"update": {"singleton": {"scanBanRate": None}}})

    def test_fully_reconciled_state_is_a_no_op(self):
        # The exact regression a _field_diff that treats None as "absent"
        # would cause: it would keep re-setting scanBanRate to None forever.
        self.assertEqual(plan_security_change(self.RECONCILED_SECURITY, SECURITY_TARGET), {})

    def test_scan_ban_period_unset_is_corrected(self):
        current = self._drifted(scanBanPeriod=None)

        plan = plan_security_change(current, SECURITY_TARGET)

        self.assertEqual(plan, {"update": {"singleton": {"scanBanPeriod": _DAY_MS}}})

    def test_auth_ban_period_unset_is_corrected(self):
        current = self._drifted(authBanPeriod=None)

        plan = plan_security_change(current, SECURITY_TARGET)

        self.assertEqual(plan, {"update": {"singleton": {"authBanPeriod": _DAY_MS}}})

    def test_abuse_ban_period_unset_is_corrected(self):
        current = self._drifted(abuseBanPeriod=None)

        plan = plan_security_change(current, SECURITY_TARGET)

        self.assertEqual(plan, {"update": {"singleton": {"abuseBanPeriod": _DAY_MS}}})

    def test_loiter_ban_period_unset_is_corrected(self):
        current = self._drifted(loiterBanPeriod=None)

        plan = plan_security_change(current, SECURITY_TARGET)

        self.assertEqual(plan, {"update": {"singleton": {"loiterBanPeriod": _DAY_MS}}})

    def test_unmanaged_scan_ban_paths_are_ignored(self):
        # Real protection for the HTTP listener whose contents this script
        # doesn't know and must never touch -- it must not appear in the
        # update payload even when present on the live object.
        current = self._drifted(scanBanPaths={"/wp-admin": "banned"})

        self.assertEqual(plan_security_change(current, SECURITY_TARGET), {})


# Documentation-range address (RFC 5737) standing in for an operator-added
# allow-list entry this script doesn't manage -- never the real monitoring
# host's address in a test fixture.
UNRELATED_OPERATOR_IP = "203.0.113.9"
MONITORING_IP = ALLOWED_IPS[0][0]


class PlanAllowedIpsTests(unittest.TestCase):
    def test_empty_list_creates_the_monitoring_entry(self):
        plan = plan_allowed_ips([], ALLOWED_IPS)

        created = list(plan["create"].values())
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["address"], MONITORING_IP)

    def test_entry_already_present_creates_nothing(self):
        current = [{"id": "a1", "address": MONITORING_IP, "reason": "monitoring host"}]

        self.assertEqual(plan_allowed_ips(current, ALLOWED_IPS), {})

    def test_unrelated_operator_entry_is_not_destroyed_and_monitoring_is_still_created(self):
        # An operator may have added an allow-list entry by hand during an
        # incident -- this script manages additively and must never
        # destroy an entry it doesn't recognise.
        current = [{"id": "a1", "address": UNRELATED_OPERATOR_IP, "reason": "manual, incident"}]

        plan = plan_allowed_ips(current, ALLOWED_IPS)

        self.assertNotIn("destroy", plan)
        created = list(plan["create"].values())
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["address"], MONITORING_IP)


if __name__ == "__main__":
    unittest.main()
