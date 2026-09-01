#!/usr/bin/env python3
"""Unit tests for configure_stalwart.py's pure diff functions -- no network
access, no live server needed. Run with: python3 -m unittest discover -s
mail/provision -p 'test_*.py' -v
"""
import copy
import io
import unittest
from unittest import mock

import configure_stalwart as cs
from configure_stalwart import (
    ACME_DIRECTORY,
    ALLOWED_IPS,
    HTTP_ENDPOINT_POLICY,
    HTTP_USE_X_FORWARDED,
    MANAGED_LISTENERS,
    METRICS_CREATE_DEFAULTS,
    METRICS_PATH,
    METRICS_SCRAPE_SOURCES,
    METRICS_SECRET_VARIABLE,
    METRICS_TARGET,
    SECURITY_TARGET,
    plan_acme_provider,
    plan_allowed_ips,
    plan_domain_sans,
    plan_http_change,
    plan_listener_changes,
    plan_metrics_change,
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
    def test_unmaterialized_singleton_is_created_with_the_endpoint_policy(self):
        plan = plan_http_change([])

        self.assertEqual(
            plan["create"]["singleton"]["allowedEndpoints"], HTTP_ENDPOINT_POLICY
        )

    def test_wrong_rule_is_corrected(self):
        current = [{"id": "singleton", "allowedEndpoints": {"match": {}, "else": "200"}}]

        plan = plan_http_change(current)

        self.assertEqual(
            plan["update"]["singleton"]["allowedEndpoints"], HTTP_ENDPOINT_POLICY
        )

    def test_correct_rule_is_a_no_op(self):
        current = [
            {
                "id": "singleton",
                "allowedEndpoints": HTTP_ENDPOINT_POLICY,
                "useXForwarded": HTTP_USE_X_FORWARDED,
            }
        ]

        self.assertEqual(plan_http_change(current), {})

    def test_trusted_forwarded_headers_are_turned_back_off(self):
        current = [
            {
                "id": "singleton",
                "allowedEndpoints": HTTP_ENDPOINT_POLICY,
                "useXForwarded": True,
            }
        ]

        plan = plan_http_change(current)

        self.assertEqual(plan["update"]["singleton"], {"useXForwarded": False})


class HttpEndpointPolicyShapeTests(unittest.TestCase):
    """The rule's *shape* is the security control, so it is asserted directly
    rather than only through the diff functions -- a policy that still equals
    itself is a no-op whatever it happens to say.
    """

    def test_the_blanket_deny_is_evaluated_last(self):
        # First match wins, so a 421 ahead of the metrics allowances would
        # swallow the scrape path and the endpoint would never be reachable.
        rules = HTTP_ENDPOINT_POLICY["match"]
        numeric_keys = sorted(rules, key=int)
        deny_key = numeric_keys[-1]

        self.assertEqual(rules[deny_key], {"if": "listener == 'https'", "then": "421"})
        for key in numeric_keys[:-1]:
            self.assertEqual(rules[key]["then"], "200")

    def test_key_ordering_is_unambiguous_however_the_evaluator_sorts(self):
        # This test file sorts by int; Stalwart's evaluator may sort the keys
        # as strings, where "10" precedes "2". Below ten rules the two orders
        # agree and the assertion above means what it says. At ten or more it
        # silently stops meaning it -- so the count is what is guarded, since
        # nothing here can see how the live evaluator sorts.
        self.assertLess(len(HTTP_ENDPOINT_POLICY["match"]), 10)

    def test_webadmin_on_443_is_still_refused(self):
        # The whole reason this rule exists (mx1-provision's "The ACME
        # decision"): the listener stays `http` so ACME works, and the
        # webadmin is kept off 443 by this rule rather than by protocol.
        denies = [
            rule
            for rule in HTTP_ENDPOINT_POLICY["match"].values()
            if rule["then"] == "421"
        ]

        self.assertEqual(len(denies), 1)
        self.assertEqual(denies[0]["if"], "listener == 'https'")

    def test_every_allowance_is_pinned_to_one_path_and_one_source(self):
        allowances = [
            rule
            for rule in HTTP_ENDPOINT_POLICY["match"].values()
            if rule["then"] == "200"
        ]

        self.assertEqual(len(allowances), len(METRICS_SCRAPE_SOURCES))
        for rule, source in zip(
            sorted(allowances, key=lambda r: r["if"]),
            sorted(METRICS_SCRAPE_SOURCES),
        ):
            self.assertIn(f"path == '{METRICS_PATH}'", rule["if"])
            self.assertIn(f"remote_ip == '{source}'", rule["if"])
            self.assertIn("listener == 'https'", rule["if"])

    def test_no_allowance_uses_an_unverified_or_operator(self):
        # `&&` appears in Stalwart's own expression examples; `||` does not.
        # One rule per source address avoids betting a live access-control
        # rule on an operator nobody has seen it parse.
        for rule in HTTP_ENDPOINT_POLICY["match"].values():
            self.assertNotIn("||", rule["if"])

    def test_the_default_is_not_widened(self):
        self.assertEqual(HTTP_ENDPOINT_POLICY["else"], "200")

    def test_no_ipv6_source_is_allowed(self):
        # Measured against the live server: the same host, credential and
        # path returns 200 over IPv4 and 421 over IPv6, so `remote_ip` does
        # not equal the compressed literal this file would spell. A rule
        # written against a guess at the real form never fires while reading
        # as coverage, so v6 is not allowed at all and the scrape is pinned
        # to v4 to match.
        for source in METRICS_SCRAPE_SOURCES:
            self.assertNotIn(":", source)

    def test_forwarded_headers_are_never_trusted(self):
        # The allowances match on `remote_ip`. With useXForwarded on and no
        # trusted-proxy allowlist, `X-Forwarded-For: 46.225.95.167` makes any
        # client match the pin -- the bypass RUNBOOK-mx1-provision.md records
        # for the webadmin rule, applied to this one.
        self.assertIs(HTTP_USE_X_FORWARDED, False)


class PlanMetricsChangeTests(unittest.TestCase):
    def test_unmaterialized_singleton_is_created_with_the_exporter_enabled(self):
        plan = plan_metrics_change([])
        created = plan["create"]["singleton"]

        self.assertEqual(created["prometheus"], METRICS_TARGET["prometheus"])

    def test_the_create_payload_carries_every_required_field(self):
        # `openTelemetry` is required by the object. Omitting it makes the
        # create a `notCreated` rejection rather than an error, which without
        # the guard in _jmap_call would have printed success.
        created = plan_metrics_change([])["create"]["singleton"]

        for field in METRICS_CREATE_DEFAULTS:
            self.assertIn(field, created)

    def test_a_redacted_secret_on_read_does_not_cause_a_rewrite(self):
        # If Stalwart redacts the credential on GET, a target compared
        # field-by-field can never equal it, so every run would rewrite the
        # singleton and restart stalwart -- bouncing production mail on a
        # sequence documented as safe to re-run.
        current = [
            {
                "id": "singleton",
                "prometheus": {
                    "@type": "Enabled",
                    "authUsername": "prometheus",
                    "authSecret": {"@type": "EnvironmentVariable"},
                },
            }
        ]

        self.assertEqual(plan_metrics_change(current), {})

    def test_an_unauthenticated_exporter_is_corrected(self):
        # Enabled, our username, but the secret explicitly None -- the one
        # authSecret state that is unambiguously wrong, because it serves the
        # endpoint open.
        current = [
            {
                "id": "singleton",
                "prometheus": {
                    "@type": "Enabled",
                    "authUsername": "prometheus",
                    "authSecret": {"@type": "None"},
                },
            }
        ]

        plan = plan_metrics_change(current)

        self.assertEqual(plan["update"]["singleton"]["prometheus"], METRICS_TARGET["prometheus"])

    def test_disabled_exporter_is_enabled(self):
        current = [{"id": "singleton", "prometheus": {"@type": "Disabled"}}]

        plan = plan_metrics_change(current)

        self.assertEqual(plan["update"]["singleton"]["prometheus"], METRICS_TARGET["prometheus"])

    def test_correct_state_is_a_no_op(self):
        current = [{"id": "singleton", **copy.deepcopy(METRICS_TARGET)}]

        self.assertEqual(plan_metrics_change(current), {})

    def test_a_different_username_is_corrected(self):
        current = [
            {
                "id": "singleton",
                "prometheus": {
                    "@type": "Enabled",
                    "authUsername": "someone-else",
                    "authSecret": {"@type": "EnvironmentVariable"},
                },
            }
        ]

        self.assertIn("update", plan_metrics_change(current))

    def test_unmanaged_fields_are_left_alone(self):
        # `openTelemetry` is a required field of the object but not one this
        # platform manages -- naming it in the target would mean this script
        # fighting whatever it is set to on every run.
        current = [
            {
                "id": "singleton",
                "openTelemetry": {"@type": "Grpc", "endpoint": "https://example.invalid"},
                "metricsPolicy": "include",
                **copy.deepcopy(METRICS_TARGET),
            }
        ]

        self.assertEqual(plan_metrics_change(current), {})


class MetricsTargetShapeTests(unittest.TestCase):
    def test_authentication_is_never_left_unset(self):
        # Both credential fields are optional in Stalwart's schema, and with
        # both unset the endpoint is served unauthenticated -- on a listener
        # bound to [::]:443 that publishes queue depth and delivery outcomes
        # to the internet.
        prometheus = METRICS_TARGET["prometheus"]

        self.assertEqual(prometheus["@type"], "Enabled")
        self.assertTrue(prometheus["authUsername"])
        self.assertNotEqual(prometheus["authSecret"]["@type"], "None")

    def test_the_secret_is_read_from_the_environment_not_embedded(self):
        # A `Value` secret would put the plaintext into this repo, the API
        # call and the settings store at once.
        auth_secret = METRICS_TARGET["prometheus"]["authSecret"]

        self.assertEqual(auth_secret["@type"], "EnvironmentVariable")
        self.assertEqual(auth_secret["variableName"], METRICS_SECRET_VARIABLE)

    def test_the_value_variants_secret_field_is_absent(self):
        # `{"@type": "Value", "secret": "..."}` is the one shape that would
        # commit a plaintext credential to this repo. Asserted structurally
        # rather than by scanning the serialised target for the word, which
        # matches `authSecret` and `STALWART_PROMETHEUS_SECRET` and so would
        # pass or fail for reasons unrelated to the thing under test.
        auth_secret = METRICS_TARGET["prometheus"]["authSecret"]

        self.assertNotIn("secret", auth_secret)
        self.assertNotIn("filePath", auth_secret)


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

    def test_target_never_asserts_an_unverified_ban_rate(self):
        # authBanRate/abuseBanRate/loiterBanRate were removed because their
        # shipped defaults can't be verified against the pinned schema --
        # this pins the target to exactly the verifiable, scalar-or-None
        # fields so a future edit can't quietly reintroduce one.
        self.assertEqual(
            set(SECURITY_TARGET),
            {
                "scanBanRate",
                "scanBanPeriod",
                "authBanPeriod",
                "abuseBanPeriod",
                "loiterBanPeriod",
            },
        )
        for field, value in SECURITY_TARGET.items():
            self.assertNotIsInstance(value, dict, f"{field} must be a scalar or None")


class ReconcileSecurityTests(unittest.TestCase):
    """_reconcile_security's literal JMAP method strings and call shape,
    against a fake _jmap_call (unittest.mock, no live server) -- sabotage
    proved these had zero coverage (renaming "x:Security/set" left the
    whole suite green), and separately proved the FIX-2 empty-list guard
    fires before any set call reaches the live server.
    """

    AUTH = ("admin", "admin-secret-not-real")

    def setUp(self):
        patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_and_set_use_the_exact_jmap_methods_and_args_when_drifted(self):
        calls = []
        current = {"id": "singleton", **SECURITY_TARGET, "authBanPeriod": None}

        def fake_jmap_call(auth, method, args):
            calls.append((method, args))
            if method == "x:Security/get":
                return {"list": [current]}
            if method == "x:Security/set":
                return {"updated": {"singleton": {}}}
            raise AssertionError(f"unexpected method: {method}")

        with mock.patch.object(cs, "_jmap_call", side_effect=fake_jmap_call):
            changed = cs._reconcile_security(self.AUTH)

        self.assertTrue(changed)
        self.assertEqual(calls[0], ("x:Security/get", {"ids": ["singleton"]}))
        self.assertEqual(
            calls[1],
            ("x:Security/set", {"update": {"singleton": {"authBanPeriod": cs._DAY_MS}}}),
        )

    def test_reconciled_state_makes_no_set_call(self):
        calls = []
        current = {"id": "singleton", **SECURITY_TARGET}

        def fake_jmap_call(auth, method, args):
            calls.append((method, args))
            if method == "x:Security/get":
                return {"list": [current]}
            raise AssertionError(f"unexpected method: {method}")

        with mock.patch.object(cs, "_jmap_call", side_effect=fake_jmap_call):
            changed = cs._reconcile_security(self.AUTH)

        self.assertFalse(changed)
        self.assertEqual(calls, [("x:Security/get", {"ids": ["singleton"]})])

    def test_empty_list_raises_before_any_set_call(self):
        calls = []

        def fake_jmap_call(auth, method, args):
            calls.append((method, args))
            return {"list": []}

        with mock.patch.object(cs, "_jmap_call", side_effect=fake_jmap_call):
            with self.assertRaises(RuntimeError):
                cs._reconcile_security(self.AUTH)

        self.assertEqual(calls, [("x:Security/get", {"ids": ["singleton"]})])


class ReconcileAllowedIpsTests(unittest.TestCase):
    """_reconcile_allowed_ips's literal JMAP method strings and call shape,
    against a fake _jmap_call -- same sabotage-proved gap as
    ReconcileSecurityTests, for "x:AllowedIp/get".
    """

    AUTH = ("admin", "admin-secret-not-real")
    MONITORING_IP = ALLOWED_IPS[0][0]

    def setUp(self):
        patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_and_set_use_the_exact_jmap_methods_and_args_when_missing(self):
        calls = []

        def fake_jmap_call(auth, method, args):
            calls.append((method, args))
            if method == "x:AllowedIp/get":
                return {"list": []}
            if method == "x:AllowedIp/set":
                return {"created": {}}
            raise AssertionError(f"unexpected method: {method}")

        with mock.patch.object(cs, "_jmap_call", side_effect=fake_jmap_call):
            changed = cs._reconcile_allowed_ips(self.AUTH)

        self.assertTrue(changed)
        self.assertEqual(calls[0], ("x:AllowedIp/get", {}))
        set_method, set_args = calls[1]
        self.assertEqual(set_method, "x:AllowedIp/set")
        created = list(set_args["create"].values())
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["address"], self.MONITORING_IP)

    def test_entry_already_present_makes_no_set_call(self):
        calls = []
        current = [{"id": "a1", "address": self.MONITORING_IP, "reason": "monitoring host"}]

        def fake_jmap_call(auth, method, args):
            calls.append((method, args))
            if method == "x:AllowedIp/get":
                return {"list": current}
            raise AssertionError(f"unexpected method: {method}")

        with mock.patch.object(cs, "_jmap_call", side_effect=fake_jmap_call):
            changed = cs._reconcile_allowed_ips(self.AUTH)

        self.assertFalse(changed)
        self.assertEqual(calls, [("x:AllowedIp/get", {})])


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
