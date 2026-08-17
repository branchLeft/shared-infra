#!/usr/bin/env python3
"""Unit tests for check_dnsbl_blocklist.py -- no network access, no live
server needed; every DNS lookup is a canned ResolutionOutcome or a fake
resolver function. Run with: python3 -m unittest discover -s mail/provision
-p 'test_*.py' -v
"""
from __future__ import annotations

import contextlib
import logging
import logging.handlers
import os
import socket
import struct
import tempfile
import unittest

# A documentation-range address (RFC 5737). The real host's address is public
# DNS, but a fixture that hardcodes it drifts silently the day the host moves.
TARGET = "198.51.100.7"
REVERSED_TARGET = "7.100.51.198"
from unittest import mock

from check_dnsbl_blocklist import (
    DNSBLS,
    QUERY_ERROR_PREFIX,
    RESOLVER_ADDRESS,
    RESOLVER_PORT,
    SENTINEL_LISTED_IP,
    CheckResult,
    DnsblSpec,
    ResolutionOutcome,
    Verdict,
    _configure_logging,
    _encode_name,
    _syslog_socket_reachable,
    build_alert,
    build_query,
    build_query_name,
    classify_outcome,
    evaluate_dnsbl,
    parse_response,
    resolve_a_records,
    resolve_target_address,
    resolver_socket_family,
    reverse_ipv4,
    run_checks,
)

SPEC = DnsblSpec("example", "Example List", "example.invalid", "https://example.invalid/delist")

LISTED_SENTINEL = ResolutionOutcome(ok=True, addresses=("127.0.0.2",))
NOT_LISTED = ResolutionOutcome(ok=True, addresses=())
LOOKUP_FAILED = ResolutionOutcome(ok=False, error="timed out")
QUERY_ERROR = ResolutionOutcome(ok=True, addresses=("127.255.255.254",))


class ReverseIpv4Tests(unittest.TestCase):
    def test_reverses_octets(self):
        self.assertEqual(reverse_ipv4(TARGET), REVERSED_TARGET)

    def test_rejects_non_ipv4(self):
        with self.assertRaises(ValueError):
            reverse_ipv4("not-an-ip")

    def test_rejects_ipv6(self):
        with self.assertRaises(ValueError):
            reverse_ipv4("::1")


class BuildQueryNameTests(unittest.TestCase):
    def test_builds_expected_hostname(self):
        self.assertEqual(
            build_query_name(TARGET, "zen.spamhaus.org"),
            f"{REVERSED_TARGET}.zen.spamhaus.org",
        )


class ClassifyOutcomeTests(unittest.TestCase):
    def test_lookup_failure_is_lookup_failed(self):
        self.assertEqual(classify_outcome(LOOKUP_FAILED), Verdict.LOOKUP_FAILED)

    def test_nxdomain_is_not_listed(self):
        self.assertEqual(classify_outcome(NOT_LISTED), Verdict.NOT_LISTED)

    def test_reputation_code_is_listed(self):
        outcome = ResolutionOutcome(ok=True, addresses=("127.0.0.2", "127.0.0.4"))
        self.assertEqual(classify_outcome(outcome), Verdict.LISTED)

    def test_spamhaus_query_error_code_is_not_listed_as_reputation(self):
        self.assertEqual(classify_outcome(QUERY_ERROR), Verdict.QUERY_ERROR)

    def test_mixed_error_and_real_code_still_counts_as_listed(self):
        # A defensive choice: if a zone ever returns both a genuine
        # reputation code and the error sentinel in the same answer, treat
        # it as listed rather than swallowing a real listing into "error".
        outcome = ResolutionOutcome(ok=True, addresses=("127.255.255.254", "127.0.0.2"))
        self.assertEqual(classify_outcome(outcome), Verdict.LISTED)

    def test_error_prefix_matches_documented_spamhaus_codes(self):
        self.assertTrue("127.255.255.254".startswith(QUERY_ERROR_PREFIX))
        self.assertTrue("127.255.255.255".startswith(QUERY_ERROR_PREFIX))


class EvaluateDnsblTests(unittest.TestCase):
    def test_target_listed_when_sentinel_confirms_zone_alive(self):
        result = evaluate_dnsbl(SPEC, LISTED_SENTINEL, ResolutionOutcome(ok=True, addresses=("127.0.0.2",)))
        self.assertEqual(result.verdict, Verdict.LISTED)
        self.assertEqual(result.addresses, ("127.0.0.2",))

    def test_target_not_listed_when_sentinel_confirms_zone_alive(self):
        result = evaluate_dnsbl(SPEC, LISTED_SENTINEL, NOT_LISTED)
        self.assertEqual(result.verdict, Verdict.NOT_LISTED)

    def test_dead_zone_reports_unresponsive_not_a_false_clean(self):
        # The load-bearing case this script exists to prevent: a zone with
        # no delegation at all (e.g. SORBS, confirmed live -- see RUNBOOK)
        # answers NXDOMAIN for *everything*, including the sentinel. Without
        # the self-test gate this would misreport as NOT_LISTED forever.
        result = evaluate_dnsbl(SPEC, NOT_LISTED, NOT_LISTED)
        self.assertEqual(result.verdict, Verdict.ZONE_UNRESPONSIVE)
        self.assertIn("self-test sentinel", result.detail)

    def test_sentinel_lookup_failure_also_gates_the_target(self):
        result = evaluate_dnsbl(SPEC, LOOKUP_FAILED, ResolutionOutcome(ok=True, addresses=("127.0.0.2",)))
        self.assertEqual(result.verdict, Verdict.ZONE_UNRESPONSIVE)

    def test_target_query_error_reported_distinctly_from_listed(self):
        result = evaluate_dnsbl(SPEC, LISTED_SENTINEL, QUERY_ERROR)
        self.assertEqual(result.verdict, Verdict.QUERY_ERROR)

    def test_target_lookup_failure_reported_distinctly_from_not_listed(self):
        result = evaluate_dnsbl(SPEC, LISTED_SENTINEL, LOOKUP_FAILED)
        self.assertEqual(result.verdict, Verdict.LOOKUP_FAILED)
        self.assertIn("timed out", result.detail)


class BuildAlertTests(unittest.TestCase):
    def test_all_clean_produces_no_alerts(self):
        results = [CheckResult(SPEC, Verdict.NOT_LISTED)]
        new_state, alerts = build_alert({}, results)
        self.assertEqual(alerts, [])
        self.assertEqual(new_state, {"example": "not_listed"})

    def test_first_time_listing_is_marked_new(self):
        results = [CheckResult(SPEC, Verdict.LISTED, addresses=("127.0.0.2",))]
        _, alerts = build_alert({}, results)
        self.assertEqual(len(alerts), 1)
        self.assertIn("NEW LISTING", alerts[0])
        self.assertIn(SPEC.delisting_url, alerts[0])

    def test_repeat_listing_is_marked_still_listed_not_new(self):
        results = [CheckResult(SPEC, Verdict.LISTED, addresses=("127.0.0.2",))]
        _, alerts = build_alert({"example": "listed"}, results)
        self.assertEqual(len(alerts), 1)
        self.assertIn("STILL LISTED", alerts[0])
        self.assertNotIn("NEW LISTING", alerts[0])

    def test_delisting_transition_is_not_re_alerted_as_new_next_time(self):
        # listed -> not_listed -> listed again must read as NEW, not STILL,
        # since it's a fresh event -- the state dict, not a boolean "ever
        # been listed", is what must drive the marker.
        state_after_delisting = {"example": "not_listed"}
        results = [CheckResult(SPEC, Verdict.LISTED, addresses=("127.0.0.2",))]
        _, alerts = build_alert(state_after_delisting, results)
        self.assertIn("NEW LISTING", alerts[0])

    def test_inconclusive_results_always_alert_even_though_not_listed(self):
        results = [CheckResult(SPEC, Verdict.ZONE_UNRESPONSIVE, detail="self-test sentinel failed")]
        _, alerts = build_alert({}, results)
        self.assertEqual(len(alerts), 1)
        self.assertIn("CHECK INCONCLUSIVE", alerts[0])

    def test_lookup_failed_always_alerts(self):
        results = [CheckResult(SPEC, Verdict.LOOKUP_FAILED, detail="timed out")]
        _, alerts = build_alert({}, results)
        self.assertEqual(len(alerts), 1)
        self.assertIn("CHECK INCONCLUSIVE", alerts[0])

    def test_state_persists_every_verdict_seen_this_run(self):
        results = [
            CheckResult(SPEC, Verdict.LISTED, addresses=("127.0.0.2",)),
            CheckResult(
                DnsblSpec("other", "Other", "other.invalid", "https://other.invalid"),
                Verdict.NOT_LISTED,
            ),
        ]
        new_state, _ = build_alert({}, results)
        self.assertEqual(new_state, {"example": "listed", "other": "not_listed"})


class RunChecksTests(unittest.TestCase):
    """Exercises the wiring end-to-end against a fake resolver -- catches
    the class of bug pure-unit tests of evaluate_dnsbl/build_alert alone
    would miss, like the sentinel and target queries getting swapped."""

    def test_queries_sentinel_and_target_per_zone_and_routes_results_correctly(self):
        spec = DnsblSpec("z", "Z", "zone.invalid", "https://zone.invalid/delist")
        sentinel_name = build_query_name(SENTINEL_LISTED_IP, spec.zone)
        target_name = build_query_name(TARGET, spec.zone)
        calls: list[str] = []

        def fake_resolver(hostname: str, timeout: int) -> ResolutionOutcome:
            calls.append(hostname)
            if hostname == sentinel_name:
                return ResolutionOutcome(ok=True, addresses=("127.0.0.2",))
            if hostname == target_name:
                return ResolutionOutcome(ok=True, addresses=("127.0.0.4",))
            raise AssertionError(f"unexpected query name: {hostname}")

        new_state, alerts, results = run_checks(TARGET, [spec], fake_resolver, {})

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].verdict, Verdict.LISTED)
        self.assertEqual(new_state, {"z": "listed"})
        self.assertEqual(len(alerts), 1)
        self.assertIn("NEW LISTING", alerts[0])
        # Both the sentinel and the real target were actually queried against
        # this zone, not just one of the two.
        self.assertIn(sentinel_name, calls)
        self.assertIn(target_name, calls)

    def test_clean_run_across_the_real_configured_dnsbl_set_produces_no_alerts(self):
        def fake_resolver(hostname: str, timeout: int) -> ResolutionOutcome:
            if hostname.startswith("2.0.0.127."):
                return ResolutionOutcome(ok=True, addresses=("127.0.0.2",))
            return ResolutionOutcome(ok=True, addresses=())

        new_state, alerts, results = run_checks(TARGET, DNSBLS, fake_resolver, {})

        self.assertEqual(alerts, [])
        self.assertEqual(len(results), len(DNSBLS))
        self.assertTrue(all(v == "not_listed" for v in new_state.values()))

    def test_a_zone_with_no_delegation_never_reports_false_clean(self):
        # Regression test for the SORBS finding: a zone that NXDOMAINs on
        # every query, including the sentinel, must come back
        # ZONE_UNRESPONSIVE for that entry, not folded into "all clean".
        def dead_zone_resolver(hostname: str, timeout: int) -> ResolutionOutcome:
            return ResolutionOutcome(ok=True, addresses=())

        spec = DnsblSpec("dead", "Dead List", "dead.invalid", "https://dead.invalid/delist")
        _, alerts, results = run_checks(TARGET, [spec], dead_zone_resolver, {})

        self.assertEqual(results[0].verdict, Verdict.ZONE_UNRESPONSIVE)
        self.assertEqual(len(alerts), 1)
        self.assertIn("CHECK INCONCLUSIVE", alerts[0])


class DnsblConfigTests(unittest.TestCase):
    def test_at_least_the_five_minimum_lists_are_configured(self):
        required_zones = {
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "dnsbl-1.uceprotect.net",
        }
        configured_zones = {spec.zone for spec in DNSBLS}
        self.assertTrue(required_zones.issubset(configured_zones))

    def test_every_spec_has_a_delisting_url(self):
        for spec in DNSBLS:
            self.assertTrue(spec.delisting_url.startswith("http"))


QUERY_ID = 0x1234
QUERY_ID_BYTES = b"\x12\x34"

_QUESTION_NAME_OFFSET = b"\xc0\x0c"  # compression pointer at the question name


def _response(
    hostname: str,
    *,
    query_id: int = QUERY_ID,
    rcode: int = 0,
    truncated: bool = False,
    is_response: bool = True,
    answers: tuple[str, ...] = (),
    extra_records: tuple[tuple[int, bytes], ...] = (),
    question_name: str | None = None,
) -> bytes:
    """A DNS response on the wire, assembled by hand so parse_response is
    exercised against real bytes rather than a mock of itself. Answer records
    reference the question name by compression pointer, which is what a real
    resolver emits and what the parser has to follow."""
    question = _encode_name(question_name if question_name is not None else hostname)
    flags = 0x0100
    if is_response:
        flags |= 0x8080
    if truncated:
        flags |= 0x0200
    flags |= rcode & 0x000F

    records = b""
    count = 0
    for address in answers:
        rdata = bytes(int(octet) for octet in address.split("."))
        records += _QUESTION_NAME_OFFSET + struct.pack(">HHIH", 1, 1, 300, len(rdata)) + rdata
        count += 1
    for rtype, rdata in extra_records:
        records += _QUESTION_NAME_OFFSET + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
        count += 1

    header = struct.pack(">HHHHHH", query_id, flags, 1, count, 0, 0)
    return header + question + struct.pack(">HH", 1, 1) + records


class BuildQueryTests(unittest.TestCase):
    def test_query_is_one_recursion_desired_a_question(self):
        query = build_query("2.0.0.127.zen.spamhaus.org", QUERY_ID)
        query_id, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", query[:12])
        self.assertEqual(query_id, QUERY_ID)
        self.assertEqual(flags, 0x0100)
        self.assertEqual((qdcount, ancount), (1, 0))
        self.assertEqual(query[12:], _encode_name("2.0.0.127.zen.spamhaus.org") + struct.pack(">HH", 1, 1))

    def test_labels_are_length_prefixed_and_root_terminated(self):
        self.assertEqual(_encode_name("a.bc"), b"\x01a\x02bc\x00")

    def test_an_over_long_label_is_rejected(self):
        with self.assertRaises(ValueError):
            _encode_name("x" * 64 + ".example.invalid")

    def test_an_empty_hostname_is_rejected(self):
        with self.assertRaises(ValueError):
            _encode_name(".")


class ParseResponseTests(unittest.TestCase):
    """parse_response decides "genuinely not listed" vs. "this lookup proved
    nothing", which every verdict above it trusts completely. Anything other
    than a well-formed NXDOMAIN or NOERROR answer must land on the
    proved-nothing side."""

    def test_nxdomain_is_a_confirmed_not_listed(self):
        outcome = parse_response(_response("clean.example.invalid", rcode=3), QUERY_ID, "clean.example.invalid")
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.addresses, ())

    def test_noerror_with_no_a_records_is_a_confirmed_not_listed(self):
        outcome = parse_response(_response("clean.example.invalid"), QUERY_ID, "clean.example.invalid")
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.addresses, ())

    def test_a_records_are_returned_sorted_and_deduplicated(self):
        payload = _response("listed.example.invalid", answers=("127.0.0.4", "127.0.0.2", "127.0.0.2"))
        outcome = parse_response(payload, QUERY_ID, "listed.example.invalid")
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.addresses, ("127.0.0.2", "127.0.0.4"))

    def test_records_of_other_types_are_ignored(self):
        payload = _response(
            "listed.example.invalid",
            answers=("127.0.0.2",),
            extra_records=((16, b"\x03txt"),),
        )
        outcome = parse_response(payload, QUERY_ID, "listed.example.invalid")
        self.assertEqual(outcome.addresses, ("127.0.0.2",))

    def test_servfail_is_a_lookup_failure_not_a_clean(self):
        payload = _response("flaky.example.invalid", rcode=2)
        outcome = parse_response(payload, QUERY_ID, "flaky.example.invalid")
        self.assertFalse(outcome.ok)
        self.assertIn("SERVFAIL", outcome.error)

    def test_refused_is_a_lookup_failure_not_a_clean(self):
        payload = _response("blocked.example.invalid", rcode=5)
        outcome = parse_response(payload, QUERY_ID, "blocked.example.invalid")
        self.assertFalse(outcome.ok)
        self.assertIn("REFUSED", outcome.error)

    def test_a_reply_carrying_another_query_id_is_not_trusted(self):
        payload = _response("clean.example.invalid", query_id=0x4321, rcode=3)
        outcome = parse_response(payload, QUERY_ID, "clean.example.invalid")
        self.assertFalse(outcome.ok)
        self.assertIn("does not match", outcome.error)

    def test_a_reply_answering_a_different_name_is_not_trusted(self):
        payload = _response("clean.example.invalid", rcode=3, question_name="other.example.invalid")
        outcome = parse_response(payload, QUERY_ID, "clean.example.invalid")
        self.assertFalse(outcome.ok)
        self.assertIn("different question", outcome.error)

    def test_a_query_echoed_back_without_the_response_bit_is_rejected(self):
        payload = _response("clean.example.invalid", is_response=False, rcode=3)
        outcome = parse_response(payload, QUERY_ID, "clean.example.invalid")
        self.assertFalse(outcome.ok)

    def test_a_truncated_reply_with_no_answer_is_a_lookup_failure(self):
        payload = _response("listed.example.invalid", truncated=True)
        outcome = parse_response(payload, QUERY_ID, "listed.example.invalid")
        self.assertFalse(outcome.ok)
        self.assertIn("truncated", outcome.error)

    def test_a_runt_response_is_a_lookup_failure(self):
        outcome = parse_response(b"\x12\x34", QUERY_ID, "clean.example.invalid")
        self.assertFalse(outcome.ok)

    def test_a_record_claiming_more_data_than_the_message_holds_is_a_lookup_failure(self):
        payload = _response("listed.example.invalid", answers=("127.0.0.2",))[:-2]
        outcome = parse_response(payload, QUERY_ID, "listed.example.invalid")
        self.assertFalse(outcome.ok)

    def test_a_compression_pointer_loop_is_a_lookup_failure_not_a_hang(self):
        payload = _response("clean.example.invalid", rcode=3)[:12] + b"\xc0\x0c"
        outcome = parse_response(payload, QUERY_ID, "clean.example.invalid")
        self.assertFalse(outcome.ok)


class ResolverSocketFamilyTests(unittest.TestCase):
    def test_ipv4_literal(self):
        self.assertEqual(resolver_socket_family("127.0.0.1"), socket.AF_INET)

    def test_ipv6_literal(self):
        self.assertEqual(resolver_socket_family("::1"), socket.AF_INET6)

    def test_a_hostname_is_rejected(self):
        # A hostname here would have to be resolved by the system resolver,
        # which is exactly the hop this script exists to bypass.
        with self.assertRaises(ValueError):
            resolver_socket_family("localhost")


@contextlib.contextmanager
def _mock_resolver_socket(*, recv=None, recv_side_effect=None):
    """Patches out the UDP socket and pins the query id, so resolve_a_records
    is exercised end to end (including which server it addresses) without
    touching the network."""
    fake = mock.MagicMock()
    if recv_side_effect is not None:
        fake.recv.side_effect = recv_side_effect
    else:
        fake.recv.return_value = recv
    with mock.patch("check_dnsbl_blocklist.os.urandom", return_value=QUERY_ID_BYTES):
        with mock.patch("check_dnsbl_blocklist.socket.socket") as socket_class:
            socket_class.return_value.__enter__.return_value = fake
            yield fake


class ResolveARecordsTests(unittest.TestCase):
    def test_the_local_resolver_is_addressed_explicitly_and_its_answer_returned(self):
        payload = _response("2.0.0.127.example.invalid", answers=("127.0.0.2",))
        with _mock_resolver_socket(recv=payload) as sock:
            outcome = resolve_a_records("2.0.0.127.example.invalid", 5)

        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.addresses, ("127.0.0.2",))
        sock.connect.assert_called_once_with((RESOLVER_ADDRESS, RESOLVER_PORT))
        sock.settimeout.assert_called_once_with(5)
        sent = sock.send.call_args[0][0]
        self.assertEqual(sent, build_query("2.0.0.127.example.invalid", QUERY_ID))

    def test_a_dead_resolver_is_a_lookup_failure_not_a_clean(self):
        # The case the whole local-resolver change hangs on: unbound stopped
        # or crashed must never resolve as "not listed".
        with _mock_resolver_socket(recv_side_effect=ConnectionRefusedError(111, "Connection refused")):
            outcome = resolve_a_records("clean.example.invalid", 5)
        self.assertFalse(outcome.ok)
        self.assertIn(RESOLVER_ADDRESS, outcome.error)

    def test_a_stalled_resolver_times_out_rather_than_hanging_the_cron_run(self):
        with _mock_resolver_socket(recv_side_effect=socket.timeout()):
            outcome = resolve_a_records("stalled.example.invalid", 3)
        self.assertFalse(outcome.ok)
        self.assertIn("no reply", outcome.error)

    def test_a_timeout_floor_of_one_second_is_enforced(self):
        payload = _response("clean.example.invalid", rcode=3)
        with _mock_resolver_socket(recv=payload) as sock:
            resolve_a_records("clean.example.invalid", 0)
        sock.settimeout.assert_called_once_with(1)


class ResolveTargetAddressTests(unittest.TestCase):
    """The check's whole value is that a "clean" verdict is about the address
    that actually sends mail. Every case here is one where returning an
    address anyway would produce a confident answer about the wrong host."""

    @staticmethod
    def _addrinfo(*addresses):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses]

    def test_a_single_a_record_is_the_target(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=self._addrinfo(TARGET)):
            self.assertEqual(resolve_target_address("mail.example.invalid"), TARGET)

    def test_duplicate_answers_for_one_address_still_resolve(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=self._addrinfo(TARGET, TARGET)):
            self.assertEqual(resolve_target_address("mail.example.invalid"), TARGET)

    def test_more_than_one_address_is_refused_rather_than_guessed(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=self._addrinfo(TARGET, "198.51.100.9")):
            with self.assertRaises(ValueError):
                resolve_target_address("mail.example.invalid")

    def test_no_address_is_refused(self):
        with mock.patch.object(socket, "getaddrinfo", return_value=[]):
            with self.assertRaises(ValueError):
                resolve_target_address("mail.example.invalid")

    def test_a_resolution_failure_propagates(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("no such host")):
            with self.assertRaises(socket.gaierror):
                resolve_target_address("mail.example.invalid")


class ResolverConfigTests(unittest.TestCase):
    @unittest.skipIf(
        "DNSBL_RESOLVER_ADDRESS" in os.environ or "DNSBL_RESOLVER_PORT" in os.environ,
        "resolver overridden in this environment",
    )
    def test_queries_default_to_the_on_box_recursive_resolver(self):
        self.assertEqual(RESOLVER_ADDRESS, "127.0.0.1")
        self.assertEqual(RESOLVER_PORT, 53)


class DeadResolverEndToEndTests(unittest.TestCase):
    def test_every_zone_reports_inconclusive_when_the_local_resolver_is_down(self):
        with _mock_resolver_socket(recv_side_effect=ConnectionRefusedError(111, "Connection refused")):
            _, alerts, results = run_checks(TARGET, DNSBLS, resolve_a_records, {})

        self.assertEqual(len(results), len(DNSBLS))
        self.assertTrue(all(result.verdict == Verdict.ZONE_UNRESPONSIVE for result in results))
        self.assertEqual(len(alerts), len(DNSBLS))
        self.assertTrue(all("CHECK INCONCLUSIVE" in alert for alert in alerts))


@contextlib.contextmanager
def _live_unix_dgram_socket():
    """A real, bound UNIX datagram socket -- the shape /dev/log actually
    is on a Linux host -- so _syslog_socket_reachable can be tested against
    something genuinely listening, not just a path that doesn't exist."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        sock_path = os.path.join(tmp_dir, "test-syslog.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(sock_path)
        try:
            yield sock_path
        finally:
            server.close()


class SyslogSocketReachableTests(unittest.TestCase):
    def test_a_path_with_nothing_listening_is_unreachable(self):
        self.assertFalse(_syslog_socket_reachable("/nonexistent/path/for/dnsbl-check-tests.sock"))

    def test_a_live_bound_socket_is_reachable(self):
        with _live_unix_dgram_socket() as sock_path:
            self.assertTrue(_syslog_socket_reachable(sock_path))


class ConfigureLoggingRegressionTests(unittest.TestCase):
    """Regression coverage for a real bug found and fixed during this
    script's own manual verification: logging.handlers.SysLogHandler's
    constructor doesn't reliably fail when its address isn't a live socket
    -- confirmed live that it instead connects lazily on the first emit(),
    so a bare try/except around *construction* alone can still select
    SysLogHandler even though nothing is listening, and the failure only
    surfaces later as a raw logging-internals traceback. These tests fail
    if _configure_logging ever reverts to that pattern."""

    def setUp(self):
        self._logger = logging.getLogger("dnsbl-check")
        self._original_handlers = self._logger.handlers[:]
        self._logger.handlers.clear()

    def tearDown(self):
        for handler in self._logger.handlers:
            handler.close()
        self._logger.handlers[:] = self._original_handlers

    def test_falls_back_to_a_stream_handler_when_nothing_is_listening(self):
        with mock.patch(
            "check_dnsbl_blocklist.SYSLOG_ADDRESS", "/nonexistent/path/for/dnsbl-check-tests.sock"
        ):
            logger = _configure_logging()

        self.assertEqual(len(logger.handlers), 1)
        self.assertIsInstance(logger.handlers[0], logging.StreamHandler)
        self.assertNotIsInstance(logger.handlers[0], logging.handlers.SysLogHandler)
        # The exact symptom of the bug this guards against: logging through
        # the chosen handler must never itself raise or print an
        # internals traceback.
        logger.error("regression check: must not raise")

    def test_uses_the_syslog_handler_when_a_socket_is_actually_listening(self):
        with _live_unix_dgram_socket() as sock_path:
            with mock.patch("check_dnsbl_blocklist.SYSLOG_ADDRESS", sock_path):
                logger = _configure_logging()

            self.assertEqual(len(logger.handlers), 1)
            self.assertIsInstance(logger.handlers[0], logging.handlers.SysLogHandler)
            logger.error("regression check: must not raise")


if __name__ == "__main__":
    unittest.main()
