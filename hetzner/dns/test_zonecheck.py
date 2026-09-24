"""Tests for zonecheck.py, against simulated authoritative servers.

The simulation speaks dig's own output format, so the parser under test is
the one that reads real servers; `hetzner/dns/RUNBOOK-dns-cutover.md` records
the same checks run against live ones.
"""

from __future__ import annotations

import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import zonecheck  # noqa: E402

ZONE = "example.test"

IONOS_NS = ["ns1.registrar.example.", "ns2.registrar.example."]
HETZNER_NS = ["hydrogen.ns.hetzner.com.", "oxygen.ns.hetzner.com."]

BASE_RECORDS = {
    ("@", "A"): (3600, ["192.0.2.10"]),
    ("@", "MX"): (3600, ["10 mx1.example.test."]),
    ("@", "TXT"): (3600, ['"v=spf1 ip4:192.0.2.25 ~all"', '"site-verification=abc"']),
    ("_dmarc", "TXT"): (3600, ['"v=DMARC1; p=none"']),
    ("sel._domainkey", "TXT"): (3600, ['"v=DKIM1; k=rsa; p=AAAA" "BBBB"']),
    ("mx1", "A"): (3600, ["192.0.2.25"]),
    ("mx1", "AAAA"): (3600, ["2001:db8::25"]),
    ("www", "CNAME"): (3600, ["example.test."]),
}
PROBES = ["@", "_dmarc", "sel._domainkey", "_domainkey", "mx1", "www", "absent"]


def write_zone(directory: pathlib.Path, records=None, probes=None) -> pathlib.Path:
    records = BASE_RECORDS if records is None else records
    data = {
        "$comment": ["kept across a capture"],
        "zone": ZONE,
        "rrsets": [
            {"name": n, "type": t, "ttl": ttl, "values": values}
            for (n, t), (ttl, values) in records.items()
        ],
        "probe_names": PROBES if probes is None else probes,
    }
    path = directory / "zone.json"
    path.write_text(json.dumps(data))
    return path


def relative(owner: str, zone: str) -> str:
    owner = owner.rstrip(".").lower()
    zone = zone.rstrip(".").lower()
    if owner == zone:
        return "@"
    suffix = "." + zone
    if not owner.endswith(suffix):
        raise ValueError(f"{owner} is not inside {zone}")
    return owner[: -len(suffix)]


class FakeServer:
    """One authoritative server's view: records by (relative name, type)."""

    def __init__(self, records, ns, aa=True, rcode_override=None):
        self.records = {k: (ttl, list(v)) for k, (ttl, v) in records.items()}
        self.records[("@", "NS")] = (86400, ns)
        self.aa = aa
        self.rcode_override = rcode_override

    def answer(self, name: str, rtype: str) -> str:
        rel = relative(name, ZONE)
        exists = any(
            owner == rel or (rel != "@" and owner.endswith("." + rel)) or rel == "@"
            for owner, _ in self.records
        )
        rcode = self.rcode_override or ("NOERROR" if exists else "NXDOMAIN")
        flags = "qr aa" if self.aa else "qr"
        lines = [
            f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 1",
            f";; flags: {flags}; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1",
            "",
        ]
        # Old dig prints the generic mnemonic for types it does not know.
        printed = {"HTTPS": "TYPE65", "SVCB": "TYPE64"}.get(rtype, rtype)
        if (rel, "CNAME") in self.records and rtype != "CNAME":
            ttl, values = self.records[(rel, "CNAME")]
            lines += [f"{name}\t{ttl}\tIN\tCNAME\t{v}" for v in values]
        ttl, values = self.records.get((rel, rtype), (0, []))
        lines += [f"{name}\t{ttl}\tIN\t{printed}\t{v}" for v in values]
        return "\n".join(lines) + "\n"


def runner(servers: dict[str, FakeServer]):
    calls = []

    def run(argv):
        calls.append(argv)
        server = argv[argv.index("-p") + 2][1:]
        port = argv[argv.index("-p") + 1]
        key = server if port == "53" else f"{server}:{port}"
        name, token = argv[-2], argv[-1]
        rtype = {"TYPE65": "HTTPS", "TYPE64": "SVCB"}.get(token, token)
        if key not in servers:
            return subprocess.CompletedProcess(argv, 9, ";; connection timed out; no servers could be reached\n", "")
        return subprocess.CompletedProcess(argv, 0, servers[key].answer(name, rtype), "")

    run.calls = calls
    return run


def two_providers(right_records=None, right_ns=None, **right_kwargs):
    return {
        "ns1.registrar.example": FakeServer(BASE_RECORDS, IONOS_NS),
        "ns2.registrar.example": FakeServer(BASE_RECORDS, IONOS_NS),
        "hydrogen.ns.hetzner.com": FakeServer(
            BASE_RECORDS if right_records is None else right_records,
            HETZNER_NS if right_ns is None else right_ns,
            **right_kwargs,
        ),
    }


LEFT = ["ns1.registrar.example", "ns2.registrar.example"]
RIGHT = ["hydrogen.ns.hetzner.com"]


class ParseDigTest(unittest.TestCase):
    def test_reads_status_flags_and_matching_records_only(self):
        output = (
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7\n"
            ";; flags: qr aa; QUERY: 1, ANSWER: 2\n"
            "www.example.test.\t300\tIN\tCNAME\tExample.Test.\n"
            "example.test.\t300\tIN\tA\t192.0.2.10\n"
        )
        rcode, flags, records = zonecheck.parse_dig(output, "www.example.test.", "CNAME")
        self.assertEqual(rcode, "NOERROR")
        self.assertEqual(flags, {"qr", "aa"})
        self.assertEqual(records, {(300, "example.test.")})

    def test_accepts_generic_type_spelling_from_old_dig(self):
        output = (
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7\n"
            ";; flags: qr aa;\n"
            "example.test.\t300\tIN\tTYPE65\t\\# 3 000100\n"
        )
        _, _, records = zonecheck.parse_dig(output, "example.test.", "HTTPS")
        self.assertEqual(records, {(300, "\\# 3 000100")})

    def test_no_header_is_an_error_not_an_empty_answer(self):
        with self.assertRaises(zonecheck.QueryError) as caught:
            zonecheck.parse_dig(";; connection timed out; no servers could be reached\n", "a.", "A")
        self.assertIn("timed out", str(caught.exception))
        with self.assertRaises(zonecheck.QueryError):
            zonecheck.parse_dig("", "a.", "A")


class NormaliseTest(unittest.TestCase):
    def test_names_are_lowercased_and_absolute(self):
        self.assertEqual(zonecheck.normalise_rdata("MX", "10 MX1.Example.Test"), "10 mx1.example.test.")
        self.assertEqual(zonecheck.normalise_rdata("SRV", "0 5 443 Host.Example.Test."), "0 5 443 host.example.test.")
        self.assertEqual(zonecheck.normalise_rdata("CNAME", "A.B."), "a.b.")

    def test_addresses_have_one_spelling(self):
        self.assertEqual(zonecheck.normalise_rdata("AAAA", "2001:0db8:0000::0025"), "2001:db8::25")
        self.assertEqual(zonecheck.normalise_rdata("A", " 192.0.2.1 "), "192.0.2.1")

    def test_caa_tag_is_case_insensitive_but_value_is_not(self):
        self.assertEqual(zonecheck.normalise_rdata("CAA", '0 ISSUE "LetsEncrypt.org"'), '0 issue "LetsEncrypt.org"')

    def test_txt_keeps_its_string_boundaries(self):
        self.assertNotEqual(
            zonecheck.normalise_rdata("TXT", '"ab" "cd"'), zonecheck.normalise_rdata("TXT", '"abcd"')
        )


class QueryTest(unittest.TestCase):
    def test_non_authoritative_answer_is_refused(self):
        run = runner({"hydrogen.ns.hetzner.com": FakeServer(BASE_RECORDS, HETZNER_NS, aa=False)})
        with self.assertRaises(zonecheck.QueryError) as caught:
            zonecheck.query("hydrogen.ns.hetzner.com", "example.test.", "A", run)
        self.assertIn("not authoritative", str(caught.exception))

    def test_refused_is_an_error(self):
        run = runner({"hydrogen.ns.hetzner.com": FakeServer(BASE_RECORDS, HETZNER_NS, rcode_override="REFUSED")})
        with self.assertRaises(zonecheck.QueryError) as caught:
            zonecheck.query("hydrogen.ns.hetzner.com", "example.test.", "A", run)
        self.assertIn("REFUSED", str(caught.exception))

    def test_unreachable_server_is_an_error(self):
        with self.assertRaises(zonecheck.QueryError):
            zonecheck.query("nowhere.example", "example.test.", "A", runner({}))

    def test_port_and_generic_type_reach_dig(self):
        run = runner({"127.0.0.1:5301": FakeServer(BASE_RECORDS, HETZNER_NS)})
        answer = zonecheck.query("127.0.0.1:5301", "example.test.", "SVCB", run)
        self.assertEqual(answer.records, frozenset())
        argv = run.calls[0]
        self.assertEqual(argv[argv.index("-p") + 1], "5301")
        self.assertEqual(argv[-1], "TYPE64")
        self.assertIn("+norec", argv)

    def test_split_server(self):
        self.assertEqual(zonecheck.split_server("ns.example:5300"), ("ns.example", 5300))
        self.assertEqual(zonecheck.split_server("ns.example"), ("ns.example", 53))
        self.assertEqual(zonecheck.split_server("2001:db8::1"), ("2001:db8::1", 53))


class ZoneFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())

    def test_expected_rcode_covers_empty_non_terminals(self):
        zone = zonecheck.load_zone(write_zone(self.tmp))
        self.assertEqual(zone.expected_rcode("_domainkey"), "NOERROR")
        self.assertEqual(zone.expected_rcode("absent"), "NXDOMAIN")
        self.assertEqual(zone.expected_rcode("@"), "NOERROR")
        self.assertEqual(zone.expected_rcode("mx1"), "NOERROR")

    def test_duplicate_rrset_is_rejected(self):
        path = write_zone(self.tmp)
        data = json.loads(path.read_text())
        data["rrsets"].append(data["rrsets"][0])
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "twice"):
            zonecheck.load_zone(path)

    def test_provider_owned_rrset_is_rejected(self):
        records = dict(BASE_RECORDS)
        records[("@", "NS")] = (86400, ["ns1.registrar.example."])
        with self.assertRaisesRegex(ValueError, "serving provider"):
            zonecheck.load_zone(write_zone(self.tmp, records))

    def test_json_round_trip_keeps_comment_and_records(self):
        zone = zonecheck.load_zone(write_zone(self.tmp))
        again = self.tmp / "again.json"
        again.write_text(zonecheck.zone_to_json(zone))
        reloaded = zonecheck.load_zone(again)
        self.assertEqual(reloaded.rrsets, zone.rrsets)
        self.assertEqual(json.loads(again.read_text())["$comment"], ["kept across a capture"])

    def test_fqdn(self):
        self.assertEqual(zonecheck.fqdn("@", "Example.Test."), "example.test.")
        self.assertEqual(zonecheck.fqdn("WWW", "example.test"), "www.example.test.")


class CaptureTest(unittest.TestCase):
    def test_capture_reads_every_probed_record(self):
        run = runner(two_providers())
        zone = zonecheck.capture(ZONE, "ns1.registrar.example", PROBES, run)
        expected = {
            k: (ttl, frozenset(zonecheck.normalise_rdata(k[1], v) for v in values))
            for k, (ttl, values) in BASE_RECORDS.items()
        }
        self.assertEqual(zone.rrsets, expected)
        self.assertNotIn(("@", "NS"), zone.rrsets)

    def test_mixed_ttls_are_refused(self):
        server = FakeServer(BASE_RECORDS, IONOS_NS)
        original = server.answer

        def answer(name, rtype):
            text = original(name, rtype)
            if rtype == "TXT" and name == "example.test.":
                text = text.replace("3600\tIN\tTXT\t\"site", "60\tIN\tTXT\t\"site")
            return text

        server.answer = answer
        with self.assertRaisesRegex(ValueError, "mixed TTLs"):
            zonecheck.capture(ZONE, "ns1", ["@"], runner({"ns1": server}))


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.zone = zonecheck.load_zone(write_zone(pathlib.Path(tempfile.mkdtemp())))

    def test_identical_providers_report_nothing_and_both_controls_pass(self):
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers()))
        self.assertEqual(report.diffs, [])
        self.assertEqual(report.control_failures, [])

    def test_an_altered_record_is_caught(self):
        records = dict(BASE_RECORDS)
        records[("@", "MX")] = (3600, ["10 mx2.example.test."])
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers(records)))
        self.assertEqual(
            [(d.server, d.name, d.rtype, d.got) for d in report.diffs],
            [("hydrogen.ns.hetzner.com", "@", "MX", "10 mx2.example.test.")],
        )

    def test_one_value_missing_from_a_multi_value_rrset_is_caught(self):
        records = dict(BASE_RECORDS)
        records[("@", "TXT")] = (3600, ['"v=spf1 ip4:192.0.2.25 ~all"'])
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers(records)))
        self.assertEqual([(d.name, d.rtype) for d in report.diffs], [("@", "TXT")])

    def test_a_resplit_txt_record_is_caught(self):
        records = dict(BASE_RECORDS)
        records[("sel._domainkey", "TXT")] = (3600, ['"v=DKIM1; k=rsa; p=AAAABBBB"'])
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers(records)))
        self.assertEqual([(d.name, d.rtype) for d in report.diffs], [("sel._domainkey", "TXT")])

    def test_a_missing_name_is_caught_as_rcode_and_record(self):
        records = {k: v for k, v in BASE_RECORDS.items() if k[0] != "_dmarc"}
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers(records)))
        self.assertEqual(
            sorted((d.name, d.rtype) for d in report.diffs), [("_dmarc", "TXT"), ("_dmarc", "rcode")]
        )

    def test_an_extra_record_at_a_probed_name_is_caught(self):
        records = dict(BASE_RECORDS)
        records[("absent", "A")] = (3600, ["192.0.2.99"])
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers(records)))
        self.assertEqual(sorted((d.name, d.rtype) for d in report.diffs), [("absent", "A"), ("absent", "rcode")])

    def test_the_left_side_is_checked_against_the_file_too(self):
        servers = two_providers()
        records = dict(BASE_RECORDS)
        records[("mx1", "A")] = (3600, ["192.0.2.26"])
        servers["ns2.registrar.example"] = FakeServer(records, IONOS_NS)
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(servers))
        self.assertEqual([(d.server, d.name) for d in report.diffs], [("ns2.registrar.example", "mx1")])

    def test_ttl_is_only_reported_when_asked(self):
        records = dict(BASE_RECORDS)
        records[("www", "CNAME")] = (300, ["example.test."])
        run = runner(two_providers(records))
        self.assertEqual(zonecheck.compare(self.zone, LEFT, RIGHT, run).diffs, [])
        report = zonecheck.compare(self.zone, LEFT, RIGHT, run, check_ttl=True)
        self.assertEqual([(d.name, d.rtype, d.got) for d in report.diffs], [("www", "CNAME ttl", "300")])

    def test_two_sides_serving_the_same_ns_set_fail_the_control(self):
        report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers(right_ns=IONOS_NS)))
        self.assertEqual(len(report.control_failures), 2)
        self.assertIn("not two different providers", report.control_failures[0])

    def test_a_diff_that_cannot_see_the_altered_record_fails_the_control(self):
        with mock.patch.object(zonecheck, "diff_server", return_value=[]):
            report = zonecheck.compare(self.zone, LEFT, RIGHT, runner(two_providers()))
        self.assertEqual(len(report.control_failures), 3)
        self.assertIn("deliberately altered @ A", report.control_failures[0])


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.zone_file = write_zone(self.tmp)

    def run_main(self, argv, servers):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = zonecheck.main(argv, runner(servers))
        return code, out.getvalue(), err.getvalue()

    def compare_args(self):
        return ["compare", "--zone-file", str(self.zone_file), "--left", ",".join(LEFT), "--right", ",".join(RIGHT)]

    def test_clean_compare_exits_zero_and_says_the_controls_ran(self):
        code, out, _ = self.run_main(self.compare_args(), two_providers())
        self.assertEqual(code, 0)
        self.assertIn("both controls caught", out)

    def test_differences_exit_one(self):
        records = dict(BASE_RECORDS)
        records[("@", "A")] = (3600, ["192.0.2.11"])
        code, out, _ = self.run_main(self.compare_args(), two_providers(records))
        self.assertEqual(code, 1)
        self.assertIn("DIFF hydrogen.ns.hetzner.com  @ A", out)

    def test_a_server_not_serving_the_zone_exits_two(self):
        code, _, err = self.run_main(self.compare_args(), two_providers(aa=False))
        self.assertEqual(code, 2)
        self.assertIn("not authoritative", err)

    def test_a_failed_control_exits_three_even_with_no_diffs(self):
        code, out, err = self.run_main(self.compare_args(), two_providers(right_ns=IONOS_NS))
        self.assertEqual(code, 3)
        self.assertIn("CONTROL FAILED", err)
        self.assertNotIn("no differences", out)

    def test_capture_writes_a_loadable_zone(self):
        out_file = self.tmp / "captured.json"
        code, out, _ = self.run_main(
            ["capture", "--zone-file", str(self.zone_file), "--server", LEFT[0], "--out", str(out_file)],
            two_providers(),
        )
        self.assertEqual(code, 0)
        self.assertIn("captured 8 rrsets", out)
        self.assertEqual(zonecheck.load_zone(out_file).rrsets, zonecheck.load_zone(self.zone_file).rrsets)

    def test_empty_server_list_is_a_usage_error(self):
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            zonecheck.main(["compare", "--left", ",", "--right", "x"], runner({}))


class CheckedInZoneTest(unittest.TestCase):
    """The real zone file: mail must survive the move, so its records are pinned."""

    def setUp(self):
        self.zone = zonecheck.load_zone(zonecheck.DEFAULT_ZONE_FILE)

    def test_mail_records_are_present(self):
        rrsets = self.zone.rrsets
        self.assertEqual(rrsets[("@", "MX")][1], frozenset({"10 mx1.branchleft.co.uk."}))
        self.assertTrue(any(v.startswith('"v=spf1 ') for v in rrsets[("@", "TXT")][1]))
        self.assertTrue(any(v.startswith('"v=DMARC1;') for v in rrsets[("_dmarc", "TXT")][1]))
        self.assertIn(("mx1", "A"), rrsets)
        self.assertIn(("mx1", "AAAA"), rrsets)
        # mx1's own signing keys. Missed by the first capture, whose probe list
        # did not know their names -- the reason the runbook counts records
        # against the registrar's listing as well.
        for selector in ("v1-ed25519-20260811._domainkey", "v1-rsa-20260811._domainkey"):
            self.assertTrue(any(v.startswith('"v=DKIM1;') for v in rrsets[(selector, "TXT")][1]))

    def test_every_record_name_is_probed(self):
        self.assertTrue({name for name, _ in self.zone.rrsets} <= set(self.zone.probe_names))

    def test_probes_include_a_name_that_must_not_exist(self):
        absent = [n for n in self.zone.probe_names if self.zone.expected_rcode(n) == "NXDOMAIN"]
        self.assertIn("zz-no-such-name-4f1c", absent)


if __name__ == "__main__":
    unittest.main()
