"""Tests for zonecheck.py, against simulated authoritative servers.

The simulation speaks dig's own output format, so the parser under test is
the one that reads real servers; `hetzner/dns/RUNBOOK-dns-cutover.md` records
the same checks run against live ones.
"""

from __future__ import annotations

import io
import json
import pathlib
import re
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
        self.records[("@", "SOA")] = (86400, [f"{ns[0]} hostmaster.example.test. 2017060113 28800 7200 604800 600"])
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


class DigTimingsTest(unittest.TestCase):
    def test_defaults_are_unchanged(self):
        run = runner(two_providers())
        zonecheck.query("ns1.registrar.example", "example.test.", "A", run)
        self.assertIn("+time=3", run.calls[0])
        self.assertIn("+tries=2", run.calls[0])

    def test_flags_reach_every_dig_in_a_compare(self):
        run = runner(two_providers())
        out, err = io.StringIO(), io.StringIO()
        zone_file = write_zone(pathlib.Path(tempfile.mkdtemp()))
        argv = [
            "compare", "--zone-file", str(zone_file), "--left", ",".join(LEFT), "--right", ",".join(RIGHT),
            "--dig-time", "7", "--dig-tries", "5",
        ]
        with redirect_stdout(out), redirect_stderr(err):
            code = zonecheck.main(argv, run)
        self.assertEqual(code, 0)
        self.assertTrue(run.calls)
        for call in run.calls:
            self.assertIn("+time=7", call)
            self.assertIn("+tries=5", call)
            self.assertNotIn("+time=3", call)

    def test_flags_reach_every_dig_in_a_capture(self):
        run = runner(two_providers())
        tmp = pathlib.Path(tempfile.mkdtemp())
        zone_file = write_zone(tmp)
        with redirect_stdout(io.StringIO()):
            code = zonecheck.main(
                ["capture", "--zone-file", str(zone_file), "--server", LEFT[0], "--out", str(tmp / "o.json"),
                 "--dig-time", "9", "--dig-tries", "4"],
                run,
            )
        self.assertEqual(code, 0)
        for call in run.calls:
            self.assertIn("+time=9", call)
            self.assertIn("+tries=4", call)


class TranscriptTest(unittest.TestCase):
    """capture --transcript, and check-capture over what it wrote."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.zone_file = write_zone(self.tmp)
        self.transcript = self.tmp / "dig.txt"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = zonecheck.main(
                ["capture", "--zone-file", str(self.zone_file), "--server", LEFT[0],
                 "--out", str(self.tmp / "captured.json"), "--transcript", str(self.transcript)],
                runner(two_providers()),
            )
        self.assertEqual(code, 0)
        self.text = self.transcript.read_text()

    def check(self, zone_file=None, transcript=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = zonecheck.main(
                ["check-capture", "--zone-file", str(zone_file or self.zone_file),
                 "--transcript", str(transcript or self.transcript)],
                runner({}),
            )
        return code, out.getvalue(), err.getvalue()

    def test_transcript_holds_every_answer_verbatim_with_apex_soa_and_ns(self):
        self.assertIn(";;; QUERY example.test. SOA @ns1.registrar.example", self.text)
        self.assertIn(";;; QUERY example.test. NS @ns1.registrar.example", self.text)
        self.assertIn("2017060113 28800 7200 604800 600", self.text)
        self.assertIn(";; flags: qr aa;", self.text)
        # One block per name and type, except the apex NS, which capture leaves
        # to the provider; the transcript then adds that NS and the SOA.
        names = zonecheck.load_zone(self.zone_file).names()
        self.assertEqual(self.text.count(";;; QUERY "), len(names) * len(zonecheck.PROBE_TYPES) + 1)

    def test_a_matching_pair_is_equal_and_makes_no_query(self):
        code, out, _ = self.check()
        self.assertEqual(code, 0)
        self.assertIn("zone file equals transcript", out)

    def test_a_record_dropped_from_the_zone_file_is_a_diff(self):
        data = json.loads(self.zone_file.read_text())
        data["rrsets"] = [r for r in data["rrsets"] if (r["name"], r["type"]) != ("_dmarc", "TXT")]
        dropped = self.tmp / "dropped.json"
        dropped.write_text(json.dumps(data))
        code, out, _ = self.check(zone_file=dropped)
        self.assertEqual(code, 1)
        self.assertIn("DIFF _dmarc TXT: in the transcript, not declared in the zone file", out)

    def test_one_value_dropped_from_a_multi_value_rrset_is_a_diff(self):
        data = json.loads(self.zone_file.read_text())
        for rrset in data["rrsets"]:
            if (rrset["name"], rrset["type"]) == ("@", "TXT"):
                rrset["values"] = rrset["values"][:1]
        dropped = self.tmp / "dropped.json"
        dropped.write_text(json.dumps(data))
        code, out, _ = self.check(zone_file=dropped)
        self.assertEqual(code, 1)
        self.assertIn("DIFF @ TXT: declared", out)

    def test_a_changed_ttl_is_a_diff(self):
        data = json.loads(self.zone_file.read_text())
        data["rrsets"][0]["ttl"] = 60
        changed = self.tmp / "changed.json"
        changed.write_text(json.dumps(data))
        code, out, _ = self.check(zone_file=changed)
        self.assertEqual(code, 1)
        self.assertIn("ttl 60", out)

    def test_an_extra_declared_record_is_a_diff(self):
        data = json.loads(self.zone_file.read_text())
        data["rrsets"].append({"name": "absent", "type": "A", "ttl": 3600, "values": ["192.0.2.99"]})
        extra = self.tmp / "extra.json"
        extra.write_text(json.dumps(data))
        code, out, _ = self.check(zone_file=extra)
        self.assertEqual(code, 1)
        self.assertIn("DIFF absent A: declared in the zone file, not in the transcript", out)

    def test_a_record_dropped_from_the_transcript_is_a_diff(self):
        lines = [
            line for line in self.text.splitlines()
            if not (line.startswith("_dmarc.example.test.") and "\tTXT\t" in line)
        ]
        self.assertLess(len(lines), len(self.text.splitlines()))
        cut = self.tmp / "cut.txt"
        cut.write_text("\n".join(lines) + "\n")
        code, out, _ = self.check(transcript=cut)
        self.assertEqual(code, 1)
        self.assertIn("DIFF _dmarc TXT: declared in the zone file, not in the transcript", out)

    def test_a_query_missing_from_the_transcript_is_a_diff_even_with_no_record_in_it(self):
        blocks = self.text.split(";;; QUERY ")
        kept = [b for b in blocks if not b.startswith("absent.example.test. MX ")]
        self.assertEqual(len(kept), len(blocks) - 1)
        cut = self.tmp / "cut.txt"
        cut.write_text(";;; QUERY ".join(kept))
        code, out, _ = self.check(transcript=cut)
        self.assertEqual(code, 1)
        self.assertIn("absent MX: probed by the zone file, absent from the transcript", out)

    def test_a_missing_apex_soa_is_a_diff(self):
        blocks = self.text.split(";;; QUERY ")
        kept = [b for b in blocks if not b.startswith("example.test. SOA ")]
        cut = self.tmp / "cut.txt"
        cut.write_text(";;; QUERY ".join(kept))
        code, out, _ = self.check(transcript=cut)
        self.assertEqual(code, 1)
        self.assertIn("@ SOA: probed by the zone file, absent from the transcript", out)

    def test_a_probed_name_that_exists_but_is_not_declared_is_a_diff(self):
        # The case that found publicpress.co.uk's s1-ionos._domainkey: a name
        # answers NOERROR with no data because a name sits below it.
        data = json.loads(self.zone_file.read_text())
        data["rrsets"] = [r for r in data["rrsets"] if r["name"] != "sel._domainkey"]
        undeclared = self.tmp / "undeclared.json"
        undeclared.write_text(json.dumps(data))
        code, out, _ = self.check(zone_file=undeclared)
        self.assertEqual(code, 1)
        self.assertIn("sel._domainkey TXT", out)
        self.assertIn("_domainkey: rcode NOERROR in the transcript, NXDOMAIN expected", out)

    def test_a_non_authoritative_transcript_is_refused(self):
        refused = self.tmp / "refused.txt"
        refused.write_text(self.text.replace(";; flags: qr aa;", ";; flags: qr;", 1))
        code, _, err = self.check(transcript=refused)
        self.assertEqual(code, 2)
        self.assertIn("not authoritative", err)

    def test_text_before_the_first_query_is_refused(self):
        junk = self.tmp / "junk.txt"
        junk.write_text("not a transcript\n" + self.text)
        code, _, err = self.check(transcript=junk)
        self.assertEqual(code, 2)
        self.assertIn("before its first query header", err)


class StripTranscriptTest(unittest.TestCase):
    """A verbose capture transcript reduces to the lines check-capture reads."""

    VERBOSE = "\n".join([
        ";;; QUERY publicpress.co.uk. A @ns1049.ui-dns.de",
        ";; Got answer:",
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56978",
        ";; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1",
        "",
        ";; OPT PSEUDOSECTION:",
        "; EDNS: version: 0, flags:; udp: 1220",
        ";; ANSWER SECTION:",
        "publicpress.co.uk.\t3600\tIN\tA\t46.225.95.167",
        "",
        ";;; QUERY zz-no-such-name-4f1c.publicpress.co.uk. A @ns1049.ui-dns.de",
        ";; Got answer:",
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1",
        ";; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1",
        "",
        ";; AUTHORITY SECTION:",
        "publicpress.co.uk.\t3600\tIN\tSOA\tns1049.ui-dns.de. hostmaster.publicpress.co.uk. 1 3600 600 86400 300",
        "",
        ";; Query time: 12 msec",
        ";; SERVER: 46.225.95.1#53(46.225.95.1) (UDP)",
    ]) + "\n"

    MINIMAL = "\n".join([
        ";;; QUERY publicpress.co.uk. A @ns1049.ui-dns.de",
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56978",
        ";; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1",
        "publicpress.co.uk.\t3600\tIN\tA\t46.225.95.167",
        ";;; QUERY zz-no-such-name-4f1c.publicpress.co.uk. A @ns1049.ui-dns.de",
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1",
        ";; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1",
        "publicpress.co.uk.\t3600\tIN\tSOA\tns1049.ui-dns.de. hostmaster.publicpress.co.uk. 1 3600 600 86400 300",
    ]) + "\n"

    def test_verbose_reduces_to_the_minimal_form(self):
        self.assertEqual(zonecheck.strip_transcript(self.VERBOSE), self.MINIMAL)

    def test_minimal_form_is_a_fixed_point(self):
        self.assertEqual(zonecheck.strip_transcript(self.MINIMAL), self.MINIMAL)

    def test_stripping_keeps_what_check_capture_reads(self):
        verbose = zonecheck.zone_from_transcript(self.VERBOSE, "publicpress.co.uk")
        minimal = zonecheck.zone_from_transcript(zonecheck.strip_transcript(self.VERBOSE), "publicpress.co.uk")
        self.assertEqual(minimal[0].rrsets, verbose[0].rrsets)
        self.assertEqual(minimal[1:], verbose[1:])


class CheckedInPublicPressTest(unittest.TestCase):
    """The committed publicpress.co.uk pair: declared must equal captured.

    Mail authentication must survive the move, so the test fails when any
    declared record is dropped from the file -- every one, by name -- and when
    any is dropped from the transcript. The transcript is raw IONOS output
    read from a runner whose port 53 is not intercepted; see
    RUNBOOK-dns-publicpress-cutover.md.
    """

    HERE = pathlib.Path(__file__).resolve().parent
    ZONE_FILE = HERE / "publicpress.co.uk.json"
    TRANSCRIPT = HERE / "captures" / "publicpress.co.uk.ionos-dig.txt"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.assertTrue(self.ZONE_FILE.exists(), "the publicpress.co.uk zone file is not committed")
        self.assertTrue(self.TRANSCRIPT.exists(), "the IONOS capture transcript is not committed")
        self.data = json.loads(self.ZONE_FILE.read_text())
        self.text = self.TRANSCRIPT.read_text()

    def check(self, zone_file=None, transcript=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = zonecheck.main(
                ["check-capture", "--zone-file", str(zone_file or self.ZONE_FILE),
                 "--transcript", str(transcript or self.TRANSCRIPT)],
                runner({}),
            )
        return code, out.getvalue(), err.getvalue()

    def test_declared_equals_captured(self):
        code, out, err = self.check()
        self.assertEqual((code, err), (0, ""), out)

    def test_mail_records_are_declared(self):
        rrsets = zonecheck.load_zone(self.ZONE_FILE).rrsets
        self.assertIn(("@", "MX"), rrsets)
        self.assertTrue(any(v.startswith('"v=spf1 ') for v in rrsets[("@", "TXT")][1]))
        self.assertTrue(any(v.startswith('"v=DMARC1;') for v in rrsets[("_dmarc", "TXT")][1]))
        # Found by a dictionary probe, not by the first capture: _domainkey
        # answered NOERROR with no data, so a name sat below it.
        self.assertEqual(rrsets[("s1-ionos._domainkey", "CNAME")][1], frozenset({"s1.dkim.ionos.com."}))
        self.assertEqual(rrsets[("s2-ionos._domainkey", "CNAME")][1], frozenset({"s2.dkim.ionos.com."}))

    # Every DKIM selector known to sign or delegate signing for this domain.
    # Names under _domainkey cannot be enumerated from outside, so the first
    # capture missed bl and a file/transcript agreement cannot show it: both
    # lacked it. Each selector is therefore named here, and one missing from
    # the file, the probe list or the transcript fails by name.
    KNOWN_DKIM_SELECTORS = ("bl", "s1-ionos", "s2-ionos")

    def pinned_selector_problems(self, data, text):
        problems = []
        zone = data["zone"]
        declared = {r["name"]: r for r in data["rrsets"]}
        for selector in self.KNOWN_DKIM_SELECTORS:
            name = f"{selector}._domainkey"
            if name not in declared:
                problems.append(f"{name}: not declared in the zone file")
            if name not in data["probe_names"]:
                problems.append(f"{name}: not in probe_names")
            owner = zonecheck.fqdn(name, zone)
            answered = [
                line for line in text.splitlines()
                if len(line.split(None, 4)) == 5 and line.split(None, 4)[0] == owner
            ]
            if not answered:
                problems.append(f"{name}: no answer in the transcript")
        return problems

    def test_every_known_dkim_selector_is_declared_probed_and_in_the_transcript(self):
        self.assertEqual(self.pinned_selector_problems(self.data, self.text), [])

    def test_bl_is_the_dkim_public_key_served_as_two_strings(self):
        rrsets = zonecheck.load_zone(self.ZONE_FILE).rrsets
        ttl, values = rrsets[("bl._domainkey", "TXT")]
        self.assertEqual(ttl, 3600)
        (value,) = values
        self.assertTrue(value.startswith('"v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBg'))
        self.assertEqual(value.count('" "'), 1)

    def test_a_selector_missing_from_file_probes_and_transcript_alike_fails_naming_it(self):
        # The control case: the state that shipped before bl was found. Every
        # existing agreement check passes on it, so only the pinned list can fail.
        for selector in self.KNOWN_DKIM_SELECTORS:
            with self.subTest(selector=selector):
                name = f"{selector}._domainkey"
                owner = zonecheck.fqdn(name, self.data["zone"])
                data = dict(self.data)
                data["rrsets"] = [r for r in self.data["rrsets"] if r["name"] != name]
                data["probe_names"] = [n for n in self.data["probe_names"] if n != name]
                blocks = re.split(r"(?m)^(?=;;; QUERY )", self.text)
                text = "".join(b for b in blocks if not b.startswith(f";;; QUERY {owner} "))
                self.assertLess(len(text), len(self.text))
                path = self.tmp / "without.json"
                path.write_text(json.dumps(data))
                transcript = self.tmp / "without.txt"
                transcript.write_text(text)
                code, out, _ = self.check(zone_file=path, transcript=transcript)
                self.assertEqual(code, 0, "the agreement check cannot see the gap: " + out)
                problems = self.pinned_selector_problems(data, text)
                self.assertEqual(len(problems), 3, problems)
                self.assertTrue(all(p.startswith(f"{name}:") for p in problems), problems)

    def test_the_transcript_shows_the_apex_soa_and_ns_that_are_not_declared(self):
        self.assertIn("\tSOA\t", self.text)
        rrsets = zonecheck.load_zone(self.ZONE_FILE).rrsets
        self.assertNotIn(("@", "NS"), rrsets)
        self.assertNotIn(("@", "SOA"), rrsets)

    def test_every_probe_name_holds_what_the_transcript_says_or_is_absent(self):
        zone = zonecheck.load_zone(self.ZONE_FILE)
        self.assertIn("zz-no-such-name-4f1c", zone.probe_names)
        self.assertEqual(zone.expected_rcode("zz-no-such-name-4f1c"), "NXDOMAIN")

    def test_dropping_any_one_declared_record_fails_naming_it(self):
        self.assertGreater(len(self.data["rrsets"]), 0)
        for rrset in self.data["rrsets"]:
            with self.subTest(record=f"{rrset['name']} {rrset['type']}"):
                dropped = dict(self.data)
                dropped["rrsets"] = [r for r in self.data["rrsets"] if r is not rrset]
                path = self.tmp / "dropped.json"
                path.write_text(json.dumps(dropped))
                code, out, _ = self.check(zone_file=path)
                self.assertEqual(code, 1)
                self.assertIn(f"DIFF {rrset['name']} {rrset['type']}: in the transcript, not declared", out)

    def test_dropping_a_mail_record_in_particular_fails(self):
        # The records a mail-breaking copy drops first: _dmarc, the SPF-bearing apex TXT, the MX.
        for name, rtype in (("_dmarc", "TXT"), ("@", "TXT"), ("@", "MX")):
            with self.subTest(record=f"{name} {rtype}"):
                dropped = dict(self.data)
                dropped["rrsets"] = [r for r in self.data["rrsets"] if (r["name"], r["type"]) != (name, rtype)]
                path = self.tmp / "dropped.json"
                path.write_text(json.dumps(dropped))
                code, out, _ = self.check(zone_file=path)
                self.assertEqual(code, 1)
                self.assertIn(f"DIFF {name} {rtype}", out)

    def test_dropping_one_record_from_the_transcript_fails(self):
        for rrset in self.data["rrsets"]:
            with self.subTest(record=f"{rrset['name']} {rrset['type']}"):
                owner = zonecheck.fqdn(rrset["name"], self.data["zone"])
                # dig pads the owner column with a space or a tab: read fields.
                cut_lines = [
                    line for line in self.text.splitlines()
                    if not (len(line.split(None, 4)) == 5
                            and line.split(None, 4)[0] == owner
                            and line.split(None, 4)[3] == rrset["type"])
                ]
                self.assertLess(len(cut_lines), len(self.text.splitlines()))
                path = self.tmp / "cut.txt"
                path.write_text("\n".join(cut_lines) + "\n")
                code, out, _ = self.check(transcript=path)
                self.assertEqual(code, 1)
                self.assertIn(f"DIFF {rrset['name']} {rrset['type']}: declared in the zone file", out)

    def test_an_extra_declared_record_fails(self):
        extra = dict(self.data)
        extra["rrsets"] = [
            *self.data["rrsets"],
            {"name": "www", "type": "A", "ttl": 3600, "values": ["192.0.2.1"]},
        ]
        path = self.tmp / "extra.json"
        path.write_text(json.dumps(extra))
        code, out, _ = self.check(zone_file=path)
        self.assertEqual(code, 1)
        self.assertIn("DIFF www A", out)


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

    def test_blog_sending_domain_records_match_mx1(self):
        rrsets = self.zone.rrsets
        self.assertEqual(rrsets[("blog", "MX")], rrsets[("@", "MX")])
        (mx1_v4,) = rrsets[("mx1", "A")][1]
        (mx1_v6,) = rrsets[("mx1", "AAAA")][1]
        self.assertEqual(
            rrsets[("blog", "TXT")][1],
            frozenset({f'"v=spf1 ip4:{mx1_v4} ip6:{mx1_v6} -all"'}),
        )

    def test_blog_dkim_name_is_probed_and_holds_a_real_key_or_nothing(self):
        selector = "bl._domainkey.blog"
        self.assertIn(selector, self.zone.probe_names)
        if (selector, "TXT") in self.zone.rrsets:
            (value,) = self.zone.rrsets[(selector, "TXT")][1]
            key_shape = r'^"v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkq[A-Za-z0-9+/=" ]+"$'
            self.assertRegex(value, key_shape)

    def test_every_record_name_is_probed(self):
        self.assertTrue({name for name, _ in self.zone.rrsets} <= set(self.zone.probe_names))

    def test_probes_include_a_name_that_must_not_exist(self):
        absent = [n for n in self.zone.probe_names if self.zone.expected_rcode(n) == "NXDOMAIN"]
        self.assertIn("zz-no-such-name-4f1c", absent)


if __name__ == "__main__":
    unittest.main()
