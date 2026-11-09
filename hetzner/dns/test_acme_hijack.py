"""Tests for acme_hijack.py. Zones are built in memory or read from a temp file; no network."""

from __future__ import annotations

import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import acme_hijack
from zonecheck import Zone, load_zone

ZONE = "example.test"
CLEAN = [
    ("@", "A", ["192.0.2.10"]),
    ("@", "MX", ["10 mx1.example.test."]),
    ("www", "A", ["192.0.2.10"]),
    ("mx1", "A", ["192.0.2.25"]),
    ("_dmarc", "TXT", ['"v=DMARC1; p=none"']),
]


def zone_of(*records: tuple[str, str, list[str]]) -> Zone:
    rrsets = {
        (name, rtype): (3600, frozenset(values)) for name, rtype, values in records
    }
    return Zone(ZONE, rrsets, [])


def kinds(zone: Zone) -> list[str]:
    return [finding.kind for finding in acme_hijack.find_hijacks(zone)]


class CleanZone(unittest.TestCase):
    def test_zone_without_challenge_records_has_no_findings(self) -> None:
        self.assertEqual(acme_hijack.find_hijacks(zone_of(*CLEAN)), [])

    def test_txt_at_a_challenge_name_is_how_dns01_works(self) -> None:
        zone = zone_of(*CLEAN, ("_acme-challenge.www", "TXT", ['"token"']))
        self.assertEqual(acme_hijack.find_hijacks(zone), [])

    def test_cname_at_a_non_leading_challenge_label_is_not_a_challenge(self) -> None:
        zone = zone_of(
            *CLEAN, ("foo._acme-challenge", "CNAME", ["target.example.net."])
        )
        self.assertEqual(acme_hijack.find_hijacks(zone), [])


class Cname(unittest.TestCase):
    def test_cname_at_apex_challenge_is_reported(self) -> None:
        zone = zone_of(
            *CLEAN, ("_acme-challenge", "CNAME", ["x.authorize.example.net."])
        )
        self.assertEqual(kinds(zone), ["cname"])

    def test_cname_at_www_challenge_is_reported(self) -> None:
        zone = zone_of(
            *CLEAN, ("_acme-challenge.www", "CNAME", ["x.authorize.example.net."])
        )
        self.assertEqual(kinds(zone), ["cname"])

    def test_cname_at_any_subject_challenge_is_reported_with_the_owner(self) -> None:
        zone = zone_of(*CLEAN, ("_acme-challenge.blog", "CNAME", ["x.example.net."]))
        findings = acme_hijack.find_hijacks(zone)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].owner, "_acme-challenge.blog")


class Delegation(unittest.TestCase):
    def test_ns_at_a_challenge_name_is_reported(self) -> None:
        zone = zone_of(*CLEAN, ("_acme-challenge.blog", "NS", ["ns1.example.net."]))
        self.assertEqual(kinds(zone), ["delegation"])

    def test_ns_at_a_subject_delegates_its_challenge(self) -> None:
        zone = zone_of(*CLEAN, ("www", "NS", ["ns1.example.net."]))
        self.assertEqual(kinds(zone), ["delegation"])


class Wildcard(unittest.TestCase):
    def test_apex_wildcard_answers_the_apex_challenge(self) -> None:
        zone = zone_of(*CLEAN, ("*", "A", ["192.0.2.99"]))
        findings = acme_hijack.find_hijacks(zone)
        self.assertEqual([f.kind for f in findings], ["wildcard"])
        self.assertIn("_acme-challenge ", findings[0].detail + " ")

    def test_wildcard_under_a_subject_answers_its_challenge(self) -> None:
        zone = zone_of(*CLEAN, ("*.www", "TXT", ['"junk"']))
        self.assertEqual(kinds(zone), ["wildcard"])

    def test_explicit_record_at_the_challenge_name_blocks_the_wildcard(self) -> None:
        zone = zone_of(
            *CLEAN,
            ("*.www", "TXT", ['"junk"']),
            ("_acme-challenge.www", "TXT", ['"token"']),
        )
        self.assertEqual(acme_hijack.find_hijacks(zone), [])

    def test_record_below_the_challenge_name_blocks_the_wildcard(self) -> None:
        zone = zone_of(
            *CLEAN,
            ("*.www", "TXT", ['"junk"']),
            ("x._acme-challenge.www", "TXT", ['"v"']),
        )
        self.assertEqual(acme_hijack.find_hijacks(zone), [])


class RealZone(unittest.TestCase):
    """The checked-in zone, with the three hijack CNAMEs removed, must be clean."""

    def test_real_zone_is_clean_once_the_known_cnames_are_gone(self) -> None:
        zone = load_zone(acme_hijack.DEFAULT_ZONE_FILE)
        kept = {
            key: value
            for key, value in zone.rrsets.items()
            if not (key[1] == "CNAME" and key[0].startswith("_acme-challenge"))
        }
        self.assertEqual(
            acme_hijack.find_hijacks(Zone(zone.name, kept, zone.probe_names)), []
        )

    def test_sabotage_a_hijack_into_the_real_zone_is_reported(self) -> None:
        # Sabotage: a challenge CNAME added to the checked-in zone once its known hijacks are gone.
        data = json.loads(acme_hijack.DEFAULT_ZONE_FILE.read_text())
        data["rrsets"] = [
            r
            for r in data["rrsets"]
            if not (r["type"] == "CNAME" and r["name"].startswith("_acme-challenge"))
        ]
        data["rrsets"].append(
            {
                "name": "_acme-challenge.mx1",
                "type": "CNAME",
                "ttl": 3600,
                "values": ["x.example.net."],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "zone.json"
            path.write_text(json.dumps(data))
            out = io.StringIO()
            with redirect_stdout(out):
                code = acme_hijack.main(["--zone-file", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("_acme-challenge.mx1", out.getvalue())


class Cli(unittest.TestCase):
    def run_cli(self, records: list[dict[str, object]]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "zone.json"
            path.write_text(
                json.dumps({"zone": ZONE, "rrsets": records, "probe_names": []})
            )
            out = io.StringIO()
            with redirect_stdout(out):
                code = acme_hijack.main(["--zone-file", str(path)])
        return code, out.getvalue()

    def test_clean_file_exits_zero(self) -> None:
        code, text = self.run_cli(
            [{"name": "@", "type": "A", "ttl": 3600, "values": ["192.0.2.10"]}]
        )
        self.assertEqual(code, 0)
        self.assertIn("no DNS-01 hijack", text)

    def test_hijack_file_exits_one_and_names_the_record(self) -> None:
        code, text = self.run_cli(
            [
                {
                    "name": "_acme-challenge",
                    "type": "CNAME",
                    "ttl": 3600,
                    "values": ["x.example.net."],
                }
            ]
        )
        self.assertEqual(code, 1)
        self.assertIn("HIJACK cname: _acme-challenge CNAME", text)


if __name__ == "__main__":
    unittest.main()
