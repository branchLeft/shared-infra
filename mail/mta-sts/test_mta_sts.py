"""Checks that the MTA-STS policy and the TLS-RPT record agree with the zone.

The policy file is served byte for byte at
https://mta-sts.branchleft.co.uk/.well-known/mta-sts.txt. The records live in
hetzner/dns/zone.json, the file every DNS change is made in.

The _mta-sts TXT record is deliberately absent from the zone in this change.
It publishes the policy id, and must only land together with the host that
serves the policy: a declared id with no host is the unsafe state. The
follow-up that adds the record also adds the host record, and the gate test
below enforces that pairing.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
POLICY = HERE / "mta-sts.txt"
ZONE = HERE.parent.parent / "hetzner" / "dns" / "zone.json"
ZONE_NAME = "branchleft.co.uk"
TLS_RPT_VALUE = "v=TLSRPTv1; rua=mailto:rob@branchleft.co.uk"
# Pinned to the policy bytes. A policy edit fails here until this pin is
# changed too, and the follow-up that publishes _mta-sts carries this value.
EXPECTED_ID = "76349e397ff4245c"
POLICY_HOST = "mta-sts"
HOST_TYPES = ("A", "AAAA", "CNAME")


def _policy_fields() -> list[tuple[str, str]]:
    fields = []
    for line in POLICY.read_bytes().decode("ascii").splitlines():
        key, sep, value = line.partition(":")
        assert sep, f"policy line without a colon: {line!r}"
        fields.append((key.strip(), value.strip()))
    return fields


def _zone_data() -> dict:
    data = json.loads(ZONE.read_text())
    assert data["zone"] == ZONE_NAME
    return data


def _zone_values(name: str, rtype: str) -> list[str]:
    for rrset in _zone_data()["rrsets"]:
        if rrset["name"] == name and rrset["type"] == rtype:
            return rrset["values"]
    raise AssertionError(f"no {rtype} rrset for {name} in zone.json")


def _zone_has(name: str, rtypes: tuple[str, ...]) -> bool:
    return any(
        rrset["name"] == name and rrset["type"] in rtypes
        for rrset in _zone_data()["rrsets"]
    )


def _policy_id() -> str:
    # The first 16 hex digits of the SHA-256 of the exact policy bytes.
    return hashlib.sha256(POLICY.read_bytes()).hexdigest()[:16]


class MtaStsRecordsTest(unittest.TestCase):
    def test_policy_uses_lf_line_endings_only(self) -> None:
        # RFC 8461 allows CRLF, but this file is served byte for byte and the
        # id is the hash of those bytes, so one ending only: LF.
        raw = POLICY.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))

    def test_policy_is_testing_stsv1_with_expected_max_age(self) -> None:
        fields = dict(_policy_fields())
        self.assertEqual(fields.get("version"), "STSv1")
        self.assertEqual(
            fields.get("mode"), "testing", "enforce is a later, separate change"
        )
        self.assertEqual(fields.get("max_age"), "86400")

    def test_policy_mx_lines_equal_zone_mx_hosts(self) -> None:
        policy_mx = sorted(value for key, value in _policy_fields() if key == "mx")
        zone_mx = sorted(
            value.split()[1].rstrip(".").lower() for value in _zone_values("@", "MX")
        )
        self.assertTrue(policy_mx, "the policy must name at least one MX host")
        self.assertEqual(policy_mx, zone_mx)

    def test_policy_hash_matches_pinned_id(self) -> None:
        # A policy edit changes the hash; the pin must then be updated with it.
        self.assertEqual(_policy_id(), EXPECTED_ID)

    def test_mta_sts_txt_declared_only_with_policy_host(self) -> None:
        # The id must never be published without a host to serve the policy.
        has_txt = _zone_has("_mta-sts", ("TXT",))
        has_host = _zone_has(POLICY_HOST, HOST_TYPES)
        self.assertFalse(
            has_txt and not has_host,
            "_mta-sts TXT is declared but no A/AAAA/CNAME for mta-sts exists",
        )
        if has_txt:
            self.assertEqual(
                _zone_values("_mta-sts", "TXT"), [f'"v=STSv1; id={EXPECTED_ID}"']
            )

    def test_tls_rpt_txt_names_the_reporting_address(self) -> None:
        self.assertEqual(_zone_values("_smtp._tls", "TXT"), [f'"{TLS_RPT_VALUE}"'])


if __name__ == "__main__":
    unittest.main()
