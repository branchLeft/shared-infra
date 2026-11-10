"""Checks that the MTA-STS policy and the TLS-RPT records agree with the zone.

The policy file is served byte for byte at
https://mta-sts.branchleft.co.uk/.well-known/mta-sts.txt. The records live in
hetzner/dns/zone.json, the file every DNS change is made in. These checks
keep the three in step: the policy's mx lines are the zone's MX hosts, and
the _mta-sts id is a hash of the policy bytes, so a policy edit that is not
followed by a new id in the zone fails here.
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


def _policy_fields() -> list[tuple[str, str]]:
    fields = []
    for line in POLICY.read_bytes().decode("ascii").splitlines():
        key, sep, value = line.partition(":")
        assert sep, f"policy line without a colon: {line!r}"
        fields.append((key.strip(), value.strip()))
    return fields


def _zone_values(name: str, rtype: str) -> list[str]:
    data = json.loads(ZONE.read_text())
    assert data["zone"] == ZONE_NAME
    for rrset in data["rrsets"]:
        if rrset["name"] == name and rrset["type"] == rtype:
            return rrset["values"]
    raise AssertionError(f"no {rtype} rrset for {name} in zone.json")


def _policy_id() -> str:
    # The first 16 hex digits of the SHA-256 of the exact policy bytes.
    return hashlib.sha256(POLICY.read_bytes()).hexdigest()[:16]


class MtaStsRecordsTest(unittest.TestCase):
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

    def test_mta_sts_txt_id_is_the_hash_of_the_policy(self) -> None:
        expected = f'"v=STSv1; id={_policy_id()}"'
        self.assertEqual(_zone_values("_mta-sts", "TXT"), [expected])

    def test_tls_rpt_txt_names_the_reporting_address(self) -> None:
        self.assertEqual(_zone_values("_smtp._tls", "TXT"), [f'"{TLS_RPT_VALUE}"'])


if __name__ == "__main__":
    unittest.main()
