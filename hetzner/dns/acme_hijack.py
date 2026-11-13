#!/usr/bin/env python3
"""Find zone records that would hijack a DNS-01 challenge.

A certificate authority proves control of a name by reading a TXT record at
_acme-challenge.<name>. A record in the zone that redirects, delegates or
answers that name takes the lookup away from the zone owner. Three shapes do
it, and this checker reads the zone file for each:

- cname: a CNAME at _acme-challenge or _acme-challenge.<anything>. The CA
  follows the CNAME to a target the zone owner does not control.
- delegation: an NS record at any name below the apex. It hands that name
  and everything under it to another set of servers, challenge included.
- wildcard: a * or *.<name> record that answers _acme-challenge.<name> when
  the zone holds no record at that name, so the CA reads a value it did not
  write.

It reads zone.json only and makes no network call. A CNAME at a label other
than the first (foo._acme-challenge) is not a challenge name and is not
reported. A TXT at a challenge name is how DNS-01 works and is not reported.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from dataclasses import dataclass

from zonecheck import Zone, load_zone

CHALLENGE = "_acme-challenge"
DEFAULT_ZONE_FILE = pathlib.Path(__file__).resolve().parent / "zone.json"


@dataclass(frozen=True)
class Finding:
    kind: str
    owner: str
    rtype: str
    detail: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.owner} {self.rtype}: {self.detail}"


def _is_challenge_name(owner: str) -> bool:
    return owner.split(".", 1)[0] == CHALLENGE


def _challenge_for_wildcard(owner: str) -> str:
    """The challenge name a wildcard owner answers: * at the apex, *.P for P."""
    if owner == "*":
        return CHALLENGE
    return f"{CHALLENGE}.{owner[2:]}"


def _has_node(name: str, owners: set[str]) -> bool:
    """True when the name, or a name below it, holds a record (RFC 4592 blocks the wildcard)."""
    return any(owner == name or owner.endswith("." + name) for owner in owners)


def find_hijacks(zone: Zone) -> list[Finding]:
    owners = {name.lower() for name, _ in zone.rrsets}
    findings: list[Finding] = []
    for name, rtype in sorted(zone.rrsets):
        owner = name.lower()
        if rtype == "CNAME" and _is_challenge_name(owner):
            findings.append(
                Finding("cname", name, rtype, f"redirects the DNS-01 lookup of {owner}")
            )
        if rtype == "NS" and owner != "@":
            findings.append(
                Finding(
                    "delegation",
                    name,
                    rtype,
                    f"delegates {owner} and all names below it",
                )
            )
        if owner == "*" or owner.startswith("*."):
            challenge = _challenge_for_wildcard(owner)
            if not _has_node(challenge, owners):
                findings.append(
                    Finding(
                        "wildcard",
                        name,
                        rtype,
                        f"answers {challenge} where the zone has no record",
                    )
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--zone-file", type=pathlib.Path, default=DEFAULT_ZONE_FILE)
    args = parser.parse_args(argv)
    zone = load_zone(args.zone_file)
    findings = find_hijacks(zone)
    for finding in findings:
        print(f"HIJACK {finding}")
    if findings:
        print(
            f"{len(findings)} record(s) would hijack a DNS-01 challenge in {args.zone_file.name}"
        )
        return 1
    print(f"no DNS-01 hijack: {len(zone.rrsets)} rrsets in {args.zone_file.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
