#!/usr/bin/env python3
"""Drift gate between the estate's address plan and its shell-side literals.

`hetzner-host/addressPlan.ts` is the one place `NETWORK_CIDR`, `SUBNET_CIDR`
and `HOST_IPS`/`APP_HOST_IPS` are decided. `hetzner/network.ts` and
`hetzner/egress.ts` import that module, so Pulumi always sees a plan change.
The NAT gateway script and the provisioning runbook cannot: the script runs on
a host with no repository checkout to import from, and the runbook is prose a
human reads, not code anything executes. Both therefore carry the plan's
subnet and edge1's address as literals, and nothing stops those literals
drifting from the module that is supposed to be their source.

**A drifted literal presents as success.** The NAT script's own
`only a /24 subnet is understood` guard validates its own literal against
itself, so it stays green after the literal goes stale -- it was never
checking the literal against the plan. The runbook's verification block greps
for the MASQUERADE rule it expects and finds it, correct for the subnet it
still names. Either way the host that is actually misconfigured is the one
outside the plan's current range, and every check available reports it
healthy.

This gate reads the plan's current values and asserts every subnet-shaped and
edge1-shaped literal in the shell script and the runbook still matches them --
every occurrence, not the first one found, because a file edited in one place
and left stale in another is the half-updated state the gate exists to catch.

Two things a naive text match over these files would get wrong, both handled
below:

* **Not every address-shaped string in these files is a copy of the value
  being checked.** The runbook mentions the internet default route
  (`0.0.0.0/0`), and could reasonably mention Docker's own bridge default
  (`172.17.0.0/16`) or another host's address in prose without either being a
  stale copy of anything. A literal only counts as a disagreement if it falls
  inside the plan's `NETWORK_CIDR` *and* matches none of the plan's current
  values -- outside the estate's own range it isn't an estate address at all,
  and inside it, it may simply be some other host's real, current address.
* **A value that only appears in a comment is not the live export.** This
  module's house style narrates reasoning at length, including earlier
  decisions, so a stale value sitting in prose ahead of the real `export
  const` is a realistic accident. Comments are stripped before any of the
  regexes below run.

    check-address-plan-drift.py [--root DIR]

Exits non-zero, naming the file, the literal it found and the plan value it
disagreed with. Reads files only; contacts nothing.
"""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import pathlib
import re
import sys

# Three parents up from hetzner/scripts/: the repository root, which is the
# common ancestor of hetzner-host/ (the plan) and hetzner/ (everything that
# has to agree with it).
DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# Not a TypeScript parser -- a reader for this one file, in the shape the
# other text-based readers in this repository already accept for themselves.
# It assumes no string value in addressPlan.ts contains `//` or `/*`, which is
# true today and checked nowhere; a value that broke it would still fail loud
# (a constant regex below would simply stop matching), not silently.
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_comments(text: str) -> str:
    """Removes `/* */` and `//` comments before anything else reads `text`.

    Without this, a value mentioned only in prose -- a deprecated setting, an
    example, a past decision -- reads as the live export if it happens to sit
    ahead of the real one, and every value downstream is then compared against
    a plan nobody actually set.
    """
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", text))


_NETWORK_CIDR_RE = re.compile(r"export const NETWORK_CIDR\s*=\s*'([^']+)'")
_SUBNET_CIDR_RE = re.compile(r"export const SUBNET_CIDR\s*=\s*'([^']+)'")
_OBJECT_ENTRY_RE = re.compile(r"(\w+)\s*:\s*'([^']+)'")


def _object_block(const_name: str, text: str) -> dict[str, str] | None:
    """Every `key: 'value'` entry inside `export const <const_name> = { ... }`.

    Matched by the exact constant name, not a substring search for it: a
    global `edge1:` search would trust whichever of `HOST_IPS` and
    `APP_HOST_IPS` happens to define that key first, and the two sit right
    next to each other in the same shape.
    """
    pattern = re.compile(
        r"export const " + re.escape(const_name) + r"\s*=\s*\{(.*?)\}\s*as const", re.S
    )
    match = pattern.search(text)
    if match is None:
        return None
    return dict(_OBJECT_ENTRY_RE.findall(match.group(1)))


@dataclasses.dataclass(frozen=True)
class AddressPlan:
    network_cidr: str
    subnet_cidr: str
    host_ips: dict[str, str]
    app_host_ips: dict[str, str]

    @property
    def edge1(self) -> str:
        return self.host_ips["edge1"]

    def known_values(self) -> set[str]:
        """Every address or range this plan currently claims as its own."""
        return {self.network_cidr, self.subnet_cidr, *self.host_ips.values(), *self.app_host_ips.values()}


def read_address_plan(path: pathlib.Path) -> AddressPlan:
    """The plan's current values, comment-stripped and read in full.

    Raises rather than returning a default for anything it cannot find. A
    default here would compare the shell side against a value nobody wrote,
    which passes regardless of whether the two actually agree -- the one
    outcome this gate exists to rule out.
    """
    try:
        text = path.read_text()
    except OSError as exc:
        raise ValueError(f"{path}: cannot read address plan ({exc})") from exc
    text = _strip_comments(text)

    network_match = _NETWORK_CIDR_RE.search(text)
    if network_match is None:
        raise ValueError(f"{path}: no `export const NETWORK_CIDR = '...'` found")

    subnet_match = _SUBNET_CIDR_RE.search(text)
    if subnet_match is None:
        raise ValueError(f"{path}: no `export const SUBNET_CIDR = '...'` found")

    host_ips = _object_block("HOST_IPS", text)
    if host_ips is None:
        raise ValueError(f"{path}: no `export const HOST_IPS = {{ ... }} as const` block found")
    if "edge1" not in host_ips:
        raise ValueError(f"{path}: HOST_IPS block names no `edge1`")

    # Optional: it only widens which addresses are recognised as someone
    # else's, legitimate value rather than a stale copy. Its absence narrows
    # that recognition; it does not make the plan unreadable.
    app_host_ips = _object_block("APP_HOST_IPS", text) or {}

    return AddressPlan(network_match.group(1), subnet_match.group(1), host_ips, app_host_ips)


_CIDR_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
# The lookahead is what keeps this disjoint from _CIDR_RE: an address that is
# immediately followed by "/" is the CIDR's own base address, not a second,
# bare literal sitting next to it.
_BARE_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b(?!/)")


def _within(literal: str, network: ipaddress.IPv4Network) -> bool:
    """Whether `literal` (a bare address or a CIDR) falls inside `network`.

    A malformed literal -- an octet over 255, a prefix over 32 -- is treated
    as outside rather than raising: the two literal regexes above already
    constrain the shape enough that this only fires on values `ipaddress`
    itself refuses, and refusing to compare is the same outcome either way.
    """
    try:
        if "/" in literal:
            candidate = ipaddress.ip_network(literal, strict=False)
            return candidate.subnet_of(network)
        return ipaddress.ip_address(literal) in network
    except ValueError:
        return False


def _check_literals(
    path: pathlib.Path,
    pattern: re.Pattern[str],
    expected: str,
    expected_label: str,
    plan: AddressPlan,
) -> list[str]:
    """Every `pattern` match in `path` must equal `expected`, once literals
    that are not a copy of anything in the plan are set aside.

    An empty result is reported as a failure rather than treated as nothing
    to compare: a file that has stopped mentioning the value at all is not
    evidence the two agree, and passing it vacuously would be worse than not
    checking the file, because it reports health.

    A mismatch is only reported if the literal also falls inside the plan's
    `NETWORK_CIDR` and matches none of the plan's other current values --
    otherwise a route default, a Docker bridge default, or a real, different
    host's real, current address read as a stale copy of `expected` on no
    stronger basis than sharing its shape.
    """
    try:
        text = path.read_text()
    except OSError as exc:
        return [f"{path}: cannot read ({exc})"]

    found = pattern.findall(text)
    if not found:
        return [
            f"{path}: expected at least one literal matching {expected_label} "
            f"({expected!r}), found none"
        ]

    network = ipaddress.ip_network(plan.network_cidr, strict=False)
    known = plan.known_values()

    failures = []
    for value in sorted(set(found)):
        if value == expected or value in known or not _within(value, network):
            continue
        count = found.count(value)
        occurrence = "occurrence" if count == 1 else "occurrences"
        failures.append(
            f"{path}: {count} {occurrence} of {value!r} disagree with "
            f"hetzner-host/addressPlan.ts's {expected_label} ({expected!r})"
        )
    return failures


def check(root: pathlib.Path) -> list[str]:
    try:
        plan = read_address_plan(root / "hetzner-host" / "addressPlan.ts")
    except ValueError as exc:
        return [str(exc)]

    failures: list[str] = []
    failures += _check_literals(
        root / "hetzner" / "provision" / "branchleft_nat.sh",
        _CIDR_RE,
        plan.subnet_cidr,
        "SUBNET_CIDR",
        plan,
    )
    failures += _check_literals(
        root / "hetzner" / "RUNBOOK-provision-host.md",
        _CIDR_RE,
        plan.subnet_cidr,
        "SUBNET_CIDR",
        plan,
    )
    failures += _check_literals(
        root / "hetzner" / "RUNBOOK-provision-host.md",
        _BARE_IPV4_RE,
        plan.edge1,
        "HOST_IPS.edge1",
        plan,
    )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(DEFAULT_ROOT))
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    failures = check(root)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print("address plan and its shell-side literals agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
