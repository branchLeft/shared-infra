#!/usr/bin/env python3
"""Drift gate between the estate's address plan and its shell-side literals.

`hetzner-host/addressPlan.ts` is the one place `SUBNET_CIDR` and
`HOST_IPS.edge1` are decided. `hetzner/network.ts` and `hetzner/egress.ts`
import that module, so Pulumi always sees a plan change. The NAT gateway
script and the provisioning runbook cannot: the script runs on a host with no
repository checkout to import from, and the runbook is prose a human reads,
not code anything executes. Both therefore carry the same values as literals,
and nothing stops those literals drifting from the module that is supposed to
be their source.

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

    check-address-plan-drift.py [--root DIR]

Exits non-zero, naming the file, the literal it found and the plan value it
disagreed with. Reads files only; contacts nothing.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# Three parents up from hetzner/scripts/: the repository root, which is the
# common ancestor of hetzner-host/ (the plan) and hetzner/ (everything that
# has to agree with it).
DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

_SUBNET_CIDR_RE = re.compile(r"export const SUBNET_CIDR\s*=\s*'([^']+)'")
# Scoped to the HOST_IPS block rather than searched over the whole file:
# APP_HOST_IPS sits right below it in the same shape, and a global `edge1:`
# search would trust whichever object happened to define that key first.
_HOST_IPS_BLOCK_RE = re.compile(r"export const HOST_IPS\s*=\s*\{(.*?)\}\s*as const", re.S)
_EDGE1_RE = re.compile(r"\bedge1\s*:\s*'([^']+)'")

_CIDR_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
# The lookahead is what keeps this disjoint from _CIDR_RE: an address that is
# immediately followed by "/" is the CIDR's own base address, not a second,
# bare literal sitting next to it.
_BARE_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b(?!/)")


def read_address_plan(path: pathlib.Path) -> tuple[str, str]:
    """`(SUBNET_CIDR, HOST_IPS.edge1)` as the plan currently states them.

    Raises rather than returning a default for anything it cannot find. A
    default here would compare the shell side against a value nobody wrote,
    which passes regardless of whether the two actually agree -- the one
    outcome this gate exists to rule out.
    """
    try:
        text = path.read_text()
    except OSError as exc:
        raise ValueError(f"{path}: cannot read address plan ({exc})") from exc

    subnet_match = _SUBNET_CIDR_RE.search(text)
    if subnet_match is None:
        raise ValueError(f"{path}: no `export const SUBNET_CIDR = '...'` found")

    block_match = _HOST_IPS_BLOCK_RE.search(text)
    if block_match is None:
        raise ValueError(f"{path}: no `export const HOST_IPS = {{ ... }} as const` block found")
    edge1_match = _EDGE1_RE.search(block_match.group(1))
    if edge1_match is None:
        raise ValueError(f"{path}: HOST_IPS block names no `edge1`")

    return subnet_match.group(1), edge1_match.group(1)


def _check_literals(
    path: pathlib.Path, pattern: re.Pattern[str], expected: str, expected_label: str
) -> list[str]:
    """Every `pattern` match in `path` must equal `expected`.

    An empty result is reported as a failure rather than treated as nothing
    to compare: a file that has stopped mentioning the value at all is not
    evidence the two agree, and passing it vacuously would be worse than not
    checking the file, because it reports health.
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

    failures = []
    for value in sorted(set(found)):
        if value != expected:
            count = found.count(value)
            occurrence = "occurrence" if count == 1 else "occurrences"
            failures.append(
                f"{path}: {count} {occurrence} of {value!r} disagree with "
                f"hetzner-host/addressPlan.ts's {expected_label} ({expected!r})"
            )
    return failures


def check(root: pathlib.Path) -> list[str]:
    try:
        subnet_cidr, edge1 = read_address_plan(root / "hetzner-host" / "addressPlan.ts")
    except ValueError as exc:
        return [str(exc)]

    failures: list[str] = []
    failures += _check_literals(
        root / "hetzner" / "provision" / "branchleft_nat.sh", _CIDR_RE, subnet_cidr, "SUBNET_CIDR"
    )
    failures += _check_literals(
        root / "hetzner" / "RUNBOOK-provision-host.md", _CIDR_RE, subnet_cidr, "SUBNET_CIDR"
    )
    failures += _check_literals(
        root / "hetzner" / "RUNBOOK-provision-host.md",
        _BARE_IPV4_RE,
        edge1,
        "HOST_IPS.edge1",
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
