#!/usr/bin/python3 -I
"""Limits the Sweego receiver's drain port to one source address, in DOCKER-USER.

The drain port is published on edge1's private address. Docker publishes a port with a DNAT
that bypasses INPUT, so the only place a host rule can see the connection is DOCKER-USER,
where the packet already carries the container's address. The rule therefore matches the
connection's original destination through conntrack, in the original direction only, so a
reply (whose source is the container, not the allowed address) is never caught by it:

    -p tcp -m conntrack --ctorigdst ADDRESS --ctorigdstport PORT --ctdir ORIGINAL
    ! -s SOURCE -j DROP

Every connection to that address and port from any source but SOURCE is dropped. Nothing is
allowed by a separate rule: the default for the port is deny, and one source is excepted.

Installed as /usr/local/sbin/branchleft-sweego-drain-rule by the sweego_receiver role and
re-run at every boot, and after every restart of Docker, by its unit. Idempotent: the rule is
checked before it is added. Takes its three values as arguments, every one of which is
checked, and has no environment and no default for any of them.

The rule is inserted at position 1, so no earlier rule can accept the port first. A rule that
is already present anywhere but first is a state the program does not repair: it stops with
a non-zero status and says so, because a rule hidden under an accept is not a rule.

Every external command runs from an argument list, never through a shell, under a timeout. A
probe that cannot run, does not finish, or exits with a status that is not one of its documented
answers counts as no answer, and the program stops rather than guess.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
from typing import NoReturn

PREFIX = "branchleft-sweego-drain-rule"
CHAIN = "DOCKER-USER"
COMMAND_TIMEOUT_SECONDS = 30
# What `iptables -C` exits with when the rule is not there. Any other non-zero status is
# no answer.
RULE_ABSENT_STATUS = 1
MIN_PORT = 1024
MAX_PORT = 65535


def die(*lines: str, status: int = 1) -> NoReturn:
    """Print each line to stderr and stop with the status."""
    for line in lines:
        print(line, file=sys.stderr)
    sys.exit(status)


def single_address(value: str, name: str) -> str:
    """Return the value if it is one IPv4 host address that can name a peer, else stop."""
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        die(f"{PREFIX}: {name} is {value!r}, which is not one IPv4 address", status=2)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        die(f"{PREFIX}: {name} is {value!r}, which cannot name one peer", status=2)
    return str(address)


def unprivileged_port(value: str) -> str:
    """Return the value if it is a whole number from 1024 to 65535, else stop."""
    if not value.isascii() or not value.isdigit() or not MIN_PORT <= int(value) <= MAX_PORT:
        die(f"{PREFIX}: --port is {value!r}, not a whole number from 1024 to 65535", status=2)
    return str(int(value))


def rule_for(address: str, port: str, source: str) -> tuple[str, ...]:
    """The one rule: drop a connection to the published address and port from any other source."""
    return (
        *("-p", "tcp", "-m", "conntrack"),
        *("--ctorigdst", address, "--ctorigdstport", port, "--ctdir", "ORIGINAL"),
        *("!", "-s", source),
        *("-j", "DROP"),
    )


def run(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run one command from its argument list, or return None if it cannot run or finish."""
    try:
        return subprocess.run(  # noqa: S603 -- argv is a fixed list, and no shell is involved
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def learn(argv: list[str], question: str) -> subprocess.CompletedProcess[str]:
    """Run a probe whose answer decides what is installed, and refuse when no answer comes."""
    result = run(argv)
    if result is None:
        die(
            f"{PREFIX}: could not learn {question}: {' '.join(argv)} did not run to completion",
            f"{PREFIX}: refusing rather than guess",
        )
    return result


def passthrough(result: subprocess.CompletedProcess[str]) -> None:
    """Pass a command's own output on, as it appeared when the command ran unredirected."""
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)


def first_rule(listing: str) -> str:
    """The first rule line of a chain listing (`iptables -S`), or an empty string."""
    for line in listing.splitlines():
        if line.startswith(f"-A {CHAIN} "):
            return line
    return ""


def is_the_rule(line: str, address: str, port: str, source: str) -> bool:
    """Whether a rule line is this rule, whatever order iptables prints its options in.

    Each value ends at a space, the end of the line or a /32, so 8081 is not read inside
    80810 and 10.20.1.50 is not read inside 10.20.1.500.
    """
    end = r"(?:/32)?(?= |$)"
    wanted = (
        rf"--ctorigdst {re.escape(address)}{end}",
        rf"--ctorigdstport {re.escape(port)}(?= |$)",
        r"--ctdir ORIGINAL(?= |$)",
        rf"! -s {re.escape(source)}{end}",
        r"-j DROP$",
    )
    return all(re.search(pattern, line) is not None for pattern in wanted)


def ensure_rule(address: str, port: str, source: str) -> None:
    """Make the rule present and first in DOCKER-USER, or stop with a reason."""
    if shutil.which("iptables") is None:
        die(f"{PREFIX}: iptables is not installed: apply the host_baseline role first")

    chain = learn(["iptables", "-t", "filter", "-S", CHAIN], f"whether {CHAIN} exists")
    if chain.returncode != 0:
        passthrough(chain)
        die(
            f"{PREFIX}: no {CHAIN} chain in iptables -- either Docker is not running yet or its "
            "nftables firewall backend is active instead of iptables, and there is no safe "
            "substitute chain for this rule"
        )

    rule = rule_for(address, port, source)
    text = " ".join(rule)
    check = learn(["iptables", "-t", "filter", "-C", CHAIN, *rule], "whether the rule is present")
    if check.returncode not in (0, RULE_ABSENT_STATUS):
        passthrough(check)
        die(
            f"{PREFIX}: could not learn whether the rule is present: it exited {check.returncode}",
            f"{PREFIX}: refusing rather than guess",
        )

    if check.returncode == 0:
        if not is_the_rule(first_rule(chain.stdout), address, port, source):
            die(
                f"{PREFIX}: the rule is present in {CHAIN} but is not its first rule, so an "
                "earlier rule may accept the drain port before it is reached",
                f"{PREFIX}: remove the earlier rule or the stale copy and run this again",
            )
        print(f"{PREFIX}: {CHAIN} already carries first: {text}")
        return

    inserted = run(["iptables", "-t", "filter", "-I", CHAIN, "1", *rule])
    if inserted is None:
        die(f"{PREFIX}: could not insert into {CHAIN}")
    passthrough(inserted)
    if inserted.returncode != 0:
        die(
            f"{PREFIX}: iptables -I {CHAIN} exited {inserted.returncode}",
            status=inserted.returncode or 1,
        )
    print(f"{PREFIX}: inserted into {CHAIN} at 1: {text}")


def main() -> None:
    """Check the arguments, then make the rule present and first."""
    parser = argparse.ArgumentParser(prog=PREFIX, allow_abbrev=False)
    parser.add_argument(
        "--address", required=True, help="the private address the port is published on"
    )
    parser.add_argument("--port", required=True, help="the published drain port")
    parser.add_argument("--allow-source", required=True, help="the one source address allowed")
    arguments = parser.parse_args()
    address = single_address(arguments.address, "--address")
    source = single_address(arguments.allow_source, "--allow-source")
    port = unprivileged_port(arguments.port)
    if address == source:
        die(
            f"{PREFIX}: --allow-source is the published address itself: that allows nothing",
            status=2,
        )
    ensure_rule(address, port, source)


if __name__ == "__main__":
    main()
