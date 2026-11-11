#!/usr/bin/python3 -I
"""Limits the Sweego receiver's drain port to one source address, in DOCKER-USER.

Two DROP rules, in this order, are the first two rules of the chain. Each drops a TCP
connection to the drain port from any source but the one allowed:

1. on the container's address and port, which is where a packet is after Docker's DNAT and
   is also where a packet routed straight to the container arrives;
2. on the connection's original destination (the published address and port), in the
   original direction only, so a reply is never caught.

Run by the role's unit at every boot and after every restart of Docker. Idempotent: each
rule is checked before it is added. Takes its five values as arguments and checks every one.
A rule that is present but not at its place is not repaired: the program stops, because a
rule under an accept is not a rule. Every command runs from an argument list under a
timeout, and a probe that gives no answer stops the program. The reasoning, the packet
paths and what stays allowed are in the role README, "The drain-port rule".
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
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


def unprivileged_port(value: str, name: str) -> str:
    """Return the value if it is a whole number from 1024 to 65535, else stop."""
    if not value.isascii() or not value.isdigit() or not MIN_PORT <= int(value) <= MAX_PORT:
        die(f"{PREFIX}: {name} is {value!r}, not a whole number from 1024 to 65535", status=2)
    return str(int(value))


@dataclass(frozen=True)
class Rule:
    """One rule of the chain: its arguments, and whether an `iptables -S` line is it."""

    argv: tuple[str, ...]
    matches: Callable[[str], bool]


def ends(value: str) -> str:
    """The pattern for a value that ends at a space, the end of the line or a /32.

    So 8081 is not read inside 80810, and 10.20.1.50 is not read inside 10.20.1.500.
    """
    return rf"{re.escape(value)}(?:/32)?(?= |$)"


def after_dnat_rule(container: str, container_port: str, source: str) -> Rule:
    """Drop a connection to the container's drain listener from any source but the one.

    A packet is at the container's address after Docker's DNAT, and a packet routed straight
    to the container arrives there too, so one match covers both ways in.
    """
    argv = (
        *("-p", "tcp", "-d", container, "--dport", container_port),
        *("!", "-s", source, "-j", "DROP"),
    )
    # `! -d` and `! --dport` would invert the match, so neither may follow a bang.
    wanted = (
        rf"(?<!! )-d {ends(container)}",
        rf"(?<!! )--dport {re.escape(container_port)}(?= |$)",
        r"-p tcp(?= )",
        rf"! -s {ends(source)}",
        r"-j DROP$",
    )
    return Rule(argv, lambda line: all(re.search(p, line) is not None for p in wanted))


def original_destination_rule(address: str, port: str, source: str) -> Rule:
    """Drop a connection made to the published address and port from any source but the one."""
    argv = (
        *("-p", "tcp", "-m", "conntrack"),
        *("--ctorigdst", address, "--ctorigdstport", port, "--ctdir", "ORIGINAL"),
        *("!", "-s", source, "-j", "DROP"),
    )
    wanted = (
        rf"--ctorigdst {ends(address)}",
        rf"--ctorigdstport {re.escape(port)}(?= |$)",
        r"--ctdir ORIGINAL(?= |$)",
        rf"! -s {ends(source)}",
        r"-j DROP$",
    )
    return Rule(argv, lambda line: all(re.search(p, line) is not None for p in wanted))


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


def rule_lines(listing: str) -> list[str]:
    """The rule lines of a chain listing (`iptables -S`), in order."""
    return [line for line in listing.splitlines() if line.startswith(f"-A {CHAIN} ")]


def ensure_rules(rules: tuple[Rule, ...]) -> None:
    """Make each rule present at its place, rule N as the Nth rule of DOCKER-USER, or stop."""
    if shutil.which("iptables") is None:
        die(f"{PREFIX}: iptables is not installed: apply the host_baseline role first")

    for place, rule in enumerate(rules, start=1):
        chain = learn(["iptables", "-t", "filter", "-S", CHAIN], f"whether {CHAIN} exists")
        if chain.returncode != 0:
            passthrough(chain)
            die(
                f"{PREFIX}: no {CHAIN} chain in iptables -- either Docker is not running yet or "
                "its nftables firewall backend is active instead of iptables, and there is no "
                "safe substitute chain for this rule"
            )
        text = " ".join(rule.argv)
        check = learn(
            ["iptables", "-t", "filter", "-C", CHAIN, *rule.argv], "whether the rule is present"
        )
        if check.returncode not in (0, RULE_ABSENT_STATUS):
            passthrough(check)
            die(
                f"{PREFIX}: could not learn whether the rule is present: it exited "
                f"{check.returncode}",
                f"{PREFIX}: refusing rather than guess",
            )

        if check.returncode == 0:
            lines = rule_lines(chain.stdout)
            if len(lines) < place or not rule.matches(lines[place - 1]):
                die(
                    f"{PREFIX}: the rule is present in {CHAIN} but is not rule {place} of it, so "
                    "an earlier rule may accept the drain port before it is reached",
                    f"{PREFIX}: remove the earlier rule or the stale copy and run this again",
                )
            print(f"{PREFIX}: {CHAIN} already carries as rule {place}: {text}")
            continue

        inserted = run(["iptables", "-t", "filter", "-I", CHAIN, str(place), *rule.argv])
        if inserted is None:
            die(f"{PREFIX}: could not insert into {CHAIN}")
        passthrough(inserted)
        if inserted.returncode != 0:
            die(
                f"{PREFIX}: iptables -I {CHAIN} exited {inserted.returncode}",
                status=inserted.returncode or 1,
            )
        print(f"{PREFIX}: inserted into {CHAIN} at {place}: {text}")


def main() -> None:
    """Check the arguments, then make both rules present, as the first and second."""
    parser = argparse.ArgumentParser(prog=PREFIX, allow_abbrev=False)
    parser.add_argument(
        "--address", required=True, help="the private address the port is published on"
    )
    parser.add_argument("--port", required=True, help="the published drain port")
    parser.add_argument("--allow-source", required=True, help="the one source address allowed")
    parser.add_argument(
        "--container-address", required=True, help="the receiver container's own address"
    )
    parser.add_argument(
        "--container-port", required=True, help="the port the receiver's drain listener binds"
    )
    arguments = parser.parse_args()
    address = single_address(arguments.address, "--address")
    source = single_address(arguments.allow_source, "--allow-source")
    container = single_address(arguments.container_address, "--container-address")
    port = unprivileged_port(arguments.port, "--port")
    container_port = unprivileged_port(arguments.container_port, "--container-port")
    if source in (address, container):
        die(
            f"{PREFIX}: --allow-source is the published or the container address itself: "
            "that allows nothing",
            status=2,
        )
    if address == container:
        die(f"{PREFIX}: --address and --container-address are the same address", status=2)
    ensure_rules(
        (
            after_dnat_rule(container, container_port, source),
            original_destination_rule(address, port, source),
        )
    )


if __name__ == "__main__":
    main()
