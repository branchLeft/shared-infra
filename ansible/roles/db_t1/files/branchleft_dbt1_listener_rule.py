#!/usr/bin/python3 -I
"""Admits one source to db-t1's database port and drops every other source, in INPUT.

The database listens on the host's private address with host networking, so a connection
to it reaches the host's INPUT chain, not DOCKER-USER. The cloud firewall does not filter
the private network. This program owns one iptables chain, BRANCHLEFT-DBT1-IN, holding two
rules in this order, and one jump to that chain from INPUT:

1. TCP to the database port from the one allowed source: ACCEPT.
2. TCP to the database port from any other source: DROP.

Nothing else is touched: no other chain, no policy, no other port (SSH included). A packet
for another port matches neither rule and falls through the chain back to INPUT.

The chain is loaded in one atomic `iptables-restore --noflush`, so a reassert at a reload
never leaves the chain empty for a moment. The jump is inserted as the first rule of INPUT
when it is absent. A jump that is present is left where it is if only fail2ban's own jumps
(`-j f2b-*`) stand above it, and is a refusal anywhere else, because a rule under an earlier
rule that accepts the port is not a rule.

Run by the role's unit at every boot, before Docker starts, and on a reload. Idempotent.
`--check` changes nothing: it prints what a run would change and exits 3 when anything
differs, 0 when everything is in place. Every command runs from an argument list under a
timeout, and a probe that gives no answer stops the program rather than guess. The design
and what stays open are in the role README, "The listener rule".
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import NoReturn

PREFIX = "branchleft-dbt1-listener-rule"
CHAIN = "BRANCHLEFT-DBT1-IN"
PARENT = "INPUT"
COMMAND_TIMEOUT_SECONDS = 30
# How long iptables waits for the xtables lock another program (fail2ban, the NAT unit) holds.
LOCK_WAIT_SECONDS = "10"
CHECK_DIFFERS_STATUS = 3
MIN_PORT = 1024
MAX_PORT = 65535
# fail2ban inserts its own jump at the top of INPUT whenever it starts; the jump to this
# program's chain may sit below those and nothing else.
FAIL2BAN_JUMP = re.compile(r"^-A INPUT .*-j f2b-[A-Za-z0-9_-]+$")


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


def normal(line: str) -> tuple[str, ...]:
    """The words of a rule line as `iptables -S` prints it, in one form.

    A source prints with its /32 and a TCP match prints `-m tcp` before the port; neither
    is part of what is meant, so the first is added and the second dropped, and a line made
    either way compares equal.
    """
    words = line.split()
    out: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word == "-m" and words[index + 1 : index + 2] == ["tcp"]:
            index += 2
            continue
        if word in ("-s", "-d") and index + 1 < len(words):
            value = words[index + 1]
            out.extend([word, value if "/" in value else f"{value}/32"])
            index += 2
            continue
        out.append(word)
        index += 1
    return tuple(out)


def wanted_rules(source: str, port: str) -> tuple[tuple[str, ...], ...]:
    """The chain's two rules, in order, in their normal form."""
    return (
        normal(f"-A {CHAIN} -s {source} -p tcp --dport {port} -j ACCEPT"),
        normal(f"-A {CHAIN} -p tcp --dport {port} -j DROP"),
    )


def restore_text(source: str, port: str) -> str:
    """The `iptables-restore --noflush` input that makes the chain exactly the two rules.

    The chain is declared (so it exists whether or not it did), emptied and refilled inside
    one transaction, and no other chain of the table is named.
    """
    lines = [
        "*filter",
        f":{CHAIN} - [0:0]",
        f"-F {CHAIN}",
        f"-A {CHAIN} -s {source} -p tcp --dport {port} -j ACCEPT",
        f"-A {CHAIN} -p tcp --dport {port} -j DROP",
        "COMMIT",
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Live:
    """What the kernel's filter table holds, as far as this program owns or reads it."""

    chain_declared: bool
    chain_rules: tuple[tuple[str, ...], ...]
    parent_rules: tuple[str, ...]


def run(argv: list[str], text: str | None = None) -> subprocess.CompletedProcess[str] | None:
    """Run one command from its argument list, or return None if it cannot run or finish."""
    try:
        return subprocess.run(  # noqa: S603 -- argv is a fixed list, and no shell is involved
            argv,
            input=text,
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def passthrough(result: subprocess.CompletedProcess[str]) -> None:
    """Pass a command's own output on, as it appeared when the command ran unredirected."""
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)


def read_live() -> Live:
    """Read the filter table once, or refuse when no answer comes."""
    argv = ["iptables", "-w", LOCK_WAIT_SECONDS, "-t", "filter", "-S"]
    result = run(argv)
    if result is None:
        die(
            f"{PREFIX}: could not read the filter table: {' '.join(argv)} did not run to "
            "completion",
            f"{PREFIX}: refusing rather than guess",
        )
    if result.returncode != 0:
        passthrough(result)
        die(f"{PREFIX}: {' '.join(argv)} exited {result.returncode}")
    lines = result.stdout.splitlines()
    return Live(
        chain_declared=f"-N {CHAIN}" in lines,
        chain_rules=tuple(normal(line) for line in lines if line.startswith(f"-A {CHAIN} ")),
        parent_rules=tuple(line for line in lines if line.startswith(f"-A {PARENT} ")),
    )


def jump_line() -> str:
    """The one rule of INPUT this program owns, as `iptables -S` prints it."""
    return f"-A {PARENT} -j {CHAIN}"


def jump_place(live: Live) -> int | None:
    """Return the 0-based place of the jump in INPUT, None if absent, or stop if misplaced.

    A refusal is not a repair: the rules above the jump are not this program's to move.
    """
    places = [i for i, line in enumerate(live.parent_rules) if line == jump_line()]
    if not places:
        return None
    if len(places) > 1:
        die(
            f"{PREFIX}: {PARENT} holds the jump to {CHAIN} {len(places)} times, not once",
            f"{PREFIX}: remove the extra copies by hand and run this again",
        )
    place = places[0]
    stray = [line for line in live.parent_rules[:place] if not FAIL2BAN_JUMP.match(line)]
    if stray:
        die(
            f"{PREFIX}: the jump to {CHAIN} is rule {place + 1} of {PARENT}, under a rule "
            f"that is not a fail2ban jump ({stray[0]}), which may accept the database port "
            "before it is reached",
            f"{PREFIX}: remove the earlier rule or the stale jump and run this again",
        )
    return place


def chain_is_right(live: Live, source: str, port: str) -> bool:
    """Whether the chain exists and holds exactly the two rules, in order."""
    return live.chain_declared and live.chain_rules == wanted_rules(source, port)


def differences(live: Live, source: str, port: str) -> list[str]:
    """Lines that say what a run would change; empty when everything is in place."""
    wanted = wanted_rules(source, port)
    found: list[str] = []
    if not live.chain_declared:
        found.append(f"+ chain {CHAIN}")
    found.extend(f"- {' '.join(rule)}" for rule in live.chain_rules if rule not in wanted)
    found.extend(f"+ {' '.join(rule)}" for rule in wanted if rule not in live.chain_rules)
    if not found and not chain_is_right(live, source, port):
        # The same two rules in the wrong order: the drop would sit above the accept.
        found.append(f"~ the rules of {CHAIN} are not in order: accept first, drop second")
    if jump_place(live) is None:
        found.append(f"+ {jump_line()}")
    return found


def load_chain(source: str, port: str) -> None:
    """Make the chain exactly the two rules, in one transaction."""
    argv = ["iptables-restore", "--noflush", "-w", LOCK_WAIT_SECONDS]
    loaded = run(argv, restore_text(source, port))
    if loaded is None:
        die(f"{PREFIX}: could not load {CHAIN}: {' '.join(argv)} did not run to completion")
    passthrough(loaded)
    if loaded.returncode != 0:
        die(f"{PREFIX}: {' '.join(argv)} exited {loaded.returncode}", status=loaded.returncode)


def insert_jump() -> None:
    """Insert the jump as the first rule of INPUT."""
    argv = ["iptables", "-w", LOCK_WAIT_SECONDS, "-t", "filter", "-I", PARENT, "1", "-j", CHAIN]
    inserted = run(argv)
    if inserted is None:
        die(f"{PREFIX}: could not insert into {PARENT}: {' '.join(argv)} did not run to completion")
    passthrough(inserted)
    if inserted.returncode != 0:
        die(
            f"{PREFIX}: iptables -I {PARENT} exited {inserted.returncode}",
            status=inserted.returncode,
        )


def ensure(source: str, port: str, *, check_only: bool) -> int:
    """Make the chain and the jump what they should be, or only say what would change."""
    for tool in ("iptables", "iptables-restore"):
        if shutil.which(tool) is None:
            die(f"{PREFIX}: {tool} is not installed: apply the host_baseline role first")
    live = read_live()
    found = differences(live, source, port)
    if check_only:
        for line in found:
            print(f"{PREFIX}: {line}")
        if not found:
            print(f"{PREFIX}: {CHAIN} and its jump in {PARENT} are as wanted")
        return CHECK_DIFFERS_STATUS if found else 0

    if not chain_is_right(live, source, port):
        load_chain(source, port)
    if jump_place(live) is None:
        insert_jump()
    after = read_live()
    left = differences(after, source, port)
    if left:
        die(
            f"{PREFIX}: the table still differs after the load:",
            *(f"{PREFIX}: {line}" for line in left),
        )
    print(f"{PREFIX}: {CHAIN} holds the two rules and {PARENT} jumps to it")
    return 0


def main() -> None:
    """Check the arguments, then make the chain and the jump present, or report a diff."""
    parser = argparse.ArgumentParser(prog=PREFIX, allow_abbrev=False)
    parser.add_argument("--allow-source", required=True, help="the one source address admitted")
    parser.add_argument("--port", required=True, help="the database's TCP port")
    parser.add_argument(
        "--check",
        action="store_true",
        help="change nothing; print the difference and exit 3 if there is one",
    )
    arguments = parser.parse_args()
    source = single_address(arguments.allow_source, "--allow-source")
    port = unprivileged_port(arguments.port, "--port")
    sys.exit(ensure(source, port, check_only=arguments.check))


if __name__ == "__main__":
    main()
