#!/usr/bin/python3 -I
"""Confines what a container on an app host may reach, in the DOCKER-USER chain.

Every container's forwarded reach is limited to db1:3306 (skipped on a host that
is not a Ghost tenant host), and everything a container on the mail spool's
drain bridge opens is refused, over IPv4 and IPv6. On ops1 alone the published
control-plane ports 8300, 8301, 8302 and 8303 are also refused to every source
but the gateway. Installed as /usr/local/sbin/branchleft-docker-user-policy by
the deploy_tooling role and re-run at boot by its unit, with no arguments and
no environment. Refuses to run on edge1. Idempotent: every rule is checked
before it is added.

Every rule is inserted at the top of its chain, so the order the calls run in is
the reverse of the order the rules are evaluated in. That order is load-bearing:
the conntrack accept must be evaluated before any drop, or the replies of
allowed flows are dropped. The role's README and the unit tests say why.

Every external command runs from an argument list, never through a shell, under
a timeout. A probe that cannot run or does not finish counts as no answer, and
the program stops rather than guess.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn

PREFIX = "branchleft-docker-user-policy"
ENVIRONMENT_PREFIX = "BRANCHLEFT_DOCKER_USER_POLICY_"

# The estate's addresses, restated because this program has no stack state to read
# them from. They are hetzner-host/addressPlan.ts's HOST_IPS and subnet. The
# environment overrides below exist so the tests can drive other values; nothing
# sets them on a host, and a value that is not an address, a port or a bridge name
# is refused.
DEFAULT_SUBNET = "10.20.1.0/24"
DEFAULT_DB_PORT = "3306"
DEFAULT_GATEWAY_PRIVATE_IP = "10.20.1.10"
DEFAULT_DB_HOST = "10.20.1.20"
# A host holding one of these addresses is not a Ghost tenant host, so it gets no
# exception for db1 and recognises itself from its own address alone.
DEFAULT_NO_DB_EXCEPTION_ADDRESSES = "10.20.1.50"
# ops1's published control-plane ports (the sign-in service, the tenant portal, the
# owner console and the status page): reachable from the gateway alone. A host
# holding the protected address gets one drop per port for every source but the
# gateway; any other host gets none.
DEFAULT_PROTECTED_ADDRESS = "10.20.1.50"
DEFAULT_PROTECTED_PORTS = "8300 8301 8302 8303"
# The spool's one non-internal network, a bridge with a fixed name so a host rule
# can match it. The spool opens no connection of its own, so everything it opens
# off this bridge is refused.
DEFAULT_MAIL_SPOOL_BRIDGE = "br-mailspool"
# The metadata service's own address: the provider's, not the estate's.
METADATA_ADDRESS = "169.254.169.254"

COMMAND_TIMEOUT_SECONDS = 30
BRIDGE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")
PORT_NUMBER = re.compile(r"[0-9]{1,5}")
CONNTRACK_REPLIES = ("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")


def die(*lines: str, status: int = 1) -> NoReturn:
    """Print each line to stderr and stop with the status."""
    for line in lines:
        print(line, file=sys.stderr)
    sys.exit(status)


@dataclass(frozen=True)
class Settings:
    """What the program was told, with the estate's values for what it was not."""

    subnet: str
    db_port: str
    gateway_ip: str
    no_db_exception_addresses: tuple[str, ...]
    db_host_override: str | None
    protected_address: str
    protected_ports: tuple[str, ...]
    mail_spool_bridge: str


def is_address(value: str) -> bool:
    """Whether a value is one IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def is_subnet(value: str) -> bool:
    """Whether a value is an IPv4 network written with its prefix length."""
    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return False
    return "/" in value


def is_port(value: str) -> bool:
    """Whether a value is a TCP port number."""
    return PORT_NUMBER.fullmatch(value) is not None and 0 < int(value) < 65536  # noqa: PLR2004


def read_settings(environment: Mapping[str, str]) -> Settings:
    """Return the settings, with an unset or empty value taking the estate's own.

    An address list, a port list, a subnet or a bridge name that is not that shape is
    refused. The database host is the one value that may be set to empty on purpose: an
    explicit empty value means no exception for db1, and wins over self-identification.
    """

    def value(name: str, default: str) -> str:
        return environment.get(ENVIRONMENT_PREFIX + name) or default

    subnet = value("SUBNET", DEFAULT_SUBNET)
    db_port = value("DB_PORT", DEFAULT_DB_PORT)
    gateway_ip = value("GATEWAY_IP", DEFAULT_GATEWAY_PRIVATE_IP)
    protected_address = value("PROTECTED_ADDRESS", DEFAULT_PROTECTED_ADDRESS)
    bridge = value("MAIL_SPOOL_BRIDGE", DEFAULT_MAIL_SPOOL_BRIDGE)
    no_db = tuple(value("NO_DB_EXCEPTION_ADDRESSES", DEFAULT_NO_DB_EXCEPTION_ADDRESSES).split())
    ports = tuple(value("PROTECTED_PORTS", DEFAULT_PROTECTED_PORTS).split())
    db_host = environment.get(ENVIRONMENT_PREFIX + "DB_HOST")

    checks = (
        ("SUBNET", subnet, is_subnet(subnet)),
        ("DB_PORT", db_port, is_port(db_port)),
        ("GATEWAY_IP", gateway_ip, is_address(gateway_ip)),
        ("PROTECTED_ADDRESS", protected_address, is_address(protected_address)),
        ("MAIL_SPOOL_BRIDGE", bridge, BRIDGE_NAME.fullmatch(bridge) is not None),
        ("DB_HOST", db_host or "", db_host is None or db_host == "" or is_address(db_host)),
        *(("NO_DB_EXCEPTION_ADDRESSES", address, is_address(address)) for address in no_db),
        *(("PROTECTED_PORTS", port, is_port(port)) for port in ports),
    )
    for name, checked, usable in checks:
        if not usable:
            die(f"{PREFIX}: {ENVIRONMENT_PREFIX}{name} is {checked!r}, which is not a usable value")
    return Settings(
        subnet=subnet,
        db_port=db_port,
        gateway_ip=gateway_ip,
        no_db_exception_addresses=no_db,
        db_host_override=db_host,
        protected_address=protected_address,
        protected_ports=ports,
        mail_spool_bridge=bridge,
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
    """Run a probe whose answer decides what is installed, and refuse when no answer comes.

    A probe that times out or cannot run has told us nothing. Reading that as "no" would
    insert rules on a guess, so the program stops with nothing more inserted.
    """
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


def status_of(result: subprocess.CompletedProcess[str] | None) -> int:
    """The status a failed command passes on: its own when it is 1 to 255, else 1."""
    if result is None or not 0 < result.returncode < 256:  # noqa: PLR2004
        return 1
    return result.returncode


def held_addresses() -> list[str]:
    """Return every IPv4 address with global scope that this host holds."""
    result = learn(
        ["ip", "-4", "-o", "addr", "show", "scope", "global"], "which addresses it holds"
    )
    found: list[str] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) > 3:  # noqa: PLR2004
            found.append(fields[3].split("/")[0])
    return found


def ensure_rule_at(tool: str, position: int, chain: str, *rule: str) -> None:
    """Insert a rule into a chain of the filter table at a position, once.

    A rule that is already present is left where it is.
    """
    text = " ".join(rule)
    where = f"filter/{chain}"
    check = learn(
        [tool, "-t", "filter", "-C", chain, *rule], f"whether {tool} {where} already carries a rule"
    )
    if check.returncode == 0:
        print(f"{PREFIX}: {tool} {where} already carries: {text}")
        return
    inserted = run([tool, "-t", "filter", "-I", chain, str(position), *rule])
    if inserted is None:
        die(f"{PREFIX}: {tool} could not insert into {where}")
    passthrough(inserted)
    if inserted.returncode != 0:
        die(status=status_of(inserted))
    print(f"{PREFIX}: {tool} inserted into {where} at {position}: {text}")


def port_drop(settings: Settings, port: str) -> tuple[str, ...]:
    """Return the rule that refuses a new connection to one published port, gateway excepted."""
    return (
        *("-p", "tcp", "-m", "conntrack"),
        *("--ctorigdst", settings.protected_address, "--ctorigdstport", port),
        *("!", "-s", settings.gateway_ip),
        *("-j", "DROP"),
    )


def ensure_spool_rules(tool: str, forward_position: int, bridge: str) -> None:
    """Refuse everything the spool's drain bridge opens, forwarded or to the host itself.

    Written after the conntrack accept so a failure here cannot drop replies. The forward
    drop goes at the position given: IPv4 puts it at 2, under the conntrack accept, so a
    re-run orders as a boot does. IPv6 has no accept of ours and Docker's own RETURN may be
    the chain's only rule, so it goes at 1, above that RETURN, which also works on an empty
    chain.
    """
    if shutil.which(tool) is None:
        die(f"{PREFIX}: {tool} is not installed")
    chain_exists = learn([tool, "-t", "filter", "-S", "DOCKER-USER"], f"whether {tool} has a chain")
    if chain_exists.returncode == 0:
        ensure_rule_at(
            tool, forward_position, "DOCKER-USER", "-i", bridge, "!", "-o", bridge, "-j", "DROP"
        )
    else:
        print(
            f"{PREFIX}: no {tool} DOCKER-USER chain, so Docker forwards no such traffic yet; "
            "forward drop skipped"
        )
    ensure_rule_at(tool, 1, "INPUT", "-i", bridge, "-j", "DROP")
    ensure_rule_at(tool, 1, "INPUT", "-i", bridge, *CONNTRACK_REPLIES)


def apply(settings: Settings) -> None:
    """Check the host is an app host with an iptables DOCKER-USER chain, then insert the rules."""
    # Debian ships no iptables in the cloud image; it arrives as a dependency of docker-ce.
    # Named explicitly because the alternative is a failure from inside a systemd oneshot,
    # which reads as a broken unit rather than a missing step.
    if shutil.which("iptables") is None:
        die(f"{PREFIX}: iptables is not installed: apply the host_baseline role first")

    # The role guard. "Holds a public address" is not the test: app1 has one too, for CI
    # SSH deploys. What identifies edge1 is its address, which no app host holds.
    addresses = held_addresses()
    if settings.gateway_ip in addresses:
        die(
            f"{PREFIX}: this host holds the estate's gateway address ({settings.gateway_ip}) -- "
            "it is edge1, not an app host, and this policy is scoped to app hosts only"
        )
    holds_protected = settings.protected_address in addresses
    no_db_exception = any(address in addresses for address in settings.no_db_exception_addresses)

    # An explicit caller value, empty included, wins over self-identification, which only
    # supplies the default for a host that was never told anything (every real boot).
    if settings.db_host_override is not None:
        db_host = settings.db_host_override
    elif no_db_exception:
        db_host = ""
    else:
        db_host = DEFAULT_DB_HOST

    # DOCKER-USER exists only under dockerd's iptables firewall backend. There is no safe
    # substitute chain: a policy that bounds container traffic has nothing to bound where
    # Docker is not enforcing through iptables, and FORWARD would filter traffic that has
    # nothing to do with any container.
    chain = learn(["iptables", "-t", "filter", "-S", "DOCKER-USER"], "whether DOCKER-USER exists")
    if chain.returncode != 0:
        die(
            f"{PREFIX}: no DOCKER-USER chain in iptables -- either Docker is not installed yet "
            "(apply the host_baseline role first) or its nftables firewall backend is active "
            "instead of iptables, and there is no safe substitute chain for this policy"
        )

    def insert(position: int, *rule: str) -> None:
        ensure_rule_at("iptables", position, "DOCKER-USER", *rule)

    # Written in the reverse of the order the rules must be evaluated in: each insert lands
    # at position 1, so whichever call runs last is matched first. The two drops go in
    # before either accept, so neither accept is pushed below them by a later insert.
    # The decided order is (1) established traffic, (2) db1, (3) drop the rest.
    #
    # DOCKER-USER sees every forwarded packet on the host, including a tenant's own outbound
    # traffic to the public internet, so the drops name the subnet and the metadata address
    # specifically rather than refusing everything that is not db1.
    insert(1, "-d", METADATA_ADDRESS, "-j", "DROP")
    insert(1, "-d", settings.subnet, "-j", "DROP")

    # The one destination a Ghost tenant legitimately opens, scoped to TCP and the port
    # MySQL listens on, not merely the address. Skipped entirely when the database host is
    # empty, which turns this into a deny-all-to-the-subnet policy for a host with no
    # reason to reach db1.
    if db_host:
        insert(1, "-d", db_host, "-p", "tcp", "--dport", settings.db_port, "-j", "ACCEPT")

    # Has to be the first rule DOCKER-USER evaluates. A published port is a DNAT, so an
    # inbound flow's reply leaves the container with a destination inside the subnet,
    # exactly what the drop above matches, and conntrack state is the only thing that tells
    # that reply apart from a tenant-initiated connection to a co-tenant.
    insert(1, *CONNTRACK_REPLIES)

    # Published ports on the protected address are refused to every source but the gateway.
    # Docker publishes a port with a DNAT, which bypasses INPUT and leaves DOCKER-USER seeing
    # the container's address and port, so the rule matches the original destination through
    # conntrack. Position 2, under the accept: the reply of an allowed flow is the accept
    # above, and a new connection from anyone else is dropped here.
    if holds_protected:
        for port in settings.protected_ports:
            insert(2, *port_drop(settings, port))

    ensure_spool_rules("iptables", 2, settings.mail_spool_bridge)
    ensure_spool_rules("ip6tables", 1, settings.mail_spool_bridge)
    print(f"{PREFIX}: app-host isolation applied in DOCKER-USER")


def main() -> None:
    """Apply the policy, or print why not and exit with a status."""
    if len(sys.argv) > 1:
        die(f"usage: {PREFIX} (takes no arguments)", status=2)
    apply(read_settings(os.environ))


if __name__ == "__main__":
    main()
