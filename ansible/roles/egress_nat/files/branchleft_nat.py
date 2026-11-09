#!/usr/bin/python3 -I
"""Makes this host forward and source-NAT the estate's private subnet out of
its own public interface, so that hosts created without public networking
have an outbound internet path at all.

Installed as /usr/local/sbin/branchleft-nat by the egress_nat role and re-run
at every boot by branchleft-nat.service. Idempotent: every rule is checked
before it is added, and re-running it is the correct response to "is that
host still the gateway".

This is only the host half. The network half is the default route declared
in the network stack; without it nothing is ever sent here to forward.

The checks run in the order the shell program they replace ran them, with the
same messages, and the rules are inserted in the same order. Every external
command runs from an argument list, never through a shell, under a timeout. A
command that cannot run or does not finish counts as a failure, and the program
stops rather than go on without it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

# Overridable by environment so the tests can drive a different range. Production
# gets the defaults, since nothing sets these in the environment.
DEFAULT_SUBNET = "10.20.1.0/24"
DEFAULT_SYSCTL_CONF = "/etc/sysctl.d/99-branchleft-nat.conf"
FORWARDING_LINE = "net.ipv4.ip_forward = 1\n"
# The membership test below is a string prefix, which is only equivalent to a
# subnet match at /24. Refusing anything else is deliberate: a widened range
# would otherwise silently narrow the guard rather than fail.
SUBNET_SUFFIX = ".0/24"
COMMAND_TIMEOUT_SECONDS = 30


def die(*lines: str, status: int = 1) -> NoReturn:
    """Print each line to stderr and stop with the status."""
    for line in lines:
        print(line, file=sys.stderr)
    sys.exit(status)


def run(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run one command from its argument list.

    Returns None when the command cannot run or does not finish in time.
    """
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
    install rules on a guess, so the program stops with nothing more installed.
    """
    result = run(argv)
    if result is None:
        die(
            f"branchleft-nat: could not learn {question}: "
            f"{' '.join(argv)} did not run to completion",
            "branchleft-nat: refusing rather than guess",
        )
    return result


def passthrough(result: subprocess.CompletedProcess[str] | None) -> None:
    """Pass a command's own output on, as the shell did when the command ran unredirected."""
    if result is None:
        return
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)


def succeeded(result: subprocess.CompletedProcess[str] | None) -> bool:
    """Whether a command ran and exited zero."""
    return result is not None and result.returncode == 0


def status_of(result: subprocess.CompletedProcess[str] | None) -> int:
    """The status a failed command passes on: its own when it is 1 to 255, else 1."""
    if result is None or not 0 < result.returncode < 256:
        return 1
    return result.returncode


def is_private_v4(address: str) -> bool:
    """Whether an IPv4 address is in a range that is not routed on the internet."""
    if address.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    octets = address.split(".")
    return (
        octets[0] == "172"
        and len(octets) > 1
        and octets[1].isdigit()
        and 16 <= int(octets[1]) <= 31
    )


def subnet_prefix(subnet: str) -> str:
    """The string prefix that tests membership of a /24 subnet."""
    if not subnet.endswith(SUBNET_SUFFIX):
        die(f"branchleft-nat: only a /24 subnet is understood, got {subnet}")
    return subnet[: -len(SUBNET_SUFFIX)] + "."


def default_uplink() -> str:
    """The interface the default route leaves through, or the empty string."""
    result = run(["ip", "-4", "route", "show", "default"])
    if result is None:
        return ""
    for line in result.stdout.splitlines():
        fields = line.split()
        for index in range(len(fields) - 1):
            if fields[index] == "dev":
                return fields[index + 1]
    return ""


def global_addresses() -> list[tuple[str, str]]:
    """Each IPv4 address with global scope, as (interface, address).

    A command that cannot run yields no addresses, which the caller refuses.
    """
    result = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    if result is None:
        return []
    found: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        ifname = fields[1] if len(fields) > 1 else ""
        address = fields[3].split("/")[0] if len(fields) > 3 else ""
        found.append((ifname, address))
    return found


def write_file(path: Path, content: bytes, mode: int) -> None:
    """Replace the file at path with content in one step, with the given mode.

    Raises:
        OSError: the file cannot be written or replaced.
    """
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def write_forwarding_drop_in(conf: Path) -> None:
    """Write the persistent forwarding setting, unless it is already there.

    The running value is not ours to rely on: dockerd turns forwarding on for its
    own bridges at start, so the setting has to be written as well as set.
    """
    try:
        current = conf.read_bytes()
    except OSError:
        current = b""
    if current == FORWARDING_LINE.encode():
        print(f"branchleft-nat: {conf} already up to date")
        return
    try:
        write_file(conf, FORWARDING_LINE.encode(), 0o644)
    except OSError:
        die(f"branchleft-nat: could not write {conf}")
    print(f"branchleft-nat: wrote {conf}")


def turn_forwarding_on() -> None:
    """Turn IPv4 forwarding on for the running kernel."""
    result = run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
    passthrough(result)
    if not succeeded(result):
        sys.exit(status_of(result))


def forward_chain() -> str:
    """The chain forwarded traffic is filtered in.

    DOCKER-USER is the chain Docker guarantees it will jump to first and will not
    flush, so it is preferred wherever it exists. FORWARD is the fallback on a host
    where Docker is not installed and the policy is still ACCEPT.
    """
    if (
        learn(
            ["iptables", "-t", "filter", "-S", "DOCKER-USER"], "whether DOCKER-USER exists"
        ).returncode
        == 0
    ):
        return "DOCKER-USER"
    # dockerd creates DOCKER-USER unconditionally at startup under the iptables
    # backend, so its absence with the daemon running means iptables is not what
    # dockerd enforces through. Its nftables firewall backend manages its own tables
    # instead, and a rule written into FORWARD is one Docker's DROP policy never
    # consults.
    active = learn(
        ["systemctl", "is-active", "--quiet", "docker.service"], "whether docker.service is active"
    )
    if active.returncode == 0:
        die(
            "branchleft-nat: docker.service is active but iptables carries no DOCKER-USER chain -- "
            "Docker is not enforcing through iptables here (its nftables firewall backend, most "
            "likely), and FORWARD is not a safe substitute"
        )
    return "FORWARD"


def ensure_rule(table: str, chain: str, *rule: str) -> None:
    """Insert a rule at the top of a chain, once.

    A rule that is already present is left where it is.
    """
    text = " ".join(rule)
    check = learn(
        ["iptables", "-t", table, "-C", chain, *rule],
        f"whether {table}/{chain} already carries the rule",
    )
    if check.returncode == 0:
        print(f"branchleft-nat: {table}/{chain} already carries: {text}")
        return
    inserted = run(["iptables", "-t", table, "-I", chain, "1", *rule])
    passthrough(inserted)
    if not succeeded(inserted):
        sys.exit(status_of(inserted))
    print(f"branchleft-nat: inserted into {table}/{chain}: {text}")


def main() -> None:
    subnet = os.environ.get("BRANCHLEFT_NAT_SUBNET") or DEFAULT_SUBNET
    conf = Path(os.environ.get("BRANCHLEFT_NAT_SYSCTL_CONF") or DEFAULT_SYSCTL_CONF)
    prefix = subnet_prefix(subnet)

    # Debian ships no iptables in the cloud image; it arrives as a dependency of
    # docker-ce. Named explicitly because the alternative is a failure from inside a
    # systemd oneshot, which reads as a broken unit rather than a missing step.
    if shutil.which("iptables") is None:
        die("branchleft-nat: iptables is not installed -- run 20-install-docker.sh first")

    uplink = default_uplink()
    if not uplink:
        die("branchleft-nat: this host has no default route, so it has nothing to forward to")

    addresses = global_addresses()
    # The failure this refuses is a routing loop that takes the whole estate's egress
    # with it: a private-only host's own default route is the network gateway, so a
    # private-only host told to masquerade sends every packet it is given straight
    # back into the network it came from. Publicness is a property of the interface
    # the default route leaves through, not of the host as a whole.
    if not any(ifname == uplink and not is_private_v4(address) for ifname, address in addresses):
        die(
            f"branchleft-nat: the default route leaves through {uplink}, "
            "which holds no public address",
            "branchleft-nat: only a host that terminates public traffic "
            "can be the estate's gateway",
        )

    if not any(address.startswith(prefix) for _, address in addresses):
        die(
            f"branchleft-nat: this host holds no address in {subnet}, "
            "so nothing routed there reaches it"
        )

    write_forwarding_drop_in(conf)
    turn_forwarding_on()
    chain = forward_chain()

    # Scoped to the subnet as source and the uplink as output, so private-to-private
    # traffic is never rewritten and no other source can be laundered through this
    # host's public address.
    ensure_rule("nat", "POSTROUTING", "-s", subnet, "-o", uplink, "-j", "MASQUERADE")

    # Directional on purpose. Outbound is accepted unconditionally; the return
    # direction is accepted only for a flow conntrack already knows, so forwarding
    # stays a one-way capability and nothing on the internet can initiate a
    # connection into a host that has no public address.
    ensure_rule(
        "filter",
        chain,
        "-s",
        subnet,
        "-o",
        uplink,
        "-j",
        "ACCEPT",
    )
    ensure_rule(
        "filter",
        chain,
        "-d",
        subnet,
        "-i",
        uplink,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    )

    # No MSS clamp. The private link's MTU is lower than the uplink's, which is the
    # usual reason one is needed, but every flow here is opened by the private host,
    # so the MSS it advertises is already derived from the lower of the two.
    print(f"branchleft-nat: forwarding {subnet} out of {uplink}, filtered in {chain}")


if __name__ == "__main__":
    main()
