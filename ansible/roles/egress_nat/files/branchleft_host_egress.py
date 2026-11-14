#!/usr/bin/python3 -I
"""Gives a private-only host (no public interface) a default route via the estate's private
network gateway, and Hetzner's own recursive resolvers.

Installed as /usr/local/sbin/branchleft-host-egress by the egress_nat role and re-run at every
boot and about every minute by branchleft-host-egress.service and its timer. Neither the route nor
the resolver config survives a reboot on its own, so this is what keeps both true for the rest of
the host's life.

A no-op, and the only thing it does, on any host that already has a public interface: nothing here
is meant to touch such a host's routing at all.

This is only the host half. The network half is the default route declared for the estate's
private network, and the far end is the NAT gateway reconciler on the gateway host.

The checks run in the order the shell program they replace ran them, with the same messages.
Every external command runs from an argument list, never through a shell, under a timeout.
A command that cannot run or does not finish counts as a failure, and the program stops.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NoReturn

# Hetzner's own recursive resolvers: documented, estate-independent addresses, not a value this
# repository derives. Overridable by environment so the tests can point the write at a throwaway
# path; production always gets the defaults, since nothing sets these in the environment.
DEFAULT_NAMESERVER_1 = "185.12.64.1"
DEFAULT_NAMESERVER_2 = "185.12.64.2"
DEFAULT_RESOLVER_HEAD = "/etc/resolvconf/resolv.conf.d/head"

# The metadata service's own address. DHCP delivers it as a host route alongside the subnet route
# this program wants. It is Hetzner's address, not the estate's.
METADATA_ADDRESS = "169.254.169.254"

# The subnet route is not always in the table when this runs: at boot the network brings it up
# after network-online.target has been reached, so one look is not enough. Polled for a bounded
# total, then given up on.
DEFAULT_ROUTE_WAIT_SECONDS = 120
DEFAULT_ROUTE_POLL_SECONDS = 5
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


def env_int(name: str, default: int) -> int:
    """An integer from the environment, or the default when the variable is unset or empty."""
    value = os.environ.get(name) or str(default)
    try:
        return int(value)
    except ValueError:
        die(f"branchleft-host-egress: {name} is not a whole number of seconds: {value}")


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


def has_public_interface() -> bool:
    """Whether any global-scope IPv4 address on this host is outside the private ranges.

    A command that cannot run yields no addresses, which reads as no public interface, as the
    shell program did.
    """
    result = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    if result is None:
        return False
    for line in result.stdout.splitlines():
        fields = line.split()
        address = fields[3].split("/")[0] if len(fields) > 3 else ""
        if address and not is_private_v4(address):
            return True
    return False


def candidate_routes() -> list[str]:
    """The routing table's entries that carry a gateway, minus the default and metadata routes.

    The same selection as the shell program's grep pipeline: a line containing " via ", not
    starting with "default " or the metadata address. A command that cannot run yields none.
    """
    result = run(["ip", "-4", "route", "show"])
    if result is None:
        return []
    return [
        line
        for line in result.stdout.splitlines()
        if " via " in line
        and not line.startswith("default ")
        and not line.startswith(f"{METADATA_ADDRESS} ")
    ]


def wait_for_candidates(wait_seconds: int, poll_seconds: int) -> list[str]:
    """Look for a candidate route, polling for a bounded total before giving up."""
    candidates = candidate_routes()
    polls_left = wait_seconds // poll_seconds
    if not candidates and polls_left > 0:
        print(
            "branchleft-host-egress: no private subnet route yet, "
            f"waiting up to {wait_seconds}s for it",
            file=sys.stderr,
        )
    while not candidates and polls_left > 0:
        time.sleep(poll_seconds)
        polls_left -= 1
        candidates = candidate_routes()
    return candidates


def field_after(route: str, keyword: str) -> str:
    """The word after the first occurrence of keyword in a route line, or the empty string."""
    fields = route.split()
    for index, field in enumerate(fields):
        if field == keyword:
            return fields[index + 1] if index + 1 < len(fields) else ""
    return ""


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


def set_default_route(gateway: str, iface: str) -> None:
    """Point the default route at the gateway, unless it already does."""
    current = run(["ip", "-4", "route", "show", "default"])
    if current is None or current.returncode != 0:
        sys.exit(status_of(current))
    if current.stdout.startswith(f"default via {gateway} dev {iface}"):
        print(f"branchleft-host-egress: default route already via {gateway} dev {iface}, no-op")
        return
    replaced = run(["ip", "route", "replace", "default", "via", gateway, "dev", iface])
    passthrough(replaced)
    if not succeeded(replaced):
        sys.exit(status_of(replaced))
    print(f"branchleft-host-egress: default route set via {gateway} dev {iface}")


def set_resolver(resolver_head: Path, nameserver_1: str, nameserver_2: str) -> None:
    """Write the resolver head and refresh resolv.conf, unless the head is already right."""
    content = f"nameserver {nameserver_1}\nnameserver {nameserver_2}\n".encode()
    try:
        current: bytes | None = resolver_head.read_bytes()
    except OSError:
        current = None
    if current == content:
        print(f"branchleft-host-egress: {resolver_head} already up to date, no-op")
        return
    try:
        resolver_head.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        write_file(resolver_head, content, 0o644)
    except OSError:
        die(f"branchleft-host-egress: could not write {resolver_head}")
    refreshed = run(["resolvconf", "-u"])
    passthrough(refreshed)
    if not succeeded(refreshed):
        sys.exit(status_of(refreshed))
    print(f"branchleft-host-egress: wrote {resolver_head} and refreshed resolv.conf")


def main() -> None:
    # A host with a public interface is left exactly as it is.
    if has_public_interface():
        print("branchleft-host-egress: this host has a public interface, no-op")
        return

    # Checked before anything is mutated, not left to fail where it is used: a missing binary
    # would otherwise read as a broken program rather than a missing package.
    if shutil.which("resolvconf") is None:
        die(
            "branchleft-host-egress: resolvconf is not installed -- install the resolvconf package "
            "on this host and re-run"
        )

    wait_seconds = env_int("BRANCHLEFT_EGRESS_ROUTE_WAIT_SECONDS", DEFAULT_ROUTE_WAIT_SECONDS)
    poll_seconds = max(
        1, env_int("BRANCHLEFT_EGRESS_ROUTE_POLL_SECONDS", DEFAULT_ROUTE_POLL_SECONDS)
    )
    candidates = wait_for_candidates(wait_seconds, poll_seconds)

    if not candidates:
        die("branchleft-host-egress: no private subnet route found to derive a gateway from")
    if len(candidates) > 1:
        die(
            "branchleft-host-egress: more than one candidate subnet route, refusing to guess:",
            *(f"  {route}" for route in candidates),
        )

    route = candidates[0]
    gateway = field_after(route, "via")
    iface = field_after(route, "dev")
    if not gateway or not iface:
        die(f"branchleft-host-egress: subnet route carries no gateway or device: {route}")

    set_default_route(gateway, iface)

    resolver_head = Path(os.environ.get("BRANCHLEFT_EGRESS_RESOLVER_HEAD") or DEFAULT_RESOLVER_HEAD)
    set_resolver(
        resolver_head,
        os.environ.get("BRANCHLEFT_EGRESS_NAMESERVER_1") or DEFAULT_NAMESERVER_1,
        os.environ.get("BRANCHLEFT_EGRESS_NAMESERVER_2") or DEFAULT_NAMESERVER_2,
    )

    print("branchleft-host-egress: private-only host egress configured")


if __name__ == "__main__":
    main()
