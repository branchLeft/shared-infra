#!/usr/bin/env python3
"""NAT gateway proof: `gateway` on edge-t or edge1 (`--sabotage` on edge-t only, owner-run), `ssh` for edge-t from any machine; fails closed.
Commands, expected output and the safety rules: hetzner/tenants/RUNBOOK-edget-gateway-proof.md (edge-t),
hetzner/RUNBOOK-edge1-gateway-proof.md (edge1)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

# Copies of hetzner-host/addressPlan.ts (SUBNET_CIDR, TENANTS_HOST_IPS.edgeT,
# HOST_IPS.edge1). This runs on a host with no checkout to import them from.
SUBNET = "10.20.1.0/24"
EDGET_HOSTNAME = "edge-t"
EDGET_PRIVATE = "10.20.1.210"
EDGE1_HOSTNAME = "edge1"
EDGE1_PRIVATE = "10.20.1.10"


@dataclass(frozen=True)
class HostProfile:
    """What one gateway host must look like before the probe builds anything on it.

    The uplink is not a field: no register names it, so it is read from the host's single
    default route and printed in the header.
    """

    hostname: str
    private_address: str
    subnet: str
    sabotage_allowed: bool


# The only hosts the probe runs on, keyed by the name `hostname` prints. A host not in this
# table is refused; there is no flag that adds one. The two networks reuse one address range
# (they are separate Hetzner networks), so each profile also forbids every other profile's
# private address. edge1 carries every private host of the estate: no sabotage there.
PROFILES = {
    EDGET_HOSTNAME: HostProfile(EDGET_HOSTNAME, EDGET_PRIVATE, SUBNET, sabotage_allowed=True),
    EDGE1_HOSTNAME: HostProfile(EDGE1_HOSTNAME, EDGE1_PRIVATE, SUBNET, sabotage_allowed=False),
}

UNIT = "branchleft-nat.service"
DEFAULT_TARGET = "9.9.9.9:53"  # Quad9 (Swiss, non-profit) resolver, answering TCP on 53; any reply counts
PROBE_TIMEOUT = 6
SETTLE_TRIES = 12
SSH_TIMEOUT = 8
SSH_PORT = 22
REACHABILITY_PORT = 443


@dataclass(frozen=True)
class Source:
    """One throwaway namespace on a /32 point-to-point veth: one route to its own address, none to the subnet."""

    key: str
    netns: str
    host_if: str
    ns_if: str
    address: str
    host_address: str


# .253 and .254 are in no register of the plan (addressPlan.ts), so they never
# collide with a host; they exist only while the probe runs.
INSIDE = Source("inside", "gwproof-in", "gwp-in-h", "gwp-in-n", "10.20.1.254", "10.20.1.253")
# TEST-NET-1 (RFC 5737): reserved, never routed, never a real host.
OUTSIDE = Source("outside", "gwproof-out", "gwp-out-h", "gwp-out-n", "192.0.2.1", "192.0.2.2")

# Run inside the namespace: REPLY (SYN-ACK or RST came back), NOREPLY, or ERROR with the errno.
# A made connection is closed with an RST so no late FIN reaches the gateway's counters.
PROBE_CODE = (
    "import socket, struct, sys\n"
    "host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "s.settimeout(timeout)\n"
    "try:\n"
    "    s.connect((host, port))\n"
    "    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))\n"
    "    print('REPLY connected')\n"
    "except ConnectionRefusedError:\n"
    "    print('REPLY refused')\n"
    "except socket.timeout:\n"
    "    print('NOREPLY timeout')\n"
    "except OSError as exc:\n"
    "    print('ERROR %s' % exc.errno)\n"
)

REQUIRED_TOOLS = ("hostname", "ip", "iptables", "sysctl", "systemctl")


class Refused(Exception):
    """The probe cannot run safely or cannot read what it needs. Exit 2."""


# Seams the tests replace; the script calls these and nothing else for the world.
def run(argv: list[str], timeout: float = 30) -> tuple[int, str, str]:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["PATH"] = env.get("PATH", "") + ":/usr/sbin:/sbin"
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except FileNotFoundError:
        raise Refused(f"{argv[0]} is not installed") from None
    except subprocess.TimeoutExpired:
        raise Refused(f"{' '.join(argv)} did not finish in {timeout}s") from None
    return done.returncode, done.stdout, done.stderr


def which(tool: str) -> str | None:
    return shutil.which(tool, path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin")


def is_root() -> bool:
    return os.geteuid() == 0


def sleep(seconds: float) -> None:
    time.sleep(seconds)


def say(line: str) -> None:
    """Print one line; a closed pipe (a dropped ssh session) must not stop the clean-up."""
    try:
        print(line, flush=True)
    except OSError:
        pass


def tcp_connect(host: str, port: int, timeout: float, want_banner: bool) -> tuple[str, str]:
    """One TCP connection: (state, detail), state in ssh, connected, connected-no-banner, refused, timeout, error."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            return "refused", "connection refused (an RST came back)"
        except socket.timeout:
            return "timeout", f"no answer in {timeout}s"
        except OSError as exc:
            return "error", f"errno {exc.errno}: {exc.strerror}"
        if not want_banner:
            return "connected", "connected"
        try:
            banner = sock.recv(64)
        except OSError:
            banner = b""
        if banner.startswith(b"SSH-"):
            return "ssh", banner.split(b"\r")[0].split(b"\n")[0].decode("ascii", "replace")
        return "connected-no-banner", "connected but no SSH banner came back"
    finally:
        sock.close()


@dataclass
class Verdict:
    control: str
    state: str
    ok: bool
    detail: str

    def line(self) -> str:
        return f"{'GREEN' if self.ok else 'RED'} {self.control} [{self.state}]: {self.detail}"


# --------------------------------------------------------------------------- reads


def must(argv: list[str], what: str, timeout: float = 30) -> str:
    code, out, err = run(argv, timeout)
    if code != 0:
        raise Refused(f"{what}: `{' '.join(argv)}` exited {code}: {err.strip() or out.strip()}")
    return out


def read_json(argv: list[str], what: str):
    out = must(argv, what)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        raise Refused(f"{what}: `{' '.join(argv)}` printed output that is not JSON") from None


def local_addresses() -> set[str]:
    rows = read_json(["ip", "-j", "-4", "addr", "show"], "reading this host's addresses")
    found: set[str] = set()
    if not isinstance(rows, list):
        raise Refused("reading this host's addresses: unexpected JSON shape")
    for row in rows:
        for info in row.get("addr_info", []) if isinstance(row, dict) else []:
            if isinstance(info, dict) and info.get("family") == "inet" and info.get("local"):
                found.add(info["local"])
    return found


def default_uplink() -> str:
    rows = read_json(["ip", "-j", "-4", "route", "show", "default"], "reading the default route")
    if not isinstance(rows, list) or len(rows) != 1 or not rows[0].get("dev"):
        raise Refused(
            "this host must have exactly one default route; "
            f"`ip -4 route show default` gave {len(rows) if isinstance(rows, list) else '?'}"
        )
    return str(rows[0]["dev"])


def rx_packets(interface: str) -> int:
    rows = read_json(["ip", "-j", "-s", "link", "show", "dev", interface], f"reading {interface}")
    try:
        return int(rows[0]["stats64"]["rx"]["packets"])
    except (KeyError, IndexError, TypeError, ValueError):
        raise Refused(f"reading {interface}: no stats64.rx.packets in `ip -j -s link`") from None


def split_target(target: str) -> tuple[str, int]:
    host, _, port = target.rpartition(":")
    try:
        ipaddress.IPv4Address(host)
        number = int(port)
    except ValueError:
        raise Refused(f"--target must be IPV4:PORT, got {target!r}") from None
    if not 0 < number < 65536:
        raise Refused(f"--target port out of range: {target!r}")
    return host, number


@dataclass(frozen=True)
class Context:
    uplink: str
    chain: str
    host: str
    port: int
    profile: HostProfile

    @property
    def subnet(self) -> str:
        return self.profile.subnet


@dataclass(frozen=True)
class Counters:
    """Packet counters of the three rules; None means the rule is not there."""

    masquerade: int | None
    out_accept: int | None
    return_accept: int | None


def rule_rows(table: str, chain: str) -> list[list[str]]:
    out = must(["iptables", "-w", "-t", table, "-vxnL", chain], f"reading {table}/{chain}")
    rows: list[list[str]] = []
    seen_header = False
    for line in out.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "pkts":
            seen_header = True
            continue
        if not seen_header or fields[0] == "Chain":
            continue
        if len(fields) < 9 or not fields[0].isdigit() or not fields[1].isdigit():
            raise Refused(f"reading {table}/{chain}: a rule line did not parse: {line!r}")
        rows.append(fields)
    if not seen_header:
        raise Refused(f"reading {table}/{chain}: no pkts/bytes header in iptables output")
    return rows


def one_counter(rows: list[list[str]], what: str) -> int | None:
    if not rows:
        return None
    if len(rows) > 1:
        raise Refused(f"{what} is present {len(rows)} times; refusing to guess which one counts")
    return int(rows[0][0])


def read_counters(ctx: Context) -> Counters:
    up = ctx.uplink
    nat = rule_rows("nat", "POSTROUTING")
    masquerade = [
        r
        for r in nat
        if r[2] == "MASQUERADE" and r[5] == "*" and r[6] == up and r[7] == ctx.subnet and r[8] == "0.0.0.0/0"
    ]
    flt = rule_rows("filter", ctx.chain)
    outbound = [
        r
        for r in flt
        if r[2] == "ACCEPT" and r[5] == "*" and r[6] == up and r[7] == ctx.subnet
        and r[8] == "0.0.0.0/0" and len(r) == 9
    ]
    returning = [
        r
        for r in flt
        if r[2] == "ACCEPT" and r[5] == up and r[6] == "*" and r[7] == "0.0.0.0/0"
        and r[8] == ctx.subnet and re.search(r"ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED)$", " ".join(r[9:]))
    ]
    return Counters(
        one_counter(masquerade, f"the MASQUERADE rule for {ctx.subnet} out of {up}"),
        one_counter(outbound, f"the {ctx.chain} accept for {ctx.subnet} out of {up}"),
        one_counter(returning, f"the {ctx.chain} return accept for {ctx.subnet} in from {up}"),
    )


def delta(before: int | None, after: int | None) -> int | None:
    return None if before is None or after is None else after - before


def settle(ctx: Context) -> Counters:
    """Wait until the rule counters stop moving: our own last flow may still be closing.

    A gateway that never goes quiet is in use by another source, and a control
    that compares counters across a probe cannot be read then.
    """
    last = read_counters(ctx)
    for _ in range(SETTLE_TRIES):
        sleep(1)
        now = read_counters(ctx)
        if now == last:
            return now
        last = now
    raise Refused(
        f"the gateway's rule counters kept moving for {SETTLE_TRIES}s, so another source is using it "
        "and a counter comparison cannot be read; re-run when it is quiet"
    )


# ------------------------------------------------------------------------- preflight


def preflight(target: str, sabotage: bool = False) -> Context:
    if not is_root():
        raise Refused("run as root: it creates network namespaces")
    for tool in REQUIRED_TOOLS:
        if which(tool) is None:
            raise Refused(f"{tool} is not installed; a proof that cannot read its evidence proves nothing")
    code, out, _ = run(["hostname"])
    name = out.strip()
    profile = PROFILES.get(name) if code == 0 else None
    if profile is None:
        raise Refused(f"this host is {name or '?'}, which has no profile; this probe only runs on {', '.join(PROFILES)}")
    if sabotage and not profile.sabotage_allowed:
        raise Refused(f"--sabotage is refused on {profile.hostname}: it would cut the egress of every host behind it")
    addresses = local_addresses()
    if profile.private_address not in addresses:
        raise Refused(
            f"this host holds no {profile.private_address}, which is {profile.hostname}'s private address; refusing"
        )
    for other in PROFILES.values():
        if other is not profile and other.private_address in addresses:
            raise Refused(f"this host holds {other.private_address}, which is {other.hostname}'s address; refusing")
    for source in (INSIDE, OUTSIDE):
        inside = ipaddress.ip_address(source.address) in ipaddress.ip_network(profile.subnet)
        if inside != (source is INSIDE):
            raise Refused(f"the {source.key} source {source.address} is on the wrong side of {profile.subnet}")
        if source.address in addresses or source.host_address in addresses:
            raise Refused(f"{source.address} or {source.host_address} is already on this host")
    host, port = split_target(target)
    uplink = default_uplink()
    code, _, _ = run(["iptables", "-w", "-t", "filter", "-S", "DOCKER-USER"])
    if code == 0:
        chain = "DOCKER-USER"
    else:
        code, out, _ = run(["systemctl", "is-active", "docker.service"])
        if out.strip() == "active":
            raise Refused(
                "docker.service is active but iptables carries no DOCKER-USER chain: "
                "Docker is not enforcing through iptables here, and FORWARD is not a safe stand-in"
            )
        chain = "FORWARD"
    return Context(uplink, chain, host, port, profile)


def gateway_problems(ctx: Context) -> list[str]:
    """What the read-only state says is wrong with the gateway, if anything."""
    problems = []
    code, out, _ = run(["sysctl", "-n", "net.ipv4.ip_forward"])
    if code != 0 or out.strip() != "1":
        problems.append(f"net.ipv4.ip_forward is {out.strip() or '?'}, not 1")
    code, out, _ = run(["systemctl", "is-enabled", UNIT])
    if code != 0 or out.strip() != "enabled":
        problems.append(f"{UNIT} is {out.strip() or '?'}, not enabled (it would not survive a reboot)")
    code, out, _ = run(["systemctl", "is-active", UNIT])
    if code != 0 or out.strip() != "active":
        problems.append(f"{UNIT} is {out.strip() or '?'}, not active")
    return problems


# ------------------------------------------------------------------------------ lab


def teardown(source: Source) -> list[str]:
    """Remove the namespace and the veth; return what could not be removed."""
    run(["ip", "netns", "del", source.netns])
    run(["ip", "link", "del", source.host_if])
    left = []
    code, out, _ = run(["ip", "netns", "list"])
    if code != 0 or any(line.split(" ")[0] == source.netns for line in out.splitlines() if line.strip()):
        left.append(f"namespace {source.netns}")
    code, _, _ = run(["ip", "link", "show", "dev", source.host_if])
    if code == 0:
        left.append(f"link {source.host_if}")
    return left


class Lab:
    """A namespace with one source address, reachable only through the host's veth."""

    def __init__(self, source: Source, problems: list[str]):
        self.source = source
        self.problems = problems

    def __enter__(self) -> "Lab":
        s = self.source
        # A leftover from a killed run has our exact name; it is ours to remove.
        left = teardown(s)
        if left:
            raise Refused(f"could not clear a leftover {', '.join(left)}")
        try:
            for argv in (
                ["ip", "netns", "add", s.netns],
                ["ip", "link", "add", s.host_if, "type", "veth", "peer", "name", s.ns_if],
                ["ip", "link", "set", s.ns_if, "netns", s.netns],
                ["ip", "addr", "add", s.host_address, "peer", f"{s.address}/32", "dev", s.host_if],
                ["ip", "link", "set", s.host_if, "up"],
                ["ip", "-n", s.netns, "link", "set", "lo", "up"],
                ["ip", "-n", s.netns, "addr", "add", s.address, "peer", f"{s.host_address}/32", "dev", s.ns_if],
                ["ip", "-n", s.netns, "link", "set", s.ns_if, "up"],
                ["ip", "-n", s.netns, "route", "add", "default", "via", s.host_address],
            ):
                must(argv, f"building the {s.key} namespace")
        except BaseException:
            self.problems.extend(teardown(s))
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self.problems.extend(teardown(self.source))

    def probe(self, host: str, port: int) -> tuple[bool | None, str]:
        """(reply?, what was seen). None means the probe itself did not work."""
        s = self.source
        code, out, err = run(
            ["ip", "netns", "exec", s.netns, sys.executable, "-c", PROBE_CODE, host, str(port), str(PROBE_TIMEOUT)],
            timeout=PROBE_TIMEOUT + 10,
        )
        line = out.strip()
        if code == 0 and line in ("REPLY connected", "REPLY refused"):
            return True, line
        if code == 0 and line == "NOREPLY timeout":
            return False, line
        return None, f"unexpected probe result (exit {code}, output {line!r}, stderr {err.strip()!r})"


# --------------------------------------------------------------------------- controls

INSIDE_CONTROL = "inside-subnet-egress-via-masquerade"
OUTSIDE_CONTROL = "outside-subnet-no-reply"


def control_inside(ctx: Context, lab: Lab, state: str = "live") -> Verdict:
    before = read_counters(ctx)
    reply, seen = lab.probe(ctx.host, ctx.port)
    after = read_counters(ctx)
    fails = list(gateway_problems(ctx))
    if reply is not True:
        fails.append(f"no reply from {ctx.host}:{ctx.port} ({seen})")
    for name, b, a in (
        (f"the nat/POSTROUTING MASQUERADE for {ctx.subnet}", before.masquerade, after.masquerade),
        (f"the {ctx.chain} accept for {ctx.subnet} out of {ctx.uplink}", before.out_accept, after.out_accept),
        (f"the {ctx.chain} return accept for {ctx.subnet} in from {ctx.uplink}", before.return_accept, after.return_accept),
    ):
        moved = delta(b, a)
        if moved is None:
            fails.append(f"{name} is not present")
        elif moved < 1:
            fails.append(f"the counter of {name} did not rise (stayed {a})")
    if fails:
        return Verdict(INSIDE_CONTROL, state, False, "; ".join(fails))
    return Verdict(
        INSIDE_CONTROL,
        state,
        True,
        f"source {lab.source.address} got a reply from {ctx.host}:{ctx.port} ({seen}); counters rose: "
        f"MASQUERADE {before.masquerade}->{after.masquerade}, "
        f"{ctx.chain} out {before.out_accept}->{after.out_accept}, "
        f"{ctx.chain} return {before.return_accept}->{after.return_accept}",
    )


def control_outside(ctx: Context, lab: Lab, inside_ok: bool) -> Verdict:
    if not inside_ok:
        return Verdict(
            OUTSIDE_CONTROL,
            "live",
            False,
            f"not established: the inside-subnet control is not GREEN, and silence from "
            f"{lab.source.address} proves nothing when nothing could have answered the inside source",
        )
    before = settle(ctx)
    rx_before = rx_packets(lab.source.host_if)
    reply, seen = lab.probe(ctx.host, ctx.port)
    rx_after = rx_packets(lab.source.host_if)
    after = read_counters(ctx)
    fails = []
    if reply is not False:
        fails.append(
            f"expected no reply from {ctx.host}:{ctx.port} and got: {seen}"
            if reply is None
            else f"{lab.source.address} GOT A REPLY from {ctx.host}:{ctx.port} ({seen}): it was laundered through the gateway"
        )
    if rx_after - rx_before < 1:
        fails.append(
            f"the host's {lab.source.host_if} received no packets from the namespace "
            f"(rx {rx_before}->{rx_after}), so the silence says nothing about the gateway"
        )
    for name, b, a in (
        ("MASQUERADE", before.masquerade, after.masquerade),
        (f"{ctx.chain} out accept", before.out_accept, after.out_accept),
        (f"{ctx.chain} return accept", before.return_accept, after.return_accept),
    ):
        moved = delta(b, a)
        if moved is None:
            fails.append(f"the {name} rule is not present, so the counter cannot be compared")
        elif moved != 0:
            fails.append(
                f"the {name} counter moved by {moved} while the outside source probed "
                f"(another source using the gateway also does this: re-run when it is quiet)"
            )
    if fails:
        return Verdict(OUTSIDE_CONTROL, "live", False, "; ".join(fails))
    return Verdict(
        OUTSIDE_CONTROL,
        "live",
        True,
        f"source {lab.source.address} got no reply from {ctx.host}:{ctx.port} ({seen}); the host received "
        f"{rx_after - rx_before} packet(s) on {lab.source.host_if} and no gateway rule counter moved",
    )


# -------------------------------------------------------------------------- sabotage


def masquerade_argv(ctx: Context, verb: str) -> list[str]:
    return ["iptables", "-w", "-t", "nat", verb, "POSTROUTING", "-s", ctx.subnet, "-o", ctx.uplink, "-j", "MASQUERADE"]


def masquerade_present(ctx: Context) -> bool:
    code, _, _ = run(masquerade_argv(ctx, "-C"))
    return code == 0


@dataclass
class Sabotage:
    ctx: Context
    began: bool = False
    restored: bool = False
    failure: str = ""
    red_seen: bool = False
    green_seen: bool = False

    def restore(self) -> bool:
        """Put the rule back the way boot does; idempotent; never interrupted."""
        if not self.began or self.restored:
            return True
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        say(f"restoring: systemctl restart {UNIT}")
        try:
            code, _, _ = run(["systemctl", "restart", UNIT], timeout=90)
        except (Refused, OSError):
            code = 1
        back = False
        try:
            back = masquerade_present(self.ctx)
        except (Refused, OSError):
            pass
        active = ""
        if code == 0:
            try:
                _, active, _ = run(["systemctl", "is-active", UNIT])
            except (Refused, OSError):
                active = ""
        if code == 0 and back and active.strip() == "active":
            self.restored = True
            return True
        self.failure = (
            f"RESTORE FAILED (restart exit {code}, rule back: {back}). {self.ctx.profile.hostname} has NO internet gateway "
            f"until this is run as root on {self.ctx.profile.hostname}: systemctl restart {UNIT}"
        )
        say(self.failure)
        return False


def sabotage_sequence(ctx: Context, lab: Lab, state: Sabotage) -> None:
    """Delete the masquerade, show red, restore, show green. Restores on any exit."""
    # Quiet first: deleting the masquerade now would cut any other source's new flows.
    settle(ctx)
    say(f"sabotage: deleting the MASQUERADE rule for {ctx.subnet}; if this process is killed, run as root: systemctl restart {UNIT}")
    state.began = True
    code, _, err = run(masquerade_argv(ctx, "-D"))
    if code != 0:
        raise Refused(f"deleting the MASQUERADE rule failed (exit {code}: {err.strip()}); nothing was changed")
    if masquerade_present(ctx):
        raise Refused("the MASQUERADE rule is still present after `iptables -D`; the sabotage did not take")
    reply, seen = lab.probe(ctx.host, ctx.port)
    counters = read_counters(ctx)
    if reply is False and counters.masquerade is None:
        verdict = Verdict(
            INSIDE_CONTROL,
            "masquerade rule deleted",
            False,
            f"source {lab.source.address} got NO reply from {ctx.host}:{ctx.port} ({seen}) with the "
            f"nat/POSTROUTING MASQUERADE rule for {ctx.subnet} deleted (iptables -C finds it absent): "
            "a private source address cannot be answered by the internet, so the masquerade is the "
            "mechanism that carries the traffic",
        )
    elif reply is None:
        raise Refused(f"the sabotaged probe did not run cleanly: {seen}")
    else:
        verdict = Verdict(
            INSIDE_CONTROL,
            "masquerade rule deleted",
            True,
            f"the probe STILL got a reply ({seen}) or the rule is back: this proof cannot tell whether "
            "the masquerade carries the traffic",
        )
    state.red_seen = not verdict.ok
    say(verdict.line())
    if not state.restore():
        return
    green = control_inside(ctx, lab, f"restored by restarting {UNIT}")
    state.green_seen = green.ok
    say(green.line())


# ------------------------------------------------------------------------------ main


def run_gateway(args: argparse.Namespace) -> int:
    ctx = preflight(args.target, args.sabotage)
    say(f"probe-edget-gateway: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} on {ctx.profile.hostname}, "
        f"uplink {ctx.uplink}, forwarding chain {ctx.chain}, target {ctx.host}:{ctx.port}")
    problems: list[str] = []
    verdicts: list[Verdict] = []
    sabotage = Sabotage(ctx)
    refusal: Refused | None = None
    try:
        with Lab(INSIDE, problems) as lab:
            inside = control_inside(ctx, lab)
            verdicts.append(inside)
            say(inside.line())
        with Lab(OUTSIDE, problems) as lab:
            outside = control_outside(ctx, lab, inside.ok)
            verdicts.append(outside)
            say(outside.line())
        if args.sabotage and not (inside.ok and outside.ok):
            say("the sabotage proves nothing unless both live controls are GREEN first; nothing was changed")
        elif args.sabotage:
            with Lab(INSIDE, problems) as lab:
                try:
                    sabotage_sequence(ctx, lab, sabotage)
                finally:
                    sabotage.restore()
    except Refused as exc:
        refusal = exc
    finally:
        sabotage.restore()
        for left in problems:
            say(f"CLEANUP FAILED: {left} is still on this host: remove it with `ip netns del` / `ip link del`")
    if sabotage.failure or problems:
        say("RESULT FAIL: the host was not left clean")
        return 3
    if refusal is not None:
        raise refusal
    if args.sabotage and all(v.ok for v in verdicts):
        if not (sabotage.red_seen and sabotage.green_seen):
            say("RESULT FAIL: the sabotage did not show red then green")
            return 1
        say("RECORD red-then-green: deleting the masquerade took the inside-subnet probe from GREEN to RED, "
            f"and restarting {UNIT} brought it back to GREEN")
    if any(not v.ok for v in verdicts):
        say("RESULT FAIL")
        return 1
    say("RESULT PASS")
    return 0


def run_ssh(args: argparse.Namespace) -> int:
    try:
        address = ipaddress.ip_address(args.target)
    except ValueError:
        raise Refused(f"--target must be an IP address, not a name: {args.target!r}") from None
    host = str(address)
    state, detail = tcp_connect(host, SSH_PORT, SSH_TIMEOUT, want_banner=True)
    if args.expect == "accepted":
        ok = state == "ssh"
        verdict = Verdict(
            "ssh-to-edge-t-accepted-from-edge1",
            "this source",
            ok,
            f"port {SSH_PORT} on {host}: {state} ({detail})"
            + ("" if ok else "; an SSH banner was expected"),
        )
        say(verdict.line())
        return 0 if ok else 1
    reach_state, reach_detail = tcp_connect(host, REACHABILITY_PORT, SSH_TIMEOUT, want_banner=False)
    reachable = reach_state in ("connected", "refused")
    control = Verdict(
        "edge-t-reachable-on-443",
        "this source",
        reachable,
        f"port {REACHABILITY_PORT} on {host}: {reach_state} ({reach_detail})"
        + ("" if reachable else "; without an answer here a timeout on 22 cannot be told from this machine's own network"),
    )
    say(control.line())
    ok = state == "timeout" and reachable
    if state == "timeout":
        note = "" if reachable else "; not established, the 443 reading above is red"
    elif state == "ssh":
        note = "; SSH IS ACCEPTED from this source"
    elif state == "refused":
        note = "; the host answered with an RST, so the firewall did not drop it"
    else:
        note = "; not a clean timeout"
    verdict = Verdict(
        "ssh-to-edge-t-refused-from-non-edge1",
        "this source",
        ok,
        f"port {SSH_PORT} on {host}: {state} ({detail}){note}",
    )
    say(verdict.line())
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="probe-edget-gateway", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gateway = sub.add_parser("gateway", help="prove the gateway from namespaces on edge-t or edge1 (run on that host, as root)")
    gateway.add_argument("--target", default=DEFAULT_TARGET, help=f"IPV4:PORT to connect to (default {DEFAULT_TARGET})")
    gateway.add_argument(
        "--sabotage",
        action="store_true",
        help="owner-run on edge-t only (refused on edge1): delete the masquerade rule, show RED, restore it, show GREEN",
    )
    ssh = sub.add_parser("ssh", help="probe SSH to edge-t's public address from this machine")
    ssh.add_argument("--target", required=True, help="edge-t's public IPv4 (or IPv6) address")
    ssh.add_argument("--expect", required=True, choices=("refused", "accepted"))
    return parser


def install_signal_handlers() -> None:
    def stop(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    install_signal_handlers()
    try:
        return run_gateway(args) if args.command == "gateway" else run_ssh(args)
    except Refused as exc:
        say(f"REFUSED: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
