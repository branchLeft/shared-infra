#!/usr/bin/env python3
"""App-host mail-spool bridge proof: a container on br-mailspool is refused off the bridge, a control is not.
Run on an app host as root, fed on stdin; fails closed. Commands, expected output and the safety rules:
hetzner/RUNBOOK-provision-host.md
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field

# Copies of hetzner-host/addressPlan.ts (SUBNET_CIDR, APP_HOST_IPS, HOST_IPS) and of the
# isolation policy's defaults (DEFAULT_DB_HOST, DEFAULT_DB_PORT, DEFAULT_MAIL_SPOOL_BRIDGE).
# This runs on a host with no checkout to import them from; the tests pin every copy.
SUBNET = "10.20.1.0/24"
APP_HOSTS = {"app1": "10.20.1.100", "app2": "10.20.1.101", "app3": "10.20.1.102"}
OTHER_HOSTS = {"edge1": "10.20.1.10", "db1": "10.20.1.20", "mon1": "10.20.1.30", "ops1": "10.20.1.50"}
DB_HOST = "10.20.1.20"
DB_PORT = 3306
BRIDGE = "br-mailspool"

DEFAULT_TARGET = "9.9.9.9:53"  # Quad9 (Swiss, non-profit) resolver, answering TCP on 53
CONNECT_SECONDS = 5
HOLD_SECONDS = 180  # a probe container ends itself if the clean-up never runs
EXEC_SECONDS = CONNECT_SECONDS + 20
NAME_PREFIX = "zz-probe-mailspool-"
REQUIRED_TOOLS = ("hostname", "ip", "iptables", "ip6tables", "docker")
IMAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,254}")

# What the policy writes, as `iptables -S` prints it (the conntrack set prints in either order).
FORWARD_DROP = f"-A DOCKER-USER -i {BRIDGE} ! -o {BRIDGE} -j DROP"
INPUT_DROP = f"-A INPUT -i {BRIDGE} -j DROP"
INPUT_REPLIES = re.compile(
    rf"-A INPUT -i {BRIDGE} -m conntrack --ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED) -j ACCEPT"
)
DB_ACCEPT = f"-A DOCKER-USER -d {DB_HOST}/32 -p tcp -m tcp --dport {DB_PORT} -j ACCEPT"
# The forward rule's target is DROP, so a blocked connect gets no answer at all: a timeout.
# A REJECT would give a refusal instead; the expectation below follows the rule, not a guess.
EXPECTED_STATE = "timeout"

# Run in the container by `node -e`: one TCP connect, one line of output, whatever happens.
CLIENT_CODE = (
    "const s = require('net').connect({host: process.env.PROBE_HOST, port: Number(process.env.PROBE_PORT)});"
    "const done = (w) => { console.log(w); s.destroy(); process.exit(0); };"
    "s.on('connect', () => done('CONNECTED'));"
    "s.on('error', (e) => done('ERROR ' + e.code));"
    f"setTimeout(() => done('TIMEOUT'), {CONNECT_SECONDS * 1000});"
)


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


def new_suffix() -> str:
    return os.urandom(3).hex()


def say(line: str) -> None:
    """Print one line; a closed pipe (a dropped ssh session) must not stop the clean-up."""
    with contextlib.suppress(OSError):
        print(line, flush=True)


@dataclass
class Verdict:
    """GREEN and RED count; INCONCLUSIVE says the run proved nothing; INFO and SKIPPED are notes."""

    kind: str
    control: str
    detail: str

    def line(self) -> str:
        return f"{self.kind} {self.control} [live]: {self.detail}"


# --------------------------------------------------------------------------- reads


def must(argv: list[str], what: str, timeout: float = 30) -> str:
    code, out, err = run(argv, timeout)
    if code != 0:
        raise Refused(f"{what}: `{' '.join(argv)}` exited {code}: {err.strip() or out.strip()}")
    return out


def local_addresses() -> set[str]:
    out = must(["ip", "-j", "-4", "addr", "show"], "reading this host's addresses")
    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        raise Refused("reading this host's addresses: `ip -j` printed output that is not JSON") from None
    if not isinstance(rows, list):
        raise Refused("reading this host's addresses: unexpected JSON shape")
    found: set[str] = set()
    for row in rows:
        for info in row.get("addr_info", []) if isinstance(row, dict) else []:
            if isinstance(info, dict) and info.get("family") == "inet" and info.get("local"):
                found.add(info["local"])
    return found


def split_target(target: str) -> tuple[str, int]:
    host, _, port = target.rpartition(":")
    try:
        address = ipaddress.IPv4Address(host)
        number = int(port)
    except ValueError:
        raise Refused(f"--target must be IPV4:PORT, got {target!r}") from None
    if not 0 < number < 65536:
        raise Refused(f"--target port out of range: {target!r}")
    if not address.is_global:
        raise Refused(f"--target {host} is not a public address, so it cannot stand for the internet")
    return host, number


def rule_lines(tool: str, chain: str) -> list[str]:
    out = must([tool, "-w", "-t", "filter", "-S", chain], f"reading {tool} {chain}")
    return [line.strip() for line in out.splitlines() if line.startswith(f"-A {chain} ")]


def rule_problems(tool: str, forward: list[str], inbound: list[str], with_db: bool) -> list[str]:
    """What is wrong with one family's spool rules, naming each rule and how many were found."""
    problems = []
    wanted = [
        (f"{tool} DOCKER-USER spool forward drop", sum(1 for r in forward if r == FORWARD_DROP)),
        (f"{tool} INPUT spool drop", sum(1 for r in inbound if r == INPUT_DROP)),
        (f"{tool} INPUT spool replies accept", sum(1 for r in inbound if INPUT_REPLIES.fullmatch(r))),
    ]
    if with_db:
        wanted.append((f"{tool} DOCKER-USER db1:{DB_PORT} accept", sum(1 for r in forward if r == DB_ACCEPT)))
    for name, found in wanted:
        if found != 1:
            problems.append(f"{name} is present {found} times, not once")
    return problems


def read_rule_sets() -> Verdict:
    problems: list[str] = []
    for tool in ("iptables", "ip6tables"):
        forward = rule_lines(tool, "DOCKER-USER")
        inbound = rule_lines(tool, "INPUT")
        problems.extend(rule_problems(tool, forward, inbound, with_db=tool == "iptables"))
    if problems:
        raise Refused(
            "the spool's rule sets are not on this host as the isolation policy writes them ("
            + "; ".join(problems)
            + "): nothing to prove, and nothing here repairs them"
        )
    return Verdict(
        "GREEN",
        "spool-rules-present",
        "iptables and ip6tables each carry the DOCKER-USER forward drop once and the INPUT replies accept and drop "
        f"once for {BRIDGE}; iptables also carries the db1:{DB_PORT} accept the forward drop must outrank",
    )


def drop_counter() -> int:
    """Packets the IPv4 spool forward drop has counted."""
    out = must(["iptables", "-w", "-t", "filter", "-vxnL", "DOCKER-USER"], "reading the DOCKER-USER counters")
    seen_header = False
    found: list[int] = []
    for raw in out.splitlines():
        fields = re.sub(r"!\s+", "!", raw).split()
        if not fields or fields[0] == "Chain":
            continue
        if fields[0] == "pkts":
            seen_header = True
            continue
        if not seen_header:
            continue
        if len(fields) < 9 or not fields[0].isdigit() or not fields[1].isdigit():
            raise Refused(f"reading the DOCKER-USER counters: a rule line did not parse: {raw!r}")
        if fields[2] == "DROP" and fields[5] == BRIDGE and fields[6] == f"!{BRIDGE}":
            found.append(int(fields[0]))
    if not seen_header:
        raise Refused("reading the DOCKER-USER counters: no pkts/bytes header in iptables output")
    if len(found) != 1:
        raise Refused(
            f"the spool forward drop appears {len(found)} times in `iptables -vxnL DOCKER-USER`; "
            "a counter that cannot be attributed to one rule proves nothing"
        )
    return found[0]


def leftovers(suffix: str = "") -> list[str]:
    """Probe containers and networks that exist now (all of this probe's names, or one run's)."""
    containers = must(
        ["docker", "ps", "-a", "--filter", f"name={NAME_PREFIX}{suffix}", "--format", "{{.Names}}"],
        "listing probe containers",
    ).split()
    networks = must(
        ["docker", "network", "ls", "--filter", f"name={NAME_PREFIX}net-{suffix}", "--format", "{{.Name}}"],
        "listing probe networks",
    ).split()
    return [f"container {name}" for name in containers] + [f"network {name}" for name in networks]


# ------------------------------------------------------------------------- preflight


@dataclass(frozen=True)
class Context:
    hostname: str
    image: str
    host: str
    port: int
    rules: Verdict


def preflight(image: str, target: str) -> Context:
    if not is_root():
        raise Refused("run as root: it starts containers and reads the firewall")
    for tool in REQUIRED_TOOLS:
        if which(tool) is None:
            raise Refused(f"{tool} is not installed; a proof that cannot read its evidence proves nothing")
    if IMAGE_NAME.fullmatch(image) is None:
        raise Refused(f"--image {image!r} is not an image name or id")
    host, port = split_target(target)
    code, out, _ = run(["hostname"])
    name = out.strip()
    if code != 0 or name not in APP_HOSTS:
        raise Refused(
            f"this host is {name or '?'}, not one of {', '.join(APP_HOSTS)}; this probe only runs on an app host"
        )
    addresses = local_addresses()
    if APP_HOSTS[name] not in addresses:
        raise Refused(f"this host holds no {APP_HOSTS[name]}, which is {name}'s private address; refusing")
    for other, address in OTHER_HOSTS.items():
        if address in addresses:
            raise Refused(f"this host holds {address}, which is {other}'s address; refusing")
    rules = read_rule_sets()
    drop_counter()
    code, out, err = run(["ip", "-o", "link", "show", "dev", BRIDGE])
    if code == 0:
        raise Refused(
            f"{BRIDGE} already exists on this host: the mail spool (or a leftover) owns that name, "
            "and this probe neither uses nor removes it"
        )
    if "does not exist" not in err:
        raise Refused(f"reading {BRIDGE}: `ip link show` exited {code}: {err.strip() or out.strip()}")
    left = leftovers()
    if left:
        raise Refused(
            "a probe run left "
            + ", ".join(left)
            + ": remove each with `docker rm -f -v NAME` or `docker network rm NAME`, then run again"
        )
    code, _, _ = run(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    if code != 0:
        raise Refused(
            f"image {image} is not present on this host; this probe never pulls: "
            "choose one from `docker image ls` that has node on its path"
        )
    return Context(name, image, host, port, rules)


# ---------------------------------------------------------------------------- the lab


def container_argv(name: str, network: str, image: str) -> list[str]:
    """One probe container: no volume, no published port, no capability, no pull, ends itself."""
    return [
        "docker", "run", "-d", "--rm", "--name", name, "--network", network, "--pull", "never",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--pids-limit", "64", "--memory", "256m", "--user", "65534:65534",
        "--entrypoint", "node", image, "-e", f"setTimeout(() => {{}}, {HOLD_SECONDS * 1000})",
    ]  # fmt: skip


@dataclass
class Lab:
    """The probe's containers and network, named for one run, removed on every exit."""

    suffix: str
    image: str
    made: list[str] = field(default_factory=list)

    @property
    def network(self) -> str:
        return f"{NAME_PREFIX}net-{self.suffix}"

    @property
    def blocked(self) -> str:
        return f"{NAME_PREFIX}{self.suffix}"

    @property
    def control(self) -> str:
        return f"{NAME_PREFIX}{self.suffix}-control"

    def start(self, name: str, network: str) -> None:
        must(container_argv(name, network, self.image), f"starting {name}", timeout=60)
        self.made.append(f"container {name}")
        out = must(["docker", "inspect", "--format", "{{.State.Running}}", name], f"inspecting {name}")
        if out.strip() != "true":
            raise Refused(f"{name} did not stay up: does the image have node as an executable?")

    def create_network(self) -> None:
        argv = ["docker", "network", "create", "--driver", "bridge", "-o", f"com.docker.network.bridge.name={BRIDGE}"]
        must([*argv, self.network], f"creating {self.network}")
        self.made.append(f"network {self.network}")
        out = must(["docker", "network", "inspect", "--format", "{{json .}}", self.network], "inspecting the network")
        try:
            info = json.loads(out)
            options = info["Options"]
            subnets = [ipaddress.ip_network(c["Subnet"]) for c in info["IPAM"]["Config"] if c.get("Subnet")]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise Refused("inspecting the network: unexpected output from `docker network inspect`") from None
        if options.get("com.docker.network.bridge.name") != BRIDGE:
            raise Refused(f"the probe network is not on {BRIDGE}; refusing to call a result a proof about it")
        if any(s.overlaps(ipaddress.ip_network(SUBNET)) for s in subnets):
            raise Refused(f"docker gave the probe network a subnet overlapping {SUBNET}; nothing was proven")

    def attempt(self, container: str, host: str, port: int) -> tuple[str, str]:
        """One TCP connect from inside a container: (state, detail), state in connected, timeout, refused, error, tool-error."""
        argv = [
            "docker",
            "exec",
            "-e",
            f"PROBE_HOST={host}",
            "-e",
            f"PROBE_PORT={port}",
            container,
            "node",
            "-e",
            CLIENT_CODE,
        ]
        code, out, err = run(argv, EXEC_SECONDS)
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        word = lines[-1] if lines else ""
        if word == "CONNECTED":
            return "connected", "the connection was made"
        if word == "TIMEOUT":
            return "timeout", f"no answer in {CONNECT_SECONDS}s"
        if word == "ERROR ECONNREFUSED":
            return "refused", "an RST came back"
        if word.startswith("ERROR "):
            return "error", f"the connect failed with {word[6:]}"
        return (
            "tool-error",
            f"no result from the client (exit {code}): {err.strip()[:160] or out.strip()[:160] or 'no output'}",
        )

    def clean(self) -> list[str]:
        """Remove what this run made, then read back that nothing of it is left; return what is."""
        for name in (self.blocked, self.control):
            run(["docker", "rm", "-f", "-v", name])
        run(["docker", "network", "rm", self.network])
        return leftovers(self.suffix)


# ---------------------------------------------------------------------------- cases


def control_cases(lab: Lab, ctx: Context) -> list[Verdict]:
    state, detail = lab.attempt(lab.control, ctx.host, ctx.port)
    if state == "connected":
        internet = Verdict(
            "GREEN",
            "control-default-bridge-internet-reachable",
            f"a container on the default bridge connected to {ctx.host}:{ctx.port}",
        )
    else:
        internet = Verdict(
            "INCONCLUSIVE",
            "control-default-bridge-internet-reachable",
            f"a container on the default bridge got {state} from {ctx.host}:{ctx.port} ({detail}); "
            "without a control that can connect, a blocked result means nothing",
        )
    state, detail = lab.attempt(lab.control, DB_HOST, DB_PORT)
    path_open = state in ("connected", "refused")
    note = (
        f"the policy's db1:{DB_PORT} exception works from the default bridge ({state})"
        if path_open
        else f"no connection ({state}: {detail}); the path to db1 is not shown by this run, "
        "which does not change the verdict"
    )
    return [internet, Verdict("INFO", "control-default-bridge-subnet-reachable", f"{DB_HOST}:{DB_PORT}: {note}")]


def blocked_verdict(control: str, target: str, state: str, detail: str, before: int, after: int) -> Verdict:
    if state != EXPECTED_STATE:
        reading = {
            "connected": "THE CONNECTION WAS MADE: the bridge is not fenced",
            "refused": "an RST came back, and a DROP answers nothing: something other than the spool rule replied",
        }.get(state, "not a clean timeout")
        return Verdict(
            "RED",
            control,
            f"{target}: expected a {EXPECTED_STATE} (what a DROP produces), got {state} ({detail}); {reading}",
        )
    if after - before < 1:
        return Verdict(
            "RED",
            control,
            f"{target}: timed out, but the spool forward drop's packet counter did not rise ({before} to {after}), "
            "so the silence is not evidence the rule dropped it",
        )
    return Verdict(
        "GREEN",
        control,
        f"{target}: {state} after {CONNECT_SECONDS}s, as a DROP produces; the spool forward drop counted "
        f"{after - before} more packet(s) ({before} to {after})",
    )


def blocked_cases(lab: Lab, ctx: Context) -> list[Verdict]:
    lab.create_network()
    lab.start(lab.blocked, lab.network)
    found = []
    for control, host, port in (
        ("drain-bridge-internet-blocked", ctx.host, ctx.port),
        ("drain-bridge-subnet-blocked", DB_HOST, DB_PORT),
    ):
        before = drop_counter()
        state, detail = lab.attempt(lab.blocked, host, port)
        after = drop_counter()
        found.append(blocked_verdict(control, f"{host}:{port}", state, detail, before, after))
    return found


# ------------------------------------------------------------------------------ main


def run_probe(args: argparse.Namespace) -> int:
    ctx = preflight(args.image, args.target)
    lab = Lab(new_suffix(), ctx.image)
    say(
        f"probe-app1-mailspool: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} on {ctx.hostname}, "
        f"image {ctx.image}, internet target {ctx.host}:{ctx.port}, subnet target {DB_HOST}:{DB_PORT}, "
        f"containers {lab.blocked} and {lab.control}"
    )
    say(ctx.rules.line())
    verdicts: list[Verdict] = []
    refusal: Refused | None = None
    left: list[str] = []
    try:
        try:
            lab.start(lab.control, "bridge")
            for verdict in control_cases(lab, ctx):
                verdicts.append(verdict)
                say(verdict.line())
            if verdicts[0].kind == "GREEN":
                for verdict in blocked_cases(lab, ctx):
                    verdicts.append(verdict)
                    say(verdict.line())
            else:
                for name in ("drain-bridge-internet-blocked", "drain-bridge-subnet-blocked"):
                    skipped = Verdict("SKIPPED", name, "not run: the control did not reach the internet")
                    verdicts.append(skipped)
                    say(skipped.line())
        except Refused as exc:
            refusal = exc
    finally:
        try:
            left = lab.clean()
        except Refused as exc:
            left = [f"(could not read back: {exc})"]
        if left:
            say(
                f"CLEANUP FAILED: {', '.join(left)} still on this host: remove them with "
                f"`docker rm -f -v {lab.blocked} {lab.control}` and `docker network rm {lab.network}`"
            )
        else:
            what = ", ".join(lab.made) or "nothing had been started"
            say(f"CLEANUP ok: removed {what}; no probe container, network or {BRIDGE} bridge is left")
    if left:
        say("RESULT FAIL: the host was not left clean")
        return 3
    if refusal is not None:
        raise refusal
    if any(v.kind == "INCONCLUSIVE" for v in verdicts):
        say("RESULT INCONCLUSIVE: the control could not connect, so nothing was proven")
        return 2
    if any(v.kind == "RED" for v in verdicts):
        say("RESULT FAIL")
        return 1
    say("RESULT PASS")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="probe-app1-mailspool", description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", required=True, help="an image already on this host that has node; never pulled")
    parser.add_argument(
        "--target", default=DEFAULT_TARGET, help=f"public IPV4:PORT for the internet case (default {DEFAULT_TARGET})"
    )
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
        return run_probe(args)
    except Refused as exc:
        say(f"REFUSED: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
