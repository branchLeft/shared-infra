#!/usr/bin/env python3
"""Run the source-IP spike on a throwaway Docker lab and print a verdict per experiment.

The lab stands in for mx1: a privileged docker:dind container (`spike-host`) with one
NIC, IP1 as its primary address and IP2 added as a /32 secondary, beside an SMTP sink
(`spike-sink`) that records the TCP peer of every message. The experiments, the
refusals and what the spike does not prove are in README.md.

The Docker experiments run only with SPIKE_DOCKER=1. The judging and refusal functions
are pure and are what test_run_spike.py pins.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

# --- Pinned inputs -----------------------------------------------------------------

DIND_IMAGE = "docker:dind@sha256:08a98015fce594af7c382883bea080ea206de74402a95da9dc52b6428c8cd121"
PYTHON_IMAGE = (
    "python:3.12-alpine@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7"
)
STALWART_IMAGE = "stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
INNER_PYTHON = "spike/python:lab"
INNER_STALWART = "spike/stalwart:lab"

# --- Lab shape ---------------------------------------------------------------------

LAB_NETWORK = "spike-lab"
HOST_NAME = "spike-host"
SINK_NAME = "spike-sink"
DEFAULT_SUBNET = "10.77.0.0/24"
SINK_PORT = 2525
SCRIPT_DIR = Path(__file__).resolve().parent
LANE_NL = "bounce-nl.spike.test"
LANE_TX = "bounce-tx.spike.test"
HELO_NL = "nl.helo.spike.test"
HELO_TX = "tx.helo.spike.test"
RECIPIENT = "rcpt@sink.spike.test"
LINUX_EADDRNOTAVAIL = 99
ALLOWED_SOCKET_SUFFIXES = (
    "/.docker/run/docker.sock",
    "/.docker/desktop/docker.sock",
    "/var/run/docker.sock",
)

GREEN = "GREEN"
RED = "RED"
UNSUPPORTED = "UNSUPPORTED"
SWAPPED = "SWAPPED"
UNPROVEN = "UNPROVEN"
SKIPPED = "SKIPPED"


class RefusedError(Exception):
    """A guard stopped the run before it touched anything."""


@dataclasses.dataclass(frozen=True)
class Addresses:
    """The lab's addresses, derived from the subnet so a different subnet needs no edits."""

    subnet: str
    ip1: str
    ip2: str
    sink: str

    @classmethod
    def from_subnet(cls, subnet: str) -> Addresses:
        """Return IP1 as .2, IP2 as .3 and the sink as .50 of `subnet`.

        Raises:
            RefusedError: the subnet is not an IPv4 network of at least a /26.
        """
        try:
            network = ipaddress.ip_network(subnet, strict=True)
        except ValueError as error:
            message = f"not a network: {subnet}: {error}"
            raise RefusedError(message) from error
        if network.version != 4 or network.prefixlen > 26:
            message = f"the lab needs an IPv4 subnet of /26 or larger, got {subnet}"
            raise RefusedError(message)
        base = network.network_address
        return cls(subnet, str(base + 2), str(base + 3), str(base + 50))


# --- Pure: sink and sender output --------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Observation:
    """One message as the sink saw it."""

    peer: str
    ehlo: str
    mail_from: str
    rcpt_to: tuple[str, ...]

    def as_line(self) -> str:
        return json.dumps(
            {
                "ehlo": self.ehlo,
                "mail_from": self.mail_from,
                "peer": self.peer,
                "rcpt_to": list(self.rcpt_to),
            },
            sort_keys=True,
        )


def parse_sink_log(text: str) -> list[Observation]:
    """Return the messages in a sink log, in order; lines that are not messages are ignored."""
    found: list[Observation] = []
    for line in text.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "peer" not in data:
            continue
        found.append(
            Observation(
                peer=str(data["peer"]),
                ehlo=str(data.get("ehlo", "")),
                mail_from=str(data.get("mail_from", "")),
                rcpt_to=tuple(str(item) for item in data.get("rcpt_to", [])),
            )
        )
    return found


@dataclasses.dataclass(frozen=True)
class SendResult:
    """What sender.py printed."""

    ok: bool
    stage: str
    error: str
    errno: int | None


def parse_send_result(text: str) -> SendResult:
    """Parse the last JSON line sender.py printed; anything else is a failed send with the text."""
    for line in reversed(text.strip().splitlines()):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and "ok" in data:
            number = data.get("errno")
            return SendResult(
                ok=bool(data["ok"]),
                stage=str(data.get("stage", "")),
                error=str(data.get("error", "")),
                errno=number if isinstance(number, int) else None,
            )
    return SendResult(
        ok=False, stage="run", error=f"no result line: {text.strip()[-200:]}", errno=None
    )


# --- Pure: verdicts ----------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Verdict:
    status: str
    reason: str


def judge_peer(
    send: SendResult, seen: Sequence[Observation], mail_from: str, expected_peer: str
) -> Verdict:
    """Judge one message: it must reach the sink from `expected_peer`.

    The verdict reads the sink's peer address, never the configuration that was meant to
    produce it. A bind to an address the interface does not carry is its own red.
    """
    if send.errno == LINUX_EADDRNOTAVAIL:
        return Verdict(
            RED,
            f"address not available on the interface (errno {LINUX_EADDRNOTAVAIL}): {send.error}",
        )
    if not send.ok:
        return Verdict(RED, f"send failed at {send.stage}: {send.error}")
    matching = [item for item in seen if item.mail_from == mail_from]
    if not matching:
        return Verdict(RED, f"the sink saw no message from {mail_from}")
    peer = matching[-1].peer
    if peer != expected_peer:
        return Verdict(RED, f"the sink saw peer {peer}, expected {expected_peer}")
    return Verdict(GREEN, f"the sink saw peer {peer} as expected")


def judge_lane_pair(observed: Mapping[str, str | None], expected: Mapping[str, str]) -> Verdict:
    """Judge the two-lane run from the peers the sink saw, keyed by sender domain.

    `expected` is what the lanes are meant to do; `observed` is the sink's peer for each
    domain (None when nothing arrived). Both domains right is green. Each domain arriving
    from the other's address is the swap, which this reports by name.
    """
    missing = [domain for domain in expected if observed.get(domain) is None]
    if missing:
        return Verdict(RED, f"the sink saw no message for {', '.join(sorted(missing))}")
    wrong = {
        domain: observed[domain] for domain in expected if observed[domain] != expected[domain]
    }
    if not wrong:
        return Verdict(GREEN, "each sender domain left from its own address: " + _pairs(observed))
    if len(wrong) == len(expected) and sorted(expected.values()) == sorted(
        str(observed[d]) for d in expected
    ):
        return Verdict(SWAPPED, "the lanes left from each other's addresses: " + _pairs(observed))
    return Verdict(
        RED,
        "wrong peer for " + ", ".join(f"{d} ({wrong[d]} not {expected[d]})" for d in sorted(wrong)),
    )


def _pairs(observed: Mapping[str, str | None]) -> str:
    return ", ".join(f"{domain} from {peer}" for domain, peer in sorted(observed.items()))


UNSUPPORTED_MARKERS = (
    "invalid option",
    "unsupported",
    "unknown option",
    "invalid network option",
    "not supported",
)


def judge_network_create(returncode: int, output: str, engine_version: str) -> Verdict:
    """Judge `docker network create -o com.docker.network.host_ipv4=...`.

    A refusal that names the option is UNSUPPORTED, with the engine version and the exact
    text. Any other failure is red. Acceptance proves nothing by itself: the peer decides.
    """
    text = output.strip()
    if returncode == 0:
        return Verdict(GREEN, f"engine {engine_version} accepted the network option")
    lowered = text.lower()
    if "host_ipv4" in lowered or any(marker in lowered for marker in UNSUPPORTED_MARKERS):
        return Verdict(UNSUPPORTED, f"engine {engine_version} rejected the option: {text}")
    return Verdict(RED, f"network create failed on engine {engine_version}: {text}")


def decide(results: Mapping[str, Verdict]) -> str:
    """The one-line decision, preferring host networking when it passes.

    Host networking needs E2 and E4 green. Failing that, a second network needs E3 green,
    then a host SNAT rule E3b. A mechanism with no passing experiment is not offered.
    """

    def green(name: str) -> bool:
        return name in results and results[name].status == GREEN

    if green("E2") and green("E4"):
        return "host networking"
    if green("E3"):
        return "second Docker network with com.docker.network.host_ipv4"
    if green("E3b"):
        return "host SNAT rule for a second network"
    return "none works"


def red_then_green(results: Mapping[str, Verdict]) -> bool:
    """True when E1 is red and the decided mechanism's experiment is green in the same run."""
    return results.get("E1", Verdict(SKIPPED, "")).status == RED and decide(results) != "none works"


def exit_code(results: Mapping[str, Verdict]) -> int:
    """1 when any experiment other than E1 (expected red) is red or swapped, else 0."""
    bad = {RED, SWAPPED}
    return 1 if any(v.status in bad for name, v in results.items() if name != "E1") else 0


# --- Pure: Stalwart objects and log parsing ----------------------------------------


def connection_rule(nl_strategy: str, tx_strategy: str) -> dict[str, Any]:
    """The sender_domain rule: the newsletter bounce domain uses `nl_strategy`, all else `tx_strategy`."""
    return {
        "match": {"0": {"if": f"sender_domain == '{LANE_NL}'", "then": f"'{nl_strategy}'"}},
        "else": f"'{tx_strategy}'",
    }


def build_outbound_update(swap_domains: bool) -> dict[str, Any]:
    """The MtaOutboundStrategy singleton update. `swap_domains` is the deliberate sabotage."""
    nl_strategy, tx_strategy = ("lane-tx", "lane-nl") if swap_domains else ("lane-nl", "lane-tx")
    return {
        "route": {
            "match": {"0": {"if": "is_local_domain(rcpt_domain)", "then": "'local'"}},
            "else": "'relay'",
        },
        "connection": connection_rule(nl_strategy, tx_strategy),
    }


def build_strategies(addresses: Addresses) -> dict[str, dict[str, Any]]:
    """The two MtaConnectionStrategy objects: IP1 (transactional) and IP2 (newsletter)."""
    return {
        "tx": {
            "name": "lane-tx",
            "ehloHostname": HELO_TX,
            "sourceIps": {"0": {"sourceIp": addresses.ip1}},
        },
        "nl": {
            "name": "lane-nl",
            "ehloHostname": HELO_NL,
            "sourceIps": {"0": {"sourceIp": addresses.ip2}},
        },
    }


def build_relay_route(addresses: Addresses) -> dict[str, Any]:
    """The relay route that stands in for the real Mx route."""
    return {
        "@type": "Relay",
        "name": "relay",
        "address": addresses.sink,
        "port": SINK_PORT,
        "protocol": "smtp",
        "implicitTls": False,
        "allowInvalidCerts": True,
    }


def find_field(keys: Iterable[str], *needles: str) -> str | None:
    """Return the first key containing any needle, ignoring case; None when no key does."""
    for key in sorted(keys):
        lowered = key.lower()
        if any(needle in lowered for needle in needles):
            return key
    return None


def find_rejections(response: Mapping[str, Any]) -> list[str]:
    """Return a description of every JMAP method error and every not-created/updated entry."""
    problems: list[str] = []
    for item in response.get("methodResponses", []):
        name, body = item[0], item[1]
        if name == "error":
            problems.append(f"method error: {body}")
        for key in ("notCreated", "notUpdated", "notDestroyed"):
            if isinstance(body, dict) and body.get(key):
                problems.append(f"{name} {key}: {body[key]}")
    return problems


def parse_delivery_connect(log_text: str) -> list[tuple[str, str]]:
    """Return (sender, localIp) for each delivery.connect event in a Stalwart log."""
    found: list[tuple[str, str]] = []
    for line in log_text.splitlines():
        if "(delivery.connect)" not in line:
            continue
        sender = _field(line, "from")
        local_ip = _field(line, "localIp")
        if sender and local_ip:
            found.append((sender.strip('"'), local_ip))
    return found


def _field(line: str, name: str) -> str:
    marker = f"{name} = "
    start = line.find(marker)
    if start == -1:
        return ""
    value = line[start + len(marker) :]
    end = value.find(", ")
    return (value if end == -1 else value[:end]).strip()


def parse_bootstrap_password(log_text: str) -> str:
    """Return the temporary administrator password Stalwart prints in bootstrap mode.

    Raises:
        RefusedError: the log has no password line.
    """
    for line in log_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("password:"):
            return stripped.split(":", 1)[1].strip()
    message = "no bootstrap password in the Stalwart log"
    raise RefusedError(message)


# --- Pure: guards ------------------------------------------------------------------


def check_docker_target(environ: Mapping[str, str], endpoint: str) -> None:
    """Refuse to run against anything but the local Docker socket.

    Raises:
        RefusedError: DOCKER_HOST is set, or the current context is not a local unix socket.
    """
    if environ.get("DOCKER_HOST"):
        message = "DOCKER_HOST is set; the spike runs only against the local Docker socket"
        raise RefusedError(message)
    if not endpoint.startswith("unix://") or not endpoint.endswith(ALLOWED_SOCKET_SUFFIXES):
        message = f"the Docker context endpoint {endpoint!r} is not a local Docker socket"
        raise RefusedError(message)


def check_subnet_free(subnet: str, existing: Iterable[str]) -> None:
    """Refuse when `subnet` overlaps any existing Docker network subnet.

    Raises:
        RefusedError: an existing network overlaps.
    """
    wanted = ipaddress.ip_network(subnet)
    for other in existing:
        if wanted.overlaps(ipaddress.ip_network(other, strict=False)):
            message = f"{subnet} overlaps an existing Docker network ({other})"
            raise RefusedError(message)


def check_spike_names(names: Iterable[str]) -> None:
    """Refuse to remove anything that is not named spike-*.

    Raises:
        RefusedError: a name outside the lab.
    """
    for name in names:
        if not name.startswith("spike-"):
            message = f"refusing to touch {name!r}: not a spike-* object"
            raise RefusedError(message)


def check_outer_argv(args: Sequence[str]) -> None:
    """Refuse an outer-engine run that would use the Desktop VM's own host network.

    Raises:
        RefusedError: a run or create with host networking against the outer engine.
    """
    if not args or args[0] not in ("run", "create"):
        return
    joined = " ".join(args)
    for flag in ("--network host", "--network=host", "--net host", "--net=host"):
        if flag in joined:
            message = "host networking on the outer Docker engine is refused"
            raise RefusedError(message)


# --- Docker access -----------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Outcome:
    returncode: int
    output: str


class Docker:
    """The only place subprocess is used: argv lists, never a shell."""

    def __init__(self) -> None:
        found = shutil.which("docker")
        if found is None:
            message = "docker is not on PATH"
            raise RefusedError(message)
        self.binary = found

    def outer(
        self, args: Sequence[str], stdin: str | None = None, timeout: float = 180.0
    ) -> Outcome:
        check_outer_argv(args)
        return self._run([self.binary, *args], stdin, timeout)

    def inner(
        self, args: Sequence[str], stdin: str | None = None, timeout: float = 180.0
    ) -> Outcome:
        """Run a docker command inside spike-host's own dockerd."""
        flags = ["-i"] if stdin is not None else []
        return self._run([self.binary, "exec", *flags, HOST_NAME, "docker", *args], stdin, timeout)

    def _run(self, argv: Sequence[str], stdin: str | None, timeout: float) -> Outcome:
        try:
            done = subprocess.run(  # noqa: S603 - argv list, fixed binary
                list(argv),
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return Outcome(124, f"timed out after {timeout}s: {error}")
        return Outcome(done.returncode, done.stdout + done.stderr)

    def pipe_image(self, reference: str) -> Outcome:
        """`docker save reference | docker exec -i spike-host docker load`."""
        saver = subprocess.Popen(  # noqa: S603
            [self.binary, "save", reference], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        loader = subprocess.Popen(  # noqa: S603
            [self.binary, "exec", "-i", HOST_NAME, "docker", "load"],
            stdin=saver.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if saver.stdout is not None:
            saver.stdout.close()
        out, _ = loader.communicate(timeout=600)
        saver.wait(timeout=60)
        return Outcome(loader.returncode or saver.returncode, out)


# --- The lab -----------------------------------------------------------------------


@dataclasses.dataclass
class Experiment:
    name: str
    title: str
    verdict: Verdict
    evidence: list[str]


class Lab:
    """Builds the lab, runs experiments against it and removes only spike-* objects."""

    def __init__(
        self, docker: Docker, addresses: Addresses, *, with_ip2: bool, dind_image: str
    ) -> None:
        self.docker = docker
        self.addresses = addresses
        self.with_ip2 = with_ip2
        self.dind_image = dind_image
        self.pulled: list[str] = []
        self.engine_version = ""
        self.login: tuple[str, str] = ("", "")

    # -- setup / teardown --

    def ensure_image(self, reference: str) -> None:
        if self.docker.outer(["image", "inspect", reference]).returncode == 0:
            return
        pulled = self.docker.outer(["pull", reference], timeout=900)
        if pulled.returncode != 0:
            message = f"could not pull {reference}: {pulled.output[-300:]}"
            raise RefusedError(message)
        self.pulled.append(reference)

    def build(self) -> None:
        for reference in (self.dind_image, PYTHON_IMAGE):
            self.ensure_image(reference)
        self._require(
            self.docker.outer(
                ["network", "create", "--subnet", self.addresses.subnet, LAB_NETWORK]
            ),
            "lab network",
        )
        self._require(
            self.docker.outer(
                [
                    "run",
                    "-d",
                    "--name",
                    HOST_NAME,
                    "--privileged",
                    "--network",
                    LAB_NETWORK,
                    "--ip",
                    self.addresses.ip1,
                    self.dind_image,
                    "dockerd",
                    "--host=unix:///var/run/docker.sock",
                ]
            ),
            "spike-host",
        )
        self._wait_for_inner_engine()
        if self.with_ip2:
            self._require(
                self.docker.outer(
                    [
                        "exec",
                        HOST_NAME,
                        "ip",
                        "addr",
                        "add",
                        f"{self.addresses.ip2}/32",
                        "dev",
                        "eth0",
                    ]
                ),
                "add IP2",
            )
        self._require(
            self.docker.outer(["cp", f"{SCRIPT_DIR}/.", f"{HOST_NAME}:/spike"]), "copy scripts"
        )
        self._load_inner_image(PYTHON_IMAGE, INNER_PYTHON)
        self._start_sink()

    def _wait_for_inner_engine(self) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = self.docker.inner(["version", "--format", "{{.Server.Version}}"], timeout=20)
            if result.returncode == 0:
                self.engine_version = result.output.strip()
                return
            time.sleep(2)
        message = "the inner dockerd did not come up in 90 s"
        raise RefusedError(message)

    def _load_inner_image(self, reference: str, tag: str) -> None:
        self.ensure_image(reference)
        loaded = self.docker.pipe_image(reference)
        self._require(loaded, f"load {reference}")
        image = loaded.output.strip().splitlines()[-1].split(": ", 1)[-1].strip()
        self._require(self.docker.inner(["tag", image, tag]), f"tag {tag}")

    def _start_sink(self) -> None:
        self._require(
            self.docker.outer(
                [
                    "create",
                    "--name",
                    SINK_NAME,
                    "--network",
                    LAB_NETWORK,
                    "--ip",
                    self.addresses.sink,
                    PYTHON_IMAGE,
                    "python3",
                    "-I",
                    "/spike/sink.py",
                    "--port",
                    str(SINK_PORT),
                ]
            ),
            "create sink",
        )
        self._require(
            self.docker.outer(["cp", f"{SCRIPT_DIR}/.", f"{SINK_NAME}:/spike"]), "copy sink"
        )
        self._require(self.docker.outer(["start", SINK_NAME]), "start sink")

    def teardown(self, *, remove_pulled: bool) -> None:
        names = [HOST_NAME, SINK_NAME]
        check_spike_names(names)
        self.docker.outer(["rm", "-f", "-v", *names])
        check_spike_names([LAB_NETWORK])
        self.docker.outer(["network", "rm", LAB_NETWORK])
        if remove_pulled:
            for reference in self.pulled:
                self.docker.outer(["image", "rm", reference])

    @staticmethod
    def _require(outcome: Outcome, what: str) -> None:
        if outcome.returncode != 0:
            message = f"{what} failed: {outcome.output.strip()[-400:]}"
            raise RefusedError(message)

    # -- observing --

    def sink_log(self) -> list[Observation]:
        return parse_sink_log(self.docker.outer(["logs", SINK_NAME]).output)

    def sink_count(self) -> int:
        return len(self.sink_log())

    def wait_for_senders(
        self, before: int, senders: Sequence[str], timeout: float
    ) -> list[Observation]:
        """Poll the sink until every sender in `senders` has a new message, or the timeout passes."""
        deadline = time.monotonic() + timeout
        while True:
            fresh = self.sink_log()[before:]
            if all(any(item.mail_from == sender for item in fresh) for sender in senders):
                return fresh
            if time.monotonic() >= deadline:
                return fresh
            time.sleep(2)

    def send(
        self,
        network: str | None,
        extra: Sequence[str],
        *,
        host: str | None = None,
        port: int = SINK_PORT,
    ) -> SendResult:
        """Run sender.py in a throwaway container inside spike-host on `network`."""
        args = ["run", "--rm"]
        if network:
            args += ["--network", network]
        args += ["-v", "/spike:/spike:ro", INNER_PYTHON, "python3", "-I", "/spike/sender.py"]
        args += ["--host", host or self.addresses.sink, "--port", str(port), *extra]
        return parse_send_result(self.docker.inner(args, timeout=60).output)

    # -- experiments --

    def experiment_bind(
        self, name: str, title: str, network: str | None, cases: Sequence[tuple[str, str, str]]
    ) -> Experiment:
        """Run `cases` of (source, mail_from, expected_peer) from one container network; green only if all are."""
        evidence: list[str] = []
        verdicts: list[Verdict] = []
        for source, mail_from, expected in cases:
            before = self.sink_count()
            extra = ["--mail-from", mail_from]
            if source:
                extra += ["--source", source]
            result = self.send(network, extra)
            fresh = self.wait_for_senders(before, [mail_from], 6) if result.ok else []
            verdict = judge_peer(result, fresh, mail_from, expected)
            verdicts.append(verdict)
            evidence.append(
                f"bind {source or 'none'} -> expect {expected}: {verdict.status}: {verdict.reason}"
            )
            evidence += [item.as_line() for item in fresh if item.mail_from == mail_from]
        failed = [v for v in verdicts if v.status != GREEN]
        overall = (
            failed[0]
            if failed
            else Verdict(GREEN, "every case reached the sink from the expected address")
        )
        return Experiment(name, title, overall, evidence)

    def run_e1(self) -> Experiment:
        a = self.addresses
        found = self.experiment_bind(
            "E1",
            "default bridge (as mx1 runs Stalwart today)",
            None,
            [(a.ip2, "e1-bound-ip2@spike.test", a.ip2)],
        )
        before = self.sink_count()
        result = self.send(None, ["--mail-from", "e1-unbound@spike.test"])
        fresh = self.wait_for_senders(before, ["e1-unbound@spike.test"], 6) if result.ok else []
        seen = [item for item in fresh if item.mail_from == "e1-unbound@spike.test"]
        found.evidence.append(
            "unbound send from a bridge container: " + (seen[-1].peer if seen else result.error)
        )
        found.evidence += [item.as_line() for item in seen]
        return found

    def run_e2(self) -> Experiment:
        a = self.addresses
        return self.experiment_bind(
            "E2",
            "host networking",
            "host",
            [(a.ip2, "e2-ip2@spike.test", a.ip2), (a.ip1, "e2-ip1@spike.test", a.ip1)],
        )

    def run_e3(self) -> tuple[Experiment, bool]:
        a = self.addresses
        created = self.docker.inner(
            ["network", "create", "-o", f"com.docker.network.host_ipv4={a.ip2}", "spike-net2"]
        )
        verdict = judge_network_create(created.returncode, created.output, self.engine_version)
        if verdict.status != GREEN:
            return Experiment(
                "E3", "second Docker network with host_ipv4", verdict, [verdict.reason]
            ), False
        found = self.experiment_bind(
            "E3",
            "second Docker network with host_ipv4",
            "spike-net2",
            [("", "e3-net2@spike.test", a.ip2)],
        )
        other = self.experiment_bind("E3", "", None, [("", "e3-default@spike.test", a.ip1)])
        found.evidence += other.evidence
        if other.verdict.status != GREEN and found.verdict.status == GREEN:
            found.verdict = other.verdict
        return found, True

    def run_e3b(self) -> Experiment:
        a = self.addresses
        created = self.docker.inner(
            [
                "network",
                "create",
                "--subnet",
                "172.30.0.0/24",
                "-o",
                "com.docker.network.bridge.name=spike-br3",
                "spike-net3",
            ]
        )
        if created.returncode != 0:
            return Experiment(
                "E3b",
                "host SNAT rule",
                Verdict(RED, created.output.strip()),
                [created.output.strip()],
            )
        rule = [
            "iptables",
            "-t",
            "nat",
            "-I",
            "POSTROUTING",
            "1",
            "-s",
            "172.30.0.0/24",
            "!",
            "-o",
            "spike-br3",
            "-j",
            "SNAT",
            "--to-source",
            a.ip2,
        ]
        added = self.docker.outer(["exec", HOST_NAME, *rule])
        if added.returncode != 0:
            return Experiment(
                "E3b", "host SNAT rule", Verdict(RED, added.output.strip()), [added.output.strip()]
            )
        found = self.experiment_bind(
            "E3b",
            "host SNAT rule for a second network",
            "spike-net3",
            [("", "e3b-snat@spike.test", a.ip2)],
        )
        found.evidence.insert(0, "rule: " + " ".join(rule))
        return found

    def jmap(self, user: str, password: str, calls: list[list[Any]]) -> dict[str, Any]:
        """One JMAP request to Stalwart's management API, from a host-network container.

        Raises:
            RefusedError: the request failed or Stalwart rejected an object.
        """
        payload = json.dumps({"user": user, "password": password, "methodCalls": calls})
        args = [
            "run",
            "--rm",
            "-i",
            "--network",
            "host",
            "-v",
            "/spike:/spike:ro",
            INNER_PYTHON,
            "python3",
            "-I",
            "/spike/run_spike.py",
            "jmap",
        ]
        result = self.docker.inner(args, stdin=payload, timeout=60)
        try:
            response = json.loads(result.output)
        except json.JSONDecodeError as error:
            message = f"JMAP call failed: {result.output.strip()[-300:]}"
            raise RefusedError(message) from error
        problems = find_rejections(response)
        if problems:
            message = "JMAP rejected: " + "; ".join(problems)
            raise RefusedError(message)
        return response  # type: ignore[no-any-return]

    def _wait_for_jmap(self, user: str, password: str, *, bootstrap: bool = False) -> None:
        probe = "x:Bootstrap/get" if bootstrap else "x:Domain/get"
        arguments: dict[str, Any] = {"ids": ["singleton"]} if bootstrap else {}
        deadline = time.monotonic() + 90
        last = ""
        while time.monotonic() < deadline:
            try:
                self.jmap(user, password, [[probe, arguments, "0"]])
            except RefusedError as error:
                last = str(error)
                time.sleep(3)
            else:
                return
        message = f"Stalwart's management API did not answer in 90 s: {last}"
        raise RefusedError(message)

    def run_e4(self, *, swap_domains: bool) -> tuple[Experiment, dict[str, Any]]:
        """Stalwart on host networking with the sender_domain connection rule."""
        a = self.addresses
        self._load_inner_image(STALWART_IMAGE, INNER_STALWART)
        self._require(
            self.docker.inner(
                [
                    "run",
                    "-d",
                    "--name",
                    "stalwart",
                    "--network",
                    "host",
                    "-e",
                    "STALWART_HOSTNAME=mx1.spike.test",
                    INNER_STALWART,
                ]
            ),
            "start stalwart",
        )
        password = self._wait_for_bootstrap_password()
        self._wait_for_jmap("admin", password, bootstrap=True)
        done = self.jmap(
            "admin", password, [["x:Bootstrap/set", {"update": {"singleton": {}}}, "0"]]
        )
        created = done["methodResponses"][0][1]["updated"]["singleton"]
        user, secret = created["username"], created["secret"]
        self.login = (user, secret)
        self._require(self.docker.inner(["restart", "stalwart"]), "restart after bootstrap")
        self._wait_for_jmap(user, secret)
        schema = self._discover_schema(user, secret)
        accounts = self._provision_lanes(user, secret, a, swap_domains)
        self._require(self.docker.inner(["restart", "stalwart"]), "restart to apply objects")
        self._wait_for_jmap(user, secret)
        senders = {LANE_NL: f"nl@{LANE_NL}", LANE_TX: f"tx@{LANE_TX}"}
        before = self.sink_count()
        results = {
            domain: self.send(
                "host",
                [
                    "--mail-from",
                    sender,
                    "--rcpt-to",
                    RECIPIENT,
                    "--implicit-tls",
                    "--auth-user",
                    sender,
                    "--auth-password",
                    accounts[domain],
                    "--ehlo",
                    "client.spike.test",
                ],
                host="127.0.0.1",
                port=465,
            )
            for domain, sender in senders.items()
        }
        fresh = self.wait_for_senders(before, list(senders.values()), 45)
        return self._judge_e4(senders, results, fresh), schema

    def _wait_for_bootstrap_password(self) -> str:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            logs = self.docker.inner(["logs", "stalwart"]).output
            try:
                return parse_bootstrap_password(logs)
            except RefusedError:
                time.sleep(2)
        message = "Stalwart printed no bootstrap password in 60 s"
        raise RefusedError(message)

    def _discover_schema(self, user: str, secret: str) -> dict[str, Any]:
        """Record the field names the running server offers for HELO name and IP family."""
        response = self.jmap(
            user,
            secret,
            [["x:MtaConnectionStrategy/get", {}, "s"], ["x:MtaRoute/get", {}, "r"]],
        )
        strategy = response["methodResponses"][0][1]["list"][0]
        routes = [
            item for item in response["methodResponses"][1][1]["list"] if item.get("@type") == "Mx"
        ]
        route_keys = sorted(routes[0]) if routes else []
        return {
            "connection_strategy_fields": sorted(strategy),
            "ehlo_field": find_field(strategy, "ehlo", "helo"),
            "mx_route_fields": route_keys,
            "ip_family_field": find_field(route_keys, "iplookup"),
            "mx_route_id": routes[0]["id"] if routes else None,
        }

    def _provision_lanes(
        self, user: str, secret: str, a: Addresses, swap_domains: bool
    ) -> dict[str, str]:
        domains = self.jmap(
            user,
            secret,
            [
                [
                    "x:Domain/set",
                    {
                        "create": {
                            "nl": {"name": LANE_NL, "dkimManagement": {"@type": "Manual"}},
                            "tx": {"name": LANE_TX, "dkimManagement": {"@type": "Manual"}},
                        }
                    },
                    "d",
                ],
                [
                    "x:Account/set",
                    {
                        "create": {
                            "nl": {"@type": "User", "name": "nl", "domainId": "#nl"},
                            "tx": {"@type": "User", "name": "tx", "domainId": "#tx"},
                        }
                    },
                    "a",
                ],
            ],
        )
        made = domains["methodResponses"][1][1]["created"]
        passwords: dict[str, str] = {}
        for key, domain in (("nl", LANE_NL), ("tx", LANE_TX)):
            granted = self.jmap(
                user,
                secret,
                [
                    [
                        "x:AppPassword/set",
                        {
                            "accountId": made[key]["id"],
                            "create": {
                                "s": {
                                    "description": "spike",
                                    "permissions": {
                                        "@type": "Replace",
                                        "permissions": {"authenticate": True, "emailSend": True},
                                    },
                                }
                            },
                        },
                        "p",
                    ]
                ],
            )
            passwords[domain] = granted["methodResponses"][0][1]["created"]["s"]["secret"]
        tracer_id = self.jmap(user, secret, [["x:Tracer/get", {}, "t"]])["methodResponses"][0][1][
            "list"
        ][0]["id"]
        self.jmap(
            user,
            secret,
            [
                ["x:MtaConnectionStrategy/set", {"create": build_strategies(a)}, "c"],
                ["x:MtaRoute/set", {"create": {"relay": build_relay_route(a)}}, "r"],
                [
                    "x:MtaOutboundStrategy/set",
                    {"update": {"singleton": build_outbound_update(swap_domains)}},
                    "o",
                ],
                [
                    "x:Tracer/set",
                    {
                        "update": {
                            tracer_id: {
                                "@type": "Stdout",
                                "ansi": False,
                                "multiline": False,
                                "enable": True,
                                "level": "trace",
                                "lossy": False,
                                "events": {},
                                "eventsPolicy": "exclude",
                            }
                        }
                    },
                    "l",
                ],
            ],
        )
        return passwords

    def _judge_e4(
        self,
        senders: Mapping[str, str],
        sent: Mapping[str, SendResult],
        fresh: Sequence[Observation],
    ) -> Experiment:
        a = self.addresses
        expected = {LANE_NL: a.ip2, LANE_TX: a.ip1}
        observed: dict[str, str | None] = {}
        evidence: list[str] = []
        for domain, sender in senders.items():
            matching = [item for item in fresh if item.mail_from == sender]
            observed[domain] = matching[-1].peer if matching else None
            if not sent[domain].ok:
                evidence.append(
                    f"submission as {sender} failed at {sent[domain].stage}: {sent[domain].error}"
                )
            evidence += [item.as_line() for item in matching]
        verdict = judge_lane_pair(observed, expected)
        trace = parse_delivery_connect(self.docker.inner(["logs", "stalwart"]).output)
        evidence += [f"delivery.connect from={sender} localIp={local}" for sender, local in trace]
        helo = {item.mail_from: item.ehlo for item in fresh}
        evidence.append(
            f"EHLO per lane: nl={helo.get(senders[LANE_NL], 'none')} tx={helo.get(senders[LANE_TX], 'none')}"
        )
        return Experiment(
            "E4", "Stalwart v0.16.17 with a sender_domain connection rule", verdict, evidence
        )

    def run_e5(self, schema: Mapping[str, Any]) -> Experiment:
        """Look for the IPv4-only setting, set it and read it back; the effect needs a dual-stack peer."""
        field, route_id = schema.get("ip_family_field"), schema.get("mx_route_id")
        if not field or not route_id:
            return Experiment(
                "E5",
                "IPv4-only delivery",
                Verdict(UNSUPPORTED, "no IP-family field on the Mx route"),
                [str(schema.get("mx_route_fields"))],
            )
        user, secret = self.login
        self.jmap(
            user, secret, [["x:MtaRoute/set", {"update": {route_id: {field: "v4Only"}}}, "u"]]
        )
        back = self.jmap(user, secret, [["x:MtaRoute/get", {"ids": [route_id]}, "g"]])[
            "methodResponses"
        ][0][1]["list"][0]
        held = back.get(field) == "v4Only"
        reason = f"field {field} accepts v4Only and reads back {back.get(field)!r}; its effect against a target with both A and AAAA is not shown by this lab"
        return Experiment(
            "E5", "IPv4-only delivery", Verdict(UNPROVEN if held else RED, reason), [reason]
        )


# --- JMAP helper (runs inside an inner container) -----------------------------------


def jmap_helper(stdin: str) -> int:
    """Read {user, password, methodCalls} on stdin, POST to Stalwart's /jmap, print the response."""
    request = json.loads(stdin)
    body = json.dumps(
        {"using": ["urn:ietf:params:jmap:core"], "methodCalls": request["methodCalls"]}
    ).encode()
    token = base64.b64encode(f"{request['user']}:{request['password']}".encode()).decode()
    call = urllib.request.Request("http://127.0.0.1:8080/jmap", data=body, method="POST")
    call.add_header("Authorization", f"Basic {token}")
    call.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(call, timeout=20) as reply:  # noqa: S310 - fixed http URL
            print(reply.read().decode())
    except (urllib.error.URLError, OSError) as error:
        print(json.dumps({"methodResponses": [["error", {"transport": str(error)}, "0"]]}))
        return 1
    return 0


# --- Orchestration -----------------------------------------------------------------


def current_endpoint(docker: Docker) -> str:
    outcome = docker.outer(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
    return outcome.output.strip() if outcome.returncode == 0 else ""


def existing_subnets(docker: Docker) -> list[str]:
    ids = docker.outer(["network", "ls", "-q"]).output.split()
    if not ids:
        return []
    inspected = docker.outer(["network", "inspect", *ids]).output
    subnets: list[str] = []
    for network in json.loads(inspected or "[]"):
        for config in (network.get("IPAM") or {}).get("Config") or []:
            if config.get("Subnet"):
                subnets.append(config["Subnet"])
    return subnets


def render_report(
    env: Mapping[str, str], experiments: Sequence[Experiment], decision: str, flags: str
) -> str:
    """The text the README's results table is built from."""
    lines = [f"Run flags: {flags}"] + [f"{key}: {value}" for key, value in env.items()] + [""]
    for item in experiments:
        lines.append(f"{item.name} {item.title}: {item.verdict.status} - {item.verdict.reason}")
        lines += [f"    {line}" for line in item.evidence[:12]]
    verdicts = {item.name: item.verdict for item in experiments}
    lines += [
        "",
        f"Decision: {decision}",
        f"Red then green in this run: {red_then_green(verdicts)}",
    ]
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    if os.environ.get("SPIKE_DOCKER") != "1":
        print("refused: set SPIKE_DOCKER=1 to run the Docker experiments", file=sys.stderr)
        return 2
    wanted = [item.strip().lower() for item in args.experiments.split(",") if item.strip()]
    docker = Docker()
    addresses = Addresses.from_subnet(args.subnet)
    check_docker_target(os.environ, current_endpoint(docker))
    check_subnet_free(addresses.subnet, existing_subnets(docker))
    lab = Lab(docker, addresses, with_ip2=not args.no_ip2, dind_image=args.dind_image)
    done: list[Experiment] = []
    env: dict[str, str] = {}
    try:
        lab.build()
        outer = docker.outer(
            [
                "version",
                "--format",
                "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}} kernel {{.Server.KernelVersion}}",
            ]
        )
        env = {
            "Date": time.strftime("%Y-%m-%d", time.gmtime()),
            "Outer engine": outer.output.strip(),
            "Inner engine (dind)": lab.engine_version,
            "dind image": args.dind_image,
            "Interface eth0": docker.outer(
                ["exec", HOST_NAME, "ip", "-4", "-o", "addr", "show", "eth0"]
            )
            .output.strip()
            .replace("\n", " | "),
        }
        done = run_experiments(lab, wanted, swap_domains=args.swap_domains)
    finally:
        lab.teardown(remove_pulled=args.remove_pulled_images)
    flags = (
        ("no-ip2 " if args.no_ip2 else "")
        + ("swap-domains " if args.swap_domains else "")
        + f"experiments={args.experiments}"
    )
    verdicts = {item.name: item.verdict for item in done}
    decision = decide(verdicts)
    report = render_report(env, done, decision, flags.strip())
    print(report)
    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "env": env,
                    "results": {k: dataclasses.asdict(v) for k, v in verdicts.items()},
                    "decision": decision,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return exit_code(verdicts)


def run_experiments(lab: Lab, wanted: Sequence[str], *, swap_domains: bool) -> list[Experiment]:
    done: list[Experiment] = []
    e3_supported = True
    if "e1" in wanted:
        done.append(lab.run_e1())
    if "e2" in wanted:
        done.append(lab.run_e2())
    if "e3" in wanted:
        e3, e3_supported = lab.run_e3()
        done.append(e3)
    if "e3b" in wanted or ("e3" in wanted and not e3_supported):
        done.append(lab.run_e3b())
    if "e4" in wanted or "e5" in wanted:
        e4, schema = lab.run_e4(swap_domains=swap_domains)
        if "e4" in wanted:
            done.append(e4)
        if "e5" in wanted:
            done.append(lab.run_e5(schema))
        done.append(
            Experiment(
                "E4-schema",
                "field names the running server offers",
                Verdict(
                    GREEN if schema.get("ehlo_field") else UNSUPPORTED,
                    f"per-strategy HELO field: {schema.get('ehlo_field')}; IP-family field: {schema.get('ip_family_field')}",
                ),
                [json.dumps(schema, sort_keys=True)],
            )
        )
    return done


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["jmap"]:
        return jmap_helper(sys.stdin.read())
    parser = argparse.ArgumentParser(description="Run the source-IP spike (needs SPIKE_DOCKER=1).")
    parser.add_argument("--experiments", default="e1,e2,e3,e4")
    parser.add_argument("--subnet", default=DEFAULT_SUBNET)
    parser.add_argument("--dind-image", default=DIND_IMAGE)
    parser.add_argument("--no-ip2", action="store_true", help="sabotage: build the lab without IP2")
    parser.add_argument(
        "--swap-domains",
        action="store_true",
        help="sabotage: swap the sender domains in the E4 rule",
    )
    parser.add_argument("--remove-pulled-images", action="store_true")
    parser.add_argument("--json", default="")
    try:
        return run(parser.parse_args(arguments))
    except RefusedError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
