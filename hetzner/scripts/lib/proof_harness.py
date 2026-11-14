"""The shared harness for the Docker-in-Docker proofs in hetzner/scripts.

A proof drives a real dockerd inside a privileged stand-in container and checks
what the host's firewall rules let through. This module holds what the proofs
share: the PASS and FAIL tally, the wait loops, the stand-in host's command
runner, the counters that read iptables output, and the cleanup. It names no
policy script; each proof does that.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable, Sequence
from subprocess import DEVNULL, PIPE


class ProofAbort(Exception):
    """A step the proof cannot go on past. Its message is printed and the proof exits 1."""


class Tally:
    """Counts PASS and FAIL lines and prints the closing summary."""

    def __init__(self) -> None:
        self.passes = 0
        self.failures = 0

    def heading(self, text: str) -> None:
        print(f"== {text}")

    def passed(self, name: str) -> None:
        self.passes += 1
        print(f"PASS: {name}")

    def failed(self, name: str) -> None:
        self.failures += 1
        print(f"FAIL: {name}")

    def expect_reach(self, name: str, reaches: Callable[[], bool]) -> None:
        if reaches():
            self.passed(name)
        else:
            self.failed(name)

    def expect_blocked(self, name: str, reaches: Callable[[], bool]) -> None:
        if reaches():
            self.failed(name)
        else:
            self.passed(name)

    def summary(self) -> int:
        print()
        print(f"{self.passes} passed, {self.failures} failed")
        return 0 if self.failures == 0 else 1


def keep_containers() -> bool:
    """True when KEEP_PROOF_CONTAINERS is set to anything non-empty: the containers are left running."""
    return bool(os.environ.get("KEEP_PROOF_CONTAINERS"))


def wait_until(
    ready: Callable[[], bool], *, limit: int, message: str, pause: float = 1.0
) -> None:
    """Poll ready() until it holds. After limit failed tries, abort with message."""
    tries = 0
    while not ready():
        tries += 1
        if tries >= limit:
            raise ProofAbort(message)
        time.sleep(pause)


def run(
    argv: Sequence[str],
    *,
    out: int | None = None,
    err: int | None = None,
    stdin: int | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run argv with no shell. out and err take subprocess.DEVNULL to discard that stream."""
    return subprocess.run(list(argv), stdout=out, stderr=err, stdin=stdin, check=check)


def ok(argv: Sequence[str]) -> bool:
    """True when argv exits 0. Its stdout and stderr are discarded, as >/dev/null 2>&1 does."""
    return run(argv, out=DEVNULL, err=DEVNULL, check=False).returncode == 0


def reaches(argv: Sequence[str]) -> bool:
    """True when argv exits 0. Its stdout is discarded and its stderr is shown, as a bare wget is."""
    return run(argv, out=DEVNULL, check=False).returncode == 0


def output(argv: Sequence[str]) -> str:
    """Return argv's stdout, as $(...) does. Its stderr is shown. A non-zero exit raises."""
    return subprocess.run(list(argv), stdout=PIPE, text=True, check=True).stdout


class StandIn:
    """A stand-in host container. Commands run in it through sh -c, as the proofs' on_host did.

    Once dockerd is up, dockerd_path is set to its own PATH, so that the policy writes
    to the iptables backend dockerd uses.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.dockerd_path = ""

    def _argv(self, command: str) -> list[str]:
        if self.dockerd_path:
            return [
                "docker",
                "exec",
                "-e",
                f"PATH={self.dockerd_path}",
                self.name,
                "sh",
                "-c",
                command,
            ]
        return ["docker", "exec", self.name, "sh", "-c", command]

    def run(
        self,
        command: str,
        *,
        out: int | None = None,
        err: int | None = None,
        check: bool = True,
    ) -> None:
        run(self._argv(command), out=out, err=err, check=check)

    def ok(self, command: str) -> bool:
        return ok(self._argv(command))

    def reaches(self, command: str) -> bool:
        return reaches(self._argv(command))

    def output(self, command: str) -> str:
        return output(self._argv(command))


def network_address(container: str, network: str) -> str:
    """The container's address on network, read with docker inspect."""
    template = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
    return output(["docker", "inspect", "-f", template, container]).strip()


def remove_resources(containers: Sequence[str], networks: Sequence[str]) -> None:
    """Remove the proof's containers and networks. Anything already gone is not an error."""
    if containers:
        run(
            ["docker", "rm", "-f", "-v", *containers],
            out=DEVNULL,
            err=DEVNULL,
            check=False,
        )
    for network in networks:
        run(["docker", "network", "rm", network], out=DEVNULL, err=DEVNULL, check=False)


def count_lines_containing(text: str, needle: str) -> int:
    """grep -c: the number of lines that contain needle."""
    return sum(1 for line in text.splitlines() if needle in line)


def packet_count(text: str) -> int | None:
    """The packet counter a one-line awk print gives, or None when the text is not one whole number.

    A shell integer test on anything else is false, so the caller treats None as a failed comparison.
    """
    value = text.strip()
    return int(value) if value.isdigit() else None
