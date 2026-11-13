#!/usr/bin/python3
"""Dead-man revert for the demo host's egress table.

The egress program loads two chains and the jumps to them. This program keeps the last
table an apply confirmed and puts it back when the next apply does not confirm in time.

  arm --seconds N   Called before an apply loads a changed table. Records that an apply is
                    unconfirmed, then starts a timer that runs `revert` after N seconds. With
                    no known-good table there is nothing to put back, so no timer is started.
  confirm           Called when the apply has finished and been read back. Saves the table now
                    loaded as the last known-good one, stops the timer and clears the record.
  revert            Run by the timer. Puts the last known-good table back and leaves it there.
  status            Prints the record, the timer and whether a known-good table is held.

The one rule: a revert never leaves an empty or an open table. A snapshot is only saved or
restored when it is whole (both chains, each with a REJECT rule, and the jump to each); anything
else is refused and the table is left as it is. Standard library only.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

FORWARD_CHAIN: Final = "BRANCHLEFT-DEMO-EGRESS"
INPUT_CHAIN: Final = "BRANCHLEFT-DEMO-INPUT"
OWN_CHAINS: Final = (FORWARD_CHAIN, INPUT_CHAIN)
# The chain each own chain is jumped to from.
JUMP_FROM: Final = {FORWARD_CHAIN: "DOCKER-USER", INPUT_CHAIN: "INPUT"}
FAMILIES: Final = ("iptables", "ip6tables")
STATE_DIR: Final = Path("/var/lib/branchleft-demo-egress-revert")
TIMER_UNIT: Final = "branchleft-demo-egress-revert"
PROGRAM: Final = "/usr/local/sbin/branchleft-demo-egress-revert"
MIN_SECONDS: Final = 10
MAX_SECONDS: Final = 3600
ARMED: Final = "armed"
REVERTED: Final = "reverted"
REJECT_RULE: Final = re.compile(r"\s-j REJECT(\s|\Z)")
# Exit codes: 0 done, 1 refused or failed, 2 nothing known-good to put back.
OK: Final = 0
FAILED: Final = 1
NOTHING_TO_RESTORE: Final = 2


class RevertError(Exception):
    """A command failed, or the loaded table is not the one the program meant to leave."""


class CommandFailedError(RevertError):
    """A command the program ran exited with a status other than 0."""

    def __init__(self, command: str, status: int, error: str) -> None:
        """Name the command, its status and what it said."""
        super().__init__(f"{command} failed with status {status}: {error}")


class NotRestoredError(RevertError):
    """The table read back after a restore is not the known-good one."""

    def __init__(self, family: str) -> None:
        """Name the family whose table is wrong."""
        super().__init__(f"the {family} table is not the known-good one after the restore")


def say(message: str) -> None:
    """Print one line, named for the program."""
    print(f"branchleft-demo-egress-revert: {message}", flush=True)


@dataclass(frozen=True)
class Table:
    """The part of one family's filter table the egress program owns.

    chain_lines: the two chains' declarations, then their rules, in saved order.
    jumps: the rules in DOCKER-USER and INPUT that jump to them.
    """

    chain_lines: tuple[str, ...]
    jumps: tuple[str, ...]

    def to_text(self) -> str:
        """Return the table as saved on disk: iptables-save lines, own chains only."""
        return "".join(f"{line}\n" for line in (*self.chain_lines, *self.jumps))

    def problem(self) -> str:
        """Return why this table is not whole, or an empty string when it is."""
        declared = {line.split()[0][1:] for line in self.chain_lines if line.startswith(":")}
        for chain in OWN_CHAINS:
            if chain not in declared:
                return f"chain {chain} is not declared"
            rules = [line for line in self.chain_lines if line.startswith(f"-A {chain} ")]
            if not any(REJECT_RULE.search(rule) for rule in rules):
                return f"chain {chain} has no REJECT rule"
            if not any(jump_target(jump) == chain for jump in self.jumps):
                return f"nothing jumps to chain {chain}"
        return ""


def jump_target(rule: str) -> str:
    """Return the own chain a rule jumps to, or an empty string when it jumps elsewhere."""
    tokens = rule.split()
    if len(tokens) >= 4 and tokens[-2] == "-j" and tokens[-1] in OWN_CHAINS:
        return tokens[-1] if tokens[1] == JUMP_FROM[tokens[-1]] else ""
    return ""


def parse_table(saved: str) -> Table:
    """Pick the egress program's chains and jumps out of iptables-save output.

    Counters are dropped so that two reads of an unchanged table are equal.
    """
    declarations: dict[str, str] = {}
    rules: list[str] = []
    jumps: list[str] = []
    for raw in saved.splitlines():
        line = raw.strip()
        if line.startswith(":"):
            name = line[1:].split()[0] if line[1:].split() else ""
            if name in OWN_CHAINS:
                declarations[name] = f":{name} - [0:0]"
        elif line.startswith("-A "):
            tokens = line.split()
            if tokens[1] in OWN_CHAINS:
                rules.append(line)
            elif jump_target(line):
                jumps.append(line)
    ordered = [declarations[name] for name in OWN_CHAINS if name in declarations]
    return Table(chain_lines=(*ordered, *rules), jumps=tuple(jumps))


class Host(Protocol):
    """What the program asks of the machine. The tests supply a fake."""

    def save(self, family: str) -> str:
        """Return `<family>-save -t filter`."""

    def restore(self, family: str, text: str) -> None:
        """Load a `*filter` ruleset without flushing the other chains."""

    def jump_present(self, family: str, rule: str) -> bool:
        """Return whether the jump rule (an `-A` line) is already in its chain."""

    def insert_jump(self, family: str, rule: str) -> None:
        """Put the jump rule first in its chain."""

    def timer_active(self) -> bool:
        """Return whether the revert timer is waiting."""

    def start_timer(self, seconds: int) -> None:
        """Start the timer that runs `revert` once, after `seconds`."""

    def stop_timer(self) -> None:
        """Stop the timer, and leave no unit behind that would stop a later start."""


def run(argv: Sequence[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command with no shell and return it, whatever its exit status."""
    return subprocess.run(  # noqa: S603
        list(argv), input=stdin, capture_output=True, text=True, check=False, timeout=60
    )


def run_ok(argv: Sequence[str], stdin: str | None = None) -> str:
    """Run a command and return its output.

    Raises:
        CommandFailedError: when the command fails.
    """
    done = run(argv, stdin)
    if done.returncode != 0:
        raise CommandFailedError(argv[0], done.returncode, done.stderr.strip())
    return done.stdout


class SystemHost:
    """The real machine: iptables, ip6tables and systemd."""

    def save(self, family: str) -> str:
        """Return `<family>-save -t filter`."""
        return run_ok([f"{family}-save", "-t", "filter"])

    def restore(self, family: str, text: str) -> None:
        """Load a `*filter` ruleset without flushing the other chains."""
        run_ok([f"{family}-restore", "--noflush"], stdin=text)

    def jump_present(self, family: str, rule: str) -> bool:
        """Return whether the jump rule is already in its chain."""
        tokens = shlex.split(rule)
        return run([family, "-t", "filter", "-C", *tokens[1:]]).returncode == 0

    def insert_jump(self, family: str, rule: str) -> None:
        """Put the jump rule first in its chain."""
        tokens = shlex.split(rule)
        run_ok([family, "-t", "filter", "-I", tokens[1], "1", *tokens[2:]])

    def timer_active(self) -> bool:
        """Return whether the revert timer is waiting."""
        return run(["systemctl", "is-active", "--quiet", f"{TIMER_UNIT}.timer"]).returncode == 0

    def start_timer(self, seconds: int) -> None:
        """Start a transient timer that runs `revert` once, after `seconds`.

        A transient unit does not survive a reboot, which is wanted: at boot the egress unit
        loads the pinned table again, and the next apply arms a new timer.
        """
        run(["systemctl", "reset-failed", f"{TIMER_UNIT}.service", f"{TIMER_UNIT}.timer"])
        run_ok(
            [
                "systemd-run",
                f"--unit={TIMER_UNIT}",
                f"--on-active={seconds}s",
                "--timer-property=AccuracySec=1s",
                "--description=branchLeft demo host: revert an unconfirmed egress table",
                PROGRAM,
                "revert",
            ]
        )

    def stop_timer(self) -> None:
        """Stop the timer, so it cannot fire."""
        run_ok(["systemctl", "stop", f"{TIMER_UNIT}.timer"])
        run(["systemctl", "reset-failed", f"{TIMER_UNIT}.service", f"{TIMER_UNIT}.timer"])


class Store:
    """The program's state directory: a lock, the record and the known-good tables."""

    def __init__(self, directory: Path) -> None:
        """Hold the directory; nothing is made until the first lock."""
        self.directory = directory

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the one lock, so a confirm and a revert never run at once."""
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.directory / "lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _write(self, name: str, text: str) -> None:
        """Write a file whole or not at all, under a name no other writer shares."""
        with tempfile.NamedTemporaryFile(
            "w", dir=self.directory, prefix=f".{name}.", delete=False
        ) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, self.directory / name)

    def state(self) -> str:
        """Return the record: `armed`, `reverted`, or an empty string when none."""
        path = self.directory / "state"
        if not path.is_file():
            return ""
        words = path.read_text(encoding="utf-8").split()
        return words[0] if words else ""

    def set_state(self, value: str) -> None:
        """Record the state with the time it was recorded."""
        self._write("state", f"{value} {int(time.time())}\n")

    def clear_state(self) -> None:
        """Remove the record."""
        (self.directory / "state").unlink(missing_ok=True)

    def last_good(self, family: str) -> Table | None:
        """Return the saved known-good table of a family, or None when there is none."""
        path = self.directory / f"last-good.{family}"
        if not path.is_file():
            return None
        return parse_table(path.read_text(encoding="utf-8"))

    def save_last_good(self, family: str, table: Table) -> bool:
        """Save a table as the known-good one and return whether that changed the file."""
        if self.last_good(family) == table:
            return False
        self._write(f"last-good.{family}", table.to_text())
        return True


def live_table(host: Host, family: str) -> Table:
    """Return the egress program's part of the loaded table of a family."""
    return parse_table(host.save(family))


def known_good(store: Store) -> dict[str, Table] | str:
    """Return the whole known-good table of each family, or the reason there is none."""
    found: dict[str, Table] = {}
    for family in FAMILIES:
        table = store.last_good(family)
        if table is None:
            return f"no known-good {family} table is held"
        problem = table.problem()
        if problem:
            return f"the known-good {family} table is not whole: {problem}"
        found[family] = table
    return found


def arm(host: Host, store: Store, seconds: int) -> int:
    """Record an unconfirmed apply and start the timer, if there is a table to put back."""
    if not MIN_SECONDS <= seconds <= MAX_SECONDS:
        say(f"refused: --seconds {seconds} is outside {MIN_SECONDS} to {MAX_SECONDS}")
        return FAILED
    with store.locked():
        # The record comes first. If anything after it fails, the next role run sees it and
        # applies again, so a file the role already wrote is never left unapplied.
        store.set_state(ARMED)
        held = known_good(store)
        if isinstance(held, str):
            say(f"not armed: {held}; the first table has no earlier one to go back to")
            return OK
        if host.timer_active():
            host.stop_timer()
        host.start_timer(seconds)
        if not host.timer_active():
            say("refused: the timer did not start")
            return FAILED
    say(f"armed: an unconfirmed table is reverted in {seconds}s")
    return OK


def confirm(host: Host, store: Store) -> int:
    """Save the table now loaded as known-good, stop the timer and clear the record."""
    with store.locked():
        if store.state() == REVERTED:
            say("refused: the timer reverted the table during this apply; apply again")
            return FAILED
        tables: dict[str, Table] = {}
        for family in FAMILIES:
            table = live_table(host, family)
            problem = table.problem()
            if problem:
                say(f"refused: the loaded {family} table is not whole: {problem}")
                return FAILED
            tables[family] = table
        # Known-good is written before the timer stops. If the stop fails, a later revert
        # puts back the table that was just confirmed, which changes nothing.
        changed = False
        for family, table in tables.items():
            changed = store.save_last_good(family, table) or changed
        if host.timer_active():
            host.stop_timer()
            changed = True
        if store.state():
            store.clear_state()
            changed = True
    say("confirmed: the loaded table is the known-good one")
    say(f"confirm: {'changed' if changed else 'unchanged'}")
    return OK


def restore_family(host: Host, family: str, table: Table) -> None:
    """Put one family's own chains back, atomically, then make sure the jumps are there.

    Raises:
        NotRestoredError: when the loaded table is not the known-good one afterwards.
    """
    text = "*filter\n" + "".join(f"{line}\n" for line in table.chain_lines) + "COMMIT\n"
    host.restore(family, text)
    for rule in table.jumps:
        if not host.jump_present(family, rule):
            host.insert_jump(family, rule)
    now = live_table(host, family)
    if now.chain_lines != table.chain_lines or not set(table.jumps) <= set(now.jumps):
        raise NotRestoredError(family)


def revert(host: Host, store: Store) -> int:
    """Put the last known-good table back. Without a whole one, leave the table as it is."""
    with store.locked():
        held = known_good(store)
        if isinstance(held, str):
            say(f"not reverted: {held}; the loaded table is left as it is")
            return NOTHING_TO_RESTORE
        failed = False
        for family, table in held.items():
            try:
                restore_family(host, family, table)
            except RevertError as error:
                say(f"revert of {family} failed: {error}")
                failed = True
        if failed:
            return FAILED
        store.set_state(REVERTED)
    say("reverted: the last known-good table is loaded again")
    return OK


def status(host: Host, store: Store) -> int:
    """Print the record, the timer and whether a known-good table is held."""
    with store.locked():
        held = known_good(store)
        say(f"state={store.state() or 'confirmed'}")
        say(f"timer={'armed' if host.timer_active() else 'none'}")
        say(f"known_good={'held' if not isinstance(held, str) else 'none'}")
    return OK


def main(
    argv: Sequence[str] | None = None, host: Host | None = None, store: Store | None = None
) -> int:
    """Run one command and return its exit status. The tests pass a host and a store."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    arm_parser = commands.add_parser("arm")
    arm_parser.add_argument("--seconds", type=int, required=True)
    for name in ("confirm", "revert", "status"):
        commands.add_parser(name)
    args = parser.parse_args(argv)
    machine: Host = host if host is not None else SystemHost()
    held = store if store is not None else Store(STATE_DIR)
    try:
        if args.command == "arm":
            return arm(machine, held, args.seconds)
        if args.command == "confirm":
            return confirm(machine, held)
        if args.command == "revert":
            return revert(machine, held)
        return status(machine, held)
    except RevertError as error:
        say(f"failed: {error}")
        return FAILED


if __name__ == "__main__":
    sys.exit(main())
