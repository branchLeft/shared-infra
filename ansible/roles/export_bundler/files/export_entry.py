#!/usr/bin/python3
"""The forced command of the demo host's export route: run one promotion export, and nothing else.

sshd runs this program as root through `sudo -n` for the ops1 controller's key, whatever the client
asked for, and leaves the client's request in SSH_ORIGINAL_COMMAND. That request is untrusted text.
It is accepted in exactly one shape,

    export-demo SLOT RECIPIENT ERASURE_DATE PORT REFERENCE

where SLOT is a demo slot's name (`demo-` and one or two digits), RECIPIENT is the age recipient
the promotion made for this one export, ERASURE_DATE is a calendar date, PORT is an unused local
port and REFERENCE says where the consented grant's evidence lives. Anything else is refused before
any file is opened or any program is run.

For a valid request the program runs the pinned export bundler, once, with an argument list it
builds itself. Nothing in the request chooses a program, a path, a flag or a lane: the grant lane is
always `consented`, the media files are always carried, and the descriptor, the output directory,
the flag directory and the audit log are fixed paths under the bundler's state directory. The
bundler reads the one-time sign-in value it needs from standard input once it is ready, so
standard input, output and error are passed straight through to the client.

Standard error carries one line, `branchleft-export-entry: refused reason=<code>`, for a refusal.
Exit status: 0 exported, 1 the bundler failed, 2 refused request, 3 not ready (the Node runtime,
the bundler or the slot's descriptor is not as the role leaves it), 4 busy (an export is running),
70 the export finished but its clean-up did not. The role's README holds the full reasoning.
"""

from __future__ import annotations

import datetime
import fcntl
import os
import re
import signal
import subprocess
import sys
import syslog
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import FrameType
from typing import Final

# ----- The request -----

COMMAND_WORD: Final = "export-demo"

# Longer than any valid request by a wide margin: a longer one is refused before it is matched, so a
# pattern never runs over unbounded input.
MAX_REQUEST_LENGTH: Final = 512

# \A and \Z, never ^ and $, because $ also matches before a trailing line break. [0-9], never \d,
# because \d also matches digits of other scripts.
SLOT_PATTERN: Final = r"demo-[0-9]{1,2}"
# An age X25519 recipient: `age1` and 58 characters of the bech32 alphabet (no 1, b, i or o).
RECIPIENT_PATTERN: Final = r"age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}"
DATE_PATTERN: Final = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
# 1000 to 65535, whole, with no leading zero. The range is checked again as a number.
PORT_PATTERN: Final = r"[1-9][0-9]{3,4}"
# Where the grant's evidence lives, as a short plain reference. It never starts with a hyphen, so it
# can never be read as a flag, and it has no space, quote, backslash or shell character.
REFERENCE_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9._#/:-]{0,127}"

REQUEST_PATTERN: Final = re.compile(
    rf"\A{re.escape(COMMAND_WORD)}"
    rf" (?P<slot>{SLOT_PATTERN})"
    rf" (?P<recipient>{RECIPIENT_PATTERN})"
    rf" (?P<erasure_date>{DATE_PATTERN})"
    rf" (?P<port>{PORT_PATTERN})"
    rf" (?P<reference>{REFERENCE_PATTERN})\Z"
)

MIN_PORT: Final = 1024
MAX_PORT: Final = 65535

# ----- What it runs, and where -----

# The Node runtime the broker_deploy role installs. A test holds this path equal to that role's own.
NODE: Final = "/opt/branchleft/broker/node/bin/node"

# The bundler and its state directory, as the export_bundler role makes them. A test holds both
# equal to the role's own constants (a role may not import another, and this program is a file).
BUNDLER_DIR: Final = "/root/export-bundler"
STATE_DIR: Final = "/root/export-bundler-state"

# Free text the bundler writes into its audit record. Fixed, so a client cannot choose them.
REQUESTED_BY: Final = "promotion-controller"
DELIVERED_TO: Final = "ops1"

# A fixed environment for the child: nothing the client or sudo carried over.
CHILD_ENVIRONMENT: Final[Mapping[str, str]] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
}

LOCK_PATH: Final = "/run/lock/branchleft-export-entry.lock"
SYSLOG_IDENT: Final = "branchleft-export-entry"

EXIT_EXPORTED: Final = 0
EXIT_FAILED: Final = 1
EXIT_REFUSED: Final = 2
EXIT_NOT_READY: Final = 3
EXIT_BUSY: Final = 4
# The bundler's own code for an export that finished while a teardown step did not.
EXIT_CLEANUP_FAILED: Final = 70


class RefusalError(Exception):
    """A request the program will not serve: a fixed reason code and the exit status it carries."""

    def __init__(self, reason: str, status: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class Paths:
    """Where the program looks: the host's paths by default, a scratch tree in a test."""

    node: str = NODE
    bundler_dir: str = BUNDLER_DIR
    state_dir: str = STATE_DIR
    lock: str = LOCK_PATH
    # Only root may own what the program runs or reads. A test owns its scratch tree itself.
    owner_uid: int = 0


@dataclass(frozen=True)
class Request:
    """A request that passed every check."""

    slot: str
    recipient: str
    erasure_date: str
    port: int
    reference: str


# Runs one fixed argument list with a fixed environment, with the program's own standard streams,
# and returns the exit status. The default is `run_child`; the tests pass a stand-in.
Runner = Callable[[Sequence[str], Mapping[str, str]], int]
Log = Callable[[str], None]


# ----- Parsing -----


def parse_request(original: str | None) -> Request:
    """The request in SSH_ORIGINAL_COMMAND, or a refusal.

    Raises:
        RefusalError: the request is absent, too long, not the one command in its one shape, or
            holds a date that is not on the calendar or a port outside the unprivileged range.
    """
    if original is None or original == "":
        raise RefusalError("no-command", EXIT_REFUSED)
    if len(original) > MAX_REQUEST_LENGTH:
        raise RefusalError("request-too-long", EXIT_REFUSED)
    match = REQUEST_PATTERN.match(original)
    if match is None:
        raise RefusalError("bad-command", EXIT_REFUSED)
    erasure_date = match.group("erasure_date")
    try:
        datetime.date.fromisoformat(erasure_date)
    except ValueError:
        raise RefusalError("bad-date", EXIT_REFUSED) from None
    port = int(match.group("port"))
    if not MIN_PORT <= port <= MAX_PORT:
        raise RefusalError("bad-port", EXIT_REFUSED)
    return Request(
        slot=match.group("slot"),
        recipient=match.group("recipient"),
        erasure_date=erasure_date,
        port=port,
        reference=match.group("reference"),
    )


def descriptor_path(paths: Paths, slot: str) -> str:
    """The slot's descriptor, a fixed name under the state directory."""
    return f"{paths.state_dir}/{slot}.descriptor.json"


def build_argv(paths: Paths, request: Request) -> list[str]:
    """The bundler's whole argument list. The request fills five values and picks nothing else."""
    return [
        paths.node,
        f"{paths.bundler_dir}/dist/cli.js",
        "--grant-lane",
        "consented",
        "--grant-reference",
        request.reference,
        "--descriptor",
        descriptor_path(paths, request.slot),
        "--age-recipient",
        request.recipient,
        "--promotion-recipient",
        request.recipient,
        "--requested-by",
        REQUESTED_BY,
        "--delivered-to",
        DELIVERED_TO,
        "--dest-dir",
        f"{paths.state_dir}/out",
        "--flag-dir",
        f"{paths.state_dir}/flags",
        "--audit-log",
        f"{paths.state_dir}/audit.jsonl",
        "--loopback-port",
        str(request.port),
        "--erasure-date",
        request.erasure_date,
        "--carry-media-files",
    ]


# ----- What must be there before anything runs -----


def _plain_file(path: str, owner_uid: int, *, private: bool) -> bool:
    """Whether `path` is a regular file (not a link) of the owner, closed to everyone else when
    `private`, and not writable by anyone else otherwise."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not os.path.isfile(path) or os.path.islink(path) or info.st_uid != owner_uid:
        return False
    forbidden = 0o077 if private else 0o022
    return info.st_mode & forbidden == 0


def check_ready(paths: Paths, request: Request) -> None:
    """Refuse unless the runtime, the bundler's entry point and the slot's descriptor are as the
    role and the owner leave them.

    Raises:
        RefusalError: one of the three is missing, is a link, is not the owner's, or can be
            written (or, for the descriptor, read) by anyone else.
    """
    if not _plain_file(paths.node, paths.owner_uid, private=False):
        raise RefusalError("no-node", EXIT_NOT_READY)
    if not _plain_file(f"{paths.bundler_dir}/dist/cli.js", paths.owner_uid, private=True):
        raise RefusalError("no-bundler", EXIT_NOT_READY)
    if not _plain_file(descriptor_path(paths, request.slot), paths.owner_uid, private=True):
        raise RefusalError("no-descriptor", EXIT_NOT_READY)


# ----- One export at a time -----


def take_lock(path: str) -> int:
    """Hold the lock for the life of the process, or refuse as busy. The file descriptor is
    returned so the caller keeps it open; it is closed when the process ends.

    Raises:
        RefusalError: another export holds the lock, or the lock cannot be made.
    """
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise RefusalError("no-lock", EXIT_NOT_READY) from None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        raise RefusalError("busy", EXIT_BUSY) from None
    return descriptor


# ----- Running it -----


def run_child(argv: Sequence[str], environment: Mapping[str, str]) -> int:
    """Run the bundler with this process's own standard streams, and pass a stop signal on to it.

    The bundler cleans up after itself on a signal. The program does not decide anything while it
    waits: it forwards the signal and returns what the child returned.
    """
    child = subprocess.Popen(list(argv), env=dict(environment), cwd="/")  # noqa: S603

    def forward(signum: int, _frame: FrameType | None) -> None:
        del signum
        child.send_signal(signal.SIGTERM)

    previous = {
        number: signal.signal(number, forward)
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    }
    try:
        return child.wait()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def exit_status_of(child_status: int) -> int:
    """The program's own status for what the bundler returned. Statuses 2 to 4 are this program's
    refusals, so the bundler's other failures are all reported as one."""
    if child_status == EXIT_EXPORTED:
        return EXIT_EXPORTED
    if child_status == EXIT_CLEANUP_FAILED:
        return EXIT_CLEANUP_FAILED
    return EXIT_FAILED


def syslog_line(text: str) -> None:
    """One line to the system log. Never the request, the recipient or the reference."""
    syslog.openlog(SYSLOG_IDENT, syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_NOTICE, text)
    syslog.closelog()


def serve(
    environment: Mapping[str, str],
    paths: Paths,
    runner: Runner,
    log: Log,
) -> int:
    """Serve one request and return the exit status.

    Raises:
        RefusalError: the request is refused, or the host is not ready, or an export is running.
    """
    request = parse_request(environment.get("SSH_ORIGINAL_COMMAND"))
    check_ready(paths, request)
    descriptor = take_lock(paths.lock)
    try:
        log(f"started slot={request.slot}")
        status = exit_status_of(runner(build_argv(paths, request), CHILD_ENVIRONMENT))
        log(f"finished slot={request.slot} status={status}")
        return status
    finally:
        os.close(descriptor)


def main() -> int:
    """The program's entry point: serve the request in this process's environment."""
    try:
        return serve(os.environ, Paths(), run_child, syslog_line)
    except RefusalError as refusal:
        syslog_line(f"refused reason={refusal.reason}")
        print(f"{SYSLOG_IDENT}: refused reason={refusal.reason}", file=sys.stderr)
        return refusal.status


if __name__ == "__main__":
    sys.exit(main())
