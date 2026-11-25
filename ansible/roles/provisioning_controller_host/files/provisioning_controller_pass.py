#!/usr/bin/python3
"""One pass of the provisioning controller: run the executor for every approval not yet complete.

The provisioning API records each owner approval in a ledger file. The executor (the bundle's
program) takes one approval id and runs that tenant's onboarding to the end or to the step that
stopped it, and it appends a `run-complete` record to its state file when the run is done. This
program is what turns the first into the second without a person typing an id: it reads the
ledger, reads the state file, and runs the executor once for each approval that has no
`run-complete` record. An approval that is complete is never run again.

It holds no secret and reads none: the ledger and the state file hold identifiers and event names.
It prints identifiers, counts and exit codes, never the executor's output (the executor's streams
go to the journal as they are). A refusal is a fixed code and a path.

Exit status: 0 when every pending approval's run completed (or there was none, or the ledger does
not exist yet), 1 when a run did not complete (the next pass takes it up again), 3 when an input
file is refused, 4 when the executor could not be started.
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

EXIT_OK = 0
EXIT_STOPPED = 1
EXIT_REFUSED = 3
EXIT_NOT_STARTED = 4
# The executor's own command line takes this shape of identifier and no other, so one that does
# not match is a ledger the executor would refuse: this program refuses it first.
APPROVAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MAX_FILE_BYTES = 4_194_304
GROUP_OR_OTHER_WRITE = 0o022
# The longest one run may take. The executor's own retry policy is far shorter.
RUN_TIMEOUT_SECONDS = 1500
FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"


class RefusalError(Exception):
    """An input file is not fit to act on. It holds a fixed code and the path, never content."""

    def __init__(self, code: str, path: str) -> None:
        """Hold the code and the path."""
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


@dataclass(frozen=True)
class Settings:
    """What one pass is given: the executor, its configuration, the ledger and its state file."""

    program: str
    config: str
    approvals: str
    state: str


def _read_regular(path: str, *, must_not_be_shared: bool) -> bytes | None:
    """Return a file's bytes, or None when it does not exist.

    The checks are on the open descriptor, so nothing swapped in afterwards is read. A link, a
    file that is not regular, one another user owns, one others can write (or, for the state file,
    reach) and one that is too big are refused.

    Raises:
        RefusalError: for any of those.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RefusalError("E-OPEN", path) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RefusalError("E-NOT-REGULAR", path)
        if info.st_uid != os.geteuid():
            raise RefusalError("E-OWNER", path)
        limit = 0o077 if must_not_be_shared else GROUP_OR_OTHER_WRITE
        if info.st_mode & limit:
            raise RefusalError("E-MODE", path)
        if info.st_size > MAX_FILE_BYTES:
            raise RefusalError("E-SIZE", path)
        return os.read(fd, MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)


def recorded_approvals(path: str) -> list[str]:
    """Return the approval ids in the ledger, in its order. An absent ledger is no approvals.

    Raises:
        RefusalError: when the ledger is unfit, is not JSON, has no `approvals` list, holds an entry
            without a usable `approvalId`, or holds one id twice.
    """
    data = _read_regular(path, must_not_be_shared=False)
    if data is None:
        return []
    try:
        document = json.loads(data)
    except ValueError as error:
        raise RefusalError("E-LEDGER-FORM", path) from error
    entries = document.get("approvals") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise RefusalError("E-LEDGER-FORM", path)
    ids: list[str] = []
    for entry in entries:
        approval_id = entry.get("approvalId") if isinstance(entry, dict) else None
        if not isinstance(approval_id, str) or not APPROVAL_ID.match(approval_id):
            raise RefusalError("E-LEDGER-ENTRY", path)
        if approval_id in ids:
            raise RefusalError("E-LEDGER-DUPLICATE", path)
        ids.append(approval_id)
    return ids


def completed_approvals(path: str) -> set[str]:
    """Return the approval ids the state file records as run to completion.

    The file is one JSON record per line; a last line with no newline is a write that never
    finished and is ignored, as the executor ignores it. A missing file is an empty history.

    Raises:
        RefusalError: when the file is unfit or a whole line is not a record with an approval id.
    """
    data = _read_regular(path, must_not_be_shared=True)
    if data is None:
        return set()
    lines = data.decode("utf-8", errors="replace").split("\n")
    lines.pop()
    done: set[str] = set()
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError as error:
            raise RefusalError("E-STATE-FORM", path) from error
        if not isinstance(record, dict) or not isinstance(record.get("approvalId"), str):
            raise RefusalError("E-STATE-FORM", path)
        if record.get("event") == "run-complete":
            done.add(str(record["approvalId"]))
    return done


def pending(settings: Settings) -> list[str]:
    """Return the recorded approvals that have no run-complete record, in the ledger's order.

    Raises:
        RefusalError: when either file is refused.
    """
    done = completed_approvals(settings.state)
    return [i for i in recorded_approvals(settings.approvals) if i not in done]


Runner = Callable[[Sequence[str], dict[str, str]], int]


def _run_executor(argv: Sequence[str], env: dict[str, str]) -> int:
    """Run the executor, its streams left to the journal, and return its exit status.

    Raises:
        OSError: when it cannot be started.
        subprocess.TimeoutExpired: when it runs past the limit.
    """
    return subprocess.run(  # noqa: S603 - a fixed program and an id the pattern checked
        list(argv), env=env, check=False, timeout=RUN_TIMEOUT_SECONDS
    ).returncode


def run_pass(settings: Settings, runner: Runner = _run_executor) -> int:
    """Run the executor for each pending approval and return the exit status of the pass."""
    try:
        todo = pending(settings)
    except RefusalError as refusal:
        print(f"pass: refused {refusal}")
        return EXIT_REFUSED
    print(f"pass: {len(todo)} approval(s) pending")
    env = {"PATH": FIXED_PATH}
    status = EXIT_OK
    for approval_id in todo:
        argv = [settings.program, "--config", settings.config, "--approval-id", approval_id]
        try:
            code = runner(argv, env)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"pass: approval {approval_id} not run ({type(error).__name__})")
            status = max(status, EXIT_NOT_STARTED if isinstance(error, OSError) else EXIT_STOPPED)
            continue
        print(f"pass: approval {approval_id} executor exit {code}")
        if code != 0:
            status = max(status, EXIT_STOPPED)
    return status


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the four paths and run one pass."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    for name in ("program", "config", "approvals", "state"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args(argv)
    for value in (args.program, args.config, args.approvals, args.state):
        if not os.path.isabs(value):
            print("pass: every path must be absolute")
            return EXIT_REFUSED
    return run_pass(Settings(args.program, args.config, args.approvals, args.state))


if __name__ == "__main__":
    sys.exit(main())
