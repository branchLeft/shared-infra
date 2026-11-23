#!/usr/bin/python3
"""The controller's own steps that need a program on ops1: the register check and the escrow.

The provisioning controller runs one step at a time through a configured program for each entry
point. For the `controller` entry point this is that program. It reads the step on standard input
as one JSON object (`key`, `id`, `idempotencyKey`, `inputs`: names and register values, never a
secret value) and settles it by its exit status alone, which is all the controller reads:

- 0 the step is done (and doing it again changes nothing),
- 3 the step is refused, and trying again cannot help,
- 1 anything else, which the controller retries.

It serves two steps and refuses every other, so a step nobody planned for fails at once and acts on
nothing:

- `confirm-register-assignment` checks the register file the controller was given: the tenant's
  entry is there once, and its slot, port, uid, media bucket and media folder are what the step was
  planned from and are shared with no other entry.
- `escrow-stack-passphrase` makes the tenant's stack passphrase from the operating system's random
  source the first time, holds it in a file only this account can read, and never makes it again.
  It prints nothing. Nobody types, reads or sees the value; it waits in the file for the escrow
  bucket's step to take it from there.

It prints nothing at all: the controller discards a program's output, and a refusal here would
only ever name a field, never a value.
"""

import argparse
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Sequence

EXIT_OK = 0
EXIT_RETRY = 1
EXIT_REFUSED = 3
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
ESCROW_NAME = re.compile(r"STACK_PASSPHRASE_[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MAX_REGISTER_BYTES = 1_048_576
GROUP_OR_OTHER_WRITE = 0o022
# 32 random bytes in URL-safe text: 43 characters, no padding.
PASSPHRASE_BYTES = 32
FIELDS = (
    ("slot", "appHostSlot"),
    ("port", "appHostPort"),
    ("uid", "appHostUid"),
    ("bucket", "mediaBucket"),
    ("folder", "mediaFolder"),
)
# What no two entries may share: each is one thing on one host.
UNIQUE = ("appHostSlot", "appHostPort", "appHostUid", "mediaBucket", "mediaFolder", "stateFolder")


class RefusedError(Exception):
    """The step cannot be done and trying again cannot help. It holds a field name at most."""


def _read_register(path: str) -> list[dict[str, object]]:
    """Return the register's entries, from a file this account owns and no one else can write.

    Raises:
        RefusedError: when the file is not fit to act on or is not a register.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise RefusedError("register-open") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise RefusedError("register-owner")
        if info.st_mode & GROUP_OR_OTHER_WRITE or info.st_size > MAX_REGISTER_BYTES:
            raise RefusedError("register-mode")
        data = os.read(fd, MAX_REGISTER_BYTES + 1)
    finally:
        os.close(fd)
    try:
        document = json.loads(data)
    except ValueError as error:
        raise RefusedError("register-form") from error
    entries = document.get("entries") if isinstance(document, dict) else None
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise RefusedError("register-form")
    return [e for e in entries if isinstance(e, dict)]


def confirm_register_assignment(inputs: dict[str, object], register_path: str) -> None:
    """Refuse unless the step's tenant has one entry that matches the step and clashes with none.

    Raises:
        RefusedError: naming the field that is missing, differs or is shared.
    """
    entries = _read_register(register_path)
    slot = inputs.get("slot")
    mine = [e for e in entries if e.get("appHostSlot") == slot]
    if len(mine) != 1:
        raise RefusedError("slot")
    entry = mine[0]
    for name, field in FIELDS:
        if inputs.get(name) != entry.get(field):
            raise RefusedError(field)
    for field in UNIQUE:
        values = [e.get(field) for e in entries]
        if values.count(entry.get(field)) != 1:
            raise RefusedError(field)


def escrow_stack_passphrase(inputs: dict[str, object], escrow_dir: str) -> None:
    """Make the named passphrase if there is none, in a file only this account can read.

    The file is made with its final mode and in one step, so it is never readable by anyone else
    and never half written under its name. One that is already there is left exactly as it is, if
    it is a regular file of this account that no one else can reach and is not empty.

    Raises:
        RefusedError: for a name that is not the escrow's shape, or a file there that is not fit.
    """
    name = inputs.get("secretName")
    if not isinstance(name, str) or not ESCROW_NAME.match(name):
        raise RefusedError("secretName")
    try:
        dfd = os.open(escrow_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise RefusedError("escrow-dir") from error
    try:
        dinfo = os.fstat(dfd)
        if dinfo.st_uid != os.geteuid() or stat.S_IMODE(dinfo.st_mode) & 0o077:
            raise RefusedError("escrow-dir")
        _ensure_file(dfd, name)
    finally:
        os.close(dfd)


def _ensure_file(dfd: int, name: str) -> None:
    """Make the file in the open directory, or judge the one that is there.

    Raises:
        RefusedError: when the file is there and is not fit, or cannot be made.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dfd)
    except FileExistsError:
        _judge_existing(dfd, name)
        return
    except OSError as error:
        raise RefusedError("escrow-file") from error
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, secrets.token_urlsafe(PASSPHRASE_BYTES).encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(dfd)


def _judge_existing(dfd: int, name: str) -> None:
    """Accept a file the escrow made earlier, and refuse anything else at its name.

    Raises:
        RefusedError: for a link, a non-regular file, another owner, a wider mode or no content.
    """
    try:
        info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except OSError as error:
        raise RefusedError("escrow-file") from error
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise RefusedError("escrow-file")
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_size == 0 or info.st_nlink != 1:
        raise RefusedError("escrow-file")


def run(request: object, register_path: str, escrow_dir: str) -> int:
    """Settle one step request and return the exit status the controller reads."""
    if not isinstance(request, dict):
        return EXIT_REFUSED
    step = request.get("id")
    inputs = request.get("inputs")
    if not isinstance(inputs, dict) or not isinstance(step, str):
        return EXIT_REFUSED
    try:
        if step == "confirm-register-assignment":
            confirm_register_assignment(inputs, register_path)
        elif step == "escrow-stack-passphrase":
            escrow_stack_passphrase(inputs, escrow_dir)
        else:
            return EXIT_REFUSED
    except RefusedError:
        return EXIT_REFUSED
    except OSError:
        return EXIT_RETRY
    return EXIT_OK


def main(argv: Sequence[str] | None = None, stdin: str | None = None) -> int:
    """Read the step from standard input and settle it."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--register", required=True)
    parser.add_argument("--escrow-dir", required=True)
    args = parser.parse_args(argv)
    if not os.path.isabs(args.register) or not os.path.isabs(args.escrow_dir):
        return EXIT_REFUSED
    try:
        request = json.loads(sys.stdin.read() if stdin is None else stdin)
    except ValueError:
        return EXIT_REFUSED
    return run(request, args.register, args.escrow_dir)


if __name__ == "__main__":
    sys.exit(main())
