#!/usr/bin/python3 -I
"""Install the pinned, hash-locked Ansible environment, in one place.

Two callers run this one program. The ``ansible_runtime`` role runs it on a host
that is already under the pull, and the first-boot document of a new host runs
it before any Ansible exists there. Both therefore get the same checks and the
same steps, in the same order:

1. read the lock without following a link, and refuse it unless its SHA-256
   is the one the caller was given;
2. refuse a lock in which any requirement has no SHA-256 hash, or which carries
   anything but pinned, hashed requirements, or which pip could read in an
   encoding other than UTF-8;
3. name the environment by a fingerprint of the lock text;
4. build ``venv-<fingerprint>`` and install the lock into it with hash checking
   required and wheels only (``--only-binary=:all:``);
5. write the marker that the install finished, then, only when asked, move the
   ``ansible-playbook`` link.

A failure at any step leaves the link where it was. It never installs an engine
that the lock does not name. Every file pip installs is a wheel whose hash the lock lists:
pip is told to build nothing, because pip does not hash-check the build dependencies of a
source build, so a package with no wheel for the host's interpreter fails the install
(the host stays un-enrolled) and is never built.

The paths and the fingerprint are the ones the role has always used, so the
role's environments do not change.
"""

import argparse
import codecs
import dataclasses
import enum
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

SEARCH_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_PYTHON: Final = "/usr/bin/python3"
FINGERPRINT_LENGTH: Final = 16
MARKER_NAME: Final = ".installed-from-lock"
SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")
FINGERPRINT_PATTERN: Final = re.compile(r"[0-9a-f]{16}")
MAX_LOCK_BYTES: Final = 4_000_000

# One pinned requirement: a name, optional extras, an exact version, an optional
# environment marker, then one or more hashes and nothing else on the line. The separators are
# the space character and nothing wider, because pip splits a line into its requirement and its
# options on " " alone (break_args_options in pip's req_file.py): a tab before "--hash" would
# leave the hash inside the requirement as pip reads it. The marker is
# written only from a positive set of characters (letters, digits, "_", ".", quotes, space,
# "=", "!", "<", ">", "(", ")"), the set MARKER_CHARS names here, and check_pins reads it from
# this file. That
# set holds no "-" and no ";" at all, so no option such as --index-url or -i can sit in the
# marker, however it is spaced or nested. It is a set to allow, not a list of forms to refuse.
#
# Why a pattern and not a maintained parser: this runs under the host's own interpreter with -I
# before any package is installed, so only the standard library exists (the maintained parser,
# packaging.requirements, is a package, and pip's vendored copy is not a supported import).
# It is also not the control. The lock's SHA-256 comes from a record built from reviewed main,
# and pip's own --require-hashes (always passed, below) is the maintained refusal of an unpinned
# or unhashed requirement and checks each requirement's downloaded file against its hash. That
# covers every installed file only because --only-binary=:all: is passed with it: pip does not
# hash-check the build dependencies of a source build, and with wheels only there is no build.
# This pattern only refuses early, with a reason of this program's own, and leaves nothing behind.
MARKER_CHARS: Final = r"[A-Za-z0-9_.'\" =!<>()]"
REQUIREMENT: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,-]+\])?"
    r"==[A-Za-z0-9.!+_-]+"
    rf"(?: *; *{MARKER_CHARS}+)?"
    r"(?: +--hash=sha256:[0-9a-f]{64})+",
)
HASH_OPTION: Final = re.compile(r"--hash=sha256:[0-9a-f]{64}")
# pip's own comment pattern (COMMENT_RE in pip's req_file.py), used with match: a line that is
# only a comment, once any white space before the "#" is allowed for.
COMMENT_LINE: Final = re.compile(r"(^|\s+)#.*$")
# How pip chooses the text encoding of a requirements file (_decode_req_file in pip's
# req_file.py): a byte-order mark first, then a "coding:" or "coding=" declaration in a comment on
# one of the first two lines (the file split on b"\n"), and UTF-8 otherwise. This program reads
# UTF-8 only, so a lock that a mark or a declaration could make pip read in another encoding is
# refused, as a lock that pip and this program would read as different text.
BYTE_ORDER_MARKS: Final = (
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,
    codecs.BOM_UTF32_LE,
    codecs.BOM_UTF32_BE,
)
CODING_DECLARATION: Final = re.compile(rb"coding[:=]\s*([-\w.]+)")
CODING_LINES: Final = 2


class Reason(enum.StrEnum):
    """Why the program refused. Each is printed, none carries a secret."""

    USAGE = "the arguments are not valid"
    LOCK_NOT_REGULAR = "the lock is not a regular file, or is a link"
    LOCK_TOO_BIG = "the lock is larger than the limit"
    LOCK_NOT_TEXT = "the lock is not UTF-8 text"
    LOCK_ENCODING = "the lock has a byte-order mark or a coding declaration that pip would obey"
    LOCK_HASH = "the lock does not have the SHA-256 it was given"
    LOCK_EMPTY = "the lock names no requirement"
    LOCK_UNHASHED = "the lock has a line that is not a pinned requirement with SHA-256 hashes"
    FINGERPRINT = "the lock has a fingerprint other than the one expected"
    ROOT = "the environments directory is a link, not a directory, or can be changed by others"
    LINK = "the link path is not an absolute path in an existing directory, or is a directory"
    VENV = "the virtual environment could not be made"
    PIP = "pip did not install the lock"
    NO_ENGINE = "the install finished without an ansible-playbook in the environment"
    INTERNAL = "an unexpected error stopped the install"


class Refusal(Exception):  # noqa: N818 - a refusal is the program's own word for it
    """The program stopped for a named reason, and changed nothing that matters."""

    def __init__(self, reason: Reason, detail: str = "") -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.detail = detail


Runner = Callable[[Sequence[str], Mapping[str, str]], int]


@dataclasses.dataclass(frozen=True)
class Request:
    """What the caller asked for."""

    lock: Path
    lock_sha256: str
    root: Path
    link: Path | None
    expect_fingerprint: str | None
    python: str


@dataclasses.dataclass(frozen=True)
class Outcome:
    """What the run did, printed as one JSON line."""

    fingerprint: str
    venv: str
    installed: bool
    linked: bool


def run_command(argv: Sequence[str], env: Mapping[str, str]) -> int:
    """Run one command to completion and return its status.

    Its standard output goes to this program's standard error, so that standard
    output carries only the result line. Its standard error is passed through,
    which is how a caller sees pip's own reason.
    """
    completed = subprocess.run(  # noqa: S603 - argv is built here from constants and checked values
        list(argv),
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=sys.stderr,
        check=False,
    )
    return completed.returncode


def read_regular_file(path: Path, limit: int) -> bytes:
    """Return the bytes of a regular file opened without following a link.

    The check and the read use the same open file, so nothing swapped in between
    can be read instead.

    Raises:
        Refusal: The path is a link or not a regular file, or the file is over the limit.
    """
    try:
        # O_NONBLOCK so that opening a FIFO does not wait for a writer; the check
        # below then refuses it. It changes nothing for a regular file.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise Refusal(Reason.LOCK_NOT_REGULAR, error.strerror or "") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise Refusal(Reason.LOCK_NOT_REGULAR)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise Refusal(Reason.LOCK_TOO_BIG)
    return data


def fingerprint(lock: bytes) -> str:
    """Return the environment's name part: 16 hex digits of the lock text's SHA-256.

    This reproduces the role's own expression: the lock is read as text with its
    trailing whitespace removed (what Ansible's file lookup does), then hashed
    as UTF-8. It is not the SHA-256 of the file, which is a different value.

    Raises:
        Refusal: The lock is not UTF-8 text.
    """
    try:
        text = lock.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(Reason.LOCK_NOT_TEXT) from error
    return hashlib.sha256(text.rstrip().encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Return the lock's requirement lines as pip joins them, each with the line it starts on.

    The joining follows pip's join_lines (pip's req_file.py) rule for rule, so that a line pip
    reads as an option is an option here too: a line continues the one before when its raw text
    ends in a backslash, tested before any strip, so a space after the backslash ends it; and a
    comment-only line ends a continuation.

    One rule is deliberately stricter than pip. After joining, pip strips a trailing comment
    from the line (ignore_comments); this does not, so a comment that sits on a requirement
    leaves a "#" in the line, which is not a requirement and is refused where pip would skip it.
    That fails closed, and the repository's lock has no such line. A comment-only line that
    starts a line (not a continuation) is dropped, as pip drops it.

    The function is the lock reader for both callers: ansible/checks/check_pins.py loads it from
    this file. It reads text, so the caller first refuses an encoding pip could choose
    differently (check_lock_encoding).
    """
    lines: list[tuple[int, str]] = []
    pending: str | None = None
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        comment = COMMENT_LINE.match(raw) is not None
        if pending is None:
            if comment or not raw.strip():
                continue
            start = number
            pending = ""
        if raw.endswith("\\") and not comment:
            pending += raw.strip("\\")
            continue
        joined = pending + (f" {raw}" if comment else raw)
        if joined.strip():
            lines.append((start, joined.strip()))
        pending = None
    if pending is not None and pending.strip():
        lines.append((start, pending.strip()))
    return lines


def check_lock_encoding(lock: bytes) -> None:
    """Refuse a lock that pip could read in an encoding other than UTF-8.

    pip chooses the encoding of a requirements file from a byte-order mark, then from a
    "coding:" declaration in a comment on one of the first two lines (_decode_req_file in pip's
    req_file.py), and the rest of this program reads UTF-8. A lock with either could show this
    program a comment and pip an option, as a "# -*- coding: utf-7 -*-" lock does. Both are
    refused whatever encoding they name; the repository's lock has neither.

    Raises:
        Refusal: The lock starts with a byte-order mark or declares an encoding.
    """
    if lock.startswith(BYTE_ORDER_MARKS):
        raise Refusal(Reason.LOCK_ENCODING, "byte-order mark")
    for line in lock.split(b"\n")[:CODING_LINES]:
        if line[:1] == b"#" and CODING_DECLARATION.search(line) is not None:
            raise Refusal(Reason.LOCK_ENCODING, "coding declaration")


def check_lock_is_hashed(lock: bytes) -> None:
    """Refuse a lock unless every line is a pinned requirement with hashes.

    pip's own hash checking is the control that matters, and it stays on. This
    refuses first, before anything is made, so that a lock with no hash at all,
    or with an option that could point pip somewhere else, fails with a reason
    of this program's own and leaves nothing behind.

    Raises:
        Refusal: The lock is not plain UTF-8, names no requirement, or has a line that is
            not hashed and pinned.
    """
    check_lock_encoding(lock)
    try:
        text = lock.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(Reason.LOCK_NOT_TEXT) from error
    lines = logical_lines(text)
    if not lines:
        raise Refusal(Reason.LOCK_EMPTY)
    for _number, line in lines:
        if REQUIREMENT.fullmatch(line) is None or HASH_OPTION.search(line) is None:
            raise Refusal(Reason.LOCK_UNHASHED, line.split()[0])


def check_root(root: Path) -> None:
    """Make the environments directory if absent, and refuse one others could change.

    Raises:
        Refusal: The path is a link, not a directory, not ours, or writable by others.
    """
    if not root.is_absolute():
        raise Refusal(Reason.ROOT)
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refusal(Reason.ROOT)


def write_file_atomically(path: Path, data: bytes) -> None:
    """Write a file of mode 0644 so that a reader sees all of it or none of it."""
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def copy_lock(root: Path, name: str, lock: bytes) -> Path:
    """Place the verified bytes beside the environment, and return their path."""
    destination = root / f"requirements-{name}.txt"
    if not destination.is_file() or destination.is_symlink() or destination.read_bytes() != lock:
        write_file_atomically(destination, lock)
    return destination


def pip_environment() -> dict[str, str]:
    """Return the environment pip runs with: a fixed search path and no PIP_ variable."""
    home = pwd.getpwuid(os.geteuid()).pw_dir
    return {"PATH": SEARCH_PATH, "HOME": home, "LANG": "C.UTF-8"}


def install_environment(
    request: Request, name: str, requirements: Path, run: Runner
) -> tuple[Path, bool]:
    """Build the environment for this lock if its marker is absent. Return it and whether it ran.

    Raises:
        Refusal: The environment could not be made, pip failed, or no ansible-playbook resulted.
    """
    venv = request.root / f"venv-{name}"
    marker = venv / MARKER_NAME
    if marker.is_file() and not marker.is_symlink() and marker.read_text() == f"{name}\n":
        return venv, False
    env = pip_environment()
    pip_path = venv / "bin" / "pip"
    if not os.access(pip_path, os.X_OK):
        # pip is what a finished venv has last: ``python -m venv`` puts bin/python down first
        # and runs ensurepip after, so a venv that failed in between has the one and not the
        # other. Without --clear the next run would find bin/python, skip this step, and fail
        # on the missing pip every time, until someone removed the directory by hand.
        make = [request.python, "-m", "venv", str(venv)]
        if os.path.lexists(venv):
            if venv.is_symlink():
                # --clear empties what the path leads to; a link would send it elsewhere.
                raise Refusal(Reason.VENV)
            make.insert(3, "--clear")
        if run(make, env):
            raise Refusal(Reason.VENV)
    pip = [
        str(pip_path),
        "install",
        "--require-virtualenv",
        "--require-hashes",
        # No source build, ever. pip does not hash-check the build dependencies of a source
        # build (build_env.py passes require_hashes=False), so a lock entry with no wheel for
        # this interpreter would otherwise run, as root, a build backend fetched from the index
        # with no hash. With this flag such an entry fails the install instead (ruling 1C: the
        # host stays un-enrolled), and every file pip installs is a wheel checked against the lock.
        "--only-binary=:all:",
        "--no-input",
        "--disable-pip-version-check",
        "-r",
        str(requirements),
    ]
    if run(pip, env):
        raise Refusal(Reason.PIP)
    if not os.access(venv / "bin" / "ansible-playbook", os.X_OK):
        raise Refusal(Reason.NO_ENGINE)
    write_file_atomically(marker, f"{name}\n".encode())
    return venv, True


def point_link(link: Path, venv: Path) -> None:
    """Move the link to this environment's ansible-playbook, replacing it in one step.

    Raises:
        Refusal: The link path is relative, has no directory, or is a directory.
    """
    if not link.is_absolute() or not link.parent.is_dir():
        raise Refusal(Reason.LINK)
    if link.is_dir() and not link.is_symlink():
        raise Refusal(Reason.LINK)
    temporary = link.parent / f".{link.name}.new-{os.getpid()}"
    temporary.unlink(missing_ok=True)
    os.symlink(venv / "bin" / "ansible-playbook", temporary)
    try:
        os.replace(temporary, link)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def install(request: Request, run: Runner = run_command) -> Outcome:
    """Do the whole install for one request.

    Raises:
        Refusal: Any check fails or any step fails. The link has not moved.
    """
    lock = read_regular_file(request.lock, MAX_LOCK_BYTES)
    if hashlib.sha256(lock).hexdigest() != request.lock_sha256:
        raise Refusal(Reason.LOCK_HASH)
    check_lock_is_hashed(lock)
    name = fingerprint(lock)
    if request.expect_fingerprint is not None and request.expect_fingerprint != name:
        raise Refusal(Reason.FINGERPRINT)
    check_root(request.root)
    requirements = copy_lock(request.root, name, lock)
    venv, installed = install_environment(request, name, requirements, run)
    if request.link is not None:
        point_link(request.link, venv)
    return Outcome(name, str(venv), installed, request.link is not None)


def parse_request(argv: Sequence[str]) -> Request:
    """Read the arguments. Every one is checked here, and none has a default that weakens a check.

    Raises:
        Refusal: An argument is missing or malformed.
    """
    parser = argparse.ArgumentParser(
        prog="install_runtime", allow_abbrev=False, exit_on_error=False
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--lock-sha256", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--link", type=Path)
    parser.add_argument("--expect-fingerprint")
    parser.add_argument("--python", default=DEFAULT_PYTHON)
    try:
        parsed = parser.parse_args(list(argv))
    except (argparse.ArgumentError, SystemExit) as error:
        raise Refusal(Reason.USAGE) from error
    expected: str | None = parsed.expect_fingerprint
    if SHA256_HEX.fullmatch(parsed.lock_sha256) is None:
        raise Refusal(Reason.USAGE, "--lock-sha256 is 64 lowercase hex digits")
    if expected is not None and FINGERPRINT_PATTERN.fullmatch(expected) is None:
        raise Refusal(Reason.USAGE, "--expect-fingerprint is 16 lowercase hex digits")
    return Request(
        lock=parsed.lock,
        lock_sha256=parsed.lock_sha256,
        root=parsed.root,
        link=parsed.link,
        expect_fingerprint=expected,
        python=parsed.python,
    )


def main(argv: Sequence[str], run: Runner | None = None) -> int:
    """Run the install and print one JSON line. A failure of any class is a non-zero status."""
    try:
        outcome = install(parse_request(argv), run if run is not None else run_command)
    except Refusal as refusal:
        print(
            f"install_runtime: refused: {refusal.reason.value} {refusal.detail}".rstrip(),
            file=sys.stderr,
        )
        return 1
    except BaseException as error:  # noqa: BLE001 - nothing may leave as success, whatever the class
        print(f"install_runtime: {Reason.INTERNAL.value}: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(dataclasses.asdict(outcome), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
