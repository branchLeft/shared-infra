#!/usr/bin/python3 -I
"""Carry one verified broker release into the broker_deploy role: its files and its pins.

Run by the owner on a workstation, after the release's attestation was verified, never on a
host. Without ``--write`` it checks everything and prints the pins; with it, it writes the
release files and the role's version and pins. Prints a verdict and a reason code, never any
text read from the tarball. The reasoning: ansible/tools/README.md."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final, NoReturn

import yaml  # type: ignore[import-untyped]

ROLE_DEFAULT: Final = Path(__file__).resolve().parents[1] / "roles" / "broker_deploy"
VERSION_PATTERN: Final = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
# Held equal to the pin check's own path rule (tasks/_release_pin.yml) by a test.
PATH_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
DOT_DOT: Final = re.compile(r"(^|/)\.\.(/|\Z)")
ENTRY_POINT: Final = "broker.mjs"
VERSION_LINE: Final = "broker_deploy_release_version: ''"
PINS_LINE: Final = "broker_deploy_release_pins: {}"
MAX_TARBALL: Final = 32 << 20
MAX_FILE: Final = 16 << 20
MAX_TOTAL: Final = 48 << 20
MAX_MEMBERS: Final = 200


class RefusedError(Exception):
    """A refusal with a reason code that holds no text from any input."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class UsageError(Exception):
    """The command line was not understood; holds no text from it."""


class Parser(argparse.ArgumentParser):
    """An argument parser that never prints an argument it was given."""

    def error(self, message: str) -> NoReturn:
        """Refuse without showing the message, which may quote a mistyped value.

        Raises:
            UsageError: always.
        """
        raise UsageError


def read_tarball(path: Path, digest: str) -> bytes:
    """Return the tarball's bytes once they are the attested digest.

    Raises:
        RefusedError: the tarball is unreadable, a link, too large or not that digest.
    """
    try:
        if path.is_symlink() or not path.is_file():
            raise RefusedError("tarball_not_a_plain_file")
        if path.stat().st_size > MAX_TARBALL:
            raise RefusedError("tarball_too_large")
        data = path.read_bytes()
    except OSError as error:
        raise RefusedError("tarball_unreadable") from error
    if hashlib.sha256(data).hexdigest() != digest:
        raise RefusedError("tarball_digest_differs")
    return data


def plain(name: str) -> bool:
    """Return whether a member name is a plain relative path with no dot-dot segment."""
    return bool(PATH_PATTERN.match(name)) and not DOT_DOT.search(name)


def read_members(data: bytes) -> dict[str, bytes]:
    """Return the regular files of the tarball by path, refusing anything else.

    Nothing is extracted by tarfile: each file's bytes are read from the archive.

    Raises:
        RefusedError: the archive is not a gzip tar, holds a link, a device, a path that is not
            plain, a repeat, a file that is also a directory, too much, or no entry point.
    """
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_MEMBERS:
                raise RefusedError("too_many_members")
            for member in members:
                name = member.name.removesuffix("/") if member.isdir() else member.name
                if not plain(name):
                    raise RefusedError("path_not_plain")
                if name in files or name in directories:
                    raise RefusedError("repeated_path")
                if member.isdir():
                    directories.add(name)
                    continue
                if not member.isreg():
                    raise RefusedError("member_not_a_plain_file")
                total += member.size
                if member.size > MAX_FILE or total > MAX_TOTAL:
                    raise RefusedError("release_too_large")
                handle = archive.extractfile(member)
                if handle is None:
                    raise RefusedError("member_unreadable")
                files[name] = handle.read()
    except (tarfile.TarError, EOFError, OSError) as error:
        raise RefusedError("not_a_gzip_tarball") from error
    for name in files:
        parts = name.split("/")
        parents = {"/".join(parts[:count]) for count in range(1, len(parts))}
        if parents & files.keys():
            raise RefusedError("file_is_also_a_directory")
    if ENTRY_POINT not in files:
        raise RefusedError("no_entry_point")
    return files


def pins_block(version: str, pins: dict[str, str]) -> str:
    """Return the two default lines for a release.

    Every key and digest is quoted, so no path or all-digit digest is read as a number, a
    boolean or a null.
    """
    lines = [f"broker_deploy_release_version: '{version}'", "broker_deploy_release_pins:"]
    lines.append(f"  '{version}':")
    lines.extend(f"    '{path}': '{pins[path]}'" for path in sorted(pins))
    return "\n".join(lines)


def new_defaults(text: str, version: str, pins: dict[str, str]) -> str:
    """Return the role defaults with the release set, after reading the result back.

    Raises:
        RefusedError: the defaults are not the placeholders, or the result does not read back as
            the version and pins.
    """
    lines = text.split("\n")
    if lines.count(VERSION_LINE) != 1 or lines.count(PINS_LINE) != 1:
        raise RefusedError("defaults_not_placeholders")
    block = pins_block(version, pins).split("\n")
    out: list[str] = []
    for line in lines:
        if line == VERSION_LINE:
            out.append(block[0])
        elif line == PINS_LINE:
            out.extend(block[1:])
        else:
            out.append(line)
    result = "\n".join(out)
    try:
        loaded = yaml.safe_load(result)
    except yaml.YAMLError as error:
        raise RefusedError("defaults_do_not_read_back") from error
    if loaded.get("broker_deploy_release_version") != version or loaded.get(
        "broker_deploy_release_pins"
    ) != {version: pins}:
        raise RefusedError("defaults_do_not_read_back")
    return result


def check_read_back(target: Path, content: bytes) -> None:
    """Refuse unless the file on disk holds exactly the bytes that were written.

    Raises:
        RefusedError: it reads back differently.
    """
    if hashlib.sha256(target.read_bytes()).hexdigest() != sha256(content):
        raise RefusedError("write_did_not_read_back")


def stays_inside(destination: Path, target: Path) -> None:
    """Refuse a target that is not below the release directory (a second line after `plain`).

    Raises:
        RefusedError: the target resolves outside the directory.
    """
    if not target.resolve().is_relative_to(destination.resolve()):
        raise RefusedError("path_escapes_release")


def write_release(destination: Path, files: dict[str, bytes]) -> None:
    """Write the files under a directory that must not exist yet, then read them back.

    Raises:
        RefusedError: the directory exists, or a written file reads back differently.
    """
    if destination.exists() or destination.is_symlink():
        raise RefusedError("release_already_carried")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        for name, content in sorted(files.items()):
            target = destination / name
            stays_inside(destination, target)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            check_read_back(target, content)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def sha256(content: bytes) -> str:
    """Return the sha256 hex digest of some bytes."""
    return hashlib.sha256(content).hexdigest()


def replace_file(path: Path, text: str) -> None:
    """Replace a file with new text through a temporary file in its own directory."""
    handle, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
        Path(name).chmod(path.stat().st_mode & 0o777)
        Path(name).replace(path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def carry(role: Path, version: str, tarball: Path, digest: str, *, write: bool) -> list[str]:
    """Check a release and, when asked, carry it; return the lines to print.

    Every check runs before anything is written.

    Raises:
        RefusedError: any check fails.
    """
    if not VERSION_PATTERN.match(version):
        raise RefusedError("version_not_major_minor_patch")
    if not DIGEST_PATTERN.match(digest):
        raise RefusedError("digest_not_64_lower_hex")
    files = read_members(read_tarball(tarball, digest))
    pins = {name: sha256(content) for name, content in files.items()}
    defaults = role / "defaults" / "main.yml"
    try:
        updated = new_defaults(defaults.read_text(encoding="utf-8"), version, pins)
    except (OSError, UnicodeDecodeError) as error:
        raise RefusedError("defaults_unreadable") from error
    destination = role / "files" / "releases" / version
    if destination.exists() or destination.is_symlink():
        raise RefusedError("release_already_carried")
    lines = [pins_block(version, pins)]
    if write:
        write_release(destination, files)
        try:
            replace_file(defaults, updated)
        except BaseException:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        lines.append(f"carry=WRITTEN files={len(files)}")
    else:
        lines.append(f"carry=CHECKED files={len(files)} (nothing written; add --write)")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """Run the tool; return its exit status: 0 done, 1 refused, 2 usage."""
    parser = Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tarball", required=True, type=Path)
    parser.add_argument("--tarball-sha256", required=True)
    parser.add_argument("--role-dir", type=Path, default=ROLE_DEFAULT)
    parser.add_argument("--write", action="store_true")
    try:
        args = parser.parse_args(argv)
    except UsageError:
        print("carry=REFUSED reason=usage_error")
        return 2
    try:
        lines = carry(
            args.role_dir, args.version, args.tarball, args.tarball_sha256, write=args.write
        )
    except RefusedError as refusal:
        print(f"carry=REFUSED reason={refusal.reason}")
        return 1
    except OSError:
        print("carry=REFUSED reason=write_failed")
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
