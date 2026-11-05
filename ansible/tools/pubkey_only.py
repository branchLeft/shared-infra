"""Check that a file holds exactly one SSH public key and nothing else.

It prints a verdict and the key's fingerprint, never any text of the file, so a private key
handed to it by mistake is not echoed. Standard library only; the other key tool imports it.
What it refuses and why is in ansible/tools/README.md."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
import struct
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn

MAX_BYTES: Final = 2048
# Held equal to the ci_login role's ci_login_key_shapes by a test.
KEY_SHAPES: Final[tuple[str, ...]] = (
    "ssh-ed25519 [A-Za-z0-9+/]{68}",
    "ecdsa-sha2-nistp256 [A-Za-z0-9+/]{139}=",
    "ecdsa-sha2-nistp384 [A-Za-z0-9+/]{182}==",
    "ecdsa-sha2-nistp521 [A-Za-z0-9+/]{230}==",
    "ssh-rsa [A-Za-z0-9+/]{200,}={0,2}",
    r"sk-ssh-ed25519@openssh\.com [A-Za-z0-9+/]{90,}={0,2}",
    r"sk-ecdsa-sha2-nistp256@openssh\.com [A-Za-z0-9+/]{160,}={0,2}",
)
# \Z, not $, so a trailing line break does not pass.
KEY_PATTERN: Final = re.compile("(" + "|".join(KEY_SHAPES) + r")( [ -~]*)?\Z")
KEY_TYPES: Final = frozenset(shape.split(" ", 1)[0].replace("\\", "") for shape in KEY_SHAPES)
# Armour of a private key, and the magic of its unarmoured form.
PRIVATE_MARKERS: Final[tuple[bytes, ...]] = (b"-----BEGIN", b"PRIVATE KEY", b"openssh-key-v1")
USAGE_ERROR: Final = "usage error"


@dataclass(frozen=True)
class KeyCheck:
    """The verdict on one file: a reason when refused, the key's parts when accepted."""

    reason: str
    key_type: str = ""
    body: str = ""
    fingerprint: str = ""

    @property
    def ok(self) -> bool:
        return not self.reason


class QuietParser(argparse.ArgumentParser):
    """An argument parser that never repeats an argument, which might be a typed secret."""

    def error(self, message: str) -> NoReturn:
        print(USAGE_ERROR, file=sys.stderr)
        raise SystemExit(2)


def refused(reason: str) -> KeyCheck:
    return KeyCheck(reason=reason)


def blob_names_type(blob: bytes, key_type: str) -> bool:
    """The key blob starts with its own type name, length first."""
    if len(blob) < 4:
        return False
    (length,) = struct.unpack(">I", blob[:4])
    return blob[4 : 4 + length] == key_type.encode("ascii")


def fingerprint_of(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def check_text(data: bytes, want_type: str | None = None) -> KeyCheck:
    """Accept exactly one public key line, refusing everything else with a reason code."""
    if len(data) > MAX_BYTES:
        return refused("too_large")
    if any(marker in data for marker in PRIVATE_MARKERS):
        return refused("private_key")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return refused("not_text")
    line = text[:-1] if text.endswith("\n") else text
    if not line.strip():
        return refused("empty")
    if "\n" in line:
        return refused("several_lines")
    match = KEY_PATTERN.match(line)
    if match is None:
        words = line.split(" ")
        if words[0] not in KEY_TYPES and any(word in KEY_TYPES for word in words[1:]):
            return refused("options_in_front")
        return refused("bad_shape")
    key_type, body = line.split(" ")[:2]
    try:
        blob = base64.b64decode(body, validate=True)
    except binascii.Error:
        return refused("bad_shape")
    if not blob_names_type(blob, key_type):
        return refused("bad_shape")
    if want_type is not None and key_type != want_type:
        return refused("wrong_type")
    return KeyCheck(reason="", key_type=key_type, body=body, fingerprint=fingerprint_of(blob))


def check_file(path: Path, want_type: str | None = None) -> KeyCheck:
    """Read at most one byte past the size limit, so a huge file is never held whole."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        return refused("unreadable")
    return check_text(data, want_type)


def main(argv: Sequence[str] | None = None) -> int:
    parser = QuietParser(prog="pubkey_only.py")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=QuietParser)
    check = commands.add_parser("check")
    check.add_argument("file", type=Path)
    check.add_argument("--type", dest="want_type", default=None)
    args = parser.parse_args(argv)
    verdict = check_file(args.file, args.want_type)
    if not verdict.ok:
        print(f"pubkey=REFUSED reason={verdict.reason}")
        return 1
    print(f"pubkey=ok type={verdict.key_type} fingerprint={verdict.fingerprint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
