"""Stop a bootstrap that would start the mail spool with no image on the host.

`ref` prints the digest-pinned image the vendored Compose file names; `check` reads the output
of `docker image inspect REF` on stdin and prints `gate=pass` or `gate=STOP reason=CODE`. It
reads and prints nothing else. Standard library only. See ansible/tools/README.md."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

SERVICE: Final = "mail-spool"
# Held equal to the demo1_egress_spool role's demo1_egress_spool_image_pattern by a test.
IMAGE_PATTERN: Final = re.compile(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z")
MAX_BYTES: Final = 1 << 20
SERVICES_LINE: Final = re.compile(r"services:\s*$")
SERVICE_LINE: Final = re.compile(rf"  {re.escape(SERVICE)}:\s*$")
OTHER_SERVICE_LINE: Final = re.compile(r"  \S")
IMAGE_LINE: Final = re.compile(r"    image:\s*(.*?)\s*$")
TOP_LEVEL_LINE: Final = re.compile(r"\S")


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def compose_ref(text: str) -> tuple[str, str]:
    """The service's image and an empty reason, or an empty image and the reason."""
    images: list[str] = []
    in_services = in_service = False
    for line in text.splitlines():
        if TOP_LEVEL_LINE.match(line):
            in_services = bool(SERVICES_LINE.match(line))
            in_service = False
        elif in_services and SERVICE_LINE.match(line):
            in_service = True
        elif in_services and OTHER_SERVICE_LINE.match(line):
            in_service = False
        elif in_service and (found := IMAGE_LINE.match(line)):
            images.append(unquote(found[1]))
    if not images:
        return "", "no_image"
    if len(images) > 1:
        return "", "several_images"
    if not IMAGE_PATTERN.match(images[0]):
        return "", "ref_not_digest_pinned"
    return images[0], ""


def digest_of(ref: str) -> str:
    return ref.rsplit("@", 1)[-1]


def judge(ref: str, stdin_text: str) -> str:
    """An empty string for a pass, else the reason the bootstrap must not start."""
    if not IMAGE_PATTERN.match(ref):
        return "ref_not_digest_pinned"
    if not stdin_text.strip():
        return "no_output"
    try:
        images = json.loads(stdin_text)
    except ValueError:
        return "unreadable"
    if not isinstance(images, list) or not all(isinstance(image, dict) for image in images):
        return "unreadable"
    if not images:
        return "image_absent"
    if len(images) > 1:
        return "several_images"
    listed = images[0].get("RepoDigests", False)
    if listed is None:
        listed = []
    if not isinstance(listed, list) or not all(isinstance(entry, str) for entry in listed):
        return "unreadable"
    # An image loaded from a file on a store that records no digest lists none. The daemon
    # still found it by the digest-form reference, which is what the role itself tests.
    if listed and digest_of(ref) not in {digest_of(entry) for entry in listed}:
        return "digest_mismatch"
    return ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spool_image_gate.py")
    commands = parser.add_subparsers(dest="command", required=True)
    ref = commands.add_parser("ref")
    ref.add_argument("--compose", required=True, type=Path)
    check = commands.add_parser("check")
    check.add_argument("--ref", required=True)
    args = parser.parse_args(argv)
    if args.command == "ref":
        try:
            with args.compose.open("rb") as handle:
                text = handle.read(MAX_BYTES + 1).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            print("ref=REFUSED reason=compose_unreadable", file=sys.stderr)
            return 1
        image, reason = compose_ref(text) if len(text) <= MAX_BYTES else ("", "compose_too_large")
        if reason:
            print(f"ref=REFUSED reason={reason}", file=sys.stderr)
            return 1
        print(image)
        return 0
    piped = sys.stdin.buffer.read(MAX_BYTES + 1)[:MAX_BYTES].decode("utf-8", errors="replace")
    reason = judge(args.ref, piped)
    if reason:
        print(f"gate=STOP reason={reason}")
        return 1
    print("gate=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
