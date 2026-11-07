"""Stop a bootstrap that would start the mail spool with no image on the host.

`ref` prints the digest-pinned image the host would run: the one in the host's pin file when
that file exists, else the one the vendored Compose file names. `check` reads the output of
`docker image inspect REF` on stdin and prints `gate=pass` or `gate=STOP reason=CODE`. It
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
# The host's pin file, which the role prefers to the Compose file once it exists: exactly one
# line. Held equal to the role's demo1_egress_spool_image_env_pattern by a test.
PIN_PATTERN: Final = re.compile("IMAGE=" + IMAGE_PATTERN.pattern)
OLD_PIN_PREFIX: Final = "MAIL_SPOOL_IMAGE="
MAX_BYTES: Final = 1 << 20
MAX_PIN_BYTES: Final = 4096
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


def pin_ref(text: str) -> tuple[str, str]:
    """The image the pin file names and an empty reason, or an empty image and the reason.

    The file is exactly one `IMAGE=<name>@sha256:<64 hex>` line, with or without its final line
    break. The older `MAIL_SPOOL_IMAGE=` form is refused, as is anything else."""
    line = text[:-1] if text.endswith("\n") else text
    if line.startswith(OLD_PIN_PREFIX):
        return "", "pin_old_form"
    if not PIN_PATTERN.match(line):
        return "", "pin_malformed"
    return line.removeprefix("IMAGE="), ""


def pin_from_file(path: Path) -> tuple[str, str]:
    """The image the pin file at `path` names, or the reason it cannot be used."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_PIN_BYTES + 1)
    except OSError:
        return "", "pin_unreadable"
    if len(data) > MAX_PIN_BYTES:
        return "", "pin_malformed"
    try:
        return pin_ref(data.decode("ascii"))
    except UnicodeDecodeError:
        return "", "pin_malformed"


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
    listed = images[0].get("RepoDigests")
    if listed is not None and (
        not isinstance(listed, list) or not all(isinstance(entry, str) for entry in listed)
    ):
        return "unreadable"
    # An image that lists no digest cannot be shown to be the pinned one, so it stops: the
    # daemon finding it by name proves only that some image has that name.
    if not listed:
        return "no_repo_digest"
    if digest_of(ref) not in {digest_of(entry) for entry in listed}:
        return "digest_mismatch"
    return ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spool_image_gate.py")
    commands = parser.add_subparsers(dest="command", required=True)
    ref = commands.add_parser("ref")
    ref.add_argument("--compose", required=True, type=Path)
    # One of the two is required, so the host's pin file is never skipped by leaving it out.
    # `--no-pin` is only for a host on which the pin file was checked to be absent.
    pin = ref.add_mutually_exclusive_group(required=True)
    pin.add_argument("--pin-file", type=Path)
    pin.add_argument("--no-pin", action="store_true")
    check = commands.add_parser("check")
    check.add_argument("--ref", required=True)
    args = parser.parse_args(argv)
    if args.command == "ref" and args.pin_file is not None:
        image, reason = pin_from_file(args.pin_file)
        if reason:
            print(f"ref=REFUSED reason={reason}", file=sys.stderr)
            return 1
        print(image)
        return 0
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
