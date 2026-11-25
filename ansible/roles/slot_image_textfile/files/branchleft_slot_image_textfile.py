#!/usr/bin/python3
"""Write each tenant stack's pinned image digest as a node_exporter textfile gauge.

Reads every CONFIG_DIR/<stack>.image.env that branchleft_deploy.py writes, and replaces one
.prom file atomically in the node_exporter textfile directory. One series per stack:

    branchleft_slot_image_info{stack="<stack>",digest="sha256:<hex>"} 1

A pin file that does not hold exactly one IMAGE= line naming a sha256 digest is refused. Its
stack gets no series, the refusal names the file and never the value, and the exit status is
1. The valid stacks are still exported. The program runs as root from a systemd timer.
"""

from __future__ import annotations

import argparse
import enum
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

DEFAULT_CONFIG_DIR = "/etc/branchleft"
DEFAULT_OUTPUT = "/var/lib/branchleft/backup-worker-exporter/branchleft_slot_image.prom"
METRIC = "branchleft_slot_image_info"
PIN_SUFFIX = ".image.env"
# A pin file is one short line. A larger file is not a pin and is refused unread.
MAX_PIN_BYTES = 4096

# The same stack name rule branchleft_deploy.py applies before it writes a pin file.
STACK_NAME = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")
# Exactly one line: IMAGE=<name>@sha256:<64 lower-case hex>. \A and \Z, not ^ and $, so a
# trailing newline inside the value cannot pass.
PIN_LINE = re.compile(r"\AIMAGE=[^\s@]+@(?P<digest>sha256:[0-9a-f]{64})\Z")


class Reason(enum.Enum):
    """Why a pin file is refused. The message names the rule, never the value in the file."""

    NOT_REGULAR = "not a regular file"
    TOO_LARGE = "file is larger than a pin file can be"
    NOT_ONE_LINE = "expected exactly one line"
    NOT_A_DIGEST = "the line is not IMAGE= with a sha256 digest"
    STACK_NAME = "rule: stack name"


class PinRefusedError(ValueError):
    """A pin file that must not be exported."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def read_digest(path: Path) -> str:
    """Return the sha256 digest a pin file names.

    Raises:
        PinRefusedError: the file is not one regular file holding one digest-pinned IMAGE= line.
    """
    status = os.lstat(path)
    if not stat.S_ISREG(status.st_mode):
        raise PinRefusedError(Reason.NOT_REGULAR)
    if status.st_size > MAX_PIN_BYTES:
        raise PinRefusedError(Reason.TOO_LARGE)
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise PinRefusedError(Reason.NOT_ONE_LINE)
    match = PIN_LINE.match(lines[0])
    if match is None:
        raise PinRefusedError(Reason.NOT_A_DIGEST)
    return match.group("digest")


def collect(config_dir: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Return the (stack, digest) pairs that are valid, and one refusal line per bad file."""
    pins: list[tuple[str, str]] = []
    refusals: list[str] = []
    for path in sorted(config_dir.glob("*" + PIN_SUFFIX)):
        stack = path.name[: -len(PIN_SUFFIX)]
        if STACK_NAME.match(stack) is None:
            refusals.append(f"{path.name}: refused ({Reason.STACK_NAME.value})")
            continue
        try:
            digest = read_digest(path)
        except PinRefusedError as error:
            refusals.append(f"{path.name}: refused ({error.reason.value})")
            continue
        except (OSError, UnicodeDecodeError):
            refusals.append(f"{path.name}: refused (the file could not be read)")
            continue
        pins.append((stack, digest))
    return pins, refusals


def render(pins: list[tuple[str, str]]) -> str:
    """Return the textfile body: one gauge line per valid stack, in stack order."""
    lines = [
        f"# HELP {METRIC} Image digest each tenant stack is pinned to.",
        f"# TYPE {METRIC} gauge",
    ]
    for stack, digest in sorted(pins):
        lines.append(f'{METRIC}{{stack="{stack}",digest="{digest}"}} 1')
    return "\n".join(lines) + "\n"


def write_atomically(path: Path, text: str) -> None:
    """Replace path with text in one rename, so a scrape never reads a partial file.

    The temporary file lives in the destination's own directory, so the rename stays on
    one filesystem, and its mode is set before the rename.
    """
    handle_fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".branchleft-slot-image-")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o644)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config-dir", type=Path, default=Path(DEFAULT_CONFIG_DIR))
    parser.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT))
    args = parser.parse_args(argv)
    pins, refusals = collect(args.config_dir)
    write_atomically(args.output, render(pins))
    for refusal in refusals:
        print(refusal, file=sys.stderr)
    return 1 if refusals else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
