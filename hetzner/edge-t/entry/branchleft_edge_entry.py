"""Publish or withdraw one tenant hostname descriptor in edge-t's descriptor directory.

The controller reaches this program through its forced-command key and one
sudoers line; both are the owner's decision and are not wired here. The
program is the only writer of the directory the certificate check reads.

It checks the slug, the size and the JSON shape of the descriptor and nothing
else. Hostname validation belongs to the caller (render-core's validate(), run
by the controller before publish), and the certificate check ignores any file
that fails it.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
from typing import BinaryIO, Sequence

DESCRIPTOR_DIR = "/var/lib/branchleft/edge-descriptors"

# Read at most one byte past the limit, so an oversize body is detected
# without buffering all of it.
STDIN_LIMIT = 64 * 1024

# \A and \Z rather than ^ and $: `$` also matches before a trailing newline.
SLUG = re.compile(r"\A[a-z0-9-]{1,63}\Z")

VERBS = ("publish", "withdraw")

USAGE = (
    "usage: branchleft-edge-entry publish SLUG   (descriptor JSON on stdin)\n"
    "       branchleft-edge-entry withdraw SLUG"
)


class EntryError(Exception):
    """A refusal caused by the caller's input. Nothing is written."""


def validate_slug(slug: str) -> str:
    if not SLUG.match(slug):
        raise EntryError(f"invalid slug: {slug!r}")
    return slug


def read_descriptor(stream: BinaryIO, *, limit: int = STDIN_LIMIT) -> bytes:
    body = stream.read(limit + 1)
    if len(body) > limit:
        raise EntryError(f"descriptor on stdin exceeds {limit} bytes")
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise EntryError("descriptor on stdin is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise EntryError("descriptor on stdin must be a JSON object")
    return body


def publish(slug: str, body: bytes, directory: str) -> str:
    """Write <slug>.json by temporary file and rename, so a reader sees the old or the new file."""
    target = os.path.join(directory, f"{slug}.json")
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{slug}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return target


def withdraw(slug: str, directory: str) -> None:
    """Remove <slug>.json. Removing a file that is not there is not an error."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(os.path.join(directory, f"{slug}.json"))


def main(
    argv: Sequence[str],
    *,
    stdin: BinaryIO,
    directory: str = DESCRIPTOR_DIR,
) -> int:
    if len(argv) != 3 or argv[1] not in VERBS:
        print(USAGE, file=sys.stderr)
        return 2
    verb, slug = argv[1], argv[2]
    try:
        validate_slug(slug)
        if verb == "publish":
            publish(slug, read_descriptor(stdin), directory)
        else:
            withdraw(slug, directory)
    except EntryError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"failed: {error.strerror or type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv, stdin=sys.stdin.buffer))
