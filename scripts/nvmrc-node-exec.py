#!/usr/bin/env python3
"""Runs a command under the Node version named in the repository's .nvmrc.

Never under whichever `node` happens to be first on PATH. The commit hooks that run Node
go through this, so a commit made from a shell on another Node cannot change which runtime
the suites run under.

Usage: scripts/nvmrc-node-exec.py <command> [args...]

Resolves the binary from the nvm install layout
($HOME/.nvm/versions/node/v<version>/bin). When that version is not installed,
prints one line naming the required version and exits 1.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ASCII_SPACE = re.compile(r"[ \t\n\r\f\v]")


def fail(message: str) -> int:
    print(f"nvmrc-node-exec: {message}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    root = Path(os.path.abspath(__file__)).parent.parent
    raw = ""
    nvmrc = root / ".nvmrc"
    if os.access(nvmrc, os.R_OK):
        raw = ASCII_SPACE.sub("", nvmrc.read_text(encoding="utf-8", errors="replace"))
    version = raw.removeprefix("v")
    if EXACT_VERSION.fullmatch(version) is None:
        return fail(f".nvmrc must name one exact Node version (found '{raw}')")

    home = os.environ.get("HOME")
    if home is None:
        return fail("HOME is not set, so the nvm install cannot be found")
    binary = Path(home, ".nvm", "versions", "node", f"v{version}", "bin")
    if not os.access(binary / "node", os.X_OK):
        return fail(
            f"this repository needs Node v{version} (.nvmrc); install it with 'nvm install {version}'"
        )

    if not argv:
        return 0
    env = dict(os.environ)
    env["PATH"] = f"{binary}:{os.environ.get('PATH', '')}"
    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        print(f"exec: {argv[0]}: not found", file=sys.stderr)
        return 127
    except PermissionError:
        print(f"exec: {argv[0]}: permission denied", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
