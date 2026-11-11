#!/usr/bin/python3 -I
"""Test stand-in for what the compose template unit runs: `docker compose up --wait`.

It records one line per start and never prints a secret: the image it was given, whether
a secret reached its environment (set or unset), and whether the deploy lock was held
while it ran. It fails while the file up_fails exists, as a stack that does not come up.
"""

import fcntl
import os
import sys
from pathlib import Path

STATE = Path("/var/lib/standin")


def lock_reading(stack: str) -> str:
    """Return "free" when the stack's deploy lock can be taken now, otherwise "held"."""
    try:
        fd = os.open(f"/etc/branchleft/{stack}.deploy.lock", os.O_RDONLY | os.O_CREAT, 0o666)
    except OSError:
        return "held"
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return "held"
        fcntl.flock(fd, fcntl.LOCK_UN)
        return "free"
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: standin-compose-up STACK", file=sys.stderr)
        return 2
    stack = argv[1]
    STATE.mkdir(parents=True, exist_ok=True)
    lock = lock_reading(stack)
    secret = "set" if os.environ.get("GHOST_DB_PASSWORD") else "unset"
    image = os.environ.get("IMAGE") or "none"
    with (STATE / "starts.log").open("a", encoding="utf-8") as log:
        log.write(f"{stack} image={image} secret={secret} lock={lock}\n")
    if (STATE / "up_fails").exists():
        print("stand-in: the stack did not come up", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
