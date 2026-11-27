#!/usr/bin/python3
"""Test stand-in for the Node runtime, in place of /opt/branchleft/broker/node/bin/node.

It is what the forced command runs where the real bundler would run: it records what it was given
(its argument list, its environment, the one line it reads from standard input) as one JSON line in
the calls file, answers on standard output and error so that the test can see the streams pass
through, and ends with the status the grant reference asks for. It exports nothing.
"""

from __future__ import annotations

import json
import os
import sys

CALLS = "/var/lib/entry-test/calls"
# The statuses a reference asks for. Any other reference is an export that went well.
STATUS_OF_REFERENCE = {"grant-fail": 1, "grant-cleanup": 70}


def reference_of(argv: list[str]) -> str:
    """The value after --grant-reference, or an empty string when the flag is absent."""
    if "--grant-reference" in argv:
        index = argv.index("--grant-reference") + 1
        if index < len(argv):
            return argv[index]
    return ""


def main(argv: list[str]) -> int:
    """Record the call, read the sign-in line, and end as the reference asks."""
    line = sys.stdin.readline().rstrip("\n")
    record = {"argv": argv, "env": dict(os.environ), "stdin": line, "cwd": os.getcwd()}
    with open(CALLS, "a", encoding="utf-8") as calls:
        calls.write(json.dumps(record) + "\n")
    sys.stdout.write(f"bundler-ready stdin-length={len(line)}\n")
    sys.stderr.write("bundler-note\n")
    return STATUS_OF_REFERENCE.get(reference_of(argv), 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
