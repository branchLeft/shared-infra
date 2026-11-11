#!/usr/bin/python3 -I
"""PLACEHOLDER program for the program_and_timer pattern. It does nothing useful.

Its install-time check is --check: exit 0 when the program is fit to run.
"""

from __future__ import annotations

import sys


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--check":
        return 0
    print("PLACEHOLDER_PROGRAM_V1")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
