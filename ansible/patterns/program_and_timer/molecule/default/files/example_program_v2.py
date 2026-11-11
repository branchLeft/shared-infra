#!/usr/bin/python3 -I
"""PLACEHOLDER program, second version.

The scenario installs it over version one.
"""

from __future__ import annotations

import sys


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--check":
        return 0
    print("PLACEHOLDER_PROGRAM_V2")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
