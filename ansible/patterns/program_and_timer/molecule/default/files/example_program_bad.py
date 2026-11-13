#!/usr/bin/python3 -I
"""PLACEHOLDER program whose install-time check fails.

The scenario must refuse it and keep the installed program.
"""

from __future__ import annotations

import sys


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--check":
        print("PLACEHOLDER_CHECK_FAILED")
        return 1
    print("PLACEHOLDER_PROGRAM_BAD")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
