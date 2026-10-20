#!/usr/bin/python3
"""A stand-in for ansible-playbook that holds the trigger's lock for a while.

Test setup only. It records the call, waits, then reports one change.
"""

import sys
import time
from pathlib import Path

ROOT = Path("/var/tmp/ptt")  # noqa: S108 - the test's own short directory
SECONDS = 12


def main() -> int:
    """Record the call, wait, and print a recap."""
    with (ROOT / "slow-calls").open("a", encoding="utf-8") as handle:
        handle.write(" ".join(sys.argv[1:]) + "\n")
    (ROOT / "slow-started").write_text("started\n", encoding="utf-8")
    time.sleep(SECONDS)
    sys.stdout.write("PLAY RECAP *****\n")
    sys.stdout.write("localhost : ok=1 changed=1 unreachable=0 failed=0 skipped=0\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
