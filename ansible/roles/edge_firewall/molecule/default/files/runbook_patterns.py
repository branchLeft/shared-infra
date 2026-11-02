#!/usr/bin/env python3
"""Test scaffolding, not part of the role: the grep patterns the runbook tells an operator to run.

Usage: runbook_patterns.py PATH-TO-RUNBOOK-provision-host.md

Prints a JSON object {"nat_table": [pattern, ...]}: the patterns of the grep commands in the
runbook's "Confirm the gateway is forwarding" block that read `nft list table ip
branchleft_edge_nat`. The scenario runs each against the real table the kernel lists, so the
check an operator pastes is tied to the kernel's own text and not to a guess at it. The
section is found with the runbook helper that the tests in hetzner/provision use.
"""

import json
import re
import sys
from pathlib import Path

HEADING = "### 3. Confirm the gateway is forwarding"
NFT_GREP = re.compile(r'nft list table ip branchleft_edge_nat \| grep -E -- "([^"]+)"')


def main() -> None:
    runbook = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(runbook.parent / "provision"))
    from runbook_sections import runbook_section

    section = runbook_section(runbook, HEADING)
    block = section.split("```bash", 1)[1].split("```", 1)[0]
    patterns = NFT_GREP.findall(block)
    if not patterns:
        raise SystemExit(f"no nft grep pattern in the first bash block under {HEADING!r}")
    print(json.dumps({"nat_table": patterns}))


if __name__ == "__main__":
    main()
