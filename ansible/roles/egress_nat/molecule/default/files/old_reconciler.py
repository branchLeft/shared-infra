#!/usr/bin/python3
"""Test scaffolding, not part of the role. Stands for the previous release of
the NAT reconciler: it does nothing except leave a marker, so that the test
can tell that the role ran it again after putting it back.
"""

from pathlib import Path

Path("/run/egress-nat-old-reconciler-ran").write_text("ran\n", encoding="utf-8")
