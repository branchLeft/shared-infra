"""The runbook names one runnable rotation path for each of the six monitoring.env keys.

Each path is `seed_host_inputs.py --host edge1 --set KEY`, which changes that key alone in the
host's inputs file. The test holds the runbook's section 3 to that: every one of the six keys has
exactly one `--set` line, no other key has one, and each key is a name the edge1 row of the
host's inputs carries and the seed tool routes. SNDS_DATA_URL is left out on purpose: section 14
rotates it, and it is not one of the six.
"""

from __future__ import annotations

import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
RUNBOOK = REPO / "hetzner" / "RUNBOOK-monitoring.md"
HOST_INPUTS_ROW = REPO / "ansible" / "roles" / "host_inputs" / "vars" / "main.yml"
SEED_TOOL = REPO / "ansible" / "tools" / "seed_host_inputs.py"

SIX_KEYS = (
    "monitoring_stack_smtp_username",
    "monitoring_stack_smtp_password",
    "monitoring_stack_healthchecks_ping_url",
    "monitoring_stack_alert_recipient_email",
    "monitoring_stack_mailhost_ping_url",
    "monitoring_stack_grafana_admin_password",
)

SET_LINE = re.compile(r"seed_host_inputs\.py --host edge1 --set (\S+?)'")


class RotationPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runbook = RUNBOOK.read_text(encoding="utf-8")

    def test_each_of_the_six_keys_has_exactly_one_set_line(self) -> None:
        named = SET_LINE.findall(self.runbook)
        self.assertEqual(sorted(SIX_KEYS), sorted(named))

    def test_no_set_line_is_a_placeholder(self) -> None:
        for name in SET_LINE.findall(self.runbook):
            self.assertRegex(name, r"^monitoring_stack_[a-z_]+$")

    def test_each_key_is_on_the_edge1_row_of_the_host_inputs(self) -> None:
        row = HOST_INPUTS_ROW.read_text(encoding="utf-8")
        for name in SIX_KEYS:
            self.assertIn(f"    - {name}\n", row)

    def test_each_key_is_routed_by_the_seed_tool(self) -> None:
        tool = SEED_TOOL.read_text(encoding="utf-8")
        for name in SIX_KEYS:
            self.assertIn(f'"{name}"', tool)

    def test_the_gap_paragraph_is_gone(self) -> None:
        self.assertNotIn("refuses an existing file", self.runbook)
        self.assertNotIn("No runnable path", self.runbook)


if __name__ == "__main__":
    unittest.main()
