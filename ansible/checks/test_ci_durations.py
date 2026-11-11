"""The Test the checks step prints the slowest checks, so the step's time can be attributed.

The step runs every test of ansible/checks, and this test reads the workflow that runs it. The
flag changes no result, so removing it would drop the timing in silence: this test fails then.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ansible.yml"
TEST_CHECKS = re.compile(r"- name: Test the checks\n(?:\s+if: .+\n)?\s+run: (?P<command>.+)")
DURATIONS = re.compile(r" --durations [1-9][0-9]*'?$")


class TestTheChecksPrintsDurations(unittest.TestCase):
    """The workflow's Test the checks step asks unittest for the slowest tests."""

    def test_the_checks_step_asks_for_the_slowest_tests(self) -> None:
        match = TEST_CHECKS.search(WORKFLOW.read_text(encoding="utf-8"))
        if match is None:
            self.fail("the workflow has no Test the checks step with a run line")
        self.assertRegex(match.group("command"), DURATIONS)


if __name__ == "__main__":
    unittest.main()
