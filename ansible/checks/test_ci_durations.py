"""The Test the checks step prints the slowest checks, so the step's time can be attributed.

The steps run every test of ansible/checks through run_check_tests.py, and this test reads that
runner. The request changes no result, so removing it would drop the timing in silence: this
test fails then.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent / "run_check_tests.py"
DURATIONS = re.compile(r"durations=[1-9][0-9]*")


class TestTheChecksPrintsDurations(unittest.TestCase):
    """The runner of the Test the checks steps asks unittest for the slowest tests."""

    def test_the_checks_runner_asks_for_the_slowest_tests(self) -> None:
        self.assertRegex(RUNNER.read_text(encoding="utf-8"), DURATIONS)


if __name__ == "__main__":
    unittest.main()
