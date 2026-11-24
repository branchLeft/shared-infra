"""The Test the checks step prints the slowest checks, so the step's time can be attributed.

The steps run every test of ansible/checks through run_check_tests.py, and this test reads that
runner. The request changes no result, so removing it would drop the timing in silence: this
test fails then. The call is read by parsing the source, so a change that keeps the text but
drops the argument from the call fails too.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent / "run_check_tests.py"


def prints_durations(source: str) -> bool:
    """True when `source` calls TextTestRunner with durations set to a positive integer literal."""
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name != "TextTestRunner":
            continue
        for keyword in node.keywords:
            value = keyword.value
            if (
                keyword.arg == "durations"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, int)
                and not isinstance(value.value, bool)
                and value.value >= 1
            ):
                return True
    return False


class TestTheChecksPrintsDurations(unittest.TestCase):
    """The runner of the Test the checks steps asks unittest for the slowest tests."""

    def test_the_checks_runner_asks_for_the_slowest_tests(self) -> None:
        self.assertTrue(prints_durations(RUNNER.read_text(encoding="utf-8")))

    def test_a_runner_that_drops_the_argument_is_refused(self) -> None:
        dropped = "import unittest\nunittest.TextTestRunner(buffer=True, verbosity=1)\n"
        self.assertFalse(prints_durations(dropped))

    def test_a_zero_or_non_literal_argument_is_refused(self) -> None:
        for call in ("durations=0", "durations=N", "durations=True"):
            with self.subTest(call=call):
                source = f"import unittest\nunittest.TextTestRunner({call})\n"
                self.assertFalse(prints_durations(source))


if __name__ == "__main__":
    unittest.main()
