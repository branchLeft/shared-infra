#!/usr/bin/env python3
"""Pins how many tests `unittest discover` finds under this directory.

See test_suite_size.md.
"""

import pathlib
import sys
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent

EXPECTED_TEST_COUNT = 458

# The lowest interpreter this suite is run on. Modules here are written to
# import under it; a lower interpreter fails some modules at import, and
# unittest reports each as one error in place of its tests.
MIN_PYTHON = (3, 9)


class SuiteSizeTests(unittest.TestCase):
    def test_the_interpreter_meets_the_recorded_floor(self):
        self.assertGreaterEqual(
            sys.version_info[:2],
            MIN_PYTHON,
            f"this suite needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer; "
            f"running under {sys.version.split()[0]} ({sys.executable}). Under an "
            "older interpreter unittest discover imports the modules that need the "
            "newer one, reports each as a single import error, and counts only the rest.",
        )

    def test_the_directory_yields_the_expected_number_of_tests(self):
        suite = unittest.TestLoader().discover(str(PROVISION), pattern="test_*.py")
        found = suite.countTestCases()
        self.assertEqual(
            found,
            EXPECTED_TEST_COUNT,
            f"unittest discover found {found} tests under hetzner/provision; "
            f"EXPECTED_TEST_COUNT says {EXPECTED_TEST_COUNT}. A number that moved "
            "without this constant moving with it is either a new test nobody "
            "recorded here or an old one that stopped running -- a module that "
            "failed to import, or one deleted from disk, each collapse to a "
            "smaller total with nothing else to say that anything shrank.",
        )


if __name__ == "__main__":
    unittest.main()
