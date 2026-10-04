#!/usr/bin/env python3
"""Pins how many tests `unittest discover` finds under this directory.

See test_suite_size.md.
"""

import pathlib
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent

EXPECTED_TEST_COUNT = 375


class SuiteSizeTests(unittest.TestCase):
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
