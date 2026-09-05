#!/usr/bin/env python3
"""Pins how many tests `unittest discover` finds under this directory.

Two ways a test module can vanish from a run both leave `unittest discover`
reporting a smaller number with no other signal: an interpreter below a
module's declared minimum (see test_compose_unit_contract.py's own version
guard) turns the whole module into one `_FailedTest` placeholder, and a
module deleted from disk is simply not there to find. Either way the suite
can still exit 0 if everything it did collect passes -- a shrunken run looks
identical to a smaller, still-complete one unless something states what the
count should be.

This can only guard the rest of the directory, never itself: a test that
vanished along with this file would leave nothing here to notice the drop.
Bump EXPECTED_TEST_COUNT in the same change that adds or removes a test
method anywhere under hetzner/provision, including in this file.
"""

import pathlib
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent

EXPECTED_TEST_COUNT = 335


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
