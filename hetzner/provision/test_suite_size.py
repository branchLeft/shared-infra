#!/usr/bin/env python3
"""Pins how many tests `unittest discover` finds in each module under this directory.

See test_suite_size.md.

The expected number lives in test_counts/<module>.txt, one small file per test
module, rather than as one constant for the whole directory. A single number is a
line every pull request that adds a test must edit, so two unrelated pull requests
adding tests to different modules collided on it. With one file per module they
touch different files and merge cleanly; only two pull requests changing the same
module's test count still meet, and they should.

The control is the same, and finer: a module that failed to
import or was deleted still turns the run red, and so does a test module with no
count file, a count file with no module, or a module whose count differs. The
directory test_counts/ is owned by the same CODEOWNERS owner as this file.
"""

import collections
import pathlib
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent
COUNTS = PROVISION / "test_counts"
SUFFIX = ".txt"


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


def discovered_counts():
    """Tests found per module, as `unittest discover` sees them.

    A module that fails to import comes back as one placeholder test named after
    the module; it is counted under that module name, so its count is 1 and no
    count file for a real module says 1 unless the module really has one test.
    """
    suite = unittest.TestLoader().discover(str(PROVISION), pattern="test_*.py")
    counts = collections.Counter()
    for test in _flatten(suite):
        if type(test).__name__ == "_FailedTest":
            counts[test._testMethodName] += 1
        else:
            counts[type(test).__module__] += 1
    return dict(counts)


def recorded_counts():
    """The count each test_counts/<module>.txt file records."""
    recorded = {}
    for path in sorted(COUNTS.glob("*" + SUFFIX)):
        recorded[path.name[: -len(SUFFIX)]] = int(path.read_text().strip())
    return recorded


class SuiteSizeTests(unittest.TestCase):
    def test_every_module_has_a_count_file_and_the_count_matches(self):
        found = discovered_counts()
        recorded = recorded_counts()
        problems = []
        for module in sorted(found.keys() - recorded.keys()):
            problems.append(
                f"{module}: {found[module]} tests found, no test_counts/{module}{SUFFIX}"
            )
        for module in sorted(recorded.keys() - found.keys()):
            problems.append(
                f"{module}: test_counts/{module}{SUFFIX} says {recorded[module]} but "
                "discover found no such module (deleted, or failed to import)"
            )
        for module in sorted(found.keys() & recorded.keys()):
            if found[module] != recorded[module]:
                problems.append(
                    f"{module}: discover found {found[module]} tests, "
                    f"test_counts/{module}{SUFFIX} says {recorded[module]}"
                )
        self.assertEqual(
            problems,
            [],
            "unittest discover under hetzner/provision disagrees with test_counts/. "
            "A count that moved without its file moving with it is either a new test "
            "nobody recorded or an old one that stopped running -- a module that "
            "failed to import, or one deleted from disk, each collapse to a smaller "
            "total with nothing else to say that anything shrank.",
        )

    def test_count_files_are_plain_positive_integers(self):
        for path in sorted(COUNTS.glob("*")):
            with self.subTest(path.name):
                self.assertTrue(path.name.endswith(SUFFIX), path.name)
                self.assertRegex(path.read_text(), r"\A[1-9][0-9]*\n\Z")


if __name__ == "__main__":
    unittest.main()
