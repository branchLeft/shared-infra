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
import sys
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent
CI_WORKFLOW = PROVISION.parent.parent / ".github" / "workflows" / "ci.yml"

# The oldest interpreter this suite runs under: macOS's system python3 is 3.9, and
# the first `python3` on a developer's PATH or a git hook is often that one. Every
# module here must import under it, so `X | None` in an annotation needs
# `from __future__ import annotations`. CI's floor step reads the same number.
MIN_PYTHON = (3, 9)
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

    def test_the_interpreter_meets_the_recorded_floor(self):
        # Below the floor a module that cannot import is one placeholder test and
        # the run reports a smaller count. This turns that into a named refusal.
        self.assertGreaterEqual(
            sys.version_info[:2],
            MIN_PYTHON,
            f"this suite needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer; "
            f"{sys.executable} is {sys.version.split()[0]}. Put a newer python3 first "
            "on PATH: below the floor unittest hides modules behind import errors "
            "and reports a smaller suite instead of refusing.",
        )

    def test_ci_checks_the_same_floor(self):
        floor = ".".join(str(part) for part in MIN_PYTHON)
        self.assertIn(
            f"assert-min-python-version.py {floor} --suite hetzner/provision",
            CI_WORKFLOW.read_text(encoding="utf-8"),
            "the CI floor step and MIN_PYTHON must name the same version",
        )


if __name__ == "__main__":
    unittest.main()
