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
import re
import sys
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent
CI_WORKFLOW = PROVISION.parent.parent / ".github" / "workflows" / "ci.yml"

# The oldest interpreter this suite runs under: macOS's system python3 is 3.9, and
# the first `python3` on a developer's PATH or a git hook is often that one. Every
# module here must import under it, so `X | None` in an annotation needs
# `from __future__ import annotations`. CI's floor step reads the same number.
MIN_PYTHON = (3, 9)
FLOOR = ".".join(str(part) for part in MIN_PYTHON)
FLOOR_STEP_NAME = "Python version floor"
FLOOR_NAME_LINE = f"- name: {FLOOR_STEP_NAME} (hetzner/provision needs >= {FLOOR})"
FLOOR_RUN_LINE = (
    f"run: python3 scripts/assert-min-python-version.py {FLOOR} --suite hetzner/provision"
)
COUNTS = PROVISION / "test_counts"
SUFFIX = ".txt"


def interpreter_below_floor(actual, floor, executable):
    """A named refusal when `actual` (a version tuple) is below `floor`, else None.

    A pure function, so a test can drive the refusal with a 3.8 value instead of
    needing an interpreter below the floor on the machine.
    """
    if tuple(actual[:2]) >= tuple(floor):
        return None
    floor_str = ".".join(str(part) for part in floor)
    actual_str = ".".join(str(part) for part in actual[:3])
    return (
        f"this suite needs Python {floor_str} or newer; {executable} is "
        f"{actual_str}. Put a newer python3 first on PATH: below the floor "
        "unittest hides modules behind import errors and reports a smaller "
        "suite instead of refusing."
    )


def floor_step_runs(ci_text):
    """The `run:` value of each CI step whose name starts with FLOOR_STEP_NAME.

    Read line by line. A commented-out step (`# - name:`, `# run:`) and a renamed
    step (another `name:`) come back with no run, so they do not match.
    """
    runs = []
    name = None
    for line in ci_text.splitlines():
        if re.match(r"^\s*- ", line):
            name_match = re.match(r"^\s*- name: (.*)$", line)
            name = name_match.group(1).strip() if name_match else None
            continue
        run_match = re.match(r"^\s*run: (.*)$", line)
        if run_match and name is not None:
            if name.startswith(FLOOR_STEP_NAME):
                runs.append(run_match.group(1).strip())
            name = None
    return runs


def floor_step_problem(ci_text, floor):
    """None when the CI floor step's run is exactly the floor command, else a message."""
    floor_str = ".".join(str(part) for part in floor)
    expected = (
        f"python3 scripts/assert-min-python-version.py {floor_str} --suite hetzner/provision"
    )
    runs = floor_step_runs(ci_text)
    if runs == [expected]:
        return None
    return (
        f"CI must have exactly one step named '{FLOOR_STEP_NAME}...' whose run is "
        f"'{expected}'; found {runs!r}"
    )


def _ci_text():
    return CI_WORKFLOW.read_text(encoding="utf-8")


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
        refusal = interpreter_below_floor(sys.version_info[:3], MIN_PYTHON, sys.executable)
        self.assertIsNone(refusal, refusal)

    def test_a_3_8_interpreter_is_refused_by_name(self):
        refusal = interpreter_below_floor((3, 8, 18), (3, 9), "/opt/python3.8")
        self.assertIsNotNone(refusal)
        self.assertIn("3.8.18", refusal)
        self.assertIn("/opt/python3.8", refusal)
        self.assertIn("3.9", refusal)

    def test_a_3_9_interpreter_is_not_refused(self):
        refusal = interpreter_below_floor((3, 9, 6), (3, 9), "/usr/bin/python3")
        self.assertIsNone(refusal, refusal)

    def test_ci_checks_the_same_floor(self):
        problem = floor_step_problem(_ci_text(), MIN_PYTHON)
        self.assertIsNone(problem, problem)

    def _refused_after(self, *edits):
        text = _ci_text()
        for old, new in edits:
            self.assertEqual(text.count(old), 1, f"fixture anchor not found once: {old!r}")
            text = text.replace(old, new)
        self.assertIsNotNone(
            floor_step_problem(text, MIN_PYTHON),
            "the edited CI still passed the floor check",
        )

    def test_ci_fixture_commented_out_step_is_refused(self):
        self._refused_after(
            (FLOOR_NAME_LINE, "# " + FLOOR_NAME_LINE),
            (FLOOR_RUN_LINE, "# " + FLOOR_RUN_LINE),
        )

    def test_ci_fixture_disabled_run_is_refused(self):
        self._refused_after(
            (FLOOR_RUN_LINE, 'run: "true"  # ' + FLOOR_RUN_LINE[len("run: "):]),
        )

    def test_ci_fixture_renamed_step_is_refused(self):
        self._refused_after(
            (FLOOR_NAME_LINE, FLOOR_NAME_LINE.replace(FLOOR_STEP_NAME, "Python tests")),
        )

    def test_ci_fixture_other_version_is_refused(self):
        self._refused_after(
            (FLOOR_RUN_LINE, FLOOR_RUN_LINE.replace(FLOOR, "3.10")),
        )


if __name__ == "__main__":
    unittest.main()
