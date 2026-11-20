"""Run the unit tests of ansible/checks in one of two parts, so two CI legs can share them.

The tests of the checks took 7 to 12 minutes in one step, the longest leg of the full lint.
`main` runs every test module except the ones named in SLOW_MODULES; `slow` runs only those.
Both parts together are every `test_*.py` in this directory, exactly once: a new module needs
no entry here and runs in `main`. The parts are chosen by file, and each file is loaded by its
own `discover` call, so a module that fails to import is reported as a failed test in the part
it belongs to, never dropped.

Usage (from the repository root, with the tool environment's interpreter):

    python ansible/checks/run_check_tests.py main|slow
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

CHECKS = Path(__file__).resolve().parent

# The modules whose tests are the slowest, measured from the "Slowest test durations" the full
# lint prints and from timing each module alone. Moving a module between the parts changes
# only which leg runs it; test_run_check_tests.py holds that nothing is left out.
SLOW_MODULES: tuple[str, ...] = ("test_check_secret_no_log",)

PARTS = ("main", "slow")


def all_modules(directory: Path = CHECKS) -> list[str]:
    """Every test module file name in `directory`, sorted."""
    return sorted(path.name for path in directory.glob("test_*.py"))


def modules_of(part: str, directory: Path = CHECKS) -> list[str]:
    """The test module file names that `part` runs.

    Raises:
        ValueError: `part` is not one of PARTS.
    """
    if part not in PARTS:
        message = f"part must be one of {PARTS}, not {part!r}"
        raise ValueError(message)
    slow = {f"{name}.py" for name in SLOW_MODULES}
    return [name for name in all_modules(directory) if (name in slow) == (part == "slow")]


def build_suite(part: str, directory: Path = CHECKS) -> unittest.TestSuite:
    """The tests of `part`: one `discover` per module file, as `discover -p <file>` does."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in modules_of(part, directory):
        suite.addTests(loader.discover(str(directory), pattern=name))
    return suite


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in PARTS:
        print(f"usage: run_check_tests.py {'|'.join(PARTS)}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(CHECKS))
    suite = build_suite(argv[0], CHECKS)
    if suite.countTestCases() == 0:
        print(f"the {argv[0]} part holds no tests, so nothing was checked", file=sys.stderr)
        return 1
    runner = unittest.TextTestRunner(buffer=True, durations=10, verbosity=1)
    return 0 if runner.run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
