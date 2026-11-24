"""Run the unit tests of ansible/checks in one of two parts, on every core of the runner.

The tests of the checks took 7 to 12 minutes in one step, the longest leg of the full lint, and
they ran one after the other in one process: a hosted runner has four cores and three of them
sat idle. `main` runs every test module except the ones named in SLOW_MODULES; `slow` runs only
those. Both parts together are every `test_*.py` in this directory, exactly once: a new module
needs no entry here and runs in `main`. The parts are chosen by file, and each file is loaded by
its own `discover` call, so a module that fails to import is reported as a failed test in the
part it belongs to, never dropped.

Within a part the tests are split into slices (at most SLICE_SIZE tests of one module each) and
the slices run side by side, one `python run_check_tests.py --worker` process per core at a time.
A slice is run by unittest exactly as a serial run would run its tests. The run fails closed:
a slice whose process exits non-zero, writes no result, or ran a different number of tests than
it was given fails the run, and so does a total that differs from the number of tests collected.

Usage (from the repository root, with the tool environment's interpreter):

    python ansible/checks/run_check_tests.py main|slow

    CHECK_TESTS_JOBS=1 python ansible/checks/run_check_tests.py main   # serial, in this process
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

CHECKS = Path(__file__).resolve().parent

# The modules whose tests are the slowest, measured from the "Slowest test durations" the full
# lint prints and from timing each module alone. Moving a module between the parts changes
# only which leg runs it; test_run_check_tests.py holds that nothing is left out.
SLOW_MODULES: tuple[str, ...] = ("test_check_secret_no_log",)

PARTS = ("main", "slow")

# The most tests of one module that one worker process runs. A module with more is cut into
# slices so that its tests spread over the cores; the cut costs one more import of the module
# per slice and nothing else.
SLICE_SIZE = 8

# The slowest tests printed after a run.
DURATIONS = 10

JOBS_VARIABLE = "CHECK_TESTS_JOBS"


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


def flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    """Every test case in `suite`, in the order a serial run would run them."""
    cases: list[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            cases.extend(flatten(item))
        else:
            cases.append(item)
    return cases


def is_load_failure(case: unittest.TestCase) -> bool:
    """Whether `case` is the stand-in unittest makes for a module that failed to import."""
    return type(case).__name__ == "_FailedTest"


def slices(test_ids: Iterable[str], size: int = SLICE_SIZE) -> list[list[str]]:
    """The test ids cut into slices of one module and at most `size` tests, largest first.

    Every id is in exactly one slice. The largest slices come first so that the long ones start
    early and the short ones fill the gaps at the end.
    """
    by_module: dict[str, list[str]] = {}
    for test_id in test_ids:
        by_module.setdefault(test_id.split(".", 1)[0], []).append(test_id)
    cut: list[list[str]] = []
    for ids in by_module.values():
        count = -(-len(ids) // size)
        width = -(-len(ids) // count)
        cut.extend(ids[start : start + width] for start in range(0, len(ids), width))
    return sorted(cut, key=len, reverse=True)


def jobs_from(environment: dict[str, str]) -> int:
    """The number of worker processes: CHECK_TESTS_JOBS, else one per core."""
    raw = environment.get(JOBS_VARIABLE, "")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            return 1
    return max(1, min(3, os.cpu_count() or 1))  # EXPERIMENT: 3 workers


@dataclass
class SliceResult:
    """What one worker process reported."""

    ran: int
    failed: bool
    durations: list[tuple[float, str]]
    output: str


def run_worker(directory: Path, ids_file: Path, result_file: Path) -> int:
    """Run the tests named in `ids_file` and write the outcome to `result_file`."""
    sys.path.insert(0, str(directory))
    ids = json.loads(ids_file.read_text(encoding="utf-8"))
    suite = unittest.TestLoader().loadTestsFromNames(ids)
    runner = unittest.TextTestRunner(buffer=True, durations=10, verbosity=1)
    result = runner.run(suite)
    durations = [[float(seconds), str(name)] for name, seconds in result.collectedDurations]
    outcome = {"ran": result.testsRun, "ok": result.wasSuccessful(), "durations": durations}
    result_file.write_text(json.dumps(outcome), encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


def run_slice(directory: Path, ids: list[str], scratch: Path, number: int) -> SliceResult:
    """Run one slice in its own process and read back what it reported."""
    ids_file = scratch / f"{number}.ids.json"
    result_file = scratch / f"{number}.result.json"
    ids_file.write_text(json.dumps(ids), encoding="utf-8")
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        str(directory),
        str(ids_file),
        str(result_file),
    ]
    done = subprocess.run(  # noqa: S603 - this interpreter, over this repository's own tests
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output = done.stdout.rstrip("\n")
    try:
        outcome = json.loads(result_file.read_text(encoding="utf-8"))
        ran = int(outcome["ran"])
        ok = bool(outcome["ok"])
        durations = [(float(seconds), str(name)) for seconds, name in outcome["durations"]]
    except (OSError, ValueError, KeyError, TypeError):
        return SliceResult(
            0, True, [], f"{output}\nthe worker wrote no result (exit {done.returncode})."
        )
    failed = done.returncode != 0 or not ok or ran != len(ids)
    if ran != len(ids):
        output += f"\nthe worker ran {ran} of its {len(ids)} tests."
    return SliceResult(ran, failed, durations, output)


def run_parallel(directory: Path, test_ids: list[str], jobs: int) -> tuple[int, bool, list[str]]:
    """Run `test_ids` over `jobs` processes; returns the tests run, whether any slice failed,
    and the printed output of the failed slices."""
    cut = slices(test_ids)
    slowest: list[tuple[float, str]] = []
    ran = 0
    failed = False
    report: list[str] = []
    with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(max_workers=jobs) as pool:
        scratch = Path(tmp)
        futures = [
            pool.submit(run_slice, directory, ids, scratch, number)
            for number, ids in enumerate(cut)
        ]
        for future in futures:
            result = future.result()
            ran += result.ran
            slowest.extend(result.durations)
            if result.failed:
                failed = True
                report.append(result.output)
    print("Slowest test durations")
    print("-" * 70)
    for seconds, name in sorted(slowest, reverse=True)[:DURATIONS]:
        print(f"{seconds:.3f}s    {name}")
    return ran, failed, report


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[0] == "--worker":
        return run_worker(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    if len(argv) != 1 or argv[0] not in PARTS:
        print(f"usage: run_check_tests.py {'|'.join(PARTS)}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(CHECKS))
    suite = build_suite(argv[0], CHECKS)
    if suite.countTestCases() == 0:
        print(f"the {argv[0]} part holds no tests, so nothing was checked", file=sys.stderr)
        return 1
    jobs = jobs_from(dict(os.environ))
    if jobs == 1:
        runner = unittest.TextTestRunner(buffer=True, durations=10, verbosity=1)
        return 0 if runner.run(suite).wasSuccessful() else 1

    started = time.monotonic()
    cases = flatten(suite)
    broken = unittest.TestSuite(case for case in cases if is_load_failure(case))
    test_ids = [case.id() for case in cases if not is_load_failure(case)]
    expected = len(cases)
    if expected != suite.countTestCases():
        print("the tests collected do not add up, so nothing was checked", file=sys.stderr)
        return 1
    # A module that failed to import is one failed test of its own. It is reported here, in
    # this process, and never handed to a worker that could not load it either.
    failed = False
    ran = 0
    if broken.countTestCases():
        result = unittest.TextTestRunner(buffer=True, verbosity=1).run(broken)
        ran += result.testsRun
        failed = failed or not result.wasSuccessful()
    more, worker_failed, report = run_parallel(CHECKS, test_ids, jobs)
    ran += more
    failed = failed or worker_failed
    for output in report:
        print(output)
    print("-" * 70)
    print(f"Ran {ran} tests in {time.monotonic() - started:.3f}s over {jobs} processes")
    if ran != expected:
        print(f"FAILED: {expected} tests were collected and {ran} ran.")
        return 1
    print("FAILED" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
