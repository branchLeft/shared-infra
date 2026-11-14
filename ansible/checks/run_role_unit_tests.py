#!/usr/bin/env python3
"""Runs the unit tests of every Ansible role that ships a tests/unit directory.

Usage: run_role_unit_tests.py <ansible-dir>
  PYTHON  the interpreter that runs the tests (the pinned tool venv in CI).

Discovery is a directory listing, so a new role is picked up with no edit here. The run
fails when no role has a tests/unit directory, when a tests/unit is not a directory or holds
no test_*.py, when a suite runs zero tests or its unittest summary is missing or not the one
result line after the last Ran line, when any suite fails, and when a suite skips or
expected-fails a test: a role suite is a control, so a skipped test is a control that does
not run. Each suite runs from its role's directory with files/ and library/ on PYTHONPATH,
because the roles' tests import from both.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

SUMMARY = re.compile(r"Ran ([0-9]+) tests? in [0-9.]+s")
RESULT = re.compile(r"(OK|FAILED)( \(.*\))?")


def discover(ansible_dir: str) -> list[Path]:
    """The tests/unit directory of every role, in name order; a role's dot-directory is skipped."""
    roles = Path(ansible_dir, "roles")
    try:
        names = sorted(entry.name for entry in roles.iterdir())
    except OSError:
        return []
    units: list[Path] = []
    for name in names:
        if name.startswith("."):
            continue
        unit = roles / name / "tests" / "unit"
        if os.path.lexists(unit):
            units.append(unit)
    return units


def run_suites(role: Path, python: str) -> tuple[int, str]:
    """Runs the role's unittest discovery and returns its exit status and its output."""
    env = {**os.environ, "PYTHONPATH": "files:library"}
    command = [python, "-m", "unittest", "discover", "-b", "-s", "tests/unit", "-p", "test_*.py"]
    try:
        done = subprocess.run(  # noqa: S603 - the interpreter named by PYTHON, over the repository's own suites
            command,
            cwd=role,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return 127, f"{python}: command not found"
    return done.returncode, done.stdout.rstrip("\n")


def summarise(name: str, status: int, output: str) -> tuple[bool, str]:
    """Reads the unittest summary; returns whether the role passed, and the line that says why."""
    lines = output.split("\n")
    ran_index = -1
    ran = ""
    for index, line in enumerate(lines):
        match = SUMMARY.fullmatch(line)
        if match is not None:
            ran_index = index
            ran = match.group(1)
    # The summary is the last Ran line, then the one result line after it. Lines before it
    # are test output and are not read as a result.
    after = [line for line in lines[ran_index + 1 :] if line != ""]
    result_line = after[0] if after else ""
    extra_line = after[1] if len(after) > 1 else ""

    if status != 0:
        return False, f"{name}: unit tests failed (exit {status})."
    if ran_index < 0:
        return (
            False,
            f"{name}: no unittest summary (a 'Ran N tests in X.XXXs' line) was printed, "
            "so the run is unknown.",
        )
    if int(ran) == 0:
        return False, f"{name}: the unit suites ran zero tests."
    if RESULT.fullmatch(result_line) is None:
        return (
            False,
            f"{name}: no OK or FAILED result line follows the Ran line, so the outcome is unknown.",
        )
    if "skipped=" in result_line or "expected failures=" in result_line:
        return (
            False,
            f"{name}: unit suites skipped or expected-failed a test, "
            "so it does not count as passed (a control suite may not skip).",
        )
    if result_line.startswith("FAILED"):
        return False, f"{name}: unit suites reported FAILED."
    if extra_line:
        return (
            False,
            f"{name}: output follows the unittest result line, so the summary is not trusted.",
        )
    return True, f"{name}: {ran} unit tests passed."


def run_role(unit: Path, python: str) -> bool:
    """Runs one role's unit suites, prints the verdict, and returns True when the role failed."""
    role = unit.parent.parent
    name = role.name
    print(f"::group::{name} unit tests")
    if not unit.is_dir():
        print(f"{name}: tests/unit is not a directory, so its tests would not run.")
        print("::endgroup::")
        return True
    if not sorted(unit.glob("test_*.py")):
        print(f"{name}: tests/unit holds no test_*.py, so nothing would be tested.")
        print("::endgroup::")
        return True
    status, output = run_suites(role, python)
    print(output)
    passed, message = summarise(name, status, output)
    print(message)
    print("::endgroup::")
    return not passed


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: run_role_unit_tests.py <ansible-dir>", file=sys.stderr)
        return 2
    ansible_dir = argv[0]
    python = os.environ.get("PYTHON", "")
    if not python:
        print(
            "run_role_unit_tests.py: PYTHON: PYTHON must name the interpreter that runs the tests",
            file=sys.stderr,
        )
        return 1

    started = time.monotonic()
    units = discover(ansible_dir)
    if not units:
        print(
            f"No role under {ansible_dir}/roles has a tests/unit directory, "
            "so no role unit test would run."
        )
        return 1

    failed = 0
    for unit in units:
        if run_role(unit, python):
            failed += 1
    if failed:
        print(f"{failed} role unit suite(s) failed or did not run.")
        return 1
    print(f"Ran the unit tests of {len(units)} role(s) in {int(time.monotonic() - started)}s.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
