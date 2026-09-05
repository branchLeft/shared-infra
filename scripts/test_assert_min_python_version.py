#!/usr/bin/env python3
"""Unit tests for assert-min-python-version.

The claim this script makes is "this interpreter is new enough to import
every module in the suite". A false PASS here (the guard reporting healthy
when it should have failed, or vice versa) is worse than the defect it
guards against, because it looks like proof of a check that never actually
ran -- so most of what follows exercises `check()` and `parse_min_version()`
directly, plus a handful of subprocess-level tests that prove the CLI wiring
(exit codes, argument handling) matches the pure-function behaviour.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "assert-min-python-version.py"
    spec = importlib.util.spec_from_file_location("assert_min_python_version", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load_module()

SCRIPT_PATH = pathlib.Path(__file__).resolve().parent / "assert-min-python-version.py"


class ParseMinVersionTests(unittest.TestCase):
    def test_parses_major_minor(self):
        self.assertEqual(guard.parse_min_version("3.10"), (3, 10))
        self.assertEqual(guard.parse_min_version("3.9"), (3, 9))

    def test_rejects_missing_minor(self):
        with self.assertRaises(ValueError):
            guard.parse_min_version("3")

    def test_rejects_patch_component(self):
        # A three-part version is refused rather than silently truncated --
        # silently accepting it would let a caller believe patch-level
        # granularity is honoured when nothing here compares below minor.
        with self.assertRaises(ValueError):
            guard.parse_min_version("3.10.1")

    def test_rejects_non_numeric(self):
        with self.assertRaises(ValueError):
            guard.parse_min_version("x.y")

    def test_rejects_empty_string(self):
        with self.assertRaises(ValueError):
            guard.parse_min_version("")


class CheckTests(unittest.TestCase):
    def test_at_floor_passes(self):
        self.assertIsNone(guard.check((3, 10), (3, 10, 0), None, "/usr/bin/python3"))

    def test_above_floor_passes(self):
        self.assertIsNone(
            guard.check((3, 10), (3, 14, 6), "hetzner/provision", "/opt/homebrew/bin/python3")
        )

    def test_below_floor_fails(self):
        message = guard.check((3, 10), (3, 9, 6), "hetzner/provision", "/usr/bin/python3")
        self.assertIsNotNone(message)

    def test_failure_message_names_actual_version(self):
        message = guard.check((3, 10), (3, 9, 6), "hetzner/provision", "/usr/bin/python3")
        self.assertIn("3.9.6", message)

    def test_failure_message_names_required_floor(self):
        message = guard.check((3, 10), (3, 9, 6), "hetzner/provision", "/usr/bin/python3")
        self.assertIn("3.10", message)

    def test_failure_message_names_the_suite(self):
        message = guard.check((3, 10), (3, 9, 6), "hetzner/provision", "/usr/bin/python3")
        self.assertIn("hetzner/provision", message)

    def test_failure_message_names_the_executable(self):
        # The executable path is what tells a reader *which* python3 ran --
        # PATH resolves differently per shell, so naming only "3.9.6" would
        # leave them guessing which of several installed interpreters it was.
        message = guard.check((3, 10), (3, 9, 6), "hetzner/provision", "/usr/bin/python3")
        self.assertIn("/usr/bin/python3", message)

    def test_failure_message_without_suite_label_is_still_usable(self):
        message = guard.check((3, 10), (3, 9, 6), None, "/usr/bin/python3")
        self.assertIsNotNone(message)
        first_line = message.split("\n", 1)[0]
        self.assertNotIn(" for ", first_line)

    def test_minor_version_boundary_is_inclusive(self):
        # (3, 10) vs a floor of (3, 10) must pass: "at least" means the
        # floor itself is healthy, not the first version strictly above it.
        self.assertIsNone(guard.check((3, 10), (3, 10, 9), None, "/usr/bin/python3"))

    def test_one_minor_below_floor_fails(self):
        self.assertIsNotNone(guard.check((3, 10), (3, 9, 99), None, "/usr/bin/python3"))


class SelfTestTests(unittest.TestCase):
    def test_self_test_passes_and_prints_ok(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            guard._self_test()
        self.assertIn("OK", buffer.getvalue())


class CliTests(unittest.TestCase):
    """Subprocess-level tests: these prove the argv/exit-code wiring, not
    just the pure functions above -- a guard whose CLI silently swallows a
    nonzero `check()` result would defeat the whole point."""

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_self_test_flag_exits_zero(self):
        result = self._run("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_floor_the_running_interpreter_already_satisfies_exits_zero(self):
        # sys.version_info of *this* interpreter, expressed as a floor one
        # minor below itself, must always be satisfied -- this is the
        # healthy-case control: a real green run, not an assumption of one.
        major, minor = sys.version_info[:2]
        floor = f"{major}.{max(minor - 1, 0)}"
        result = self._run(floor)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_floor_above_the_running_interpreter_exits_nonzero(self):
        # No real interpreter satisfies Python 99.0 -- this is the guard's
        # own control case for the unhealthy path, independent of whatever
        # interpreter happens to run this test file.
        result = self._run("99.0")
        self.assertEqual(result.returncode, 1)
        self.assertIn("interpreter too old", result.stderr)

    def test_suite_label_appears_in_cli_output(self):
        result = self._run("99.0", "--suite", "hetzner/provision")
        self.assertEqual(result.returncode, 1)
        self.assertIn("hetzner/provision", result.stderr)

    def test_missing_min_version_without_self_test_is_a_usage_error(self):
        result = self._run()
        self.assertNotEqual(result.returncode, 0)

    def test_malformed_min_version_is_a_usage_error(self):
        result = self._run("not-a-version")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
