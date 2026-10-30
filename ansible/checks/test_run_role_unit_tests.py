"""Tests for ansible/checks/run_role_unit_tests.sh, the one home for running role unit tests.

Each case builds a scratch ansible/ tree in a temporary directory and runs the script over
it with the interpreter that runs this suite. The workflow tests pin that the lint job calls
the script once, and that no second copy of the unittest command for tests/unit is left in
the workflow.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible" / "checks" / "run_role_unit_tests.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"

PASSING = (
    "import unittest\n\n\n"
    "class Passing(unittest.TestCase):\n"
    "    def test_passes(self) -> None:\n"
    "        self.assertTrue(True)\n"
)
FAILING = (
    "import unittest\n\n\n"
    "class Failing(unittest.TestCase):\n"
    "    def test_broken_assertion(self) -> None:\n"
    "        self.assertEqual(1, 2)\n"
)
NO_TESTS = "import unittest\n"
LIBRARY_PASSING = (
    "import unittest\n\n"
    "from helper import NAME\n"
    "from mod import VALUE\n\n\n"
    "class Library(unittest.TestCase):\n"
    "    def test_imports_library_and_files(self) -> None:\n"
    "        self.assertEqual(2, VALUE)\n"
    '        self.assertEqual("helper", NAME)\n'
)
LIBRARY_FAILING = (
    "import unittest\n\n"
    "from mod import VALUE\n\n\n"
    "class Library(unittest.TestCase):\n"
    "    def test_library_value(self) -> None:\n"
    "        self.assertEqual(3, VALUE)\n"
)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def role_with_test(ansible: Path, name: str, text: str) -> Path:
    role = ansible / "roles" / name
    write(role / "tests" / "unit" / "test_role.py", text)
    return role


def run_script(ansible: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHON": sys.executable}
    return subprocess.run(  # noqa: S603 - the fixed script in this repository, run with this suite's interpreter
        [str(SCRIPT), str(ansible)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class RoleUnitTestScript(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible = Path(self.tmp.name) / "ansible"
        (self.ansible / "roles").mkdir(parents=True)

    def assert_red(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)

    def test_empty_discovery_fails(self) -> None:
        result = run_script(self.ansible)
        self.assert_red(result)
        self.assertIn("has a tests/unit directory", result.stdout)

    def test_a_tree_with_no_roles_directory_fails(self) -> None:
        bare = Path(self.tmp.name) / "bare"
        bare.mkdir()
        self.assert_red(run_script(bare))

    def test_a_zero_test_directory_fails(self) -> None:
        (self.ansible / "roles" / "empty" / "tests" / "unit").mkdir(parents=True)
        result = run_script(self.ansible)
        self.assert_red(result)
        self.assertIn("holds no test_*.py", result.stdout)

    def test_a_tests_unit_that_is_a_file_fails(self) -> None:
        write(self.ansible / "roles" / "filey" / "tests" / "unit", "not a directory\n")
        result = run_script(self.ansible)
        self.assert_red(result)
        self.assertIn("is not a directory", result.stdout)

    def test_a_suite_that_runs_no_test_fails(self) -> None:
        role_with_test(self.ansible, "hollow", NO_TESTS)
        result = run_script(self.ansible)
        self.assert_red(result)
        self.assertIn("hollow:", result.stdout)

    def test_a_new_role_is_run_with_no_edit_to_the_script(self) -> None:
        role_with_test(self.ansible, "alpha", PASSING)
        role_with_test(self.ansible, "beta", PASSING)
        result = run_script(self.ansible)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("alpha: 1 unit tests passed", result.stdout)
        self.assertIn("beta: 1 unit tests passed", result.stdout)
        self.assertIn("Ran the unit tests of 2 role(s)", result.stdout)

    def test_a_failing_test_fails_the_gate_and_is_named(self) -> None:
        role_with_test(self.ansible, "alpha", PASSING)
        role_with_test(self.ansible, "gamma", FAILING)
        result = run_script(self.ansible)
        self.assert_red(result)
        self.assertIn("test_broken_assertion", result.stdout)
        self.assertIn("gamma: unit tests failed", result.stdout)

    def test_a_role_library_and_its_files_are_on_the_path(self) -> None:
        role = role_with_test(self.ansible, "typed", LIBRARY_PASSING)
        write(role / "library" / "mod.py", "VALUE = 2\n")
        write(role / "files" / "helper.py", 'NAME = "helper"\n')
        result = run_script(self.ansible)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_a_failing_test_in_a_role_with_a_library_fails(self) -> None:
        role = role_with_test(self.ansible, "typed", LIBRARY_FAILING)
        write(role / "library" / "mod.py", "VALUE = 2\n")
        result = run_script(self.ansible)
        self.assert_red(result)
        self.assertIn("test_library_value", result.stdout)

    def test_an_unset_python_aborts_and_names_the_variable(self) -> None:
        role_with_test(self.ansible, "alpha", PASSING)
        env = {key: value for key, value in os.environ.items() if key != "PYTHON"}
        result = subprocess.run(  # noqa: S603 - the fixed script in this repository
            [str(SCRIPT), str(self.ansible)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PYTHON must name the interpreter", result.stderr)

    def test_a_wrong_argument_count_exits_2_with_usage(self) -> None:
        result = subprocess.run(  # noqa: S603 - the fixed script in this repository
            [str(SCRIPT)],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHON": sys.executable},
            check=False,
        )
        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("usage: run_role_unit_tests.sh", result.stderr)


class WorkflowCallsTheScript(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.lint = self.text.split("\n  lint:\n", 1)[1].split("\n  shard:\n", 1)[0]

    def test_the_lint_job_calls_the_script_once(self) -> None:
        self.assertEqual(1, self.lint.count("ansible/checks/run_role_unit_tests.sh"))
        self.assertEqual(1, self.text.count("ansible/checks/run_role_unit_tests.sh"))

    def test_no_second_unittest_run_reaches_the_role_tests(self) -> None:
        lines = self.text.splitlines()
        offending = [line for line in lines if "unittest" in line and "tests/unit" in line]
        self.assertEqual([], offending)


if __name__ == "__main__":
    unittest.main()
