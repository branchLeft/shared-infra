"""Tests that the Python under ansible/ is checked by the Ansible workflow.

A program a new host runs as root, and the tool that builds its first-boot record, are
code like any other: mypy, ruff and their unit tests must run on them in CI. These tests
read .github/workflows/ansible.yml and fail when a directory of such Python is not named
there, so adding one without wiring it is red rather than silently unchecked.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
WORKFLOW = (ROOT / ".github" / "workflows" / "ansible.yml").read_text(encoding="utf-8")

# The Python directories directly under ansible/ that hold their own tests.
UNITTEST_STEP = re.compile(r"-m unittest discover -b -s ansible/(?P<name>[a-z_]+) -p")
SELECTOR = re.compile(r"grep -qs '(?P<pattern>[^']+)' \"\$role/pyproject.toml\"")


def python_directories() -> set[str]:
    """Return the directories directly under ansible/ with a test_*.py file in them."""
    return {path.parent.name for path in ANSIBLE.glob("*/test_*.py")}


def step_lines(command: str) -> list[str]:
    """Return the workflow's lines that run one tool over the directories named after it."""
    return [line for line in WORKFLOW.splitlines() if command in line]


class WorkflowPythonStepsTest(unittest.TestCase):
    def test_the_scan_finds_the_directories_it_is_meant_to_find(self) -> None:
        # A control: an empty scan would make every other test here pass.
        self.assertLessEqual({"harness", "checks", "tools"}, python_directories())

    def test_each_python_directory_has_a_unittest_step(self) -> None:
        run = {match.group("name") for match in UNITTEST_STEP.finditer(WORKFLOW)}
        self.assertEqual(set(), python_directories() - run)

    def test_each_python_directory_is_type_checked_linted_and_format_checked(self) -> None:
        for command in (
            'ansible-venv/bin/mypy" ',
            'ansible-venv/bin/ruff" check ',
            'ansible-venv/bin/ruff" format --check ',
        ):
            lines = step_lines(command)
            self.assertEqual(1, len(lines), f"{command!r}: {lines}")
            named = set(lines[0].split(command, 1)[1].rstrip("'").split())
            with self.subTest(command=command):
                self.assertEqual(set(), python_directories() - named)

    def test_the_role_program_step_selects_each_role_that_ships_a_program(self) -> None:
        selector = SELECTOR.search(WORKFLOW)
        self.assertIsNotNone(selector, "the role program step has no pyproject.toml selector")
        if selector is None:
            return
        pattern = re.compile(selector.group("pattern"), re.MULTILINE)
        roles = {
            role.name
            for role in (ANSIBLE / "roles").iterdir()
            if (role / "files").is_dir()
            and (role / "tests" / "unit").is_dir()
            and (role / "pyproject.toml").is_file()
            and pattern.search((role / "pyproject.toml").read_text(encoding="utf-8"))
        }
        self.assertLessEqual({"ansible_runtime", "pull_trigger"}, roles)

    def test_the_role_program_step_does_not_select_a_role_with_no_program(self) -> None:
        selector = SELECTOR.search(WORKFLOW)
        if selector is None:
            self.fail("the role program step has no pyproject.toml selector")
        pattern = re.compile(selector.group("pattern"), re.MULTILINE)
        text = (ANSIBLE / "roles" / "egress_nat" / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIsNone(pattern.search(text))


if __name__ == "__main__":
    unittest.main()
