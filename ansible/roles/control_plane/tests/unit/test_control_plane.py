"""Unit tests for the order of the control_plane role's secret tasks.

The role writes each secret in two steps. Each file is created empty at its final
owner and mode, then the owner, group and mode of both files are set on every run,
and only then is each file's content written into the file. A fill writes through
the existing file, which keeps the owner and mode it has, so an attribute task that
runs after a fill leaves the content in a file that is still wide. These tests read
tasks/main.yml as text and fail when one of the five tasks is missing, or when the
attribute task is not between the two create-empty tasks and the two fills.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"

CREATE_ENV = "Create the environment file empty, if it is absent"
CREATE_KEY = "Create the master key empty, if it is absent"
ATTRIBUTES = "Set the owner, group and mode of each secret file on every run"
FILL_ENV = "Write the environment file's content while the file is empty"
FILL_KEY = "Write the master key's content while the file is empty"


def _task_names() -> list[str]:
    """Return the name of every task in tasks/main.yml, in file order, read as text."""
    names: list[str] = []
    for line in TASKS.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^- name: (.+)$", line)
        if match:
            names.append(match.group(1).strip())
    return names


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = _task_names()

    def _position(self, name: str) -> int:
        self.assertEqual(self.names.count(name), 1, f"{name!r} must appear exactly once in tasks/main.yml")
        return self.names.index(name)

    def test_the_five_secret_tasks_are_all_present(self) -> None:
        for name in (CREATE_ENV, CREATE_KEY, ATTRIBUTES, FILL_ENV, FILL_KEY):
            self.assertIn(name, self.names)

    def test_both_create_empty_tasks_come_before_the_attribute_task(self) -> None:
        attributes = self._position(ATTRIBUTES)
        self.assertLess(self._position(CREATE_ENV), attributes, "the environment file is created after its attributes are set")
        self.assertLess(self._position(CREATE_KEY), attributes, "the master key is created after its attributes are set")

    def test_the_attribute_task_comes_before_both_fills(self) -> None:
        attributes = self._position(ATTRIBUTES)
        self.assertLess(attributes, self._position(FILL_ENV), "the environment file is filled before its attributes are set")
        self.assertLess(attributes, self._position(FILL_KEY), "the master key is filled before its attributes are set")


if __name__ == "__main__":
    unittest.main()
