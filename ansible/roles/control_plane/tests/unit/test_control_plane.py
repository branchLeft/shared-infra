"""Order tests for the control_plane secret tasks: attributes are set before each fill."""

import sys
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests" / "support"))

from role_tasks import task_lines  # noqa: E402

CREATE_ENV = "Create the environment file empty, if it is absent"
CREATE_KEY = "Create the master key empty, if it is absent"
ATTRIBUTES = "Set the owner, group and mode of each secret file on every run"
FILL_ENV = "Write the environment file's content while the file is empty"
FILL_KEY = "Write the master key's content while the file is empty"


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

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
