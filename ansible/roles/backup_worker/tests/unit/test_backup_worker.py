"""Task-order and one-home unit tests for the backup_worker environment-file tasks.

The narrative and the hand-run command are in the role README.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"

CREATE_ENV = "Create the environment file empty, closed to everyone but root"
ATTRIBUTES = "Set the owner, group and mode of the environment file on every run"
FILL_ENV = "Write the environment file"
SECRET_TASKS = (CREATE_ENV, ATTRIBUTES, FILL_ENV)

TASK_LINE = re.compile(r"^- name: (.+)$")
LITERAL_ATTRIBUTE = re.compile(r"^\s+(owner|group|mode):\s*['\"]?(root|0[0-7]{3})['\"]?\s*$")


def _task_lines() -> list[tuple[str, list[str]]]:
    """Return (name, body lines) for every task in tasks/main.yml, in file order, as text."""
    tasks: list[tuple[str, list[str]]] = []
    for line in TASKS.read_text(encoding="utf-8").splitlines():
        match = TASK_LINE.match(line)
        if match:
            tasks.append((match.group(1).strip(), []))
        elif tasks:
            tasks[-1][1].append(line)
    return tasks


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in _task_lines()]

    def _position(self, name: str) -> int:
        self.assertEqual(self.names.count(name), 1, f"{name!r} must appear exactly once in tasks/main.yml")
        return self.names.index(name)

    def test_the_three_environment_file_tasks_are_all_present(self) -> None:
        for name in SECRET_TASKS:
            self.assertIn(name, self.names)

    def test_the_create_empty_task_comes_before_the_attribute_task(self) -> None:
        self.assertLess(
            self._position(CREATE_ENV),
            self._position(ATTRIBUTES),
            "the environment file is created after its attributes are set",
        )

    def test_the_attribute_task_comes_before_the_write(self) -> None:
        self.assertLess(
            self._position(ATTRIBUTES),
            self._position(FILL_ENV),
            "the environment file is written before its attributes are set",
        )


class OneHomeTests(unittest.TestCase):
    def test_the_secret_tasks_take_owner_group_and_mode_from_the_lookup(self) -> None:
        for name, body in _task_lines():
            if name not in SECRET_TASKS:
                continue
            for line in body:
                self.assertIsNone(
                    LITERAL_ATTRIBUTE.match(line),
                    f"{name!r} carries a literal owner, group or mode ({line.strip()!r}); "
                    "it must read backup_worker_env_secret",
                )


if __name__ == "__main__":
    unittest.main()
