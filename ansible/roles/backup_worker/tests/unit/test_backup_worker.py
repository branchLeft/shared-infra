"""Order and one-home unit tests for the backup_worker environment-file tasks.

The README in the role holds the narrative and the hand-run command.
"""

import sys
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests" / "support"))

from role_tasks import task_lines  # noqa: E402

CREATE_ENV = "Create the environment file empty, closed to everyone but root"
ATTRIBUTES = "Set the owner, group and mode of the environment file on every run"
FILL_ENV = "Write the environment file"
SECRET_TASKS = (CREATE_ENV, ATTRIBUTES, FILL_ENV)

# Each secret task names the value it takes from: the create-empty and write tasks
# read the lookup, the attribute task loops over the list the lookup finds it in.
EXPECTED_REFERENCE = {
    CREATE_ENV: "backup_worker_env_secret",
    ATTRIBUTES: "item.item",
    FILL_ENV: "backup_worker_env_secret",
}


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

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
        bodies = {name: body for name, body in task_lines(TASKS)}
        for name in SECRET_TASKS:
            lines = [line.strip() for line in bodies.get(name, [])]
            reference = EXPECTED_REFERENCE[name]
            for attribute in ("owner", "group", "mode"):
                expected = f"{attribute}: '{{{{ {reference}.{attribute} }}}}'"
                self.assertEqual(
                    lines.count(expected),
                    1,
                    f"{name!r} must set {attribute} as exactly {expected!r}, once",
                )


if __name__ == "__main__":
    unittest.main()
