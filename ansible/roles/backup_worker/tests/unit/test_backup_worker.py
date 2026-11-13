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


CREATE_TENANTS = "Create the tenants file empty, closed to everyone but root and the service account"
CREATE_RECIPIENTS = "Create the recipients file empty, closed to everyone but root and the service account"
PRIVATE_ATTRIBUTES = "Set the owner, group and mode of the tenants and recipients files on every run"
FILL_TENANTS = "Write the tenants file"
FILL_RECIPIENTS = "Write the recipients file"
PRIVATE_TASKS = (CREATE_TENANTS, CREATE_RECIPIENTS, PRIVATE_ATTRIBUTES, FILL_TENANTS, FILL_RECIPIENTS)

# The tenants and recipients tasks name the lookup that finds their entry in
# backup_worker_private_files, the one home of their owner, group and mode.
PRIVATE_REFERENCE = {
    CREATE_TENANTS: "backup_worker_tenants_private",
    CREATE_RECIPIENTS: "backup_worker_recipients_private",
    PRIVATE_ATTRIBUTES: "item.item",
    FILL_TENANTS: "backup_worker_tenants_private",
    FILL_RECIPIENTS: "backup_worker_recipients_private",
}


class PrivateFileOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

    def _position(self, name: str) -> int:
        self.assertEqual(self.names.count(name), 1, f"{name!r} must appear exactly once in tasks/main.yml")
        return self.names.index(name)

    def test_the_five_tenants_and_recipients_tasks_are_all_present(self) -> None:
        for name in PRIVATE_TASKS:
            self.assertIn(name, self.names)

    def test_both_files_are_created_before_the_attribute_task(self) -> None:
        for name in (CREATE_TENANTS, CREATE_RECIPIENTS):
            self.assertLess(
                self._position(name),
                self._position(PRIVATE_ATTRIBUTES),
                f"{name!r} comes after the attributes are set",
            )

    def test_the_attribute_task_comes_before_both_writes(self) -> None:
        for name in (FILL_TENANTS, FILL_RECIPIENTS):
            self.assertLess(
                self._position(PRIVATE_ATTRIBUTES),
                self._position(name),
                f"{name!r} writes the file before its attributes are set",
            )


class PrivateFileOneHomeTests(unittest.TestCase):
    def test_the_private_tasks_take_owner_group_and_mode_from_their_lookup(self) -> None:
        bodies = {name: body for name, body in task_lines(TASKS)}
        for name in PRIVATE_TASKS:
            lines = [line.strip() for line in bodies.get(name, [])]
            reference = PRIVATE_REFERENCE[name]
            for attribute in ("owner", "group", "mode"):
                expected = f"{attribute}: '{{{{ {reference}.{attribute} }}}}'"
                self.assertEqual(
                    lines.count(expected),
                    1,
                    f"{name!r} must set {attribute} as exactly {expected!r}, once",
                )


if __name__ == "__main__":
    unittest.main()
