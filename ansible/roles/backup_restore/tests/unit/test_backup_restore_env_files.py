"""Order and one-home unit tests for the backup_restore environment-file tasks.

Each of the two environment files is written in four steps: created empty, looked
at, given its owner, group and mode, and only then written. The README in the role
holds the narrative and the hand-run command.
"""

import sys
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests" / "support"))

from role_tasks import all_task_lines  # noqa: E402

# Per file: the lookup its tasks read, and its four task names, in the order they must run.
FILES = {
    "state-copy": (
        "backup_restore_state_copy_env_secret",
        (
            "Create the state-copy environment file empty, closed to everyone but root",
            "Look at the state-copy environment file before its owner, group and mode are set",
            "Set the owner, group and mode of the state-copy environment file on every run",
            "Write the state-copy environment file",
        ),
    ),
    "restore-drill": (
        "backup_restore_drill_env_secret",
        (
            "Create the restore-drill environment file empty, closed to everyone but root",
            "Look at the restore-drill environment file before its owner, group and mode are set",
            "Set the owner, group and mode of the restore-drill environment file on every run",
            "Write the restore-drill environment file",
        ),
    ),
}


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in all_task_lines(TASKS)]

    def _position(self, name: str) -> int:
        self.assertEqual(self.names.count(name), 1, f"{name!r} must appear exactly once in tasks/main.yml")
        return self.names.index(name)

    def test_each_file_has_all_four_tasks_in_order(self) -> None:
        for label, (_, names) in FILES.items():
            positions = [self._position(name) for name in names]
            self.assertEqual(
                positions,
                sorted(positions),
                f"the {label} environment file's tasks are not create, look, set attributes, write",
            )


class OneHomeTests(unittest.TestCase):
    def test_the_create_attribute_and_write_tasks_take_their_values_from_the_lookup(self) -> None:
        bodies = {name: body for name, body in all_task_lines(TASKS)}
        for label, (reference, names) in FILES.items():
            create, _, attributes, write = names
            for name in (create, attributes, write):
                lines = [line.strip() for line in bodies.get(name, [])]
                for attribute in ("owner", "group", "mode"):
                    expected = f"{attribute}: '{{{{ {reference}.{attribute} }}}}'"
                    self.assertEqual(
                        lines.count(expected),
                        1,
                        f"{label}: {name!r} must set {attribute} as exactly {expected!r}, once",
                    )


if __name__ == "__main__":
    unittest.main()
