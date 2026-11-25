"""Static checks of the task that writes the portal's support mail password file.

The password comes from the host's inputs through control_plane_portal_support_smtp_password.
The write must take its content from that variable, hide its output with no_log, and leave the
file readable only by root and the portal's group, so the portal can read it and nothing else can.
These tests read tasks/main.yml and fail when any of those is lost.
"""

import unittest
from collections.abc import Mapping
from pathlib import Path

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"

WRITE_NAME = "Write the portal's support mail password from the host's inputs"
VARIABLE = "control_plane_portal_support_smtp_password"


def _tasks() -> list[dict[str, object]]:
    """Return every task of tasks/main.yml, nested blocks included, in file order.

    Raises:
        TypeError: the file is not a list of tasks.
    """
    loaded: object = YAML(typ="safe").load(TASKS.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        message = "tasks/main.yml is not a list of tasks"
        raise TypeError(message)
    flat: list[dict[str, object]] = []
    stack: list[object] = list(loaded)
    while stack:
        item = stack.pop(0)
        if not isinstance(item, dict):
            continue
        flat.append(item)
        for key in ("block", "rescue", "always"):
            nested = item.get(key)
            if isinstance(nested, list):
                stack[0:0] = nested
    return flat


def _write_task() -> Mapping[str, object]:
    """Return the one task that writes the support password file.

    Raises:
        LookupError: no task has that name, or more than one does.
    """
    found = [task for task in _tasks() if task.get("name") == WRITE_NAME]
    if len(found) != 1:
        message = f"expected one task named {WRITE_NAME!r}, found {len(found)}"
        raise LookupError(message)
    return found[0]


class PortalSupportPasswordWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = _write_task()
        copy = self.task.get("ansible.builtin.copy")
        if not isinstance(copy, Mapping):
            self.fail("the write task does not use ansible.builtin.copy")
        self.copy: Mapping[str, object] = copy

    def test_the_content_is_taken_from_the_host_input_variable(self) -> None:
        self.assertEqual("{{ " + VARIABLE + " }}", str(self.copy.get("content")).strip())

    def test_the_task_output_is_hidden_with_no_log(self) -> None:
        self.assertIs(self.task.get("no_log"), True)

    def test_the_file_is_owned_by_root_and_the_portal_group_with_mode_0440(self) -> None:
        # 0440 and group 1000 let the portal's container user read the file through its group
        # and let nothing else read it. 0400 or 0600 would stop the portal reading it.
        self.assertEqual("root", str(self.copy.get("owner")))
        self.assertEqual("1000", str(self.copy.get("group")))
        self.assertEqual("0440", str(self.copy.get("mode")))


if __name__ == "__main__":
    unittest.main()
