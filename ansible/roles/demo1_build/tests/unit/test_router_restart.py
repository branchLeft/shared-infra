"""The apply that changes the router program or its unit restarts every slot's health router.

A running router keeps the code it started with, so an apply that installs a new
``health_router.py`` (or a new router unit) leaves the old code running until each router is
restarted (workspace#4429, seen on demo1: routers started before the port change kept the old
port). A Molecule container cannot run the router unit, so this holds the wiring in the role's own
task and handler text: the install task for the router program, and the task that writes the router
unit, each notify one handler topic; the handlers under that topic restart every slot's router, and
only look at the unit's presence first so a fresh host in check mode restarts nothing. Removing a
notify or the restart makes a test here red.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parent.parent.parent
TOPIC = "Restart the health routers"
LOOP_TASK = "Install a program where its grant or its unit expects it"
LOOK = "Look at whether the router template unit is installed, before restarting the routers"
NOT_A_LIST = "a role tasks file is not a list"
NOT_A_MAPPING = "a role variables file is not a mapping"


def tasks(name: str) -> list[dict[str, object]]:
    """The tasks of one role file (tasks/ or handlers/), as plain mappings.

    Raises:
        TypeError: the file is not a list of mappings.
    """
    raw = yaml.safe_load((ROLE / name).read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not all(isinstance(t, dict) for t in raw):
        raise TypeError(NOT_A_LIST)
    return raw


def notified(task: dict[str, object]) -> list[str]:
    """The handler names a task notifies, whether given as one string or a list."""
    value = task.get("notify", [])
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def the_task(name: str, file: str) -> dict[str, object]:
    """The one task of a file with this name.

    Raises:
        LookupError: no task, or more than one, has the name.
    """
    found = [t for t in tasks(file) if t.get("name") == name]
    if len(found) != 1:
        message = f"{file} has {len(found)} tasks named {name!r}, not one"
        raise LookupError(message)
    return found[0]


class RouterRestartOnChange(unittest.TestCase):
    """The install task and the unit task notify the restart, and the restart reaches every slot."""

    def test_installing_the_router_program_notifies_the_restart(self) -> None:
        task = the_task(
            "Install the health router program, and restart the routers when it changed",
            "tasks/_programs.yml",
        )
        self.assertIn(TOPIC, notified(task))
        copy = task["ansible.builtin.copy"]
        self.assertIsInstance(copy, dict)
        self.assertEqual(copy["dest"], "{{ demo1_build_router_script_path }}")  # type: ignore[index]
        self.assertEqual(copy["src"], "{{ demo1_build_provision_dir }}/health_router.py")  # type: ignore[index]

    def test_the_router_program_is_installed_once_and_by_that_task_alone(self) -> None:
        """The loop leaves the router out, so a changed wrapper or sidecar restarts no router."""
        loop = the_task(LOOP_TASK, "tasks/_programs.yml")
        self.assertNotIn(TOPIC, notified(loop))
        self.assertIn("demo1_build_router_script_path", str(loop["loop"]))
        self.assertIn("rejectattr", str(loop["loop"]))

    def test_writing_the_router_unit_notifies_the_restart(self) -> None:
        task = the_task("Write the health router's template unit", "tasks/_units.yml")
        self.assertIn(TOPIC, notified(task))
        self.assertIn("Reload systemd manager", notified(task))

    def test_the_restart_handler_restarts_every_slot_and_listens_for_the_topic(self) -> None:
        handler = the_task("Restart the health router of each slot", "handlers/main.yml")
        self.assertEqual(handler["listen"], TOPIC)
        module = handler["ansible.builtin.systemd_service"]
        self.assertIsInstance(module, dict)
        self.assertEqual(module["state"], "restarted")  # type: ignore[index]
        self.assertEqual(module["name"], "branchleft-health-router@{{ item }}.service")  # type: ignore[index]
        self.assertEqual(handler["loop"], "{{ demo1_build_slots }}")

    def test_the_restart_is_skipped_in_check_mode_on_a_host_without_the_unit(self) -> None:
        look = the_task(LOOK, "handlers/main.yml")
        self.assertEqual(look["listen"], TOPIC)
        handler = the_task("Restart the health router of each slot", "handlers/main.yml")
        register = look["register"]
        self.assertIn(f"{register}.stat.exists", str(handler["when"]))
        self.assertIn("ansible_check_mode", str(handler["when"]))

    def test_the_look_runs_before_the_restart(self) -> None:
        """Listening handlers run in the order written, so the look must come first."""
        names = [str(t.get("name")) for t in tasks("handlers/main.yml")]
        look = names.index(LOOK)
        restart = names.index("Restart the health router of each slot")
        reload = names.index("Reload systemd manager")
        self.assertLess(reload, look)
        self.assertLess(look, restart)

    def test_a_second_apply_with_nothing_changed_has_no_unconditional_restart(self) -> None:
        """The enabling task never restarts, so a quiet apply restarts nothing."""
        enable = the_task("Enable and start the health router of each slot", "tasks/_routers.yml")
        module = enable["ansible.builtin.systemd_service"]
        self.assertIsInstance(module, dict)
        self.assertEqual(module["state"], "started")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
