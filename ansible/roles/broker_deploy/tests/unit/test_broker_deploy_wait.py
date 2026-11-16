"""The role waits while no release is carried, and still refuses one that is half carried.

The role is in the play of a host before the first release is carried (the carrying is its own
change). A refusal there fails the host's plan, and a plan needs every host clean or drifted, so
one host would block every delivery. Until a version or any pin is carried, the role says so and
ends with nothing read from the host or written to it. The first task of the pin check does that.
These tests read the file for the wait's condition and its place, and run the real pin check in a
scratch role to prove the three outcomes: nothing carried ends the role, a half-carried release
is refused with the existing message, and a carried release goes on.

A missing ansible-playbook is a failure, not a skip: the suite of a role is a control.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks"
SCENARIO_RELEASE = ROLE / "molecule" / "default" / "files" / "release"
VERSION = "0.0.1"
NOTHING_CARRIED = "broker_deploy_release_version == '' and broker_deploy_release_pins | length == 0"
WAIT_MESSAGE = "carries no release yet"
REFUSAL = "must have pinned files"
AFTER_THE_PIN_CHECK = "reached the task after the pin check"
PIN_CHECK_TASK = "Refuse a release version that is not MAJOR.MINOR.PATCH or has no pinned files"


def steps(path: Path) -> list[dict[str, object]]:
    """Return the tasks of a task file.

    Raises:
        TypeError: the file does not hold a list of mappings.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, list) or not all(isinstance(task, dict) for task in document):
        message = f"{path.name} is not a list of tasks"
        raise TypeError(message)
    return cast("list[dict[str, object]]", document)


def module_of(task: dict[str, object]) -> str:
    """Return the fully qualified module a task runs."""
    return next(key for key in task if key.startswith("ansible.builtin."))


class WaitInTheFile(unittest.TestCase):
    """The wait is the first thing the pin check does, and it is the whole of the exception."""

    def setUp(self) -> None:
        """Read the pin check's tasks."""
        self.pin_check = steps(TASKS / "_release_pin.yml")

    def test_the_first_two_tasks_say_so_and_end_the_role(self) -> None:
        say, end = self.pin_check[:2]
        self.assertEqual(module_of(say), "ansible.builtin.debug")
        self.assertEqual(module_of(end), "ansible.builtin.meta")
        self.assertEqual(end["ansible.builtin.meta"], "end_role")

    def test_the_wait_is_for_an_empty_version_and_empty_pins_and_nothing_else(self) -> None:
        say, end = self.pin_check[:2]
        self.assertEqual(say["when"], NOTHING_CARRIED)
        self.assertEqual(end["when"], NOTHING_CARRIED)

    def test_the_message_says_why_the_role_waits(self) -> None:
        debug = cast("dict[str, str]", self.pin_check[0]["ansible.builtin.debug"])
        self.assertIn(WAIT_MESSAGE, debug["msg"])
        self.assertIn("changes nothing", debug["msg"])

    def test_the_refusal_follows_the_wait_unchanged_in_what_it_requires(self) -> None:
        refusal = self.pin_check[2]
        self.assertEqual(refusal["name"], PIN_CHECK_TASK)
        self.assertNotIn("when", refusal)
        self.assertEqual(
            refusal["ansible.builtin.assert"],
            {
                "that": [
                    r"broker_deploy_release_version is match('^[0-9]+\.[0-9]+\.[0-9]+\Z')",
                    "broker_deploy_release_version in broker_deploy_release_pins",
                    "broker_deploy_release_pins[broker_deploy_release_version] is mapping",
                    "'broker.mjs' in broker_deploy_release_pins[broker_deploy_release_version]",
                ],
                "quiet": True,
                "fail_msg": cast("dict[str, object]", refusal["ansible.builtin.assert"])[
                    "fail_msg"
                ],
            },
        )

    def test_nothing_else_in_the_pin_check_is_made_to_wait(self) -> None:
        for task in self.pin_check[2:]:
            with self.subTest(task=task.get("name")):
                self.assertNotIn(module_of(task), {"ansible.builtin.meta"})
                self.assertNotEqual(task.get("when"), NOTHING_CARRIED)

    def test_the_pin_check_is_the_first_task_of_the_role(self) -> None:
        first = steps(TASKS / "main.yml")[0]
        self.assertEqual(first["ansible.builtin.include_tasks"], "_release_pin.yml")

    def test_the_role_waits_in_no_other_place(self) -> None:
        for path in sorted(TASKS.glob("*.yml")):
            ending = [
                task for task in steps(path) if task.get("ansible.builtin.meta") == "end_role"
            ]
            with self.subTest(file=path.name):
                self.assertEqual(len(ending), 1 if path.name == "_release_pin.yml" else 0)

    def test_the_molecule_scenario_runs_the_waiting_and_the_half_carried_cases(self) -> None:
        scenario = ROLE / "molecule" / "default"
        verify = (scenario / "verify.yml").read_text(encoding="utf-8")
        self.assertIn("tasks/wait_probe.yml", verify)
        probe = (scenario / "tasks" / "wait_probe.yml").read_text(encoding="utf-8")
        for fragment in (WAIT_MESSAGE, REFUSAL, "broker_deploy_release_version", "--check"):
            self.assertIn(fragment, probe)
        self.assertIn("branchleft.broker_deploy", (scenario / "wait.yml").read_text("utf-8"))


@dataclass
class Outcome:
    """What one run of ansible-playbook did."""

    code: int
    output: str


def ansible_playbook() -> Path:
    """Return the ansible-playbook beside the interpreter that runs the tests.

    Raises:
        AssertionError: the interpreter's environment has no ansible-playbook.
    """
    found = Path(sys.executable).parent / "ansible-playbook"
    if not found.exists():
        message = f"{found} is missing: run these tests with the pinned tool environment"
        raise AssertionError(message)
    return found


class WaitRun(unittest.TestCase):
    """The real pin check, run as the first task file of a scratch role with a task after it."""

    def setUp(self) -> None:
        """Make a scratch role that includes the real pin check and then names a task."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        role = self.root / "roles" / "pin_probe" / "tasks"
        role.mkdir(parents=True)
        (role / "main.yml").write_text(
            f"- ansible.builtin.include_tasks: {TASKS / '_release_pin.yml'}\n"
            f"- ansible.builtin.debug:\n    msg: {AFTER_THE_PIN_CHECK}\n",
            encoding="utf-8",
        )
        self.play = self.root / "play.yml"
        self.play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {ROLE / 'defaults' / 'main.yml'}\n"
            f"    - {ROLE / 'vars' / 'main.yml'}\n"
            "  tasks:\n"
            "    - ansible.builtin.include_role:\n"
            "        name: pin_probe\n"
            "    - ansible.builtin.debug:\n"
            "        msg: the play goes on after the role\n",
            encoding="utf-8",
        )
        self.carried = self.root / "carried"
        shutil.copytree(SCENARIO_RELEASE, self.carried)

    def run_pin_check(self, variables: dict[str, object], *, check: bool = False) -> Outcome:
        """Run the scratch play once, with the variables over the role's defaults."""
        extra = self.root / "extra.json"
        extra.write_text(
            json.dumps({**variables, "ansible_python_interpreter": sys.executable}),
            encoding="utf-8",
        )
        command = [str(ansible_playbook()), "-i", "localhost,", "-e", f"@{extra}"]
        if check:
            command.append("--check")
        command.append(str(self.play))
        environment = {
            **os.environ,
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(self.root / "ansible-home"),
            "ANSIBLE_ROLES_PATH": str(self.root / "roles"),
        }
        # The command is built here from fixed paths and the scratch tree.
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, env=environment, timeout=180
        )
        return Outcome(done.returncode, done.stdout + done.stderr)

    def test_nothing_carried_ends_the_role_and_the_play_goes_on(self) -> None:
        for check in (False, True):
            with self.subTest(check=check):
                outcome = self.run_pin_check({}, check=check)
                self.assertEqual(outcome.code, 0, outcome.output)
                self.assertIn(WAIT_MESSAGE, outcome.output)
                self.assertNotIn(AFTER_THE_PIN_CHECK, outcome.output)
                self.assertIn("the play goes on after the role", outcome.output)
                self.assertRegex(outcome.output, r"changed=0\b")

    def test_a_version_with_no_pins_is_still_refused(self) -> None:
        outcome = self.run_pin_check({"broker_deploy_release_version": VERSION})
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(REFUSAL, outcome.output)
        self.assertNotIn(WAIT_MESSAGE, outcome.output)
        self.assertNotIn(AFTER_THE_PIN_CHECK, outcome.output)

    def test_pins_with_no_version_are_still_refused(self) -> None:
        pins = {VERSION: {"broker.mjs": "0" * 64}}
        for version in ("", None):
            with self.subTest(version=version):
                outcome = self.run_pin_check(
                    {"broker_deploy_release_version": version, "broker_deploy_release_pins": pins}
                )
                self.assertNotEqual(outcome.code, 0, outcome.output)
                self.assertNotIn(WAIT_MESSAGE, outcome.output)
                self.assertNotIn(AFTER_THE_PIN_CHECK, outcome.output)

    def test_a_version_that_is_not_pinned_is_still_refused(self) -> None:
        pins = {"0.0.2": {"broker.mjs": "0" * 64}}
        outcome = self.run_pin_check(
            {"broker_deploy_release_version": VERSION, "broker_deploy_release_pins": pins}
        )
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(REFUSAL, outcome.output)
        self.assertNotIn(WAIT_MESSAGE, outcome.output)

    def test_a_carried_release_goes_on_past_the_pin_check(self) -> None:
        pins = {
            VERSION: {
                str(path.relative_to(self.carried / VERSION)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sorted((self.carried / VERSION).rglob("*"))
                if path.is_file()
            }
        }
        outcome = self.run_pin_check(
            {
                "broker_deploy_release_version": VERSION,
                "broker_deploy_release_pins": pins,
                "broker_deploy_release_dir": str(self.carried),
            }
        )
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertNotIn(WAIT_MESSAGE, outcome.output)
        self.assertIn(AFTER_THE_PIN_CHECK, outcome.output)
        self.assertIsNone(re.search(r"failed=[1-9]", outcome.output))


if __name__ == "__main__":
    unittest.main()
