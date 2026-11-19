"""The owner's due-diligence address: the role refuses a run that would start the broker without it.

The broker refuses to start without OWNER_DUE_DILIGENCE_EMAIL, so the role must refuse before it
writes the environment file. The refusal task is run for real in a scratch play, with the value
the test gives it, and the play must stop for an unset, blank or non-address value and go on for a
plain address. The value is never printed. Static checks hold the template line and the place of
the refusal, ahead of every write and of the templating.

A missing ansible-playbook is a failure, not a skip: the suite of a role is a control.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
TEMPLATE = ROLE / "templates" / "broker.env.j2"
REFUSAL_NAME = "Refuse an owner address that is unset or not a plain address"
ENV_TEMPLATE_NAME = "Install the environment file"
OWNER_LINE = "OWNER_DUE_DILIGENCE_EMAIL={{ broker_deploy_owner_due_diligence_email }}"
PLAIN_ADDRESS = "owner-review@example.invalid"
SENTINEL_BAD = "not-an-address"


def tasks_of(path: Path) -> list[dict[str, object]]:
    """Return a task file's tasks."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        message = f"{path.name} is not a task list"
        raise TypeError(message)
    return cast("list[dict[str, object]]", document)


def find(tasks: list[dict[str, object]], name: str) -> int:
    """Return the index of the named task.

    Raises:
        LookupError: no task has the name.
    """
    for index, task in enumerate(tasks):
        if task.get("name") == name:
            return index
    message = f"no task named {name!r}"
    raise LookupError(message)


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


class Static(unittest.TestCase):
    """What the files say about the address, read from the files."""

    def setUp(self) -> None:
        """Read the role's tasks and template."""
        self.tasks = tasks_of(TASKS)
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_the_template_carries_the_broker_setting_from_the_variable(self) -> None:
        self.assertEqual(self.template.count(OWNER_LINE), 1)

    def test_the_template_holds_no_address(self) -> None:
        self.assertNotIn("@", "".join(line for line in self.template.splitlines() if "OWNER" in line))

    def test_the_refusal_comes_before_the_environment_file_and_before_any_write(self) -> None:
        refusal = find(self.tasks, REFUSAL_NAME)
        env = find(self.tasks, ENV_TEMPLATE_NAME)
        self.assertLess(refusal, env)
        first_write = find(self.tasks, "Create the configuration directory")
        self.assertLess(refusal, first_write)

    def test_the_refusal_is_not_hidden_behind_a_wait_it_does_not_share(self) -> None:
        refusal = self.tasks[find(self.tasks, REFUSAL_NAME)]
        self.assertNotIn("when", refusal)
        self.assertIs(refusal.get("no_log"), True)

    def test_the_environment_file_task_hides_its_content(self) -> None:
        env = self.tasks[find(self.tasks, ENV_TEMPLATE_NAME)]
        self.assertIs(env.get("no_log"), True)
        self.assertIs(env.get("diff"), False)


class Refusal(unittest.TestCase):
    """The refusal task run for real, with the value the test gives it."""

    def run_with(self, value: str) -> tuple[int, str]:
        """Run the refusal task alone in a scratch role, and return the exit code and output."""
        task = tasks_of(TASKS)[find(tasks_of(TASKS), REFUSAL_NAME)]
        with tempfile.TemporaryDirectory() as scratch_name:
            scratch = Path(scratch_name)
            role_tasks = scratch / "roles" / "probe" / "tasks"
            role_tasks.mkdir(parents=True)
            (role_tasks / "main.yml").write_text(yaml.safe_dump([task]), encoding="utf-8")
            play = scratch / "play.yml"
            play.write_text(
                yaml.safe_dump(
                    [
                        {
                            "hosts": "localhost",
                            "connection": "local",
                            "gather_facts": False,
                            "vars": {"broker_deploy_owner_due_diligence_email": value},
                            "roles": ["probe"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(ansible_playbook()), "-i", "localhost,", str(play)],
                cwd=scratch,
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode, result.stdout + result.stderr

    def test_a_plain_address_goes_on(self) -> None:
        code, output = self.run_with(PLAIN_ADDRESS)
        self.assertEqual(code, 0, output)

    def test_an_unset_value_refuses(self) -> None:
        code, output = self.run_with("")
        self.assertNotEqual(code, 0, output)
        self.assertIn("unset or is not a plain", output)

    def test_a_blank_value_refuses(self) -> None:
        code, output = self.run_with("   ")
        self.assertNotEqual(code, 0, output)

    def test_a_value_that_is_not_an_address_refuses_and_is_not_printed(self) -> None:
        code, output = self.run_with(SENTINEL_BAD)
        self.assertNotEqual(code, 0, output)
        self.assertNotIn(SENTINEL_BAD, output)

    def test_a_quoted_value_refuses(self) -> None:
        code, output = self.run_with("a'b@example.invalid")
        self.assertNotEqual(code, 0, output)


if __name__ == "__main__":
    unittest.main()
