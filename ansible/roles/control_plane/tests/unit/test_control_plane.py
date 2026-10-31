"""Unit tests for the order and the gates of the control_plane role's tasks.

Each secret is written in two steps: created empty at its final owner and mode, then
filled. The attribute task must sit between the create-empty tasks and the fills, or a
fill leaves content in a file that is still wide. The role also settles its inputs before
its first write and leaves a deployed stack's containers to the unit. These tests read
tasks/main.yml and fail when that order or those gates are lost.
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests" / "support"))

from role_tasks import task_lines  # noqa: E402

CREATE_ENV = "Create the environment file empty, if it is absent"
CREATE_KEY = "Create the master key empty, if it is absent"
ATTRIBUTES = "Set the owner, group and mode of each secret file on every run"
FILL_ENV = "Write the environment file's content while the file is empty"
FILL_KEY = "Write the master key's content while the file is empty"

FIRST_WRITE = "Create the host configuration directories of the control plane"
INPUT_REFUSALS = (
    "Refuse an absent or empty environment file when no content was given",
    "Refuse an absent or empty master key when no content was given",
    "Refuse a run with no image to deploy",
    "Refuse an image that is not pinned by digest",
)
REFUSAL_CODES = ("env-missing", "masterkey-missing", "image-missing", "image-not-pinned")
DOCKER_READS = (
    "Look for the portal container of the stack",
    "Read the image the portal container was created from",
)


def _tasks() -> list[dict[str, Any]]:
    """Return every task of tasks/main.yml, parsed."""
    return list(yaml.safe_load(TASKS.read_text(encoding="utf-8")))


def _argv(task: dict[str, Any]) -> list[str]:
    command = task.get("ansible.builtin.command")
    return [str(word) for word in command["argv"]] if isinstance(command, dict) else []


def _conditions(task: dict[str, Any]) -> list[str]:
    when = task.get("when", [])
    return [str(item) for item in (when if isinstance(when, list) else [when])]


class TaskOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

    def _position(self, name: str) -> int:
        self.assertEqual(
            self.names.count(name), 1, f"{name!r} must appear exactly once in tasks/main.yml"
        )
        return self.names.index(name)

    def test_the_five_secret_tasks_are_all_present(self) -> None:
        for name in (CREATE_ENV, CREATE_KEY, ATTRIBUTES, FILL_ENV, FILL_KEY):
            self.assertIn(name, self.names)

    def test_both_create_empty_tasks_come_before_the_attribute_task(self) -> None:
        attributes = self._position(ATTRIBUTES)
        self.assertLess(
            self._position(CREATE_ENV),
            attributes,
            "the environment file is created after its attributes are set",
        )
        self.assertLess(
            self._position(CREATE_KEY),
            attributes,
            "the master key is created after its attributes are set",
        )

    def test_the_attribute_task_comes_before_both_fills(self) -> None:
        attributes = self._position(ATTRIBUTES)
        self.assertLess(
            attributes,
            self._position(FILL_ENV),
            "the environment file is filled before its attributes are set",
        )
        self.assertLess(
            attributes,
            self._position(FILL_KEY),
            "the master key is filled before its attributes are set",
        )


class InputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = [name for name, _ in task_lines(TASKS)]

    def test_every_input_refusal_comes_before_the_first_write(self) -> None:
        first_write = self.names.index(FIRST_WRITE)
        for name in INPUT_REFUSALS:
            self.assertEqual(self.names.count(name), 1, name)
            self.assertLess(self.names.index(name), first_write, f"{name!r} comes after a write")

    def test_the_refusals_name_their_input_and_show_no_value(self) -> None:
        by_name = {str(task.get("name")): task for task in _tasks()}
        for name, needle in zip(INPUT_REFUSALS, REFUSAL_CODES, strict=True):
            task = by_name[name]
            self.assertIn(
                f"control_plane[{needle}]", str(task["ansible.builtin.assert"]["fail_msg"])
            )
            self.assertNotIn("no_log", task, f"{name!r} hides its own message")
        for name in INPUT_REFUSALS[:2]:
            message = str(by_name[name]["ansible.builtin.assert"]["fail_msg"])
            self.assertNotIn("control_plane_env_content }}", message)
            self.assertNotIn("control_plane_masterkey }}", message)

    def test_the_direct_compose_tasks_are_gated_on_a_stack_not_yet_deployed(self) -> None:
        gated = 0
        for task in _tasks():
            words = _argv(task)
            direct = words[:2] == ["docker", "compose"]
            stamp = "Record that the init phase has completed" == task.get("name")
            if not direct and not stamp:
                continue
            gated += 1
            self.assertTrue(
                any(
                    "control_plane_deployed" in condition and "not" in condition
                    for condition in _conditions(task)
                ),
                f"{task.get('name')!r} runs without the not-yet-deployed gate",
            )
        self.assertEqual(
            gated, 4, "expected the database start, the init run, its stamp and the sign-in start"
        )

    def test_the_reads_of_the_running_stack_run_in_check_mode_and_change_nothing(self) -> None:
        by_name = {str(task.get("name")): task for task in _tasks()}
        for name in DOCKER_READS:
            task = by_name[name]
            self.assertIs(task.get("check_mode"), False, f"{name!r} is skipped in check mode")
            self.assertIs(task.get("changed_when"), False, f"{name!r} can report a change")
            self.assertEqual(_argv(task)[0], "docker")
            self.assertIn(_argv(task)[1], ("ps", "inspect"), f"{name!r} is not a read")

    def test_only_the_settled_image_is_used_by_the_tasks_that_run_it(self) -> None:
        for task in _tasks():
            command = task.get("ansible.builtin.command")
            if not isinstance(command, dict):
                continue
            used = f"{command} {task.get('environment', '')}"
            self.assertNotIn(
                "control_plane_app_image", used, f"{task.get('name')!r} uses the image as given"
            )


class WrapperRecordTests(unittest.TestCase):
    """The role reads the deploy wrapper's record, so the path and the key come from its source."""

    def setUp(self) -> None:
        source = ROLE.parents[2] / "hetzner" / "provision" / "branchleft_deploy.py"
        spec = importlib.util.spec_from_file_location("branchleft_deploy", source)
        if spec is None or spec.loader is None:
            self.fail(f"cannot load {source}")
        self.wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.wrapper)

    def test_the_role_reads_the_file_the_wrapper_writes(self) -> None:
        variables = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
        self.assertEqual(
            variables["control_plane_image_record"], self.wrapper.image_env_path("control-plane")
        )

    def test_the_wrapper_writes_the_key_the_role_reads(self) -> None:
        image = "example.invalid/app@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control-plane.image.env"
            self.wrapper.write_image_env(str(path), image)
            self.assertEqual(path.read_text(encoding="utf-8"), f"IMAGE={image}\n")
        self.assertIn("^IMAGE=", TASKS.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
