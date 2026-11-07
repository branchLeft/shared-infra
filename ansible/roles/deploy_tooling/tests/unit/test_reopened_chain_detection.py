"""The check-mode read-back that detects a reopened DOCKER-USER chain, pinned in fast CI.

The role detects a chain that no longer holds the policy by reading the chains back in
``tasks/_isolation.yml``. The nightly drift check runs every enrolled host in check mode, so
that read-back is the detection path only while it runs in check mode on a configured host.
A ``when: not ansible_check_mode`` added to it passes lint and both of the harness's check
steps (it reports no change), and the nightly would then go green on an open chain. The
Molecule case "check mode on a flushed chain" proves the path, in a shard that takes about
25 minutes; this file is the fast pin of the same property.

It reads the role's own task file and renders its two conditions with Jinja against a truth
table, so what is asserted is the behaviour of the conditions as written and not their
text. It restates no literal of the policy: the policy lives in the program and the module.
"""

import ast
import json
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import jinja2
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
PLAYBOOKS = ROLE.parents[1] / "playbooks"
ISOLATION = ROLE / "tasks" / "_isolation.yml"

DECIDE_TASK = "Decide whether the firewall read-back must wait for the apply"
FLUSH_TASK = "Apply the changed files"
READ_BACK = "the read-back block"
PENDING = "deploy_tooling_apply_pending"
RESTART_TASK = "Restart the policy unit after a failed read-back"
CHECK_MODE = "ansible_check_mode"

Task = dict[str, object]


class RoleShapeError(AssertionError):
    """The task file is not shaped the way this test reads it."""

    def __init__(self, what: str, found: int) -> None:
        super().__init__(
            f"expected exactly one match for {what!r} in tasks/_isolation.yml, found {found}"
        )


def load_tasks(path: Path) -> list[Task]:
    return cast("list[Task]", YAML(typ="safe").load(path.read_text(encoding="utf-8")))


def isolation_tasks() -> list[Task]:
    return load_tasks(ISOLATION)


def decide_task() -> Task:
    """The task that sets the pending fact.

    Raises:
        RoleShapeError: there is not exactly one such task.
    """
    found = [task for task in isolation_tasks() if task.get("name") == DECIDE_TASK]
    if len(found) != 1:
        raise RoleShapeError(DECIDE_TASK, len(found))
    return found[0]


def steps_of(block: Task) -> list[Task]:
    """The tasks of a block and of its rescue, in file order."""
    return [*cast("list[Task]", block["block"]), *cast("list[Task]", block.get("rescue", []))]


def read_back_block() -> Task:
    """The one block that reads the chains back.

    Raises:
        RoleShapeError: there is not exactly one such block.
    """
    found = [
        task
        for task in isolation_tasks()
        if "block" in task and any("deploy_tooling_chain" in step for step in steps_of(task))
    ]
    if len(found) != 1:
        raise RoleShapeError(READ_BACK, len(found))
    return found[0]


def pending_for(variables: Mapping[str, object]) -> bool:
    """Render the ``deploy_tooling_apply_pending`` fact the role sets, for these variables.

    Raises:
        TypeError: the template did not render to a boolean.
    """
    set_fact = cast("Mapping[str, str]", decide_task()["ansible.builtin.set_fact"])
    env = jinja2.Environment(undefined=jinja2.Undefined, autoescape=jinja2.select_autoescape())
    rendered = env.from_string(set_fact[PENDING]).render(**variables)
    # Ansible reads the rendered word back as a boolean; literal_eval does the same here.
    value = ast.literal_eval(rendered.strip())
    if not isinstance(value, bool):
        raise TypeError(rendered)
    return value


def read_back_runs(variables: Mapping[str, object]) -> bool:
    """Whether the read-back block runs: the block's own ``when``, given the rendered fact."""
    env = jinja2.Environment(
        undefined=jinja2.StrictUndefined, autoescape=jinja2.select_autoescape()
    )
    condition = env.compile_expression(str(read_back_block()["when"]))
    return bool(condition(**variables, **{PENDING: pending_for(variables)}))


def facts(*, check_mode: bool, files_changed: bool, unit_changed: bool | None) -> dict[str, object]:
    """The variables the decision reads.

    ``unit_changed`` is None when the "Enable the policy unit at boot" task was skipped: a
    skipped task registers a result with ``skipped`` set and no ``changed`` key.
    """
    unit: dict[str, object] = (
        {"skipped": True} if unit_changed is None else {"changed": unit_changed}
    )
    return {
        CHECK_MODE: check_mode,
        "deploy_tooling_app_files_written": {"changed": files_changed},
        "deploy_tooling_policy_unit_enabled": unit,
    }


class ReadBackRunsInCheckModeTests(unittest.TestCase):
    """The detection path: a configured host, planned in check mode, is read back."""

    def test_check_mode_on_a_configured_host_runs_the_read_back(self) -> None:
        for unit_changed in (False, None):
            with self.subTest(unit_changed=unit_changed):
                variables = facts(check_mode=True, files_changed=False, unit_changed=unit_changed)
                self.assertFalse(
                    pending_for(variables),
                    "skipped on a configured host: nothing is changing, so no apply is pending",
                )
                self.assertTrue(
                    read_back_runs(variables),
                    "check mode on a configured host must run the read-back, or the nightly "
                    "drift check cannot see a reopened chain",
                )

    def test_check_mode_skips_the_read_back_only_while_the_apply_is_pending(self) -> None:
        pending_cases = {
            "program or unit files would change": (True, False),
            "unit enabled state would change": (False, True),
            "both would change": (True, True),
        }
        for name, (files_changed, unit_changed) in pending_cases.items():
            with self.subTest(name):
                variables = facts(
                    check_mode=True, files_changed=files_changed, unit_changed=unit_changed
                )
                self.assertTrue(pending_for(variables))
                self.assertFalse(
                    read_back_runs(variables),
                    "skipped on a configured host: the read-back may wait only for an apply "
                    "that check mode cannot simulate",
                )

    def test_a_real_apply_always_runs_the_read_back(self) -> None:
        for files_changed in (False, True):
            for unit_changed in (False, True, None):
                with self.subTest(files_changed=files_changed, unit_changed=unit_changed):
                    variables = facts(
                        check_mode=False, files_changed=files_changed, unit_changed=unit_changed
                    )
                    self.assertFalse(pending_for(variables))
                    self.assertTrue(read_back_runs(variables))


class ReadBackShapeTests(unittest.TestCase):
    """Nothing in the read-back may hide it from check mode, except the one restart."""

    def test_the_read_back_block_is_gated_on_the_pending_fact_alone(self) -> None:
        condition = str(read_back_block()["when"])
        self.assertIn(PENDING, condition)
        self.assertNotIn("check_mode", condition)

    def test_only_the_unit_restart_in_the_block_or_rescue_is_gated_on_check_mode(self) -> None:
        steps = steps_of(read_back_block())
        self.assertTrue(steps)
        gated = [step["name"] for step in steps if CHECK_MODE in json.dumps(step)]
        self.assertEqual(
            gated,
            [RESTART_TASK],
            "a task in the read-back block or its rescue is skipped in check mode, which "
            "hides a reopened chain from the nightly drift check",
        )
        restart = next(step for step in steps if step["name"] == RESTART_TASK)
        self.assertEqual(restart["when"], f"not {CHECK_MODE}")
        self.assertEqual(
            cast("Mapping[str, object]", restart["ansible.builtin.systemd_service"])["state"],
            "restarted",
        )

    def test_every_read_back_reads_for_real_in_check_mode(self) -> None:
        reads = [step for step in steps_of(read_back_block()) if "deploy_tooling_chain" in step]
        self.assertEqual(len(reads), 2, "one read-back, and one more after the repair")
        for step in reads:
            with self.subTest(step["name"]):
                self.assertIs(step.get("check_mode"), False)
                self.assertNotIn("mode", cast("Mapping[str, object]", step["deploy_tooling_chain"]))
                self.assertNotIn("when", step)

    def test_the_read_back_runs_after_the_handlers_have_applied_the_changes(self) -> None:
        tasks = isolation_tasks()
        block = read_back_block()
        flush = [i for i, task in enumerate(tasks) if task.get("name") == FLUSH_TASK]
        placed = [i for i, task in enumerate(tasks) if task == block]
        self.assertEqual(len(flush), 1)
        self.assertEqual(len(placed), 1)
        self.assertLess(flush[0], placed[0])


class AppPlaybooksPlayTheRoleTests(unittest.TestCase):
    """A host that is told it is an app host must also run the role that reads its chains."""

    def test_every_playbook_that_sets_the_app_class_lists_the_role(self) -> None:
        app_playbooks: list[str] = []
        for path in sorted(PLAYBOOKS.glob("*.yml")):
            for play in load_tasks(path):
                play_vars = cast("Mapping[str, object]", play.get("vars") or {})
                if play_vars.get("deploy_tooling_host_class") != "app":
                    continue
                app_playbooks.append(path.name)
                entries = cast("list[str | Mapping[str, str]]", play.get("roles", []))
                roles = [entry if isinstance(entry, str) else entry["role"] for entry in entries]
                names = [role.rstrip("/").rsplit("/", 1)[-1] for role in roles]
                self.assertIn(
                    "deploy_tooling",
                    names,
                    f"{path.name} sets deploy_tooling_host_class: app and does not play the role, "
                    "so nothing reads that host's DOCKER-USER chain back",
                )
        self.assertTrue(
            app_playbooks, "no playbook sets the app class, so the check looked at nothing"
        )


if __name__ == "__main__":
    unittest.main()
