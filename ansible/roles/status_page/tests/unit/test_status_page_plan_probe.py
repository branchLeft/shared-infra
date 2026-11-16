"""Unit tests for when the role asks the page for its health.

A plan (check mode) brings nothing up, so a stack due to be brought up still runs the content of
the last apply. Asking it then judges old content at the address the new content would publish,
and a plan that moves the listen address fails although the apply would succeed. The role asks
in a plan only when no bring-up is due, says why when it does not, and always asks in an apply.
These tests read the role's tasks and fail when that is lost; the Molecule case
tasks/plan_probe.yml runs both plans.
"""

import unittest
from pathlib import Path
from typing import Any

import yaml

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
WORK_OUT = "Work out whether the stack must be brought up"
SAY = "Say the plan does not ask a stack that is due to be brought up"
ASK = "Ask the page whether it is healthy"
REFUSE = "Refuse a page that does not answer 200 on /health"
NOT_IN_A_DUE_PLAN = "not (ansible_check_mode and (status_page_up_needed | ansible.builtin.bool))"


def _tasks() -> list[dict[str, Any]]:
    """Return the role's tasks, parsed, in order."""
    return list(yaml.safe_load(TASKS.read_text(encoding="utf-8")))


def _named(name: str) -> dict[str, Any]:
    """Return the first task with this name, or an empty mapping when there is none."""
    found = [task for task in _tasks() if task.get("name") == name]
    return found[0] if found else {}


def _when(task: dict[str, Any]) -> list[str]:
    """Return a task's conditions as a list of strings."""
    when = task.get("when", [])
    return [str(item) for item in (when if isinstance(when, list) else [when])]


class PlanProbeTest(unittest.TestCase):
    """The health check is skipped only in a plan whose stack is due to be brought up."""

    # Safety class: a health gate. Drop the condition and a plan that moves the address fails on a
    # stack it did not start; widen it past check mode and an apply records an unhealthy page.
    def test_the_check_and_its_refusal_skip_only_a_plan_with_a_bring_up_due(self) -> None:
        for name in (ASK, REFUSE):
            with self.subTest(task=name):
                self.assertEqual(
                    _when(_named(name)),
                    ["status_page_compose_file_stat.stat.exists", NOT_IN_A_DUE_PLAN],
                )

    def test_the_plan_says_why_it_did_not_ask(self) -> None:
        say = _named(SAY)
        self.assertIn("ansible.builtin.debug", say)
        self.assertEqual(
            _when(say),
            [
                "status_page_compose_file_stat.stat.exists",
                "ansible_check_mode",
                "status_page_up_needed | ansible.builtin.bool",
            ],
        )

    def test_the_order_is_work_out_then_say_then_ask_then_refuse(self) -> None:
        names = [str(task.get("name")) for task in _tasks()]
        positions = [names.index(name) for name in (WORK_OUT, SAY, ASK, REFUSE)]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
