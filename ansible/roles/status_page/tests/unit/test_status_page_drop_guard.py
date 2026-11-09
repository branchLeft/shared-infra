"""Unit tests for the status_page role's refusal to bind the private address without its drop.

The playbook order puts the role after control_plane, but control_plane restarts the firewall
policy only when its files changed, so a re-run after a failed restart finds no change and
reaches the bind with the port's DOCKER-USER drop not loaded. The role therefore reads the live
chain for the exact rule the host's isolation policy inserts and stops, before it writes
anything, when the rule is absent. These tests read the role's tasks and its constants, and fail
when the guard is removed, weakened, moved after the bind, or changes the rule it looks for. The
rule is pinned here as a literal. That literal is the role's own copy of the contract; the policy
side compares itself to the role's rule in that policy's own test.
"""

import re
import unittest
from pathlib import Path
from typing import Any

import yaml

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
PINNED_MATCH = [
    "-p",
    "tcp",
    "-m",
    "conntrack",
    "--ctorigdst",
    "10.20.1.50",
    "--ctorigdstport",
    "8303",
    "!",
    "-s",
    "10.20.1.10",
    "-j",
    "DROP",
]
READ_DROP = "Read the live DOCKER-USER chain for the rule that confines the page's port"
REFUSE_BIND = "Refuse to bind the private address while its DOCKER-USER drop is not loaded"
REPORT_BIND = "Report in a plan that the private bind would be refused"
FIRST_WRITE = "Create the project directory"
BRING_UP = "Bring up the stack"
LOOPBACK_TEST = "status_page_listen_address != '127.0.0.1'"
VARIABLE = re.compile(r"\{\{\s*(\w+)\s*\}\}")
_CASE = unittest.TestCase()


def _tasks() -> list[dict[str, Any]]:
    """Return every task of the role, parsed."""
    return list(yaml.safe_load(TASKS.read_text(encoding="utf-8")))


def _task(name: str) -> dict[str, Any]:
    """Return the one task of that name, or fail the test naming it."""
    found = [task for task in _tasks() if task.get("name") == name]
    _CASE.assertEqual(len(found), 1, f"tasks named {name!r}")
    return found[0]


def _names() -> list[str]:
    return [str(task.get("name")) for task in _tasks()]


def _constants() -> dict[str, Any]:
    """The role's constants and its defaults, as the role sees them with no caller input."""
    values: dict[str, Any] = {}
    for part in ("defaults", "vars"):
        values.update(yaml.safe_load((ROLE / part / "main.yml").read_text(encoding="utf-8")))
    return values


def _role_match() -> list[str]:
    """The role's -C arguments after the chain name, with the role's constants filled in."""
    argv = [str(item) for item in _task(READ_DROP)["ansible.builtin.command"]["argv"]]
    values = _constants()
    rendered = [VARIABLE.sub(lambda m: str(values[m.group(1)]), item) for item in argv]
    return rendered[rendered.index("DOCKER-USER") + 1 :]


def _conditions(task: dict[str, Any]) -> list[str]:
    when = task.get("when", [])
    return [str(item) for item in (when if isinstance(when, list) else [when])]


class StatusPageDropGuardTest(unittest.TestCase):
    """The private bind is refused unless the live chain carries the port's drop."""

    # The read is the evidence. It must be a read that changes nothing, runs in a plan too, and
    # waits for the xtables lock instead of failing on contention with Docker.
    def test_the_live_chain_is_read_without_changing_anything(self) -> None:
        task = _task(READ_DROP)
        argv = [str(item) for item in task["ansible.builtin.command"]["argv"]]
        self.assertIn("-C", argv)
        self.assertNotIn("-I", argv)
        self.assertNotIn("-A", argv)
        self.assertIn("-w", argv)
        self.assertIs(task.get("changed_when"), False)
        self.assertIs(task.get("failed_when"), False)
        self.assertIs(task.get("check_mode"), False)
        self.assertIn(LOOPBACK_TEST, _conditions(task))
        self.assertEqual(task["register"], "status_page_drop")

    # The rule the guard looks for is the rule the host's policy inserts, word for word: the same
    # protocol, the same conntrack original destination and port, the same gateway exception
    # and the same target. A change to the role's side alone fails here.
    def test_the_guard_looks_for_the_pinned_rule(self) -> None:
        self.assertEqual(_role_match(), PINNED_MATCH)

    # The refusal fails the play, names what is missing and what to do, and is skipped only for
    # loopback (nothing to guard) and in a plan (reported instead, so the first plan does not fail).
    def test_a_missing_drop_stops_the_play_before_anything_is_written(self) -> None:
        task = _task(REFUSE_BIND)
        conditions = _conditions(task)
        self.assertIn("ansible.builtin.assert", task)
        that = [str(item) for item in task["ansible.builtin.assert"]["that"]]
        self.assertEqual(that, ["status_page_drop.rc | ansible.builtin.default(-1) == 0"])
        self.assertIn(LOOPBACK_TEST, conditions)
        self.assertIn("not ansible_check_mode", conditions)
        message = str(task["ansible.builtin.assert"]["fail_msg"])
        self.assertIn("DOCKER-USER", message)
        self.assertIn("{{ status_page_gateway_address }}", message)
        names = _names()
        self.assertLess(names.index(READ_DROP), names.index(REFUSE_BIND))
        self.assertLess(names.index(REFUSE_BIND), names.index(FIRST_WRITE))
        self.assertLess(names.index(REFUSE_BIND), names.index(BRING_UP))

    # In a plan the refusal cannot fire (the first plan runs before control_plane loads the
    # rule), so a plan reports it instead of staying silent.
    def test_a_plan_reports_the_refusal_it_would_make(self) -> None:
        task = _task(REPORT_BIND)
        conditions = _conditions(task)
        self.assertIn("ansible.builtin.debug", task)
        self.assertIn("ansible_check_mode", conditions)
        self.assertIn(LOOPBACK_TEST, conditions)
        self.assertIn("status_page_drop.rc | ansible.builtin.default(-1) != 0", conditions)


if __name__ == "__main__":
    unittest.main()
