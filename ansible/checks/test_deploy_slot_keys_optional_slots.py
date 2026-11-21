"""deploy_slot_keys_slots is optional: undefined installs the program and never revokes.

A host that is not given a slot list (appt1 holds the slot program for tenant_entry's key step,
and has no list of its own) must install the program and skip the reconcile. The skip is the
reconcile task's `when`, so these tests evaluate that expression with Jinja2, the engine Ansible
uses for `when`, for an undefined list, a declared one, and a sabotaged copy in which undefined
means an empty list. The sabotage must make the same assertion fail, or the assertion proves
nothing.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping

import jinja2
import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT

ROLE = ROOT / "ansible" / "roles" / "deploy_slot_keys"
TASKS = ROLE / "tasks" / "main.yml"
SPEC = ROLE / "meta" / "argument_specs.yml"
RECONCILE = "deploy_slot_keys_reconcile"
SLOTS = "deploy_slot_keys_slots"
DECLARED = [{"stack": "alpha", "public_key": "ssh-ed25519 AAAA", "adopt_existing": False}]
UNDEFINED = object()


def _tasks(text: str) -> list[dict[str, object]]:
    loaded: object = yaml.safe_load(text)
    assert isinstance(loaded, list)  # noqa: S101 - narrows the type for the caller
    return [task for task in loaded if isinstance(task, dict)]


def _reconcile(text: str) -> dict[str, object]:
    for task in _tasks(text):
        if RECONCILE in task:
            return task
    raise LookupError(RECONCILE)


def _runs(task: Mapping[str, object], slots: object, check_mode: bool, changed: bool) -> bool:
    """Whether the task would run: its `when`, evaluated as Ansible does, for these facts."""
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True)
    env.tests["changed"] = lambda value: bool(value.get("changed"))
    when = str(task.get("when", "true"))
    facts: dict[str, object] = {
        "ansible_check_mode": check_mode,
        "deploy_slot_keys_program": {"changed": changed},
    }
    if slots is not UNDEFINED:
        facts[SLOTS] = slots
    return bool(env.compile_expression(when, undefined_to_none=False)(**facts))


def undefined_is_skipped(text: str) -> bool:
    """True when an undefined slot list leaves the reconcile task skipped in every mode."""
    task = _reconcile(text)
    return not any(
        _runs(task, UNDEFINED, check_mode, changed)
        for check_mode in (False, True)
        for changed in (False, True)
    )


def slots_are_optional(spec: str) -> bool:
    options = yaml.safe_load(spec)["argument_specs"]["main"]["options"]
    slot = options[SLOTS]
    return slot.get("required") is not True and "default" not in slot


DEFINED_GUARD = "deploy_slot_keys_slots is defined and "


def sabotaged(text: str) -> str:
    """Undefined behaves as an empty list: the reconcile task's `is defined` guard is dropped and
    its argument defaults to []. An empty list is the 'not declared' case, so the reconcile would
    run and, on a host with slots, revoke them. Edits the parsed task, so line breaks in the
    folded `when` do not matter."""
    tasks = _tasks(text)
    for task in tasks:
        if RECONCILE in task:
            when = str(task["when"])
            assert DEFINED_GUARD in when, "the sabotage found no guard to remove"  # noqa: S101
            task["when"] = when.replace(DEFINED_GUARD, "")
            args = task[RECONCILE]
            assert isinstance(args, dict)  # noqa: S101
            args["slots"] = "{{ deploy_slot_keys_slots | default([]) }}"
    dumped: str = yaml.safe_dump(tasks, sort_keys=False)
    return dumped


class OptionalSlotsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tasks = TASKS.read_text(encoding="utf-8")
        self.spec = SPEC.read_text(encoding="utf-8")

    def test_the_spec_makes_the_slot_list_optional_with_no_default(self) -> None:
        self.assertTrue(slots_are_optional(self.spec))

    def test_undefined_slots_skip_the_reconcile_in_every_mode(self) -> None:
        # (a) An undefined list installs the program (the copy above is unconditional) and does
        # not reach the module, so no granted slot is touched.
        self.assertTrue(undefined_is_skipped(self.tasks))

    def test_the_program_install_is_not_conditional(self) -> None:
        install = [t for t in _tasks(self.tasks) if "ansible.builtin.copy" in t][0]
        self.assertNotIn("when", install)

    def test_a_declared_list_still_reconciles(self) -> None:
        # (b) app1's declared list runs the module, outside check mode or after a changed program.
        task = _reconcile(self.tasks)
        self.assertTrue(_runs(task, DECLARED, check_mode=False, changed=False))
        self.assertTrue(_runs(task, DECLARED, check_mode=True, changed=False))

    def test_sabotage_treating_undefined_as_empty_is_caught(self) -> None:
        # (c) The same assertion, on a copy where undefined means an empty list, must fail.
        bad = sabotaged(self.tasks)
        self.assertNotEqual(bad, self.tasks, "the sabotage changed nothing")
        self.assertFalse(undefined_is_skipped(bad))

    def test_sabotage_of_the_spec_back_to_required_is_caught(self) -> None:
        bad = self.spec.replace("        required: false", "        required: true")
        self.assertNotEqual(bad, self.spec, "the sabotage changed nothing")
        self.assertFalse(slots_are_optional(bad))


if __name__ == "__main__":
    unittest.main()
