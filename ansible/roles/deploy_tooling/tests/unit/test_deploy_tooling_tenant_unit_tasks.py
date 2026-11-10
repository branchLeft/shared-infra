"""Tests that the tenant instance step is wired as its control needs it to be.

The module refuses a unit for a name that is not one of the host's tenants, but only if the task
that enables units takes its names from the module and the module takes its known names from the
host's tenant list. These tests hold that chain in the role's task files, which the unit tests of
the module cannot see and which Molecule alone would otherwise be the only check of.
"""

import unittest
from pathlib import Path
from typing import cast

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
MODULE = "deploy_tooling_tenant_unit_names"
ENABLE = "ansible.builtin.systemd_service"


def load(relative: str) -> object:
    return YAML(typ="safe").load((ROLE / relative).read_text(encoding="utf-8"))


def mapping(value: object) -> dict[str, object]:
    """Return a loaded YAML mapping.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"expected a mapping, found {type(value).__name__}"
        raise TypeError(message)
    return cast("dict[str, object]", value)


def tasks(relative: str) -> list[dict[str, object]]:
    loaded = load(relative)
    if not isinstance(loaded, list):
        message = f"{relative} is not a task list"
        raise TypeError(message)
    return [mapping(entry) for entry in loaded]


def arguments(task: dict[str, object], action: str) -> dict[str, object]:
    return mapping(task[action])


class TenantUnitTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.steps = tasks("tasks/_tenant_units.yml")

    def test_the_file_has_the_three_steps_in_order(self) -> None:
        self.assertEqual(
            ["ansible.builtin.set_fact", MODULE, ENABLE],
            [
                next(key for key in step if key in {"ansible.builtin.set_fact", MODULE, ENABLE})
                for step in self.steps
            ],
        )

    def test_the_tenant_list_is_read_for_its_names_only_and_hidden(self) -> None:
        step = self.steps[0]
        expression = str(arguments(step, "ansible.builtin.set_fact")["deploy_tooling_tenant_names"])
        self.assertIn("tenant_compose_stacks", expression)
        self.assertIn("map(attribute='slug')", expression)
        self.assertNotIn("secrets", expression)
        self.assertIs(True, step["no_log"])

    def test_the_module_takes_the_known_names_from_that_list_and_the_request_from_the_input(
        self,
    ) -> None:
        given = arguments(self.steps[1], MODULE)
        self.assertEqual("{{ deploy_tooling_tenant_names }}", given["known"])
        self.assertEqual("{{ deploy_tooling_tenant_units }}", given["requested"])
        self.assertEqual("{{ deploy_tooling_compose_unit_prefix }}", given["unit_prefix"])
        self.assertNotIn("no_log", self.steps[1], "a refusal must stay readable")

    def test_only_the_modules_names_are_enabled_and_none_is_started(self) -> None:
        step = self.steps[2]
        self.assertEqual("{{ deploy_tooling_tenant_unit_list }}", step["loop"])
        given = arguments(step, ENABLE)
        self.assertEqual({"name": "{{ item }}", "enabled": True}, given)
        self.assertIs(True, step["no_log"])

    def test_the_enable_waits_for_a_template_unit_check_mode_did_not_write(self) -> None:
        condition = str(self.steps[2]["when"])
        self.assertIn("ansible_check_mode", condition)
        self.assertIn("deploy_tooling_common_files_written", condition)


class MainWiringTests(unittest.TestCase):
    def test_the_step_is_included_for_a_host_of_class_app_after_the_isolation_policy(self) -> None:
        names = [
            str(step.get("ansible.builtin.include_tasks", "")) for step in tasks("tasks/main.yml")
        ]
        self.assertLess(names.index("_isolation.yml"), names.index("_tenant_units.yml"))
        step = tasks("tasks/main.yml")[names.index("_tenant_units.yml")]
        self.assertEqual("deploy_tooling_host_class == 'app'", step["when"])

    def test_the_template_unit_copy_records_whether_it_wrote_anything(self) -> None:
        copies = [
            step
            for step in tasks("tasks/main.yml")
            if step.get("name") == "Install the deploy wrapper and the compose template unit"
        ]
        self.assertEqual(1, len(copies))
        self.assertEqual("deploy_tooling_common_files_written", copies[0]["register"])

    def test_the_request_defaults_to_empty_and_the_spec_says_so(self) -> None:
        options = mapping(
            mapping(mapping(mapping(load("meta/argument_specs.yml"))["argument_specs"])["main"])[
                "options"
            ]
        )
        option = mapping(options["deploy_tooling_tenant_units"])
        self.assertEqual("list", option["type"])
        self.assertEqual([], option["default"])
        self.assertEqual([], mapping(load("defaults/main.yml"))["deploy_tooling_tenant_units"])


if __name__ == "__main__":
    unittest.main()
