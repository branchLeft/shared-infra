"""deploy_tooling enables each listed tenant's compose instance, and never starts or restarts one.

Owner ruling, 22 Nov: the tenant list is the one place a tenant's compose
instance is enabled, and deploy_tooling makes that enable. A start or restart would deploy a stack
before the deploy wrapper has written its first pin, so the task carries no state. An undefined list
enables nothing. These tests read the role's tasks and vars only.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ANSIBLE = Path(__file__).resolve().parents[1]
ROLE = ANSIBLE / "roles" / "deploy_tooling"
ENABLE_NAME = "Enable each listed tenant's compose unit, without starting it"
FLUSH_NAME = "Make the template unit known to systemd before any instance is enabled"


def _load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _tasks() -> list[dict[str, object]]:
    raw = _load(ROLE / "tasks" / "main.yml")
    if not isinstance(raw, list):
        return []
    return [_mapping(entry) for entry in raw]


def _named(name: str) -> list[dict[str, object]]:
    return [t for t in _tasks() if t.get("name") == name]


class TenantUnitEnable(unittest.TestCase):
    def test_the_enable_task_exists_once_and_enables_without_a_state(self) -> None:
        tasks = _named(ENABLE_NAME)
        self.assertEqual(len(tasks), 1)
        body = _mapping(tasks[0].get("ansible.builtin.systemd_service"))
        self.assertIs(body["enabled"], True)
        self.assertNotIn("state", body)
        self.assertNotIn("started", yaml.safe_dump(body))
        self.assertNotIn("restarted", yaml.safe_dump(body))

    def test_the_instance_name_is_the_prefix_at_the_slug(self) -> None:
        body = _mapping(_named(ENABLE_NAME)[0].get("ansible.builtin.systemd_service"))
        self.assertEqual(
            body["name"], "{{ deploy_tooling_compose_unit_prefix }}@{{ item }}.service"
        )

    def test_the_loop_is_the_slugs_and_is_empty_when_the_list_is_undefined(self) -> None:
        loop = str(_named(ENABLE_NAME)[0].get("loop"))
        self.assertIn("tenant_compose_stacks | default([])", loop)
        self.assertIn('map(attribute="slug")', loop)

    def test_the_task_hides_the_list_it_reads(self) -> None:
        self.assertIs(_named(ENABLE_NAME)[0]["no_log"], True)

    def test_systemd_knows_the_template_before_an_instance_is_enabled(self) -> None:
        tasks = _tasks()
        names = [str(t.get("name", "")) for t in tasks]
        flush_at = names.index(FLUSH_NAME)
        enable_at = names.index(ENABLE_NAME)
        self.assertLess(flush_at, enable_at)
        self.assertEqual(tasks[flush_at].get("ansible.builtin.meta"), "flush_handlers")

    def test_the_prefix_is_a_role_variable(self) -> None:
        vars_doc = _mapping(_load(ROLE / "vars" / "main.yml"))
        self.assertEqual(vars_doc["deploy_tooling_compose_unit_prefix"], "branchleft-compose")


if __name__ == "__main__":
    unittest.main()
