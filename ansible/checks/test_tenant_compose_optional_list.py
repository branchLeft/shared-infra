"""tenant_compose_stacks is optional: an undefined list delivers nothing, and a defined one is untouched.

A host with no tenant yet has no list in its host_inputs file, and the loader counts an empty list
as missing, so the list cannot be required on such a host. The role reads an undefined list as the
empty list its argument spec already accepts. These tests hold that guard in place: the argument
is not required, and the first task that touches the list sets it to empty only when it is not
defined. Owner-held checks (checks/) are not edited by this change; the test reads the role only.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ANSIBLE = Path(__file__).resolve().parents[1]
ROLE = ANSIBLE / "roles" / "tenant_compose"
GUARD_NAME = "Read an undefined tenant list as an empty one"


def _load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _spec() -> dict[str, object]:
    doc = _mapping(_load(ROLE / "meta" / "argument_specs.yml"))
    main = _mapping(_mapping(doc.get("argument_specs")).get("main"))
    options = _mapping(main.get("options"))
    return _mapping(options.get("tenant_compose_stacks"))


def _tasks() -> list[dict[str, object]]:
    raw = _load(ROLE / "tasks" / "main.yml")
    if not isinstance(raw, list):
        return []
    return [_mapping(entry) for entry in raw]


class OptionalTenantList(unittest.TestCase):
    def test_the_argument_is_not_required_and_has_no_default(self) -> None:
        spec = _spec()
        self.assertIs(spec["required"], False)
        self.assertNotIn("default", spec)

    def test_the_guard_sets_the_empty_list_only_when_undefined(self) -> None:
        guards = [t for t in _tasks() if t.get("name") == GUARD_NAME]
        self.assertEqual(len(guards), 1)
        guard = guards[0]
        self.assertEqual(guard["ansible.builtin.set_fact"], {"tenant_compose_stacks": []})
        self.assertEqual(guard["when"], "tenant_compose_stacks is not defined")
        self.assertIs(guard["no_log"], True)

    def test_the_guard_runs_before_any_task_reads_the_list(self) -> None:
        tasks = _tasks()
        names = [str(t.get("name", "")) for t in tasks]
        guard_at = names.index(GUARD_NAME)
        for task in tasks[:guard_at]:
            self.assertNotIn("tenant_compose_stacks", yaml.safe_dump(task))


if __name__ == "__main__":
    unittest.main()
