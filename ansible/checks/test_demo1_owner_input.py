"""demo1 receives the owner's due-diligence address from its host inputs file (workspace#1825).

The address is never in this repository. demo1 takes it the way the other hosts take their
private values: a row of the host_inputs loader, listed as optional (so the pull is not stopped
before the owner places the value), and the loader applied in demo1's playbook before any role
that reads the value. The loader's own refusals (an empty or blank value) are held by its
registry test; the broker's refusal of an absent value is held by the broker_deploy unit tests.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ANSIBLE = Path(__file__).resolve().parents[1]
INPUT = "broker_deploy_owner_due_diligence_email"
LOADER = "host_inputs"
PULL_ROLES = frozenset(("ansible_runtime", "pull_trigger"))


def _doc(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class Demo1OwnerInput(unittest.TestCase):
    def setUp(self) -> None:
        self.loader = _doc(ANSIBLE / "roles" / LOADER / "vars" / "main.yml")
        self.playbook = _doc(ANSIBLE / "playbooks" / "demo1.yml")

    def test_demo1_row_names_the_owner_address(self) -> None:
        rows = self.loader["host_inputs_required_by_host"]
        self.assertIn(INPUT, rows["demo1"])

    def test_demo1_lists_the_address_as_optional(self) -> None:
        optional = self.loader["host_inputs_optional_by_host"]
        self.assertIn(INPUT, optional["demo1"])

    def test_demo1_applies_the_loader_after_the_pull_roles_and_before_any_reader(self) -> None:
        roles = [Path(str(entry.get("role", entry))).name for entry in self.playbook[0]["roles"]]
        self.assertIn(LOADER, roles)
        self.assertEqual(roles[: roles.index(LOADER)], ["ansible_runtime", "pull_trigger"])
        self.assertLess(roles.index(LOADER), roles.index("broker_deploy"))
        self.assertLess(roles.index(LOADER), roles.index("demo1_build"))
        self.assertEqual(set(roles[: roles.index(LOADER)]), PULL_ROLES)


if __name__ == "__main__":
    unittest.main()
