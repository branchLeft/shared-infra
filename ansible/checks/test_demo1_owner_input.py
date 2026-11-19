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
from typing import cast

import yaml  # type: ignore[import-untyped]

ANSIBLE = Path(__file__).resolve().parents[1]
INPUT = "broker_deploy_owner_due_diligence_email"
LOADER = "host_inputs"
PULL_ROLES = frozenset(("ansible_runtime", "pull_trigger"))


def _mapping(value: object) -> dict[str, object]:
    """Return a YAML mapping as a dict, or fail the test when it is not one."""
    if not isinstance(value, dict):
        message = f"expected a mapping, got {type(value).__name__}"
        raise TypeError(message)
    return cast("dict[str, object]", value)


def _names(value: object) -> dict[str, list[str]]:
    """Return a host-to-names mapping of the loader, with each name list as strings."""
    found: dict[str, list[str]] = {}
    for host, names in _mapping(value).items():
        if not isinstance(names, list):
            message = f"{host} holds no list of names"
            raise TypeError(message)
        found[host] = [str(name) for name in names]
    return found


def _doc(path: Path) -> dict[str, object]:
    return _mapping(yaml.safe_load(path.read_text(encoding="utf-8")))


def _play_roles(path: Path) -> list[object]:
    """Return the roles of a host playbook's one play."""
    plays = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(plays, list) or not plays:
        message = f"{path.name} holds no play"
        raise TypeError(message)
    return cast("list[object]", _mapping(plays[0])["roles"])


class Demo1OwnerInput(unittest.TestCase):
    def setUp(self) -> None:
        self.loader = _doc(ANSIBLE / "roles" / LOADER / "vars" / "main.yml")
        self.playbook = ANSIBLE / "playbooks" / "demo1.yml"

    def test_demo1_row_names_the_owner_address(self) -> None:
        rows = _names(self.loader["host_inputs_required_by_host"])
        self.assertIn(INPUT, rows["demo1"])

    def test_demo1_lists_the_address_as_optional(self) -> None:
        optional = _names(self.loader["host_inputs_optional_by_host"])
        self.assertIn(INPUT, optional["demo1"])

    def test_demo1_applies_the_loader_after_the_pull_roles_and_before_any_reader(self) -> None:
        roles = [
            Path(str(_mapping(entry).get("role", entry))).name for entry in _play_roles(self.playbook)
        ]
        self.assertIn(LOADER, roles)
        self.assertEqual(roles[: roles.index(LOADER)], ["ansible_runtime", "pull_trigger"])
        self.assertLess(roles.index(LOADER), roles.index("broker_deploy"))
        self.assertLess(roles.index(LOADER), roles.index("demo1_build"))
        self.assertEqual(set(roles[: roles.index(LOADER)]), PULL_ROLES)


if __name__ == "__main__":
    unittest.main()
