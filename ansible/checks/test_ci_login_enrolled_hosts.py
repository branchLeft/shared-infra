"""Pins: ci_login is wired on dbt1 and appt1 as on edge1, after egress_nat.

The full role-list pin in test_check_host_roles.py covers the hosts it names; dbt1 and appt1 are
not among them. This test holds the two new hosts to the same wiring: the role is in the host's
playbook and in its host-roles list, and comes after egress_nat and before the deploy roles. Each
pin runs red on a sabotaged playbook and green once it is put back.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
HOSTS = ("dbt1", "appt1")
ROLE = "ci_login"


def _read(path: Path) -> object:
    document, finding = load_yaml(path)
    if finding is not None:
        raise AssertionError(finding)
    return document


def _playbook_roles(host: str) -> list[str]:
    plays = cast(
        list[dict[str, list[dict[str, str]]]], _read(ROOT / "ansible" / "playbooks" / f"{host}.yml")
    )
    return [Path(entry["role"]).name for entry in plays[0]["roles"]]


def _host_roles(host: str) -> list[str]:
    lines = (ROOT / "ansible" / "checks" / "host_roles" / f"{host}.yml").read_text().splitlines()
    return [line[2:].strip() for line in lines if line.startswith("- ")]


class CiLoginWiringTest(unittest.TestCase):
    def test_playbook_applies_ci_login_after_egress_nat(self) -> None:
        for host in HOSTS:
            with self.subTest(host=host):
                names = _playbook_roles(host)
                self.assertIn(ROLE, names)
                self.assertEqual(names.count(ROLE), 1)
                self.assertLess(names.index("egress_nat"), names.index(ROLE))
                self.assertLess(names.index("pull_trigger"), names.index(ROLE))

    def test_host_roles_list_ci_login_after_egress_nat(self) -> None:
        for host in HOSTS:
            with self.subTest(host=host):
                names = _host_roles(host)
                self.assertIn(ROLE, names)
                self.assertLess(names.index("egress_nat"), names.index(ROLE))


if __name__ == "__main__":
    unittest.main()
