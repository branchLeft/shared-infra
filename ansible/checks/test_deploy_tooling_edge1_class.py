"""Check that the playbook of the gateway host gives the deploy_tooling role the gateway class.

edge1 holds the estate's shared address, and the Docker user policy program refuses to run on
the host that holds it. The role has no default class, so the play must state `gateway`; a
play that states `app` would install the program there and the host's apply would fail at the
first restart. The role must also be in the play's role list, or the class is never read.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars
from ruamel.yaml import YAML

PLAYBOOK = role_vars.REPO_ROOT / "ansible" / "playbooks" / "edge1.yml"
CLASS_VARIABLE = "deploy_tooling_host_class"
EXPECTED_CLASS = "gateway"


def class_problems(playbook: Path) -> list[str]:
    """Return what is wrong with how the playbook's plays give the role its host class."""
    document: object = YAML(typ="safe").load(playbook.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        return ["the playbook is not a list of plays"]
    problems: list[str] = []
    carrying = 0
    for play in document:
        if not isinstance(play, dict):
            problems.append("a play is not a mapping")
            continue
        roles = play.get("roles", [])
        names = [
            str(entry.get("role", "")) if isinstance(entry, dict) else str(entry)
            for entry in (roles if isinstance(roles, list) else [])
        ]
        if not any(name.rstrip("/").endswith("deploy_tooling") for name in names):
            continue
        carrying += 1
        variables = play.get("vars")
        value = variables.get(CLASS_VARIABLE) if isinstance(variables, dict) else None
        if value != EXPECTED_CLASS:
            problems.append(
                f"a play with the role sets {CLASS_VARIABLE} to {value!r},"
                f" expected {EXPECTED_CLASS!r}"
            )
    if carrying == 0:
        problems.append("no play of the playbook carries the deploy_tooling role")
    return problems


class TestEdge1Class(unittest.TestCase):
    """The real playbook states the gateway class, and each other state is found."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="deploy-tooling-class-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.copy = self.work / "edge1.yml"
        shutil.copy(PLAYBOOK, self.copy)

    def altered(self, old: str, new: str) -> list[str]:
        text = self.copy.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.copy.write_text(text.replace(old, new, 1), encoding="utf-8")
        return class_problems(self.copy)

    def test_the_real_playbook_states_the_gateway_class(self) -> None:
        self.assertEqual(class_problems(PLAYBOOK), [])

    def test_the_app_class_is_found(self) -> None:
        found = self.altered(f"{CLASS_VARIABLE}: gateway", f"{CLASS_VARIABLE}: app")
        self.assertEqual(
            found,
            ["a play with the role sets deploy_tooling_host_class to 'app', expected 'gateway'"],
        )

    def test_a_missing_class_is_found(self) -> None:
        found = self.altered(f"    {CLASS_VARIABLE}: gateway\n", "    unrelated: true\n")
        self.assertEqual(
            found,
            ["a play with the role sets deploy_tooling_host_class to None, expected 'gateway'"],
        )

    def test_a_playbook_without_the_role_is_found(self) -> None:
        found = self.altered("    - role: ../roles/deploy_tooling # noqa: role-name[path]\n", "")
        self.assertEqual(found, ["no play of the playbook carries the deploy_tooling role"])


if __name__ == "__main__":
    unittest.main()
