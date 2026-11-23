"""Tests of check_required_inputs: a required, no-default role input must come from the host.

Each fixture builds a small tree (one playbook, its roles, the loader's rows) in a temporary
directory and runs the check on it, so every supply path and every refusal is seen on its own.
The real-tree test reads the repository and holds the playbooks as they are.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_required_inputs import ROOT, findings

REQUIRED = {"options": {"needed": {"type": "str", "required": True}}}


class Tree:
    """A temporary tree with one host playbook, the roles it names, and the loader's rows."""

    def __init__(self, test: unittest.TestCase) -> None:
        holder = tempfile.TemporaryDirectory()
        test.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        self.playbooks = self.root / "ansible" / "playbooks"
        self.roles = self.root / "ansible" / "roles"
        self.playbooks.mkdir(parents=True)
        self.roles.mkdir(parents=True)

    def write(self, relative: str, data: object) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data), encoding="utf-8")

    def role(
        self,
        name: str,
        options: dict[str, object] | None = None,
        defaults: dict[str, object] | None = None,
        vars_: dict[str, object] | None = None,
    ) -> None:
        spec = {"argument_specs": {"main": options if options is not None else REQUIRED}}
        self.write(f"ansible/roles/{name}/meta/argument_specs.yml", spec)
        if defaults is not None:
            self.write(f"ansible/roles/{name}/defaults/main.yml", defaults)
        if vars_ is not None:
            self.write(f"ansible/roles/{name}/vars/main.yml", vars_)

    def loader(
        self,
        required: dict[str, list[str]] | None = None,
        optional: dict[str, list[str]] | None = None,
    ) -> None:
        self.write(
            "ansible/roles/host_inputs/vars/main.yml",
            {
                "host_inputs_required_by_host": required or {},
                "host_inputs_optional_by_host": optional or {},
            },
        )

    def host(
        self,
        roles: list[object],
        play_vars: dict[str, object] | None = None,
        vars_files: list[str] | None = None,
    ) -> None:
        play: dict[str, object] = {"hosts": "all", "roles": roles}
        if play_vars is not None:
            play["vars"] = play_vars
        if vars_files is not None:
            play["vars_files"] = vars_files
        self.write("ansible/playbooks/h1.yml", [play])

    def run(self) -> list[str]:
        return findings(self.root)


def role_entry(name: str, **extra: object) -> dict[str, object]:
    return {"role": f"../roles/{name}", **extra}


class RequiredInputTests(unittest.TestCase):
    def test_a_required_input_with_nothing_supplying_it_is_found(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.host([role_entry("r1")])
        found = tree.run()
        self.assertEqual(1, len(found), found)
        self.assertIn("h1: role r1 requires needed", found[0])

    def test_a_default_of_the_role_supplies_it(self) -> None:
        tree = Tree(self)
        tree.role("r1", defaults={"needed": "x"})
        tree.host([role_entry("r1")])
        self.assertEqual([], tree.run())

    def test_a_var_of_the_role_supplies_it(self) -> None:
        tree = Tree(self)
        tree.role("r1", vars_={"needed": "x"})
        tree.host([role_entry("r1")])
        self.assertEqual([], tree.run())

    def test_a_var_of_the_play_supplies_it(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.host([role_entry("r1")], play_vars={"needed": "x"})
        self.assertEqual([], tree.run())

    def test_a_var_of_the_role_entry_supplies_it(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.host([role_entry("r1", vars={"needed": "x"})])
        self.assertEqual([], tree.run())

    def test_a_vars_file_of_the_play_supplies_it_and_a_missing_one_is_found(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.write("ansible/playbooks/includes/shared.yml", {"needed": "x"})
        tree.host([role_entry("r1")], vars_files=["{{ playbook_dir }}/includes/shared.yml"])
        self.assertEqual([], tree.run())
        tree.host([role_entry("r1")], vars_files=["{{ playbook_dir }}/includes/gone.yml"])
        found = tree.run()
        self.assertTrue(any("gone.yml does not resolve to a file" in item for item in found), found)

    def test_a_host_row_supplies_it_when_the_loader_is_applied_before_the_role(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.loader(required={"h1": ["needed"]})
        tree.host([role_entry("host_inputs"), role_entry("r1")])
        self.assertEqual([], tree.run())

    def test_a_host_row_supplies_nothing_when_the_loader_comes_after_the_role(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.role("host_inputs", options={"options": {}}, defaults={})
        tree.loader(required={"h1": ["needed"]})
        tree.host([role_entry("r1"), role_entry("host_inputs")])
        self.assertEqual(1, len(tree.run()))

    def test_a_host_row_supplies_nothing_when_the_play_does_not_apply_the_loader(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.loader(required={"h1": ["needed"]})
        tree.host([role_entry("r1")])
        self.assertEqual(1, len(tree.run()))

    def test_an_optional_row_name_supplies_it_when_the_loader_is_applied_before(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.loader(optional={"h1": ["needed"]})
        tree.host([role_entry("host_inputs"), role_entry("r1")])
        self.assertEqual([], tree.run())

    def test_a_row_of_another_host_supplies_nothing(self) -> None:
        tree = Tree(self)
        tree.role("r1")
        tree.loader(required={"h2": ["needed"]})
        tree.host([role_entry("host_inputs"), role_entry("r1")])
        self.assertEqual(1, len(tree.run()))

    def test_a_spec_with_a_default_or_not_required_is_not_a_required_input(self) -> None:
        tree = Tree(self)
        tree.role("r1", options={"options": {"needed": {"type": "str", "default": "x"}}})
        tree.role("r2", options={"options": {"needed": {"type": "str", "required": False}}})
        tree.host([role_entry("r1"), role_entry("r2")])
        self.assertEqual([], tree.run())


class RealTreeTests(unittest.TestCase):
    def test_the_repository_has_no_unsupplied_required_input(self) -> None:
        self.assertEqual([], findings(ROOT))


if __name__ == "__main__":
    unittest.main()
