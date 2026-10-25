"""Check that this role's Molecule fixtures name no instance the deploy wrapper would accept.

The compose unit contract test reads the repository for instance names and requires each to
be a registered stack. The role's probe instance is not one, and a register entry for it would
be an exemption. Its name is one the wrapper refuses, which that scan applies too, so it is not
read. This check fails when a fixture under this role's `molecule/` names an instance that the
wrapper's own rule accepts. Other roles' fixtures name real stacks, which the register covers.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars

# A name class wide enough to include the names the wrapper refuses.
_NAME = r"[A-Za-z0-9_-]+"


def mention_shapes(provision: Path) -> tuple[re.Pattern[str], ...]:
    """Return every written shape that names one instance, with a name class that is wide.

    The shapes are the contract scan's own, built by its function from the class given here, so
    that a shape added to that scan is read here too and this check holds no list of its own.

    Raises:
        RuntimeError: the contract scan cannot be loaded as a module.
        TypeError: its shapes are not a tuple of compiled patterns.
    """
    path = provision / "test_compose_unit_contract.py"
    spec = importlib.util.spec_from_file_location("compose_unit_contract_for_probe_check", path)
    if spec is None or spec.loader is None:
        message = f"{path} cannot be loaded"
        raise RuntimeError(message)
    module = importlib.util.module_from_spec(spec)
    # The scan imports the deploy wrapper by name, from the directory it sits in.
    sys.path.insert(0, str(provision))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(provision))
    shapes = module.stack_mention_shapes(_NAME)
    if not isinstance(shapes, tuple) or not all(isinstance(s, re.Pattern) for s in shapes):
        message = "stack_mention_shapes did not return a tuple of compiled patterns"
        raise TypeError(message)
    return shapes


def wrapper_rule(provision: Path) -> re.Pattern[str]:
    """Return the stack-name rule the deploy wrapper applies, read from the wrapper itself.

    Raises:
        RuntimeError: the wrapper cannot be loaded as a module.
        TypeError: the wrapper's rule is not a compiled pattern.
    """
    spec = importlib.util.spec_from_file_location(
        "branchleft_deploy_for_probe_check", provision / "branchleft_deploy.py"
    )
    if spec is None or spec.loader is None:
        message = "hetzner/provision/branchleft_deploy.py cannot be loaded"
        raise RuntimeError(message)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rule = module.STACK_NAME
    if not isinstance(rule, re.Pattern):
        message = "branchleft_deploy.STACK_NAME is not a compiled pattern"
        raise TypeError(message)
    return rule


def fixture_instance_problems(
    role: Path, rule: re.Pattern[str], shapes: tuple[re.Pattern[str], ...]
) -> list[str]:
    """Return each fixture under the role's molecule directory that names a possible stack."""
    problems: list[str] = []
    for path in sorted(role.glob("molecule/**/*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        shown = path.relative_to(role.parent).as_posix()
        for pattern in shapes:
            problems.extend(
                f"{shown} names the instance {found}, which the deploy wrapper accepts"
                for found in sorted({m.group(1) for m in pattern.finditer(text)})
                if rule.fullmatch(found)
            )
    return problems


class TestRealTree(unittest.TestCase):
    """The role's fixtures name no instance that could be a stack."""

    def test_no_fixture_names_an_instance_the_wrapper_accepts(self) -> None:
        self.assertEqual(
            fixture_instance_problems(
                role_vars.ROLE,
                wrapper_rule(role_vars.PROVISION),
                mention_shapes(role_vars.PROVISION),
            ),
            [],
        )

    def test_the_rule_is_the_wrappers_own(self) -> None:
        rule = wrapper_rule(role_vars.PROVISION)
        self.assertIsNotNone(rule.fullmatch("website"))
        self.assertIsNone(rule.fullmatch("Molecule-Probe"))


class TestControls(unittest.TestCase):
    """A fixture that names a valid stack is found, and one the wrapper refuses is not."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="deploy-tooling-probe-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.role = self.work / "roles" / "some_role"
        self.fixtures = self.role / "molecule" / "default"
        self.fixtures.mkdir(parents=True)
        self.rule = wrapper_rule(role_vars.PROVISION)
        self.shapes = mention_shapes(role_vars.PROVISION)

    def test_a_name_the_wrapper_accepts_is_found_in_every_shape(self) -> None:
        (self.fixtures / "prepare.yml").write_text(
            "- ansible.builtin.file: {path: /opt/branchleft/molecule-probe}\n"
            "- ansible.builtin.copy: {dest: /etc/branchleft/molecule-probe.image.env}\n"
            "- ansible.builtin.systemd_service:"
            " {name: 'branchleft-compose@molecule-probe.service'}\n"
            "- ansible.builtin.lineinfile:"
            " {line: 'ssh-ed25519 AAAAC3 branchleft-slot:molecule-probe'}\n",
            encoding="utf-8",
        )
        self.assertEqual(
            fixture_instance_problems(self.role, self.rule, self.shapes),
            [
                "some_role/molecule/default/prepare.yml names the instance molecule-probe,"
                " which the deploy wrapper accepts"
            ]
            * 4,
        )

    def test_a_name_the_wrapper_refuses_is_not_found(self) -> None:
        (self.fixtures / "prepare.yml").write_text(
            "- ansible.builtin.file: {path: /opt/branchleft/Molecule-Probe}\n"
            "- ansible.builtin.copy: {dest: /etc/branchleft/Molecule-Probe.image.env}\n"
            "- ansible.builtin.systemd_service:"
            " {name: 'branchleft-compose@Molecule-Probe.service'}\n",
            encoding="utf-8",
        )
        self.assertEqual(fixture_instance_problems(self.role, self.rule, self.shapes), [])

    def test_the_template_and_the_slot_register_are_not_instances(self) -> None:
        (self.fixtures / "prepare.yml").write_text(
            "- ansible.builtin.copy: {dest: /etc/systemd/system/branchleft-compose@.service}\n"
            "- ansible.builtin.file: {path: /etc/branchleft/deploy-slots/blog.pub}\n",
            encoding="utf-8",
        )
        self.assertEqual(fixture_instance_problems(self.role, self.rule, self.shapes), [])

    def test_a_name_outside_a_molecule_directory_is_not_this_checks_to_find(self) -> None:
        (self.role / "tasks").mkdir()
        (self.role / "tasks" / "main.yml").write_text(
            "- ansible.builtin.file: {path: /opt/branchleft/website}\n", encoding="utf-8"
        )
        self.assertEqual(fixture_instance_problems(self.role, self.rule, self.shapes), [])


if __name__ == "__main__":
    unittest.main()
