"""Check that this role's Molecule fixtures name no instance the deploy wrapper would accept.

The role's container test starts a probe instance of the compose template unit. The compose
unit contract test (`hetzner/provision/test_compose_unit_contract.py`) reads the whole
repository for instance names and requires each to be a stack it covers or one that another
repository owns. The probe is neither, and an entry for it in the register that names an
owning repository would be an exemption. The probe is not a stack: its name is one the wrapper
refuses, which the contract scan applies too, so it is not read. This check keeps the probe
that way: it fails when a fixture under the role's `molecule/` names an instance that the
wrapper's own rule accepts. Other roles' fixtures name real stacks other repositories own, and
the register classifies those; they are not this role's probe and are not read here.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars

_NAME = r"[A-Za-z0-9_-]+"
# Every written shape that names one instance: the same shapes the contract scan reads, with
# a name class wide enough to include the names the wrapper refuses.
_MENTIONS = (
    re.compile(rf"branchleft-compose@({_NAME})"),
    re.compile(rf"/opt/branchleft/({_NAME})"),
    re.compile(rf"/etc/branchleft/({_NAME})(?:\.image)?\.env"),
)


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


def fixture_instance_problems(role: Path, rule: re.Pattern[str]) -> list[str]:
    """Return each fixture under the role's molecule directory that names a possible stack."""
    problems: list[str] = []
    for path in sorted(role.glob("molecule/**/*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        shown = path.relative_to(role.parent).as_posix()
        for pattern in _MENTIONS:
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
            fixture_instance_problems(role_vars.ROLE, wrapper_rule(role_vars.PROVISION)), []
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

    def test_a_name_the_wrapper_accepts_is_found_in_every_shape(self) -> None:
        (self.fixtures / "prepare.yml").write_text(
            "- ansible.builtin.file: {path: /opt/branchleft/molecule-probe}\n"
            "- ansible.builtin.copy: {dest: /etc/branchleft/molecule-probe.image.env}\n"
            "- ansible.builtin.systemd_service:"
            " {name: 'branchleft-compose@molecule-probe.service'}\n",
            encoding="utf-8",
        )
        self.assertEqual(
            fixture_instance_problems(self.role, self.rule),
            [
                "some_role/molecule/default/prepare.yml names the instance molecule-probe,"
                " which the deploy wrapper accepts"
            ]
            * 3,
        )

    def test_a_name_the_wrapper_refuses_is_not_found(self) -> None:
        (self.fixtures / "prepare.yml").write_text(
            "- ansible.builtin.file: {path: /opt/branchleft/Molecule-Probe}\n"
            "- ansible.builtin.copy: {dest: /etc/branchleft/Molecule-Probe.image.env}\n"
            "- ansible.builtin.systemd_service:"
            " {name: 'branchleft-compose@Molecule-Probe.service'}\n",
            encoding="utf-8",
        )
        self.assertEqual(fixture_instance_problems(self.role, self.rule), [])

    def test_the_template_and_the_slot_register_are_not_instances(self) -> None:
        (self.fixtures / "prepare.yml").write_text(
            "- ansible.builtin.copy: {dest: /etc/systemd/system/branchleft-compose@.service}\n"
            "- ansible.builtin.file: {path: /etc/branchleft/deploy-slots/blog.pub}\n",
            encoding="utf-8",
        )
        self.assertEqual(fixture_instance_problems(self.role, self.rule), [])

    def test_a_name_outside_a_molecule_directory_is_not_this_checks_to_find(self) -> None:
        (self.role / "tasks").mkdir()
        (self.role / "tasks" / "main.yml").write_text(
            "- ansible.builtin.file: {path: /opt/branchleft/website}\n", encoding="utf-8"
        )
        self.assertEqual(fixture_instance_problems(self.role, self.rule), [])


if __name__ == "__main__":
    unittest.main()
