"""Tests for check_role_imports: the real tree passes, and each way to import a role fails."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_role_imports import ROOT, check


class RealTree(unittest.TestCase):
    def test_no_role_imports_another(self) -> None:
        self.assertEqual(check(ROOT), [])


class Imports(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def _write(self, relative: str, text: str) -> None:
        path = self.root / "ansible" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _refused(self, relative: str, text: str, expected: str) -> None:
        self._write(relative, text)
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn(expected, findings[0])

    def test_a_role_that_applies_no_other_role_passes(self) -> None:
        copy = "- ansible.builtin.copy: {dest: /etc/a, content: x}\n"
        self._write("roles/a/tasks/main.yml", copy)
        self._write("roles/a/meta/main.yml", "dependencies: []\n")
        self.assertEqual(check(self.root), [])

    def test_include_role_is_refused(self) -> None:
        self._refused(
            "roles/a/tasks/main.yml", "- ansible.builtin.include_role: {name: b}\n", "include_role"
        )

    def test_import_role_in_a_block_is_refused_in_any_spelling(self) -> None:
        self._refused(
            "patterns/a/handlers/main.yml",
            "- block:\n    - import_role: {name: b}\n",
            "import_role",
        )

    def test_a_meta_dependency_is_refused(self) -> None:
        self._refused("roles/a/meta/main.yml", "dependencies:\n  - role: b\n", "dependencies")

    def test_a_task_file_from_outside_the_role_is_refused(self) -> None:
        self._refused(
            "roles/a/tasks/main.yml",
            "- ansible.builtin.include_tasks: ../../b/tasks/main.yml\n",
            "reaches outside",
        )

    def test_a_molecule_playbook_may_apply_roles(self) -> None:
        self._write("roles/a/molecule/default/converge.yml", "- hosts: all\n  roles: [a, b]\n")
        self.assertEqual(check(self.root), [])

    def test_a_file_that_does_not_parse_is_refused(self) -> None:
        self._write("roles/a/tasks/main.yml", "- [unclosed\n")
        self.assertEqual(1, len(check(self.root)))


CAPABILITY_SPEC = (
    "argument_specs:\n  main:\n    options:\n      target_path:\n        type: path\n"
    "        required: true\n      mode:\n        type: str\n        default: '0644'\n"
)
CALLER_INCLUDE = (
    "- ansible.builtin.include_role:\n    name: cap\n    vars:\n      target_path: /etc/x\n"
    "      mode: '0600'\n"
)


class CapabilityRoles(unittest.TestCase):
    """ANS-12: a role may include a capability role with include_role, every input given."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def _write(self, relative: str, text: str) -> None:
        path = self.root / "ansible" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _capability(self, readme: str = "Called by a.\n") -> None:
        self._write("roles/cap/meta/argument_specs.yml", CAPABILITY_SPEC)
        self._write("roles/cap/tasks/main.yml", "- ansible.builtin.copy: {dest: x, content: y}\n")
        self._write("roles/cap/README.md", readme)

    def test_a_capability_role_included_with_every_input_passes(self) -> None:
        self._capability()
        self._write("roles/a/tasks/main.yml", CALLER_INCLUDE)
        self.assertEqual(check(self.root), [])

    def test_a_capability_role_with_an_input_not_given_is_refused(self) -> None:
        self._capability()
        self._write(
            "roles/a/tasks/main.yml",
            "- ansible.builtin.include_role:\n    name: cap\n    vars:\n"
            "      target_path: /etc/x\n",
        )
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn("mode", findings[0])

    def test_a_capability_include_with_no_vars_is_refused_when_inputs_exist(self) -> None:
        self._capability()
        self._write("roles/a/tasks/main.yml", "- ansible.builtin.include_role: {name: cap}\n")
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn("target_path", findings[0])

    def test_include_of_a_role_with_no_argument_specs_is_refused(self) -> None:
        self._write("roles/b/tasks/main.yml", "- ansible.builtin.copy: {dest: x, content: y}\n")
        self._write("roles/a/tasks/main.yml", "- ansible.builtin.include_role: {name: b}\n")
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn("not a capability role", findings[0])

    def test_include_of_a_role_that_restarts_a_service_is_refused(self) -> None:
        self._capability()
        self._write(
            "roles/cap/tasks/main.yml",
            "- ansible.builtin.copy: {dest: x, content: y}\n  notify: restart app\n",
        )
        self._write("roles/a/tasks/main.yml", CALLER_INCLUDE)
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn("restarts or reloads", findings[0])

    def test_a_caller_missing_from_the_capability_readme_is_refused(self) -> None:
        self._capability(readme="Called by nothing yet.\n")
        self._write("roles/a/tasks/main.yml", CALLER_INCLUDE)
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn("README", findings[0])

    def test_a_free_form_include_of_a_capability_role_is_refused(self) -> None:
        self._capability()
        self._write("roles/a/tasks/main.yml", "- ansible.builtin.include_role: name=cap\n")
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)

    def test_import_of_a_capability_role_is_still_refused(self) -> None:
        self._capability()
        self._write(
            "roles/a/tasks/main.yml",
            "- ansible.builtin.import_role:\n    name: cap\n    vars:\n      target_path: /etc/x\n"
            "      mode: '0600'\n",
        )
        findings = check(self.root)
        self.assertEqual(1, len(findings), findings)
        self.assertIn("import_role", findings[0])

    def test_a_templated_role_name_is_refused(self) -> None:
        self._capability()
        self._write(
            "roles/a/tasks/main.yml",
            "- ansible.builtin.include_role:\n    name: '{{ which }}'\n"
            "    vars: {target_path: x}\n",
        )
        self.assertEqual(1, len(check(self.root)))


if __name__ == "__main__":
    unittest.main()
