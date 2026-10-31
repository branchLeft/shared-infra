"""Unit tests for the tenant_onboarding role's guard, its pins and its single home.

The guard is what keeps a tenant step from running on a plain apply or from a copied
tag. Ansible enforces the tag: a step is imported with the never tag and its own step
tag. The first task of each step file enforces the confirmation: it refuses unless
tenant_onboarding_confirm names that step. These tests read the role's own files and fail
when a step file loses its confirmation assertion, when an import loses its never tag or
its own tag, when a step confirms another step's id, or when a second home for the
program appears.

Sabotage, the CI-runnable red and then green for this guard: delete the confirmation
assert from a step file, or the never tag from an import, and the guard tests fail; put
it back and they pass.
"""

import re
import unittest
from pathlib import Path
from typing import Any

import yaml

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks"
VARS = ROLE / "vars" / "main.yml"
ROLES_DIR = ROLE.parent
PATTERNS_DIR = ROLE.parent.parent / "patterns"

# Each guarded step: its file, its step id and its tag. The ids and tags are the contract
# a maintainer types on the command line, so a rename is a change these tests show.
STEPS: dict[str, tuple[str, str]] = {
    "_volumes.yml": ("PROVISION_TENANT_VOLUMES", "tenant_onboarding_provision_volumes"),
}

SHELL_MODULES = ("ansible.builtin.shell", "ansible.builtin.raw", "ansible.builtin.script")


class NotATaskListError(TypeError):
    """A tasks file is not a YAML list of tasks."""


def _tasks(path: Path) -> list[dict[str, Any]]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise NotATaskListError(path.name)
    return loaded


def _tags(task: dict[str, Any]) -> list[str]:
    tags = task.get("tags", [])
    return [tags] if isinstance(tags, str) else list(tags)


def _module(task: dict[str, Any]) -> str | None:
    for key in task:
        if key.startswith("ansible.builtin.") or "." in key:
            return key
    return None


class GuardShapeTests(unittest.TestCase):
    def test_each_step_file_starts_with_its_confirmation_assert(self) -> None:
        for filename, (step_id, _tag) in STEPS.items():
            with self.subTest(step=step_id):
                first = _tasks(TASKS / filename)[0]
                self.assertIn(
                    "ansible.builtin.assert", first, f"{filename} must start with its assert"
                )
                self.assertEqual(
                    first["ansible.builtin.assert"]["that"],
                    [f"tenant_onboarding_confirm == '{step_id}'"],
                    f"{filename} must confirm exactly {step_id}",
                )
                self.assertTrue(
                    first["ansible.builtin.assert"]["fail_msg"].startswith("REFUSED:"),
                    f"{filename}'s refusal must begin REFUSED:",
                )

    def test_each_step_is_imported_with_never_and_its_own_tag(self) -> None:
        imports = {
            task["ansible.builtin.import_tasks"]: task
            for task in _tasks(TASKS / "main.yml")
            if "ansible.builtin.import_tasks" in task
        }
        for filename, (step_id, tag) in STEPS.items():
            with self.subTest(step=step_id):
                self.assertIn(filename, imports, f"{step_id} is not imported in tasks/main.yml")
                tags = _tags(imports[filename])
                self.assertIn("never", tags, f"{step_id}'s import lost its never tag")
                self.assertIn(tag, tags, f"{step_id}'s import lost its own tag {tag}")

    def test_no_step_is_imported_without_a_step_file(self) -> None:
        imported = {
            task["ansible.builtin.import_tasks"]
            for task in _tasks(TASKS / "main.yml")
            if "ansible.builtin.import_tasks" in task
        }
        guarded = {name for name in imported if name.startswith("_") and name != "_claims.yml"}
        self.assertEqual(guarded, set(STEPS), "the guarded imports and the step files disagree")

    def test_the_confirmation_check_runs_on_every_request(self) -> None:
        first = _tasks(TASKS / "main.yml")[0]
        self.assertIn("always", _tags(first), "the step id check must carry the always tag")
        self.assertIn("ansible.builtin.assert", first)

    def test_each_step_reads_the_claims_through_an_import(self) -> None:
        # An import inherits the tags of the file that imports it; an include would not, and
        # its tasks would be skipped under --tags. Both steps that read the claims import them.
        for filename in STEPS:
            with self.subTest(file=filename):
                imports = [
                    task["ansible.builtin.import_tasks"]
                    for task in _tasks(TASKS / filename)
                    if "ansible.builtin.import_tasks" in task
                ]
                self.assertIn("_claims.yml", imports)
                self.assertFalse(
                    [t for t in _tasks(TASKS / filename) if "ansible.builtin.include_tasks" in t],
                    f"{filename} must not include: an include does not inherit the step's tag",
                )

    def test_the_role_names_no_unit_the_deployment_tooling_installs(self) -> None:
        # The single-owner check (ansible/checks/test_deploy_tooling_single_owner.py) reads a
        # reference to a unit that deploy_tooling installs as a second owner of it. This role
        # names none, in its code or its values, so the check is not asked to exempt it.
        for path in [*TASKS.glob("*.yml"), VARS]:
            with self.subTest(file=path.name):
                self.assertNotIn("branchleft-compose", path.read_text(encoding="utf-8"))

    def test_step_ids_are_capitals_digits_and_underscore(self) -> None:
        for step_id, _tag in STEPS.values():
            self.assertRegex(step_id, r"\A[A-Z][A-Z0-9_]*\Z")


class RuleTests(unittest.TestCase):
    def test_no_task_uses_shell_raw_or_script(self) -> None:
        # ANS-3: no shell, raw or script in a role's tasks.
        for path in sorted(TASKS.glob("*.yml")):
            for task in _tasks(path):
                module = _module(task)
                with self.subTest(file=path.name, module=module):
                    self.assertNotIn(module, SHELL_MODULES)

    def test_no_python_is_shipped_in_the_role(self) -> None:
        # The program is fetched from ghost-platform. A .py file in the role is a second home.
        shipped = [
            p for p in ROLE.rglob("*.py") if "molecule" not in p.parts and "tests" not in p.parts
        ]
        self.assertEqual(shipped, [], "the role must not hold a copy of the tenant program")

    def test_no_other_role_or_pattern_names_the_program(self) -> None:
        # The program has one installer. Another role that installed it would be a second
        # home, and a second copy of the register it reads beside it.
        others = [
            path
            for base in (ROLES_DIR, PATTERNS_DIR)
            for path in base.rglob("*")
            if path.is_file() and ROLE not in path.parents
        ]
        offenders = []
        for path in others:
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if "provision_tenant_volume" in text:
                offenders.append(str(path.relative_to(ROLES_DIR.parent)))
        self.assertEqual(offenders, [], "another role or pattern names the tenant program")


class PinTests(unittest.TestCase):
    def _vars(self) -> dict[str, Any]:
        loaded = yaml.safe_load(VARS.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}

    def test_the_commit_is_a_full_sha(self) -> None:
        self.assertRegex(self._vars()["tenant_onboarding_ghost_commit"], r"\A[0-9a-f]{40}\Z")

    def test_each_digest_is_a_full_sha256(self) -> None:
        for key in ("tenant_onboarding_program_sha256", "tenant_onboarding_register_sha256"):
            with self.subTest(key=key):
                self.assertRegex(self._vars()[key], r"\A[0-9a-f]{64}\Z")

    def test_the_fetch_names_the_pinned_commit_not_a_branch(self) -> None:
        base = self._vars()["tenant_onboarding_ghost_raw_base"]
        self.assertIn("{{ tenant_onboarding_ghost_commit }}", base)
        self.assertNotIn("main", base)

    def test_the_program_and_register_paths_match_the_program_contract(self) -> None:
        # The program reads its register beside itself; the two must sit in one directory.
        values = self._vars()
        self.assertEqual(
            Path(values["tenant_onboarding_register"]).parent,
            Path(values["tenant_onboarding_program"]).parent,
        )

    def test_the_step_id_pattern_ends_with_z_not_dollar(self) -> None:
        # \Z, not $, so a confirmation with a trailing line break does not pass the check.
        pattern = self._vars()["tenant_onboarding_step_id_pattern"]
        self.assertTrue(pattern.endswith(r"\Z"))
        self.assertIsNotNone(re.match(pattern, "PROVISION_TENANT_VOLUMES"))
        self.assertIsNone(re.match(pattern, "PROVISION_TENANT_VOLUMES\n"))


class DefaultsTests(unittest.TestCase):
    def test_the_tenant_inputs_default_to_empty(self) -> None:
        defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        self.assertEqual(defaults["tenant_onboarding_confirm"], "")
        self.assertEqual(defaults["tenant_onboarding_slug"], "")
        self.assertEqual(defaults["tenant_onboarding_uid"], "")


if __name__ == "__main__":
    unittest.main()
