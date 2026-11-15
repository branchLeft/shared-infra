"""Unit tests for how tenant_compose pins a tenant's image: only through the deploy wrapper.

The behaviour is proven in the role's Molecule scenario, which runs the real wrapper with a
stand-in verifier. These tests hold the names the role shares with other homes to those homes,
and the shape of the pin tasks, so a review need not find either by eye: the tenant image
pattern is an image the wrapper's register verifies, the program the role runs is the path the
deploy tooling installs the wrapper to, and no task but the spool's copies a pin into place.
They need no network and no Docker.
"""

import importlib.util
import re
import unittest
from pathlib import Path
from types import ModuleType

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
ROOT = ROLE.parents[2]
WRAPPER = ROOT / "hetzner" / "provision" / "branchleft_deploy.py"
TOOLING_VARS = ROOT / "ansible" / "roles" / "deploy_tooling" / "vars" / "main.yml"
TENANT_IMAGE = "ghcr.io/branchleft/ghost-tenant"
SIGNER = "branchLeft/ghost-platform/.github/workflows/registry-push.yml"
DIGEST = "sha256:" + "a" * 64


def load_yaml(path: Path) -> object:
    """Return the YAML document at path."""
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def mapping(value: object) -> dict[str, object]:
    """Return a mapping with text keys.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"expected a mapping, got {type(value).__name__}"
        raise TypeError(message)
    return {str(key): item for key, item in value.items()}


def tasks(name: str) -> list[dict[str, object]]:
    """Return the tasks of one of the role's task files.

    Raises:
        TypeError: the file is not a list of tasks.
    """
    loaded = load_yaml(ROLE / "tasks" / name)
    if not isinstance(loaded, list):
        message = f"{name} is not a list of tasks"
        raise TypeError(message)
    return [mapping(task) for task in loaded]


def section(task: dict[str, object], key: str) -> list[dict[str, object]]:
    """Return the tasks of a block, rescue or always section of a task, or none."""
    inner = task.get(key)
    if not isinstance(inner, list):
        return []
    return [mapping(item) for item in inner]


def flat_tasks(name: str) -> list[dict[str, object]]:
    """Return the tasks of a task file, with those inside a block, rescue or always in line."""
    found: list[dict[str, object]] = []

    def walk(items: list[dict[str, object]]) -> None:
        for task in items:
            found.append(task)
            for section in ("block", "rescue", "always"):
                inner = task.get(section)
                if isinstance(inner, list):
                    walk([mapping(item) for item in inner])

    walk(tasks(name))
    return found


def command_argv(task: dict[str, object]) -> list[object]:
    """Return the argv of a command task, or an empty list for any other task."""
    command = task.get("ansible.builtin.command")
    if command is None:
        return []
    argv = mapping(command).get("argv")
    return list(argv) if isinstance(argv, list) else []


def role_var(name: str) -> str:
    """Return a text variable of the role's vars/main.yml.

    Raises:
        TypeError: the variable is not text.
    """
    value = mapping(load_yaml(ROLE / "vars" / "main.yml"))[name]
    if not isinstance(value, str):
        message = f"{name} is not text"
        raise TypeError(message)
    return value


def wrapper() -> ModuleType:
    """Import the deploy wrapper from its one home, without running it.

    Raises:
        ImportError: the wrapper cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location("branchleft_deploy", WRAPPER)
    if spec is None or spec.loader is None:
        message = f"cannot import {WRAPPER}"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def register() -> dict[str, str]:
    """Return the wrapper's register: image name to the workflow that must attest it."""
    found = mapping(wrapper().ATTESTED_IMAGES)
    return {name: str(signer) for name, signer in found.items()}


def pattern() -> re.Pattern[str]:
    """Return the role's tenant image pattern, compiled."""
    return re.compile(role_var("tenant_compose_tenant_image_pattern"))


def pin(image: str) -> str:
    """Return the pin line the role's module writes for an image."""
    return f"IMAGE={image}\n"


class TenantImage(unittest.TestCase):
    """The one image a tenant may run is one the deploy wrapper verifies."""

    def test_the_tenant_image_is_in_the_wrappers_register_with_its_signer(self) -> None:
        self.assertEqual(SIGNER, register()[TENANT_IMAGE])

    def test_the_pattern_accepts_the_tenant_image_pinned_by_digest(self) -> None:
        self.assertIsNotNone(pattern().match(pin(f"{TENANT_IMAGE}@{DIGEST}")))

    def test_every_image_the_pattern_accepts_is_one_the_wrapper_verifies(self) -> None:
        module = wrapper()
        image = f"{TENANT_IMAGE}@{DIGEST}"
        self.assertIsNotNone(pattern().match(pin(image)))
        self.assertIn(module.attested_name(image), register())

    def test_the_pattern_refuses_every_other_image_and_form(self) -> None:
        for line in (
            pin(f"example.invalid/app@{DIGEST}"),
            pin(f"ghcr.io/branchleft/portal-apps@{DIGEST}"),
            pin(f"ghcr.io/branchleft/ghost-tenant-other@{DIGEST}"),
            pin(f"ghcr.io/branchleft/ghost-tenant:8.0.0@{DIGEST}"),
            pin(f"ghcr.io:443/branchleft/ghost-tenant@{DIGEST}"),
            pin(f"evil.example/ghcr.io/branchleft/ghost-tenant@{DIGEST}"),
            pin(f"{TENANT_IMAGE}@sha256:{'a' * 63}"),
            pin(f"{TENANT_IMAGE}@sha256:{'A' * 64}"),
            pin(f"{TENANT_IMAGE}:latest"),
            f"IMAGE={TENANT_IMAGE}@{DIGEST}",
            f"IMAGE={TENANT_IMAGE}@{DIGEST}\n\n",
            pin(f"{TENANT_IMAGE}@{DIGEST}") + pin(f"{TENANT_IMAGE}@{DIGEST}"),
            "",
        ):
            with self.subTest(line=line):
                self.assertIsNone(pattern().match(line))


class DeployProgram(unittest.TestCase):
    """The program the role runs is the wrapper the deploy tooling installs."""

    def test_the_program_is_the_path_the_deploy_tooling_installs_the_wrapper_to(self) -> None:
        tooling = mapping(load_yaml(TOOLING_VARS))
        self.assertEqual(
            tooling["deploy_tooling_wrapper_path"], role_var("tenant_compose_deploy_program")
        )


class PinTasks(unittest.TestCase):
    """A tenant's pin is written by the wrapper; the role copies only the spool's."""

    def test_only_the_spools_pin_is_copied_into_place(self) -> None:
        copies = [
            task
            for task in tasks("_stack.yml")
            if "tenant_compose_image_env_path"
            in str(mapping(task.get("ansible.builtin.copy", {})).get("dest", ""))
        ]
        self.assertEqual(1, len(copies))
        self.assertEqual("tenant_compose_is_spool | bool", copies[0].get("when"))

    def test_the_tenants_first_pin_is_the_wrappers_with_the_slug_and_the_image(self) -> None:
        runs = [
            task
            for task in flat_tasks("_stack.yml")
            if command_argv(task)[:1] == ["{{ tenant_compose_deploy_program }}"]
        ]
        self.assertEqual(1, len(runs))
        argv = command_argv(runs[0])
        self.assertEqual(
            [
                "{{ tenant_compose_deploy_program }}",
                "{{ tenant_compose_stack.slug }}",
                "{{ tenant_compose_verdict.image_env | regex_replace('^IMAGE=', '') | trim }}",
            ],
            argv,
        )
        enclosing = [task for task in tasks("_stack.yml") if runs[0] in section(task, "block")]
        self.assertEqual(1, len(enclosing))
        self.assertEqual("tenant_compose_deploy_due | bool", enclosing[0].get("when"))

    def test_a_first_deploy_is_due_only_for_a_tenant_with_no_pin(self) -> None:
        due = [
            mapping(task["ansible.builtin.set_fact"])["tenant_compose_deploy_due"]
            for task in tasks("_stack.yml")
            if "tenant_compose_deploy_due" in mapping(task.get("ansible.builtin.set_fact", {}))
        ]
        self.assertEqual(1, len(due))
        expression = " ".join(str(due[0]).split())
        self.assertIn("not (tenant_compose_is_spool | bool)", expression)
        self.assertIn("not (tenant_compose_pin.stat.exists | default(false))", expression)

    def test_the_role_refuses_an_unverifiable_tenant_image_before_it_writes(self) -> None:
        main = tasks("main.yml")
        names = [str(task.get("name", "")) for task in main]
        refusal = names.index(
            "Refuse a tenant image the deploy wrapper would not verify, before anything is written"
        )
        first_delivery = names.index("Deliver the mail spool")
        self.assertLess(refusal, first_delivery)
        inner = section(main[refusal], "block")
        self.assertEqual(1, len(inner))
        expression = str(mapping(inner[0]["vars"])["tenant_compose_unverifiable"])
        self.assertIn(
            "rejectattr('image_env', 'match', tenant_compose_tenant_image_pattern)", expression
        )


class RefusalReadable(unittest.TestCase):
    """The wrapper's output is hidden, so the failure names the journal that holds its reason."""

    def _wrapper_run(self) -> dict[str, object]:
        runs = [
            task
            for task in flat_tasks("_stack.yml")
            if command_argv(task)[:1] == ["{{ tenant_compose_deploy_program }}"]
        ]
        self.assertEqual(1, len(runs))
        return runs[0]

    def test_the_wrapper_run_and_the_spools_pin_copy_are_hidden(self) -> None:
        self.assertIs(True, self._wrapper_run().get("no_log"))
        spool = [
            task
            for task in tasks("_stack.yml")
            if "tenant_compose_image_env_path"
            in str(mapping(task.get("ansible.builtin.copy", {})).get("dest", ""))
        ][0]
        self.assertIs(True, spool.get("no_log"))
        self.assertIs(False, spool.get("diff"))

    def test_the_reason_command_reads_the_tag_the_wrapper_logs_under(self) -> None:
        tag = wrapper().JOURNAL_TAG
        self.assertEqual(tag, role_var("tenant_compose_deploy_log_tag"))
        command = role_var("tenant_compose_deploy_reason_command")
        self.assertEqual(f"journalctl -t {tag} -n 20 --no-pager", command)

    def test_a_refused_tenant_fails_in_the_open_naming_the_tenant_and_the_command(self) -> None:
        deploy = self._wrapper_run()
        enclosing = [task for task in tasks("_stack.yml") if deploy in section(task, "block")][0]
        rescue = section(enclosing, "rescue")
        self.assertEqual(1, len(rescue))
        fail = mapping(rescue[0]["ansible.builtin.fail"])
        self.assertNotIn("no_log", rescue[0])
        message = " ".join(str(fail["msg"]).split())
        self.assertIn("The deploy wrapper refused {{ tenant_compose_stack.slug }}", message)
        self.assertIn("{{ tenant_compose_deploy_reason_command }}", message)

    def test_the_register_of_a_hidden_task_is_not_named_in_the_failure(self) -> None:
        for task in flat_tasks("_stack.yml"):
            fail = task.get("ansible.builtin.fail")
            if fail is not None:
                self.assertNotIn("tenant_compose_verdict", str(mapping(fail).get("msg", "")))


if __name__ == "__main__":
    unittest.main()
