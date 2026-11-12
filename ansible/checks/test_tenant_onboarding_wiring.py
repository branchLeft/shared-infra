"""Tests that the tenant onboarding role is wired to app1, and that what it installs is what
tenant_compose calls.

tenant_compose calls its volume program at one fixed path and refuses to run unless that file is
executable. The tenant onboarding role installs the program. Three things must hold together: the
host's list in host_roles.yml names the onboarding role, app1's playbook applies it, the program
it installs is the program tenant_compose calls, executable, and the register is installed in the
same directory as the program (the program refuses every slug otherwise). When both roles are
applied, the onboarding role comes first, so the program exists before the compose role looks for
it.

The checks are plain functions over values. The real-tree tests read the real files; the
sabotage tests change one value in memory and require the named check to refuse it, so each
control is seen red and then green without editing a file.
"""

from __future__ import annotations

import unittest
from pathlib import Path, PurePosixPath

import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT

ROLE = "tenant_onboarding"
CALLER = "tenant_compose"
HOST = "app1"
PROGRAM_NAME = "provision_tenant_volume.py"
# The program's path in the onboarding role's vars: the directory, then the program's name. Any
# other spelling is a literal path and is compared as one.
PROGRAM_TEMPLATE = "{{ tenant_onboarding_program_dir }}/" + PROGRAM_NAME
# The task that fetches the program, named by its destination as the role's tasks write it.
PROGRAM_DEST = "{{ tenant_onboarding_program }}"
# The register's path in the role's vars and the task that fetches it, written the same way.
REGISTER_DIR_TEMPLATE = "{{ tenant_onboarding_program_dir }}"
REGISTER_DEST = "{{ tenant_onboarding_register }}"
REGISTER_URL_SUFFIX = "/registers/tenant-names.json"

# The directory the role installed into before it moved to the path tenant_compose calls.
OLD_DIR = "/usr/local/lib/branchleft/provision"

HOST_ROLES = ROOT / "ansible" / "checks" / "host_roles.yml"
APP1 = ROOT / "ansible" / "playbooks" / f"{HOST}.yml"
ROLE_VARS = ROOT / "ansible" / "roles" / ROLE / "vars" / "main.yml"
ROLE_TASKS = ROOT / "ansible" / "roles" / ROLE / "tasks" / "main.yml"
CALLER_VARS = ROOT / "ansible" / "roles" / CALLER / "vars" / "main.yml"


def play_roles(playbook_text: str) -> list[str]:
    """The role names of the one play in a playbook, in the order the play applies them."""
    play = yaml.safe_load(playbook_text)[0]
    return [Path(str(entry["role"])).name for entry in play["roles"]]


def installed_program(onboarding_vars: dict[str, object]) -> str:
    """The path the onboarding role installs the program at."""
    directory = str(onboarding_vars.get("tenant_onboarding_program_dir", ""))
    program = str(onboarding_vars.get("tenant_onboarding_program", ""))
    if program == PROGRAM_TEMPLATE:
        return f"{directory}/{PROGRAM_NAME}"
    return program


def installed_register(onboarding_vars: dict[str, object]) -> str:
    """The path the onboarding role installs the register at."""
    directory = str(onboarding_vars.get("tenant_onboarding_program_dir", ""))
    register = str(onboarding_vars.get("tenant_onboarding_register", ""))
    return register.replace(REGISTER_DIR_TEMPLATE, directory)


def register_dest(tasks: list[dict[str, object]]) -> str | None:
    """The destination the onboarding role's task gives the register, or None if no such task."""
    for task in tasks:
        fetch = task.get("ansible.builtin.get_url")
        if isinstance(fetch, dict) and str(fetch.get("url", "")).endswith(REGISTER_URL_SUFFIX):
            return str(fetch.get("dest"))
    return None


def program_mode(tasks: list[dict[str, object]]) -> str | None:
    """The mode the onboarding role's task gives the program, or None if no such task exists."""
    for task in tasks:
        fetch = task.get("ansible.builtin.get_url")
        if isinstance(fetch, dict) and fetch.get("dest") == PROGRAM_DEST:
            return str(fetch.get("mode"))
    return None


def wiring_problems(host_list: list[str], roles: list[str]) -> list[str]:
    """Checks (a) and (b): the role is on the host's list and applied, and before the caller."""
    problems: list[str] = []
    if ROLE not in host_list:
        problems.append(f"{ROLE} is not on {HOST}'s list in host_roles.yml")
    if ROLE not in roles:
        problems.append(f"{ROLE} is not applied in {HOST}.yml")
    if ROLE in roles and CALLER in roles and roles.index(ROLE) > roles.index(CALLER):
        problems.append(f"{ROLE} is applied after {CALLER} in {HOST}.yml; it must come first")
    return problems


def program_problems(
    caller_program: str, onboarding_vars: dict[str, object], mode: str | None
) -> list[str]:
    """Check (c): the program installed is the program the caller calls, and it is executable."""
    problems: list[str] = []
    installed = installed_program(onboarding_vars)
    if installed != caller_program:
        problems.append(f"{ROLE} installs {installed}, but {CALLER} calls {caller_program}")
    if mode is None or not int(mode, 8) & 0o100:
        problems.append(f"the program task in {ROLE} does not give the program an execute bit")
    return problems


def register_problems(onboarding_vars: dict[str, object], dest: str | None) -> list[str]:
    """Check (d): the register is installed in the same directory as the program.

    The program refuses every slug unless the register sits beside it, so moving only one of the
    two would leave a host that installs both and refuses every tenant.
    """
    problems: list[str] = []
    program_dir = str(PurePosixPath(installed_program(onboarding_vars)).parent)
    register_dir = str(PurePosixPath(installed_register(onboarding_vars)).parent)
    if register_dir != program_dir:
        problems.append(
            f"{ROLE} installs the register in {register_dir}, "
            f"not beside the program in {program_dir}"
        )
    if dest != REGISTER_DEST:
        problems.append(f"the register task in {ROLE} does not install it at {REGISTER_DEST}")
    return problems


class RealTree(unittest.TestCase):
    """The checks on the files as they are on this tree."""

    def test_the_real_tree_wires_the_role_to_app1(self) -> None:
        host_roles = yaml.safe_load(HOST_ROLES.read_text(encoding="utf-8"))
        roles = play_roles(APP1.read_text(encoding="utf-8"))
        self.assertEqual(wiring_problems(host_roles[HOST], roles), [])

    def test_the_real_tree_installs_the_program_tenant_compose_calls(self) -> None:
        caller = yaml.safe_load(CALLER_VARS.read_text(encoding="utf-8"))
        onboarding = yaml.safe_load(ROLE_VARS.read_text(encoding="utf-8"))
        tasks = yaml.safe_load(ROLE_TASKS.read_text(encoding="utf-8"))
        caller_program = str(caller["tenant_compose_volume_program"])
        self.assertEqual(program_problems(caller_program, onboarding, program_mode(tasks)), [])

    def test_the_real_tree_installs_the_register_beside_the_program(self) -> None:
        onboarding = yaml.safe_load(ROLE_VARS.read_text(encoding="utf-8"))
        tasks = yaml.safe_load(ROLE_TASKS.read_text(encoding="utf-8"))
        self.assertEqual(register_problems(onboarding, register_dest(tasks)), [])

    def test_moving_only_the_register_on_the_real_vars_is_refused(self) -> None:
        # The real vars with one edit: the register alone moves to another directory.
        onboarding = yaml.safe_load(ROLE_VARS.read_text(encoding="utf-8"))
        tasks = yaml.safe_load(ROLE_TASKS.read_text(encoding="utf-8"))
        onboarding["tenant_onboarding_register"] = OLD_DIR + "/tenant-names.json"
        problems = register_problems(onboarding, register_dest(tasks))
        self.assertTrue(any("not beside the program" in problem for problem in problems), problems)


class Mutations(unittest.TestCase):
    """Each control refuses its own sabotage, and accepts the same tree with the fault removed."""

    def setUp(self) -> None:
        self.host_list = ["host_inputs", "deploy_tooling", ROLE, "export_bundler"]
        self.roles_ok = [
            "ansible_runtime",
            "pull_trigger",
            "host_inputs",
            "deploy_slot_keys",
            ROLE,
            CALLER,
            "export_bundler",
        ]
        self.caller_program = "/root/platform-provision/" + PROGRAM_NAME
        self.onboarding: dict[str, object] = {
            "tenant_onboarding_program_dir": "/root/platform-provision",
            "tenant_onboarding_program": PROGRAM_TEMPLATE,
            "tenant_onboarding_register": REGISTER_DIR_TEMPLATE + "/tenant-names.json",
        }

    def test_the_positive_case_passes_first(self) -> None:
        self.assertEqual(wiring_problems(self.host_list, self.roles_ok), [])
        self.assertEqual(program_problems(self.caller_program, self.onboarding, "0755"), [])
        self.assertEqual(register_problems(self.onboarding, REGISTER_DEST), [])

    def test_role_missing_from_the_host_list_is_refused(self) -> None:
        # Fault: the role is taken off the host's list.
        without = [name for name in self.host_list if name != ROLE]
        problems = wiring_problems(without, self.roles_ok)
        self.assertTrue(any("host_roles.yml" in problem for problem in problems), problems)

    def test_role_applied_after_the_caller_is_refused(self) -> None:
        # Fault: the role is moved after tenant_compose in the playbook.
        moved = [name for name in self.roles_ok if name != ROLE] + [ROLE]
        problems = wiring_problems(self.host_list, moved)
        self.assertTrue(any("must come first" in problem for problem in problems), problems)

    def test_program_in_the_old_directory_is_refused(self) -> None:
        # Fault: the install directory is put back under /usr/local/lib.
        old = dict(
            self.onboarding, tenant_onboarding_program_dir="/usr/local/lib/branchleft/provision"
        )
        problems = program_problems(self.caller_program, old, "0755")
        self.assertTrue(any("installs" in problem for problem in problems), problems)

    def test_register_in_another_directory_is_refused(self) -> None:
        # Fault: the register's path moves to another directory while the program stays.
        moved = dict(
            self.onboarding,
            tenant_onboarding_register="/usr/local/lib/branchleft/provision/tenant-names.json",
        )
        problems = register_problems(moved, REGISTER_DEST)
        self.assertTrue(any("not beside the program" in problem for problem in problems), problems)

    def test_register_task_with_its_own_destination_is_refused(self) -> None:
        # Fault: the register task writes to a literal path instead of the role's register var.
        problems = register_problems(self.onboarding, "/usr/local/lib/branchleft/provision/x.json")
        self.assertTrue(any("does not install it at" in problem for problem in problems), problems)

    def test_program_mode_without_execute_is_refused(self) -> None:
        # Fault: the program's mode is put back to 0644 (no execute bit).
        problems = program_problems(self.caller_program, self.onboarding, "0644")
        self.assertTrue(any("execute bit" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
