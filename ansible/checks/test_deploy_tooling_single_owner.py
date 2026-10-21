"""Check that the deploy_tooling role is the single owner of the programs it installs.

The four programs each have one home in `hetzner/provision/` and one installing role. A second
role is a second writer of the same host files if it links to or copies a program, reads one from
its home (by path, file name or variable), or has a `dest` that is a path this role installs.
The README's named limits say what these checks cannot see. One role is allowed for now: it is
retired by its own follow-up after this role has run on the host that has it.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path

import deploy_tooling_vars as role_vars
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

OWNER = "deploy_tooling"
ALLOWED_SECOND_OWNERS = frozenset({"control_plane"})
PROGRAMS = (
    "branchleft_deploy.py",
    "branchleft-compose@.service",
    "branchleft_docker_user_policy.sh",
    "branchleft-docker-user-policy.service",
)
# What a role does lives in these directories. Its molecule/ holds fixtures that stand in for
# a host, and its README and files/ are prose and data.
ROLE_CODE_DIRECTORIES = ("tasks", "handlers", "vars", "defaults")


def _strings(node: object, key: str = "") -> Iterator[tuple[str, str]]:
    """Yield every (key, text) pair of a loaded YAML document, however deep."""
    if isinstance(node, str):
        yield key, node
    elif isinstance(node, dict):
        for name, value in node.items():
            yield from _strings(value, str(name))
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value, key)


def _variables(role: Path) -> dict[str, object]:
    """Return a role's own variables (its defaults, then its vars), as far as they load."""
    merged: dict[str, object] = {}
    for directory in ("defaults", "vars"):
        path = role / directory / "main.yml"
        if path.is_file():
            document: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
            if isinstance(document, dict):
                merged.update({str(key): value for key, value in document.items()})
    return merged


def _code_files(role: Path) -> Iterator[Path]:
    """Yield the YAML files of a role that say what it does."""
    for directory in ROLE_CODE_DIRECTORIES:
        yield from sorted(
            path
            for pattern in ("*.yml", "*.yaml")
            for path in (role / directory).rglob(pattern)
            if path.is_file()
        )


def _names_a_program(text: str) -> str | None:
    """Return the program a string is, or a path into its home names; None for any other string.

    A path the program is installed at is not one: two units are installed under the file
    name they are read by, and where a role writes to is the other rule's to find.
    """
    for name in PROGRAMS:
        if text == name or f"hetzner/provision/{name}" in text:
            return name
    return None


def _resolved(text: str, variables: dict[str, object]) -> str:
    """Return ``text`` with its simple variable references filled in, or as it was if it cannot."""
    try:
        return role_vars.resolve(text, variables)
    except role_vars.RoleVarsError:
        return text


def reference_problems(role: Path, install_paths: frozenset[str], shown_root: Path) -> list[str]:
    """Return each place a role's code reads a program from its home or writes an install path."""
    variables = _variables(role)
    problems: list[str] = []
    for path in _code_files(role):
        shown = path.relative_to(shown_root).as_posix()
        try:
            document: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
        except YAMLError:
            problems.append(f"{shown} is not YAML that can be read, so what it installs is unknown")
            continue
        for key, text in _strings(document):
            program = _names_a_program(_resolved(text, variables))
            if program is not None:
                problems.append(f"{shown} reads {program}, which the {OWNER} role installs")
            if key == "dest" and _resolved(text, variables) in install_paths:
                problems.append(
                    f"{shown} writes {_resolved(text, variables)}, which the {OWNER} role installs"
                )
    return problems


def second_owner_problems(
    roles: Path, provision: Path, allowed: frozenset[str] = ALLOWED_SECOND_OWNERS
) -> list[str]:
    """Return each way a role other than the owner links to, copies, reads or writes a program."""
    digests = {
        hashlib.sha256((provision / name).read_bytes()).hexdigest(): name for name in PROGRAMS
    }
    home = provision.resolve()
    owner_variables = role_vars.load_vars(roles / OWNER)
    install_paths = frozenset(
        target.path for target in role_vars.targets(owner_variables) if target.kind == "file"
    )
    problems: list[str] = []
    for role in sorted(entry for entry in roles.iterdir() if entry.is_dir()):
        if role.name == OWNER or role.name in allowed:
            continue
        for path in sorted(role.rglob("*")):
            shown = path.relative_to(roles).as_posix()
            if path.is_symlink():
                target = path.resolve()
                if target.parent == home and target.name in PROGRAMS:
                    problems.append(f"{shown} is a link to {target.name}")
            elif path.is_file():
                copy = digests.get(hashlib.sha256(path.read_bytes()).hexdigest())
                if copy is not None:
                    problems.append(f"{shown} is a copy of {copy}")
        problems.extend(reference_problems(role, install_paths, roles))
    return problems


class TestSingleOwner(unittest.TestCase):
    """The real tree has one owner, and a second one is found in a copy of the tree."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="deploy-tooling-owner-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.provision = self.work / "provision"
        self.roles = self.work / "roles"
        self.provision.mkdir()
        (self.roles / OWNER / "vars").mkdir(parents=True)
        shutil.copy(role_vars.ROLE / "vars" / "main.yml", self.roles / OWNER / "vars" / "main.yml")
        (self.roles / "control_plane").mkdir()
        for name in PROGRAMS:
            (self.provision / name).write_bytes(f"home of {name}\n".encode())

    def test_the_real_tree_has_one_owner(self) -> None:
        roles = role_vars.REPO_ROOT / "ansible" / "roles"
        self.assertEqual(second_owner_problems(roles, role_vars.PROVISION), [])

    def test_the_allow_list_is_the_one_named_role(self) -> None:
        self.assertEqual(ALLOWED_SECOND_OWNERS, frozenset({"control_plane"}))

    def test_a_second_role_holding_a_link_is_found(self) -> None:
        (self.roles / "other_role" / "files").mkdir(parents=True)
        link = self.roles / "other_role" / "files" / "wrapper"
        link.symlink_to(self.provision / "branchleft_deploy.py")
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            ["other_role/files/wrapper is a link to branchleft_deploy.py"],
        )

    def test_a_second_role_holding_a_copy_is_found(self) -> None:
        (self.roles / "other_role" / "files").mkdir(parents=True)
        copy = self.roles / "other_role" / "files" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            ["other_role/files/policy.sh is a copy of branchleft_docker_user_policy.sh"],
        )

    def test_the_allowed_role_may_hold_a_copy(self) -> None:
        copy = self.roles / "control_plane" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])

    def test_the_same_copy_under_a_role_not_on_the_list_is_found(self) -> None:
        (self.roles / "not_listed").mkdir()
        copy = self.roles / "not_listed" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            ["not_listed/policy.sh is a copy of branchleft_docker_user_policy.sh"],
        )

    def write_tasks(self, role: str, text: str, directory: str = "tasks") -> None:
        folder = self.roles / role / directory
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "main.yml").write_text(text, encoding="utf-8")

    def test_a_second_role_reading_a_program_by_path_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Install the wrapper\n"
            "  ansible.builtin.copy:\n"
            "    src: '{{ role_path }}/../../../hetzner/provision/branchleft_deploy.py'\n"
            "    dest: /opt/other/wrapper\n",
        )
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            [
                "other_role/tasks/main.yml reads branchleft_deploy.py,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_second_role_reading_a_program_through_a_variable_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "other_role_source: '{{ other_role_dir }}/branchleft_docker_user_policy.sh'\n"
            "other_role_dir: /srv/checkout/hetzner/provision\n",
            directory="vars",
        )
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            [
                "other_role/vars/main.yml reads branchleft_docker_user_policy.sh,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_second_role_writing_a_path_from_another_source_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Install a wrapper of its own\n"
            "  ansible.builtin.copy:\n"
            "    src: wrapper.py\n"
            "    dest: /usr/local/sbin/branchleft-deploy\n",
        )
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            [
                "other_role/tasks/main.yml writes /usr/local/sbin/branchleft-deploy,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_second_role_writing_a_path_named_by_a_variable_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Install a unit of its own\n"
            "  ansible.builtin.template:\n"
            "    src: unit.j2\n"
            "    dest: '{{ other_role_unit }}'\n",
        )
        self.write_tasks(
            "other_role",
            "other_role_unit: /etc/systemd/system/branchleft-docker-user-policy.service\n",
            directory="defaults",
        )
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            [
                "other_role/tasks/main.yml writes"
                " /etc/systemd/system/branchleft-docker-user-policy.service,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_role_that_only_runs_the_wrapper_or_writes_its_own_paths_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Deploy\n"
            "  ansible.builtin.command:\n"
            "    argv: [sudo, -n, /usr/local/sbin/branchleft-deploy, website]\n"
            "- name: Install its own file\n"
            "  ansible.builtin.copy:\n"
            "    src: own.sh\n"
            "    dest: /usr/local/sbin/own-program\n",
        )
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])

    def test_a_fixture_under_molecule_standing_in_for_a_host_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy:\n"
            "    src: unit\n"
            "    dest: /etc/systemd/system/branchleft-compose@.service\n",
            directory="molecule/default",
        )
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])

    def test_the_allowed_role_may_read_a_program(self) -> None:
        self.write_tasks("control_plane", "- ansible.builtin.copy: {src: branchleft_deploy.py}\n")
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])

    def test_a_task_file_that_cannot_be_read_is_found_rather_than_skipped(self) -> None:
        self.write_tasks("other_role", "- name: [unclosed\n")
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            [
                "other_role/tasks/main.yml is not YAML that can be read,"
                " so what it installs is unknown"
            ],
        )

    def test_a_role_with_other_content_is_not_found(self) -> None:
        (self.roles / "other_role").mkdir()
        (self.roles / "other_role" / "README.md").write_text("not a program\n", encoding="utf-8")
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])


if __name__ == "__main__":
    unittest.main()
