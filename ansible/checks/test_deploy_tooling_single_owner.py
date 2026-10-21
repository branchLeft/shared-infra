"""Check that the deploy_tooling role is the single owner of the programs it installs.

The programs each have one home in `hetzner/provision/` and one installing role. Another role
is a second writer of the same host files if it links to or copies a program, reads one from its
home (by path, file name or variable), or names a path this role installs under any key, in a
free-form string, a shell string or an argument list. A playbook is read as a role's code is.
A command that only runs the wrapper is not a write and is not found. The README's named
limits say what these checks cannot see. One role is allowed for now, and only for the policy
program and its unit: it is retired by its own follow-up after this role has run on the host.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import shlex
import shutil
import tempfile
import unittest
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path

import deploy_tooling_vars as role_vars
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

OWNER = "deploy_tooling"
# A second role is exempt only for the target lists named here, never for the whole role.
ALLOWED_SECOND_OWNERS: dict[str, frozenset[str]] = {
    "control_plane": frozenset({"deploy_tooling_app_file_targets"}),
}
# Only to fill a test tree: the check itself reads the programs from the role's own target lists.
PROGRAMS = role_vars.program_names(role_vars.load_vars())
# What a role does lives in these directories. Its molecule/ holds fixtures that stand in for
# a host, and its README and files/ are prose and data.
ROLE_CODE_DIRECTORIES = ("tasks", "handlers", "vars", "defaults")
# Where a role only defines values. A path set there is read where it is used.
DEFINITION_DIRECTORIES = ("vars", "defaults")
# A key whose string is a command that is run, as the last part of its dotted name.
COMMAND_KEYS = frozenset({"argv", "cmd", "command", "shell", "raw"})
# Anything that lets a command string do more than run one program.
SHELL_SYNTAX = re.compile(r"[;&|<>`$()\\\n]")
# The options of sudo that take a value.
SUDO_VALUED = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"})
# A word made of the characters a path is made of that holds a slash.
_PATH_WORD = re.compile(r"[\w.@%+~-]*(?:/[\w.@%+~-]*)+")


def _pieces(node: object, key: str = "") -> Iterator[tuple[str, str, tuple[str, ...] | None]]:
    """Yield every (key, text, argument list) of a loaded YAML document, however deep.

    An argument list under `argv` is one piece, its words joined by spaces, with the words
    beside it, so that a command is read as a command and not as separate strings.
    """
    if isinstance(node, str):
        yield key, node, None
    elif isinstance(node, dict):
        for name, value in node.items():
            yield from _pieces(value, str(name))
    elif isinstance(node, list):
        if key.rsplit(".", 1)[-1] == "argv" and all(isinstance(word, str) for word in node):
            words = tuple(str(word) for word in node)
            yield key, " ".join(words), words
        else:
            for value in node:
                yield from _pieces(value, key)


def _load_mapping(path: Path) -> dict[str, object]:
    """Return the mapping a YAML file holds, or an empty one if there is none or it is not YAML."""
    if not path.is_file():
        return {}
    try:
        document: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except YAMLError:
        return {}
    if isinstance(document, dict):
        return {str(key): value for key, value in document.items()}
    return {}


def _playbook_files(ansible: Path) -> list[Path]:
    """Return the playbooks of the tree."""
    return sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in (ansible / "playbooks").glob(pattern)
        if path.is_file()
    )


def _shared_variables(ansible: Path) -> dict[str, object]:
    """Return the variables no single role owns: group and host variables, and play variables."""
    merged: dict[str, object] = {}
    for kind in ("group_vars", "host_vars"):
        for pattern in ("*.yml", "*.yaml"):
            for path in sorted((ansible / "inventories").glob(f"**/{kind}/**/{pattern}")):
                merged.update(_load_mapping(path))
    for playbook in _playbook_files(ansible):
        try:
            document: object = YAML(typ="safe").load(playbook.read_text(encoding="utf-8"))
        except YAMLError:
            continue
        for play in document if isinstance(document, list) else []:
            if isinstance(play, dict) and isinstance(play.get("vars"), dict):
                merged.update({str(key): value for key, value in play["vars"].items()})
    return merged


def _variables(role: Path, shared: dict[str, object]) -> dict[str, object]:
    """Return the variables a role's code can see, as far as they load: shared, then its own.

    Every YAML file under the role's `defaults/` and `vars/` is read, at any depth, not only
    `main.yml`: a file there is loaded by `include_vars` or `vars_files`, so a path set in
    `vars/other.yml` is as much the role's as one in `vars/main.yml`.
    """
    merged = dict(shared)
    for directory in ("defaults", "vars"):
        for pattern in ("*.yml", "*.yaml"):
            for path in sorted((role / directory).rglob(pattern)):
                merged.update(_load_mapping(path))
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


def _names_a_program(text: str, programs: Iterable[str]) -> str | None:
    """Return the program a string is, or a path into its home names; None for any other string.

    A path the program is installed at is not one: two units are installed under the file
    name they are read by, and a path is the other rule's to find.
    """
    for name in programs:
        if text == name or f"hetzner/provision/{name}" in text:
            return name
    return None


def _resolved(text: str, variables: dict[str, object]) -> str:
    """Return ``text`` with its simple variable references filled in, or as it was if it cannot."""
    try:
        return role_vars.resolve(text, variables)
    except (role_vars.RoleVarsError, RecursionError):
        return text


def _tidy(match: re.Match[str]) -> str:
    """Return one path-shaped word with its `//`, `/./` and `x/../` spellings removed."""
    tidy = posixpath.normpath(match.group(0))
    # POSIX keeps exactly two leading slashes; on a host they are the same as one.
    return "/" + tidy.lstrip("/") if tidy.startswith("//") else tidy


def _normalised(text: str) -> str:
    """Return ``text`` with every path-shaped word written in its one normal spelling.

    `/usr/local//sbin/x` and `/usr/local/./sbin/x` name the same file as `/usr/local/sbin/x`,
    so a path is compared only after `posixpath.normpath`. A word is a run of characters a path
    is made of that holds a slash, wherever it sits in the string (a `dest=...` or a shell
    string included).
    """
    return _PATH_WORD.sub(_tidy, text)


def _mentions(key: str, text: str, path: str) -> bool:
    """Say whether a string names an install path.

    The value of a `name` key is a task's label unless it is the path alone (the file module
    takes `name` for `path`). Anywhere else the path is looked for inside the string, so a
    free-form `dest=...`, a shell string and an argument all count, and a longer name that only
    begins with the path does not.
    """
    if key == "name":
        return text == path
    return re.search(re.escape(path) + r"(?![\w.@-])", text) is not None


def _after_sudo(words: Sequence[str]) -> Sequence[str]:
    """Return a command's words without a leading sudo and its options."""
    if not words or words[0] != "sudo":
        return words
    index = 1
    while index < len(words) and words[index].startswith("-"):
        index += 2 if words[index] in SUDO_VALUED else 1
    return words[index:]


def _runs(key: str, text: str, argv: tuple[str, ...] | None, path: str) -> bool:
    """Say whether a command key only runs the program at ``path`` (a read, not a write).

    A command string is a run only when it has no shell syntax and the program is its first
    word (after sudo): any other place the path appears in it is not.
    """
    if key.rsplit(".", 1)[-1] not in COMMAND_KEYS:
        return False
    words = argv
    if words is None:
        if SHELL_SYNTAX.search(text):
            return False
        try:
            words = tuple(shlex.split(text))
        except ValueError:
            return False
    return tuple(_after_sudo(words)[:1]) == (path,)


def reference_problems(
    files: Iterable[Path],
    shown_root: Path,
    variables: dict[str, object],
    owned: Sequence[role_vars.Target],
    exempt_groups: frozenset[str],
) -> list[str]:
    """Return each place code reads a program from its home or names a path this role installs.

    Raises nothing: a file that is not YAML is a problem returned, not an error, because what
    it installs is then unknown.
    """
    held = [
        target for target in owned if target.kind == "file" and target.group not in exempt_groups
    ]
    programs = sorted({target.program for target in held})
    paths = sorted({target.path for target in held})
    problems: list[str] = []
    for path in files:
        relative = path.relative_to(shown_root)
        shown = relative.as_posix()
        in_definitions = any(part in DEFINITION_DIRECTORIES for part in relative.parts[1:-1])
        try:
            document: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
        except YAMLError:
            problems.append(f"{shown} is not YAML that can be read, so what it installs is unknown")
            continue
        for key, text, argv in _pieces(document):
            resolved = _normalised(_resolved(text, variables))
            program = _names_a_program(resolved, programs)
            if program is not None:
                problems.append(f"{shown} reads {program}, which the {OWNER} role installs")
            if in_definitions:
                continue
            words = (
                None
                if argv is None
                else tuple(_normalised(_resolved(word, variables)) for word in argv)
            )
            problems.extend(
                f"{shown} names {install}, which the {OWNER} role installs"
                for install in paths
                if _mentions(key, resolved, install) and not _runs(key, resolved, words, install)
            )
    return problems


def second_owner_problems(
    roles: Path,
    provision: Path,
    allowed: Mapping[str, frozenset[str]] = ALLOWED_SECOND_OWNERS,
) -> list[str]:
    """Return each way a role other than the owner, or a playbook, holds or names a program."""
    ansible = roles.parent
    owned = role_vars.targets(role_vars.load_vars(roles / OWNER))
    shared = _shared_variables(ansible)
    home = provision.resolve()
    problems: list[str] = []
    for role in sorted(entry for entry in roles.iterdir() if entry.is_dir()):
        if role.name == OWNER:
            continue
        exempt_groups = allowed.get(role.name, frozenset())
        exempt_programs = {target.program for target in owned if target.group in exempt_groups}
        digests = {
            hashlib.sha256((provision / target.program).read_bytes()).hexdigest(): target.program
            for target in owned
            if target.program and target.program not in exempt_programs
        }
        for path in sorted(role.rglob("*")):
            shown = path.relative_to(roles).as_posix()
            if path.is_symlink():
                target_path = path.resolve()
                if target_path.parent == home and target_path.name in digests.values():
                    problems.append(f"{shown} is a link to {target_path.name}")
            elif path.is_file():
                copy = digests.get(hashlib.sha256(path.read_bytes()).hexdigest())
                if copy is not None:
                    problems.append(f"{shown} is a copy of {copy}")
        problems.extend(
            reference_problems(
                _code_files(role), roles, _variables(role, shared), owned, exempt_groups
            )
        )
    problems.extend(
        reference_problems(_playbook_files(ansible), ansible, shared, owned, frozenset())
    )
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

    def found(self) -> list[str]:
        return second_owner_problems(self.roles, self.provision)

    def write_tasks(
        self, role: str, text: str, directory: str = "tasks", name: str = "main.yml"
    ) -> None:
        folder = self.roles / role / directory
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(text, encoding="utf-8")

    def write_playbook(self, text: str, name: str = "other.yml") -> None:
        folder = self.work / "playbooks"
        folder.mkdir(exist_ok=True)
        (folder / name).write_text(text, encoding="utf-8")

    def names(self, shown: str, path: str) -> str:
        return f"{shown} names {path}, which the deploy_tooling role installs"

    def test_the_real_tree_has_one_owner(self) -> None:
        roles = role_vars.REPO_ROOT / "ansible" / "roles"
        self.assertEqual(second_owner_problems(roles, role_vars.PROVISION), [])

    def test_the_allow_list_is_one_role_and_the_policy_files_only(self) -> None:
        self.assertEqual(
            ALLOWED_SECOND_OWNERS,
            {"control_plane": frozenset({"deploy_tooling_app_file_targets"})},
        )

    def test_the_programs_are_the_role_target_lists_own(self) -> None:
        self.assertEqual(
            PROGRAMS,
            tuple(
                sorted({t.program for t in role_vars.targets(role_vars.load_vars()) if t.program})
            ),
        )
        self.assertEqual(len(PROGRAMS), 4)

    def test_a_program_added_to_the_target_lists_is_covered_with_no_edit_here(self) -> None:
        vars_file = self.roles / OWNER / "vars" / "main.yml"
        text = vars_file.read_text(encoding="utf-8").replace(
            "deploy_tooling_app_file_targets:\n",
            "deploy_tooling_app_file_targets:\n"
            "  - label: fifth program\n"
            "    program: branchleft_fifth.sh\n"
            "    path: /usr/local/sbin/branchleft-fifth\n"
            "    mode: '0755'\n"
            "    kind: file\n",
        )
        vars_file.write_text(text, encoding="utf-8")
        (self.provision / "branchleft_fifth.sh").write_bytes(b"home of the fifth\n")
        (self.roles / "other_role" / "files").mkdir(parents=True)
        (self.roles / "other_role" / "files" / "fifth").symlink_to(
            self.provision / "branchleft_fifth.sh"
        )
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: {src: x, dest: /usr/local/sbin/branchleft-fifth}\n",
        )
        self.assertEqual(
            self.found(),
            [
                "other_role/files/fifth is a link to branchleft_fifth.sh",
                self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-fifth"),
            ],
        )

    def test_a_second_role_holding_a_link_is_found(self) -> None:
        (self.roles / "other_role" / "files").mkdir(parents=True)
        link = self.roles / "other_role" / "files" / "wrapper"
        link.symlink_to(self.provision / "branchleft_deploy.py")
        self.assertEqual(
            self.found(), ["other_role/files/wrapper is a link to branchleft_deploy.py"]
        )

    def test_a_second_role_holding_a_copy_is_found(self) -> None:
        (self.roles / "other_role" / "files").mkdir(parents=True)
        copy = self.roles / "other_role" / "files" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(
            self.found(),
            ["other_role/files/policy.sh is a copy of branchleft_docker_user_policy.sh"],
        )

    def test_the_allowed_role_may_hold_a_copy_of_the_policy_program(self) -> None:
        copy = self.roles / "control_plane" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(self.found(), [])

    def test_the_allowed_role_may_not_hold_a_copy_of_the_wrapper(self) -> None:
        copy = self.roles / "control_plane" / "wrapper.py"
        copy.write_bytes((self.provision / "branchleft_deploy.py").read_bytes())
        self.assertEqual(
            self.found(), ["control_plane/wrapper.py is a copy of branchleft_deploy.py"]
        )

    def test_the_allowed_role_may_not_link_the_compose_unit(self) -> None:
        link = self.roles / "control_plane" / "unit"
        link.symlink_to(self.provision / "branchleft-compose@.service")
        self.assertEqual(
            self.found(), ["control_plane/unit is a link to branchleft-compose@.service"]
        )

    def test_the_same_copy_under_a_role_not_on_the_list_is_found(self) -> None:
        (self.roles / "not_listed").mkdir()
        copy = self.roles / "not_listed" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(
            self.found(), ["not_listed/policy.sh is a copy of branchleft_docker_user_policy.sh"]
        )

    def test_a_second_role_reading_a_program_by_path_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Install the wrapper\n"
            "  ansible.builtin.copy:\n"
            "    src: '{{ role_path }}/../../../hetzner/provision/branchleft_deploy.py'\n"
            "    dest: /opt/other/wrapper\n",
        )
        self.assertEqual(
            self.found(),
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
            self.found(),
            [
                "other_role/vars/main.yml reads branchleft_docker_user_policy.sh,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_second_role_writing_a_path_through_dest_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Install a wrapper of its own\n"
            "  ansible.builtin.copy:\n"
            "    src: wrapper.py\n"
            "    dest: /usr/local/sbin/branchleft-deploy\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
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
            self.found(),
            [
                self.names(
                    "other_role/tasks/main.yml",
                    "/etc/systemd/system/branchleft-docker-user-policy.service",
                )
            ],
        )

    def test_a_link_made_with_the_file_module_path_key_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.file:\n"
            "    path: /usr/local/sbin/branchleft-deploy\n"
            "    src: /srv/x\n"
            "    state: link\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_touch_made_with_the_file_module_name_key_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.file:\n"
            "    name: /usr/local/sbin/branchleft-deploy\n"
            "    state: touch\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_task_title_that_says_a_path_in_a_sentence_is_a_label_not_a_write(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Leave /usr/local/sbin/branchleft-deploy alone\n  ansible.builtin.debug:\n"
            "    msg: hello\n",
        )
        self.assertEqual(self.found(), [])

    def test_an_edit_in_place_with_lineinfile_and_blockinfile_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.lineinfile:\n"
            "    path: /usr/local/sbin/branchleft-docker-user-policy\n"
            "    line: exit 0\n"
            "- ansible.builtin.blockinfile:\n"
            "    path: /etc/systemd/system/branchleft-compose@.service\n"
            "    block: x\n",
        )
        self.assertEqual(
            self.found(),
            [
                self.names(
                    "other_role/tasks/main.yml", "/usr/local/sbin/branchleft-docker-user-policy"
                ),
                self.names(
                    "other_role/tasks/main.yml", "/etc/systemd/system/branchleft-compose@.service"
                ),
            ],
        )

    def test_a_free_form_string_with_a_dest_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: src=x dest=/usr/local/sbin/branchleft-deploy mode=0755\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_shell_string_that_links_the_path_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.shell: ln -sf /srv/x /usr/local/sbin/branchleft-deploy\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_command_argument_list_that_writes_the_path_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.command:\n"
            "    argv: [ln, -sf, /srv/x, /usr/local/sbin/branchleft-deploy]\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_shell_string_that_runs_the_wrapper_and_then_writes_it_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.shell:"
            " /usr/local/sbin/branchleft-deploy blog && rm /usr/local/sbin/branchleft-deploy\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_path_only_beginning_with_an_install_path_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: {src: x, dest: /usr/local/sbin/branchleft-deploy-notes}\n",
        )
        self.assertEqual(self.found(), [])

    def test_a_playbook_naming_a_path_is_found(self) -> None:
        self.write_playbook(
            "- hosts: all\n"
            "  tasks:\n"
            "    - ansible.builtin.copy:\n"
            "        src: x\n"
            "        dest: /usr/local/sbin/branchleft-deploy\n"
        )
        self.assertEqual(
            self.found(), [self.names("playbooks/other.yml", "/usr/local/sbin/branchleft-deploy")]
        )

    def test_a_playbook_reading_a_program_is_found(self) -> None:
        self.write_playbook(
            "- hosts: all\n"
            "  tasks:\n"
            "    - ansible.builtin.copy:\n"
            "        src: ../../hetzner/provision/branchleft_deploy.py\n"
            "        dest: /opt/x\n"
        )
        self.assertEqual(
            self.found(),
            [
                "playbooks/other.yml reads branchleft_deploy.py,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_playbook_that_cannot_be_read_is_found_rather_than_skipped(self) -> None:
        self.write_playbook("- hosts: [unclosed\n")
        self.assertEqual(
            self.found(),
            ["playbooks/other.yml is not YAML that can be read, so what it installs is unknown"],
        )

    def test_a_path_named_by_a_play_variable_is_found(self) -> None:
        self.write_playbook(
            "- hosts: all\n"
            "  vars:\n"
            "    unit_path: /etc/systemd/system/branchleft-docker-user-policy.service\n"
        )
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: {src: x, dest: '{{ unit_path }}'}\n",
        )
        unit = "/etc/systemd/system/branchleft-docker-user-policy.service"
        self.assertEqual(
            self.found(),
            [
                self.names("other_role/tasks/main.yml", unit),
                self.names("playbooks/other.yml", unit),
            ],
        )

    def test_a_path_named_by_a_group_variable_is_found(self) -> None:
        group_vars = self.work / "inventories" / "production" / "group_vars" / "edge"
        group_vars.mkdir(parents=True)
        (group_vars / "paths.yml").write_text(
            "other_path: /usr/local/sbin/branchleft-deploy\n", encoding="utf-8"
        )
        self.write_tasks(
            "other_role", "- ansible.builtin.copy: {src: x, dest: '{{ other_path }}'}\n"
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_role_that_only_runs_the_wrapper_or_writes_its_own_paths_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- name: Deploy with an argument list\n"
            "  ansible.builtin.command:\n"
            "    argv: [sudo, -n, /usr/local/sbin/branchleft-deploy, website]\n"
            "- name: Deploy with a string\n"
            "  ansible.builtin.command: sudo -n -u root /usr/local/sbin/branchleft-deploy website\n"
            "- name: Install its own file\n"
            "  ansible.builtin.copy:\n"
            "    src: own.sh\n"
            "    dest: /usr/local/sbin/own-program\n",
        )
        self.assertEqual(self.found(), [])

    def test_a_role_that_runs_the_wrapper_named_by_a_variable_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.command:\n"
            "    argv:\n"
            "      - sudo\n"
            "      - -n\n"
            "      - '{{ other_role_program }}'\n"
            "      - website\n",
        )
        self.write_tasks(
            "other_role",
            "other_role_program: /usr/local/sbin/branchleft-deploy\n",
            directory="vars",
        )
        self.assertEqual(self.found(), [])

    def test_a_path_only_defined_in_role_variables_is_read_where_it_is_used(self) -> None:
        self.write_tasks(
            "other_role",
            "other_role_target: /usr/local/sbin/branchleft-deploy\n",
            directory="defaults",
        )
        self.assertEqual(self.found(), [])

    def test_a_path_set_in_a_sibling_vars_file_is_found_where_it_is_used(self) -> None:
        self.write_tasks(
            "other_role",
            "other_role_dest: /usr/local/sbin/branchleft-deploy\n",
            directory="vars",
            name="other.yml",
        )
        self.write_tasks(
            "other_role", "- ansible.builtin.copy: {src: x, dest: '{{ other_role_dest }}'}\n"
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_path_set_in_a_sibling_defaults_file_is_found_where_it_is_used(self) -> None:
        self.write_tasks(
            "other_role",
            "other_role_dest: /etc/systemd/system/branchleft-compose@.service\n",
            directory="defaults/extra",
            name="paths.yml",
        )
        self.write_tasks(
            "other_role", "- ansible.builtin.copy: {src: x, dest: '{{ other_role_dest }}'}\n"
        )
        self.assertEqual(
            self.found(),
            [
                self.names(
                    "other_role/tasks/main.yml", "/etc/systemd/system/branchleft-compose@.service"
                )
            ],
        )

    def test_a_program_read_through_a_sibling_vars_file_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "other_role_home: /srv/checkout/hetzner/provision\n",
            directory="vars",
            name="other.yml",
        )
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy:\n"
            "    src: '{{ other_role_home }}/branchleft_docker_user_policy.sh'\n"
            "    dest: /opt/x\n",
        )
        self.assertEqual(
            self.found(),
            [
                "other_role/tasks/main.yml reads branchleft_docker_user_policy.sh,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_path_respelled_with_a_doubled_slash_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: {src: x, dest: /usr/local//sbin/branchleft-deploy}\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_path_respelled_with_a_dot_segment_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: {src: x, dest: /usr/local/./sbin/branchleft-deploy}\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_path_respelled_with_a_parent_segment_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy: {src: x, dest: /usr/local/bin/../sbin/branchleft-deploy}\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_respelled_path_in_a_shell_string_and_a_variable_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "other_role_dest: /usr/local//sbin/branchleft-deploy\n",
            directory="vars",
            name="other.yml",
        )
        self.write_tasks(
            "other_role",
            "- ansible.builtin.shell:"
            " ln -sf /srv/x /etc//systemd/./system/branchleft-compose@.service\n"
            "- ansible.builtin.copy: {src: x, dest: '{{ other_role_dest }}'}\n",
        )
        self.assertEqual(
            self.found(),
            [
                self.names(
                    "other_role/tasks/main.yml", "/etc/systemd/system/branchleft-compose@.service"
                ),
                self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy"),
            ],
        )

    def test_a_respelled_path_as_a_file_module_name_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.file:\n"
            "    name: /usr/local//sbin/branchleft-deploy\n"
            "    state: touch\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("other_role/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_a_program_read_by_a_respelled_path_is_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy:\n"
            "    src: ../../hetzner//provision/./branchleft_deploy.py\n"
            "    dest: /opt/x\n",
        )
        self.assertEqual(
            self.found(),
            [
                "other_role/tasks/main.yml reads branchleft_deploy.py,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_a_role_that_runs_the_wrapper_by_a_respelled_path_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.command:\n"
            "    argv: [sudo, -n, /usr/local//sbin/branchleft-deploy, website]\n",
        )
        self.assertEqual(self.found(), [])

    def test_a_fixture_under_molecule_standing_in_for_a_host_is_not_found(self) -> None:
        self.write_tasks(
            "other_role",
            "- ansible.builtin.copy:\n"
            "    src: unit\n"
            "    dest: /etc/systemd/system/branchleft-compose@.service\n",
            directory="molecule/default",
        )
        self.assertEqual(self.found(), [])

    def test_the_allowed_role_may_read_the_policy_program_and_write_its_paths(self) -> None:
        self.write_tasks(
            "control_plane",
            "- ansible.builtin.copy:\n"
            "    src: '{{ role_path }}/../../../hetzner/provision/"
            "branchleft_docker_user_policy.sh'\n"
            "    dest: /usr/local/sbin/branchleft-docker-user-policy\n"
            "- ansible.builtin.copy:\n"
            "    src: branchleft-docker-user-policy.service\n"
            "    dest: /etc/systemd/system/branchleft-docker-user-policy.service\n",
        )
        self.assertEqual(self.found(), [])

    def test_the_allowed_role_reading_the_wrapper_is_found(self) -> None:
        self.write_tasks("control_plane", "- ansible.builtin.copy: {src: branchleft_deploy.py}\n")
        self.assertEqual(
            self.found(),
            [
                "control_plane/tasks/main.yml reads branchleft_deploy.py,"
                " which the deploy_tooling role installs"
            ],
        )

    def test_the_allowed_role_writing_the_wrapper_path_is_found(self) -> None:
        self.write_tasks(
            "control_plane",
            "- ansible.builtin.copy: {src: x, dest: /usr/local/sbin/branchleft-deploy}\n",
        )
        self.assertEqual(
            self.found(),
            [self.names("control_plane/tasks/main.yml", "/usr/local/sbin/branchleft-deploy")],
        )

    def test_the_allowed_role_writing_the_compose_unit_path_is_found(self) -> None:
        self.write_tasks(
            "control_plane",
            "- ansible.builtin.copy:\n"
            "    src: x\n"
            "    dest: /etc/systemd/system/branchleft-compose@.service\n",
        )
        self.assertEqual(
            self.found(),
            [
                self.names(
                    "control_plane/tasks/main.yml",
                    "/etc/systemd/system/branchleft-compose@.service",
                )
            ],
        )

    def test_a_task_file_that_cannot_be_read_is_found_rather_than_skipped(self) -> None:
        self.write_tasks("other_role", "- name: [unclosed\n")
        self.assertEqual(
            self.found(),
            [
                "other_role/tasks/main.yml is not YAML that can be read,"
                " so what it installs is unknown"
            ],
        )

    def test_a_role_with_other_content_is_not_found(self) -> None:
        (self.roles / "other_role").mkdir()
        (self.roles / "other_role" / "README.md").write_text("not a program\n", encoding="utf-8")
        self.assertEqual(self.found(), [])


if __name__ == "__main__":
    unittest.main()
