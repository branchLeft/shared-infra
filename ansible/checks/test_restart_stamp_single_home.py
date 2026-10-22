"""Fails when a role other than restart_stamp reads, writes or decides from a stamp.

What it reports and what it allows is in ansible/roles/restart_stamp/README.md,
"The single-home check". The tests after the scan prove it can fail.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from role_tasks import (
    BLOCK_KEYS,
    included_role,
    own_file,
    parsed_tasks,
    role_call,
    task_modules,
    text_of,
)

ROOT = Path(__file__).resolve().parents[2]
ROLE_DIRS = (ROOT / "ansible" / "roles", ROOT / "ansible" / "patterns")
OWNER = "restart_stamp"
EDGE = "edge_stack"

# A stamp is named by its file name, or by the variable a role keeps its stamp paths in.
STAMP_FILE = re.compile(r"\.applied(?![\w-])")
STAMP_VARIABLE = re.compile(r"(?:_stamp_files?|_stamps)(?![\w])")
CONDITION_KEYS = (
    "loop",
    "with_items",
    "with_dict",
    "with_list",
    "until",
    "when",
    "changed_when",
    "failed_when",
    "register",
)
PENDING_MARK = re.compile(r"(?<![\w-])pending(?![\w-])")
LOOKUP = re.compile(r"(?<![\w.])(?:lookup|query|q)\s*\(")

# The tasks of another role that do not act on a file, a command or a service, so they may
# carry a stamp as data. Every other module is screened, whether or not this list knows it.
NON_ACTING = frozenset({"assert", "debug", "set_fact"})

# Modules restart_stamp may use: they read or write a file it is given, or work on facts.
OWNER_MODULES = frozenset({"assert", "copy", "include_tasks", "set_fact", "slurp", "stat"})


def does_not_act(role: Path, module: str, arguments: object) -> bool:
    """Say whether a task of another role is one of the three that may carry a stamp.

    These are a fact, an assertion or a message; an include of restart_stamp, resolved by the
    check that finds compositions; and an include of one of the role's own files.
    """
    if module == "include_role":
        target = included_role(role, role_call(arguments)[0])
        return target is not None and target.name == OWNER
    if module == "include_tasks":
        return own_file(role, arguments)
    return module in NON_ACTING


def violations(role: Path) -> list[str]:
    """Return every way a role other than restart_stamp reads, writes or runs on a stamp."""
    found: list[str] = []
    for name, task in parsed_tasks(role):
        # Every key of a task, not only the module's arguments: the stamp may be reached
        # through the task's vars or its loop. The tasks of a block are read as tasks of their own.
        around = text_of({k: v for k, v in task.items() if k != "name" and k not in BLOCK_KEYS})
        names_stamp = bool(STAMP_FILE.search(around) or STAMP_VARIABLE.search(around))
        for module, arguments in task_modules(task):
            if does_not_act(role, module, arguments):
                continue
            label = f"{name}: {module}"
            if names_stamp:
                found.append(f"{label} is given a stamp")
            if PENDING_MARK.search(text_of(arguments)):
                found.append(f"{label} writes the pending mark")
        # A lookup reads a file whatever the task is, so a lookup in a task that names a stamp
        # is a read in the making, even in a fact.
        if names_stamp and LOOKUP.search(around):
            found.append(f"{name}: a lookup or query is given a stamp")
        # A stamp named in a loop or a condition is a read or write in the making, whatever
        # the task is.
        for key in task:
            if key not in CONDITION_KEYS and not str(key).startswith("with_"):
                continue
            if STAMP_FILE.search(text_of(task[key])):
                found.append(f"{name}: {key} names a stamp file")
            if STAMP_VARIABLE.search(text_of(task[key])):
                found.append(f"{name}: {key} names a stamp variable")
    for path in sorted(role.rglob("*")):
        if not path.is_file() or path.suffix in {".yml", ".yaml", ".md"}:
            continue
        relative = path.relative_to(role)
        if relative.parts[0] in {"molecule", "tests"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if STAMP_FILE.search(text):
            found.append(f"{relative.as_posix()} names a stamp file")
    return found


def owner_modules(role: Path) -> set[str]:
    """Return every module restart_stamp's tasks call, by short name, whatever the module."""
    return {module for _, task in parsed_tasks(role) for module, _ in task_modules(task)}


OWNER_ROLE_VARIABLE = "other_stamp_role: '{{ role_path | realpath | dirname }}/restart_stamp'\n"


def make_role(
    base: Path,
    name: str,
    tasks_text: str,
    script_text: str | None = None,
    vars_text: str | None = None,
    extra_files: Mapping[str, str] | None = None,
) -> Path:
    """Write a throwaway role with one task file and, when asked, a script, a vars file and more."""
    role = base / name
    (role / "tasks").mkdir(parents=True)
    (role / "tasks" / "main.yml").write_text(tasks_text, encoding="utf-8")
    for relative, text in (extra_files or {}).items():
        (role / relative).parent.mkdir(parents=True, exist_ok=True)
        (role / relative).write_text(text, encoding="utf-8")
    if script_text is not None:
        (role / "files").mkdir()
        (role / "files" / "apply.sh").write_text(script_text, encoding="utf-8")
    if vars_text is not None:
        (role / "vars").mkdir()
        (role / "vars" / "main.yml").write_text("---\n" + vars_text, encoding="utf-8")
    return role


WRITE_BACK = """\
---
- name: Record a class
  ansible.builtin.copy:
    content: "{{ other_fingerprint }}\\n"
    dest: '{{ other_stamp_files.caddy }}'
    mode: '0600'
"""


class RestartStampSingleHomeTest(unittest.TestCase):
    def reported(
        self,
        tasks_text: str,
        vars_text: str | None = None,
        extra_files: Mapping[str, str] | None = None,
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", tasks_text, vars_text=vars_text, extra_files=extra_files
            )
            return violations(role)

    def test_no_other_role_reads_writes_or_decides_from_a_stamp(self) -> None:
        found: dict[str, list[str]] = {}
        for base in ROLE_DIRS:
            if not base.is_dir():
                continue
            for role in sorted(base.iterdir()):
                if not role.is_dir() or role.name == OWNER:
                    continue
                problems = violations(role)
                if problems:
                    found[f"{base.name}/{role.name}"] = problems
        self.assertEqual({}, found, "only restart_stamp may read or write a stamp")

    def test_the_owner_acts_on_nothing_but_the_stamps_and_the_facts(self) -> None:
        used = owner_modules(ROLE_DIRS[0] / OWNER)
        self.assertNotEqual(
            set(), used, "the owner must use some module, or the scan reads nothing"
        )
        self.assertEqual(set(), used - OWNER_MODULES, "restart_stamp may use only these modules")

    def test_the_scan_reads_the_tasks_where_the_stamps_are_written(self) -> None:
        # A control for the scan of the others: pointed at the owner, the parse must find the
        # stat, the slurp and the copy that read and write the stamps, or a clean result for
        # the other roles would only mean the parse saw no task.
        used = owner_modules(ROLE_DIRS[0] / OWNER)
        self.assertLessEqual({"stat", "slurp", "copy"}, used)

    def test_a_write_to_a_stamp_is_reported(self) -> None:
        self.assertEqual(["tasks/main.yml: copy is given a stamp"], self.reported(WRITE_BACK))

    def test_a_write_of_the_pending_mark_is_reported_whatever_the_destination(self) -> None:
        text = (
            "---\n- name: Mark\n  ansible.builtin.copy:\n"
            "    content: \"pending\\n\"\n    dest: '{{ somewhere }}'\n"
        )
        self.assertEqual(["tasks/main.yml: copy writes the pending mark"], self.reported(text))

    def test_a_write_of_the_pending_mark_by_a_module_that_is_not_a_file_module_is_reported(
        self,
    ) -> None:
        text = "---\n- name: Mark\n  ansible.builtin.shell: echo pending > /somewhere\n"
        self.assertEqual(["tasks/main.yml: shell writes the pending mark"], self.reported(text))

    def test_a_read_of_a_stamp_is_reported(self) -> None:
        text = (
            "---\n- name: Read\n  ansible.builtin.slurp:\n"
            "    src: '{{ other_stamp_files.caddy }}'\n"
        )
        self.assertEqual(["tasks/main.yml: slurp is given a stamp"], self.reported(text))

    def test_a_look_at_a_stamp_by_its_file_name_is_reported(self) -> None:
        text = (
            "---\n- name: Look\n  ansible.builtin.stat:\n"
            "    path: /var/lib/branchleft/other.applied\n"
        )
        self.assertEqual(["tasks/main.yml: stat is given a stamp"], self.reported(text))

    def test_a_command_on_a_stamp_is_reported(self) -> None:
        text = (
            "---\n- name: Cat\n  ansible.builtin.command:\n"
            "    argv:\n      - cat\n      - /var/lib/branchleft/other.applied\n"
        )
        self.assertEqual(["tasks/main.yml: command is given a stamp"], self.reported(text))

    def test_a_module_the_screen_does_not_list_is_reported_when_it_is_given_a_stamp(self) -> None:
        # The screen allows three kinds of task and reports a stamp in every other, so a module
        # nobody listed is screened. These two were outside the list the screen used to hold.
        waiting = (
            "---\n- name: Wait\n  ansible.builtin.wait_for:\n"
            "    path: /var/lib/branchleft/other.applied\n"
        )
        editing = (
            "---\n- name: Edit\n  community.general.ini_file:\n"
            "    path: /var/lib/branchleft/other.applied\n    option: x\n    value: y\n"
        )
        self.assertEqual(["tasks/main.yml: wait_for is given a stamp"], self.reported(waiting))
        self.assertEqual(["tasks/main.yml: ini_file is given a stamp"], self.reported(editing))

    def test_a_task_in_the_action_or_local_action_form_is_read_by_its_module_word(self) -> None:
        legacy = (
            "---\n- name: Write\n"
            "  action: copy content=pending dest=/var/lib/branchleft/o.applied\n"
        )
        local = "---\n- name: Cat\n  local_action: command cat /var/lib/branchleft/o.applied\n"
        mapping = (
            "---\n- name: Write\n  action:\n    module: ansible.builtin.copy\n"
            "    dest: /var/lib/branchleft/o.applied\n    content: x\n"
        )
        self.assertEqual(
            [
                "tasks/main.yml: copy is given a stamp",
                "tasks/main.yml: copy writes the pending mark",
            ],
            self.reported(legacy),
        )
        self.assertEqual(["tasks/main.yml: command is given a stamp"], self.reported(local))
        self.assertEqual(["tasks/main.yml: copy is given a stamp"], self.reported(mapping))

    def test_a_stamp_in_a_block_or_a_rescue_is_reported(self) -> None:
        nested = (
            "---\n- name: Outer\n  block:\n    - name: Inner\n      rescue:\n"
            "        - name: Read\n          ansible.builtin.slurp:\n"
            "            src: /var/lib/branchleft/other.applied\n"
        )
        self.assertEqual(["tasks/main.yml: slurp is given a stamp"], self.reported(nested))

    def test_a_condition_on_a_stamp_file_is_reported(self) -> None:
        text = (
            "---\n- name: Do\n  ansible.builtin.debug:\n    msg: x\n"
            "  when: \"'other.applied' in other_list\"\n"
        )
        self.assertEqual(["tasks/main.yml: when names a stamp file"], self.reported(text))

    def test_a_copy_looped_over_the_stamp_variable_is_reported(self) -> None:
        # The module arguments name no stamp: the destination is the loop item. The loop is
        # where the stamps are named.
        text = (
            "---\n- name: Record\n  ansible.builtin.copy:\n"
            "    content: \"{{ item.value }}\\n\"\n    dest: '{{ item.key }}'\n"
            '  loop: "{{ other_stamp_files | dict2items }}"\n'
        )
        problems = self.reported(text)
        self.assertIn("tasks/main.yml: loop names a stamp variable", problems)
        self.assertIn("tasks/main.yml: copy is given a stamp", problems)

    def test_a_loop_over_a_stamp_variable_of_another_name_is_reported(self) -> None:
        text = (
            "---\n- name: Look\n  ansible.builtin.debug:\n    msg: x\n"
            '  with_dict: "{{ other_stamps }}"\n'
        )
        self.assertEqual(["tasks/main.yml: with_dict names a stamp variable"], self.reported(text))

    def test_a_loop_that_reads_files_is_reported_whatever_its_with_word(self) -> None:
        text = (
            "---\n- name: Look\n  ansible.builtin.debug:\n    msg: x\n"
            '  with_file: "{{ other_stamp_files.caddy }}"\n'
        )
        self.assertEqual(["tasks/main.yml: with_file names a stamp variable"], self.reported(text))

    def test_a_stamp_variable_named_in_the_vars_of_a_file_task_is_reported(self) -> None:
        text = (
            "---\n- name: Record\n  ansible.builtin.copy:\n"
            "    content: x\n    dest: '{{ target }}'\n"
            "  vars:\n    target: '{{ other_stamps.caddy }}'\n"
        )
        self.assertEqual(["tasks/main.yml: copy is given a stamp"], self.reported(text))

    def test_a_script_that_names_a_stamp_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", "---\n[]\n", "cat /var/lib/branchleft/other.applied\n"
            )
            self.assertEqual(["files/apply.sh names a stamp file"], violations(role))

    def test_a_lookup_that_reads_a_stamp_in_a_fact_is_reported(self) -> None:
        # A fact is allowed to carry a stamp as data, but not to read one: the lookup runs
        # on the controller and reads the file whatever module the task is.
        for call in (
            "lookup('file', other_stamp_files.caddy)",
            "lookup('pipe', 'cat ' + other_stamp_files.caddy)",
            "query('file', other_stamp_files.caddy)",
            "q('file', other_stamp_files.caddy)",
        ):
            text = f'---\n- name: Keep\n  ansible.builtin.set_fact:\n    x: "{{{{ {call} }}}}"\n'
            with self.subTest(call=call):
                self.assertEqual(
                    ["tasks/main.yml: a lookup or query is given a stamp"], self.reported(text)
                )

    def test_a_lookup_that_names_no_stamp_is_not_reported(self) -> None:
        text = (
            "---\n- name: Keep\n  ansible.builtin.set_fact:\n"
            "    x: \"{{ lookup('ansible.builtin.env', 'HOME') }}\"\n"
        )
        self.assertEqual([], self.reported(text))

    def test_a_call_to_restart_stamp_is_not_reported(self) -> None:
        text = (
            "---\n- name: Read\n  ansible.builtin.include_role:\n"
            "    name: '{{ other_stamp_role }}'\n    tasks_from: read\n"
            "  vars:\n    restart_stamp_classes: '{{ other_stamp_files }}'\n"
            "- name: Keep\n  ansible.builtin.set_fact:\n"
            "    other_due: '{{ restart_stamp_decisions.caddy.due }}'\n"
        )
        self.assertEqual([], self.reported(text, OWNER_ROLE_VARIABLE))

    def test_a_call_to_another_role_is_given_no_stamp(self) -> None:
        # The name resolves to a role that is not restart_stamp, so the include is a task like
        # any other and a stamp in it is reported.
        text = (
            "---\n- name: Hand over\n  ansible.builtin.include_role:\n"
            "    name: '{{ other_stamp_role }}'\n"
            "  vars:\n    classes: '{{ other_stamp_files }}'\n"
        )
        elsewhere = "other_stamp_role: '{{ role_path | realpath | dirname }}/another_role'\n"
        self.assertEqual(
            ["tasks/main.yml: include_role is given a stamp"], self.reported(text, elsewhere)
        )

    def test_a_block_is_read_by_its_own_tasks_and_not_through_its_children(self) -> None:
        # The lookup of a script in one child and the stamp in the call to restart_stamp in
        # another are not one task: the outer block names both, and is not given either.
        text = (
            "---\n- name: Outer\n  block:\n"
            "    - name: Script\n      ansible.builtin.command:\n"
            "        argv: ['/bin/sh', \"{{ lookup('ansible.builtin.file', 'apply.sh') }}\"]\n"
            "    - name: Hand over\n      ansible.builtin.include_role:\n"
            "        name: '{{ other_stamp_role }}'\n"
            "      vars:\n        classes: '{{ other_stamp_files }}'\n"
        )
        self.assertEqual([], self.reported(text, OWNER_ROLE_VARIABLE))

    def test_a_call_whose_name_cannot_be_resolved_is_given_no_stamp(self) -> None:
        # The same include with no variable behind its name: the check cannot show it is the
        # owner, which is what the composition check also says of it.
        text = (
            "---\n- name: Hand over\n  ansible.builtin.include_role:\n"
            "    name: '{{ somebody_elses_variable }}'\n"
            "  vars:\n    classes: '{{ other_stamp_files }}'\n"
        )
        self.assertEqual(["tasks/main.yml: include_role is given a stamp"], self.reported(text))

    def test_an_include_of_the_roles_own_file_may_carry_a_stamp_and_another_may_not(self) -> None:
        own = (
            "---\n- name: Go on\n  ansible.builtin.include_tasks: _next.yml\n"
            "  vars:\n    next_stamp_file: '{{ other_stamp_files.caddy }}'\n"
        )
        outside = (
            "---\n- name: Go on\n"
            "  ansible.builtin.include_tasks: '{{ role_path }}/../x/tasks/y.yml'\n"
            "  vars:\n    next_stamp_file: '{{ other_stamp_files.caddy }}'\n"
        )
        self.assertEqual([], self.reported(own))
        self.assertEqual(["tasks/main.yml: include_tasks is given a stamp"], self.reported(outside))

    def test_an_include_of_a_file_the_scan_does_not_read_may_carry_no_stamp(self) -> None:
        # The scan reads tasks/ and handlers/ only, so a file anywhere else in the role is not
        # an own file, even when the path stays inside the role: what it does is never seen.
        # The first path in each pair is the one the scan reads, the control of the second.
        stamp_var = "  vars:\n    next_stamp_file: '{{ other_stamp_files.caddy }}'\n"
        for path, extra in (
            ("'{{ role_path }}/tasks/more.yml'", {}),
            ("'{{ role_path }}/handlers/more.yml'", {}),
            ("_more.yml", {"tasks/_more.yml": "---\n[]\n"}),
        ):
            text = f"---\n- name: Go on\n  ansible.builtin.include_tasks: {path}\n{stamp_var}"
            with self.subTest(path=path):
                self.assertEqual([], self.reported(text, extra_files=extra))
        for path, extra in (
            ("'{{ role_path }}/vars/more.yml'", {"vars/more.yml": "---\n[]\n"}),
            ("'{{ role_path }}/files/more.yml'", {"files/more.yml": "---\n[]\n"}),
            ("files/more.yml", {"files/more.yml": "---\n[]\n"}),
            # A bare name that is also a file at the root of the role: Ansible may find it there.
            ("more.yml", {"tasks/more.yml": "---\n[]\n", "more.yml": "---\n[]\n"}),
            ("'{{ role_path }}/tasks/more.txt'", {"tasks/more.txt": "---\n[]\n"}),
        ):
            text = f"---\n- name: Go on\n  ansible.builtin.include_tasks: {path}\n{stamp_var}"
            with self.subTest(path=path):
                self.assertEqual(
                    ["tasks/main.yml: include_tasks is given a stamp"],
                    self.reported(text, extra_files=extra),
                )

    def test_stamp_files_named_in_vars_and_the_stamp_directory_are_not_reported(self) -> None:
        text = (
            "---\n- name: Create the directory of the stamps\n  ansible.builtin.file:\n"
            "    path: '{{ other_stamp_dir }}'\n    state: directory\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp),
                "other",
                text,
                vars_text=(
                    "other_stamp_dir: /var/lib/branchleft\nother_stamp_files:\n"
                    "  caddy: /var/lib/branchleft/other.caddy.applied\n"
                ),
            )
            self.assertEqual([], violations(role))

    def test_a_module_that_acts_on_more_than_a_stamp_is_reported_in_the_owner(self) -> None:
        # Named in no list the screen holds: the owner's tasks are all read, so a module that
        # is neither a stamp module nor a fact module is reported by name.
        texts = {
            "command": "---\n- name: Run\n  ansible.builtin.command:\n    argv: [/bin/true]\n",
            "reboot": "---\n- name: Reboot\n  ansible.builtin.reboot:\n",
            "docker_container": (
                "---\n- name: Start\n  community.docker.docker_container:\n    name: x\n"
            ),
            "wait_for": "---\n- name: Wait\n  ansible.builtin.wait_for:\n    timeout: 1\n",
        }
        for module, text in texts.items():
            with self.subTest(module=module), tempfile.TemporaryDirectory() as tmp:
                role = make_role(Path(tmp), OWNER, text)
                self.assertEqual({module}, owner_modules(role) - OWNER_MODULES)

    def test_a_module_in_the_legacy_form_is_reported_in_the_owner_by_its_module_word(self) -> None:
        text = "---\n- name: Reboot\n  action: reboot\n"
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), OWNER, text)
            self.assertEqual({"reboot"}, owner_modules(role) - OWNER_MODULES)

    def test_the_real_edge_stack_with_a_stamp_write_put_back_is_reported(self) -> None:
        # The real role passes, so the scan is also run on it with the copy of the stamp
        # write that was removed from it put back: that is the defect this check is for.
        source = ROLE_DIRS[0] / EDGE
        with tempfile.TemporaryDirectory() as tmp:
            role = Path(tmp) / EDGE
            shutil.copytree(source, role, symlinks=True, ignore=shutil.ignore_patterns("molecule"))
            self.assertEqual([], violations(role))
            deliver = role / "tasks" / "_deliver.yml"
            deliver.write_text(
                deliver.read_text(encoding="utf-8")
                + WRITE_BACK.replace("other_stamp_files", "edge_stack_stamp_files").replace(
                    "---\n", ""
                ),
                encoding="utf-8",
            )
            problems = violations(role)
            self.assertTrue(any("copy is given a stamp" in line for line in problems), problems)


if __name__ == "__main__":
    unittest.main()
