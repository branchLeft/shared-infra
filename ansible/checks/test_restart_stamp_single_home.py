"""Fails when a role other than restart_stamp reads, writes or decides from a stamp.

What it reports and what it allows is in ansible/roles/restart_stamp/README.md,
"The single-home check". The tests after the scan prove it can fail.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from role_tasks import parsed_tasks, short_name

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

# Modules that act on a file, a command or a service. Another role may not point one at a stamp.
ACTING = frozenset(
    {
        "assemble",
        "blockinfile",
        "command",
        "copy",
        "fetch",
        "file",
        "find",
        "get_url",
        "lineinfile",
        "raw",
        "replace",
        "script",
        "service",
        "shell",
        "slurp",
        "stat",
        "synchronize",
        "systemd",
        "systemd_service",
        "template",
        "unarchive",
        "uri",
    }
)
WRITING = frozenset({"blockinfile", "copy", "lineinfile", "replace", "template"})

# Modules restart_stamp may use: they read or write a file it is given, or work on facts.
OWNER_MODULES = frozenset({"assert", "copy", "include_tasks", "set_fact", "slurp", "stat"})


def text_of(value: object) -> str:
    """Return a task's arguments as one text, so a pattern can be searched in all of them."""
    return repr(value)


def violations(role: Path) -> list[str]:
    """Return every way a role other than restart_stamp reads, writes or runs on a stamp."""
    found: list[str] = []
    for name, task in parsed_tasks(role):
        for key, value in task.items():
            module = short_name(str(key))
            if module not in ACTING:
                continue
            arguments = text_of(value)
            label = f"{name}: {module}"
            # Every key of a task that acts, not only the module's arguments: the stamp may
            # be reached through the task's vars or its loop.
            around = text_of({k: v for k, v in task.items() if k != "name"})
            if STAMP_FILE.search(around) or STAMP_VARIABLE.search(around):
                found.append(f"{label} is given a stamp")
            if module in WRITING and PENDING_MARK.search(arguments):
                found.append(f"{label} writes the pending mark")
        # A stamp named in a task that does not act is data in the call to restart_stamp, or a
        # fact, and is allowed; a stamp named in a loop or a condition is a read or write in
        # the making, whatever the task is.
        for key in CONDITION_KEYS:
            if key not in task:
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
    """Return every module restart_stamp's tasks call, by short name."""
    used: set[str] = set()
    for _, task in parsed_tasks(role):
        for key in task:
            module = short_name(str(key))
            if module in ACTING or module in OWNER_MODULES:
                used.add(module)
    return used


def make_role(base: Path, name: str, tasks_text: str, script_text: str | None = None) -> Path:
    """Write a throwaway role with one task file and, when asked, a script in files/."""
    role = base / name
    (role / "tasks").mkdir(parents=True)
    (role / "tasks" / "main.yml").write_text(tasks_text, encoding="utf-8")
    if script_text is not None:
        (role / "files").mkdir()
        (role / "files" / "apply.sh").write_text(script_text, encoding="utf-8")
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
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", WRITE_BACK)
            self.assertEqual(["tasks/main.yml: copy is given a stamp"], violations(role))

    def test_a_write_of_the_pending_mark_is_reported_whatever_the_destination(self) -> None:
        text = (
            "---\n- name: Mark\n  ansible.builtin.copy:\n"
            "    content: \"pending\\n\"\n    dest: '{{ somewhere }}'\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: copy writes the pending mark"], violations(role))

    def test_a_read_of_a_stamp_is_reported(self) -> None:
        text = (
            "---\n- name: Read\n  ansible.builtin.slurp:\n"
            "    src: '{{ other_stamp_files.caddy }}'\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: slurp is given a stamp"], violations(role))

    def test_a_look_at_a_stamp_by_its_file_name_is_reported(self) -> None:
        text = (
            "---\n- name: Look\n  ansible.builtin.stat:\n"
            "    path: /var/lib/branchleft/other.applied\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: stat is given a stamp"], violations(role))

    def test_a_command_on_a_stamp_is_reported(self) -> None:
        text = (
            "---\n- name: Cat\n  ansible.builtin.command:\n"
            "    argv:\n      - cat\n      - /var/lib/branchleft/other.applied\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: command is given a stamp"], violations(role))

    def test_a_stamp_in_a_block_or_a_rescue_is_reported(self) -> None:
        nested = (
            "---\n- name: Outer\n  block:\n    - name: Inner\n      rescue:\n"
            "        - name: Read\n          ansible.builtin.slurp:\n"
            "            src: /var/lib/branchleft/other.applied\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", nested)
            self.assertEqual(["tasks/main.yml: slurp is given a stamp"], violations(role))

    def test_a_condition_on_a_stamp_file_is_reported(self) -> None:
        text = (
            "---\n- name: Do\n  ansible.builtin.debug:\n    msg: x\n"
            "  when: \"'other.applied' in other_list\"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: when names a stamp file"], violations(role))

    def test_a_copy_looped_over_the_stamp_variable_is_reported(self) -> None:
        # The module arguments name no stamp: the destination is the loop item. The loop is
        # where the stamps are named.
        text = (
            "---\n- name: Record\n  ansible.builtin.copy:\n"
            "    content: \"{{ item.value }}\\n\"\n    dest: '{{ item.key }}'\n"
            '  loop: "{{ other_stamp_files | dict2items }}"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            problems = violations(role)
            self.assertIn("tasks/main.yml: loop names a stamp variable", problems)
            self.assertIn("tasks/main.yml: copy is given a stamp", problems)

    def test_a_loop_over_a_stamp_variable_of_another_name_is_reported(self) -> None:
        text = (
            "---\n- name: Look\n  ansible.builtin.debug:\n    msg: x\n"
            '  with_dict: "{{ other_stamps }}"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: with_dict names a stamp variable"], violations(role))

    def test_a_stamp_variable_named_in_the_vars_of_a_file_task_is_reported(self) -> None:
        text = (
            "---\n- name: Record\n  ansible.builtin.copy:\n"
            "    content: x\n    dest: '{{ target }}'\n"
            "  vars:\n    target: '{{ other_stamps.caddy }}'\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual(["tasks/main.yml: copy is given a stamp"], violations(role))

    def test_a_script_that_names_a_stamp_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", "---\n[]\n", "cat /var/lib/branchleft/other.applied\n"
            )
            self.assertEqual(["files/apply.sh names a stamp file"], violations(role))

    def test_a_call_to_restart_stamp_is_not_reported(self) -> None:
        text = (
            "---\n- name: Read\n  ansible.builtin.include_role:\n"
            "    name: '{{ other_stamp_role }}'\n    tasks_from: read\n"
            "  vars:\n    restart_stamp_classes: '{{ other_stamp_files }}'\n"
            "- name: Keep\n  ansible.builtin.set_fact:\n"
            "    other_due: '{{ restart_stamp_decisions.caddy.due }}'\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            self.assertEqual([], violations(role))

    def test_stamp_files_named_in_vars_and_the_stamp_directory_are_not_reported(self) -> None:
        text = (
            "---\n- name: Create the directory of the stamps\n  ansible.builtin.file:\n"
            "    path: '{{ other_stamp_dir }}'\n    state: directory\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", text)
            (role / "vars").mkdir()
            (role / "vars" / "main.yml").write_text(
                "other_stamp_dir: /var/lib/branchleft\nother_stamp_files:\n"
                "  caddy: /var/lib/branchleft/other.caddy.applied\n",
                encoding="utf-8",
            )
            self.assertEqual([], violations(role))

    def test_a_module_that_acts_on_more_than_a_stamp_is_reported_in_the_owner(self) -> None:
        text = "---\n- name: Restart\n  ansible.builtin.command:\n    argv: [/bin/true]\n"
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), OWNER, text)
            self.assertEqual({"command"}, owner_modules(role) - OWNER_MODULES)

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
