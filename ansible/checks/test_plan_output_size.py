"""The size of demo1's plan must not grow with the host, and its shown diff stays under the cap.

The plan job of the gated apply reads one host's check-mode output and withholds all of it when it
is over 300,000 bytes (900,000 in all) or matches the secret scan. demo1's plan was once
1,029,385 bytes, far more than the files its roles ship, so two things are held here:

- a task of demo1's roles loops over nothing the host decides. A loop prints one line per item in
  every run, and a list made by a command on the host (the links under the scanned roots) has as
  many items as the host has links. A loop over a fixed list or a registered result of one is
  bounded by the role, and is not a finding. The one loop over a host list that remains is named in
  BOUNDED_HOST_LOOPS with the reason it is small.
- the refusal of the host scan (roles/demo1_build/tasks/_secret_holders.yml) names a bounded part of
  the unlisted paths. A host once held thousands, and a message naming every one was 486,151 bytes,
  printed twice, in front of the credential scan.
- the files the roles copy, with their diffs shown, add up to less than SHOWN_DIFF_BUDGET bytes.
  Ansible skips the diff of a source over 104,448 bytes, and a task that sets `diff: false` shows
  none, so only the rest is counted, once per loop item.

See README.md, "test_plan_output_size.py".
"""

from __future__ import annotations

import re
import unittest
from collections.abc import Iterator
from pathlib import Path

from check_pins import load_yaml
from test_plan_diff_scan import (
    COPIERS,
    ROOT,
    _including_environments,
    _loop_environments,
    _module_args,
    _source_files,
    render,
    role_variables,
    tasks_of,
)

PLAYBOOKS = ROOT / "ansible" / "playbooks"
DEMO1 = PLAYBOOKS / "demo1.yml"
# Ansible shows no diff for a source over this size (MAX_FILE_SIZE_FOR_DIFF).
ANSIBLE_DIFF_LIMIT = 104448
# The shown diff of the files demo1's roles copy, in bytes. The plan's cap per host is 300,000 and
# the rest of the output (task lines, results, failures) needs room, so the files get two thirds.
SHOWN_DIFF_BUDGET = 200_000
# A loop over a list a command or a find makes on the host. Each is a task file and a task name, and
# why the list has a few items at most. None is added for a scan: a list that grows with the host
# is collected in one expression and not looped.
BOUNDED_HOST_LOOPS: dict[tuple[str, str], str] = {
    (
        "ansible/roles/demo1_build/tasks/_candidate.yml",
        "Remove the superseded per-slot candidates",
    ): "one file per slot of the slot table, left by an earlier version of the role",
}
HOST_LISTS = re.compile(r"\.(stdout_lines|stdout|files|content)\b")
LOOP_KEYS = ("loop", "with_items", "with_list", "with_dict", "with_fileglob", "with_lines")


SECRET_HOLDERS = ROOT / "ansible" / "roles" / "demo1_build" / "tasks" / "_secret_holders.yml"
DEMO1_VARS = ROOT / "ansible" / "roles" / "demo1_build" / "vars" / "main.yml"
# The most paths and directories a refusal may name, and what one full message may weigh.
MOST_PATHS_NAMED = 50
MOST_DIRECTORIES_NAMED = 20
# A name of a list in a message that is bounded by what the role does to it before the message.
SHOWN_LISTS = ("demo1_build_secret_unlisted_shown", "demo1_build_secret_unlisted_by_directory")
JOIN_OF = re.compile(r"(\w+)\s*\|\s*join\b")


def refusal_messages() -> Iterator[tuple[str, str]]:
    """Yield (task name, message) of each fail and debug task of the host scan."""
    document, _problem = load_yaml(SECRET_HOLDERS)
    for task in document if isinstance(document, list) else []:
        for module in ("ansible.builtin.fail", "ansible.builtin.debug"):
            args = task.get(module)
            if isinstance(args, dict) and isinstance(args.get("msg"), str):
                yield str(task.get("name", "")), args["msg"]


def demo1_role_names() -> list[str]:
    """Return the roles the demo1 playbook lists."""
    names: list[str] = []
    document, _problem = load_yaml(DEMO1)
    for play in document if isinstance(document, list) else []:
        for entry in play.get("roles", []) if isinstance(play, dict) else []:
            value = entry.get("role", entry.get("name")) if isinstance(entry, dict) else entry
            names.append(Path(str(value)).name)
    return names


def host_loops(root: Path, names: list[str]) -> Iterator[tuple[str, str, str]]:
    """Yield (file, task name, loop text) for each loop over a list the host makes."""
    for name in names:
        for path, task, _off in tasks_of(root / "ansible" / "roles" / name):
            for key in LOOP_KEYS:
                spec = task.get(key)
                if isinstance(spec, str) and HOST_LISTS.search(spec):
                    yield path.relative_to(root).as_posix(), str(task.get("name", "")), spec


def shown_diff_bytes(root: Path, names: list[str]) -> tuple[int, list[tuple[int, str]]]:
    """Return (total, per-source sizes) of the copied files whose diff the plan would show."""
    roles_dir = root / "ansible" / "roles"
    every = {role.name: role_variables(role) for role in sorted(roles_dir.glob("*"))}
    fallback = {k: v for variables in every.values() for k, v in variables.items()}
    sized: list[tuple[int, str]] = []
    for name in names:
        role = roles_dir / name
        base = {**fallback, **every[name], "role_path": str(role)}
        for path, task, diff_is_off in tasks_of(role):
            used = _module_args(task, COPIERS)
            args = used[1] if used else None
            if used is None or not isinstance(args, dict) or diff_is_off:
                continue
            src = args.get("src")
            if "content" in args or args.get("remote_src") or not isinstance(src, str):
                continue
            for outer in _including_environments(role, path, base):
                for env in _loop_environments(task, outer):
                    text = render(src, env)
                    if "{{" in text:
                        continue
                    for source in _source_files(role, used[0], text):
                        size = source.stat().st_size
                        if size <= ANSIBLE_DIFF_LIMIT:
                            sized.append((size, f"{name}:{source.relative_to(root).as_posix()}"))
    return sum(size for size, _ in sized), sorted(sized, reverse=True)


class PlanOutputSizeCase(unittest.TestCase):
    """demo1's plan output is bounded by its roles, not by what the host holds."""

    def test_the_walk_reaches_the_roles_and_the_loop_it_is_about(self) -> None:
        names = demo1_role_names()
        for role in ("demo1_build", "demo1_egress_spool", "pull_trigger"):
            self.assertIn(role, names)
        remaining = {(file, task) for file, task, _ in host_loops(ROOT, names)}
        self.assertEqual(set(BOUNDED_HOST_LOOPS), remaining)

    def test_no_task_loops_over_a_list_the_host_makes(self) -> None:
        found = [
            f"{file}: {task}"
            for file, task, _ in host_loops(ROOT, demo1_role_names())
            if (file, task) not in BOUNDED_HOST_LOOPS
        ]
        self.assertEqual([], found, "\n".join(found))

    def test_a_loop_over_a_command_result_is_found(self) -> None:
        self.assertTrue(HOST_LISTS.search("{{ found.stdout_lines | zip(other.stdout_lines) }}"))
        self.assertFalse(HOST_LISTS.search("{{ demo1_build_slots }}"))
        self.assertFalse(HOST_LISTS.search("{{ demo1_build_units_load.results }}"))

    def test_the_refusal_of_the_host_scan_names_a_bounded_part_of_the_paths(self) -> None:
        messages = dict(refusal_messages())
        refusal = "Refuse a host that holds a secret-bearing file the holder list does not name"
        self.assertIn(refusal, messages)
        for name, message in messages.items():
            for listed in JOIN_OF.findall(message):
                self.assertIn(listed, SHOWN_LISTS, f"{name}: joins {listed}, which grows with the host")
        self.assertNotIn("demo1_build_secret_unlisted |", messages[refusal].replace("demo1_build_secret_unlisted | length", ""))
        document, _problem = load_yaml(DEMO1_VARS)
        if not isinstance(document, dict):
            self.fail("vars/main.yml is not a mapping")
        shown = document.get("demo1_build_secret_refusal_paths_shown")
        directories = document.get("demo1_build_secret_refusal_directories_shown")
        self.assertTrue(isinstance(shown, int) and 1 <= shown <= MOST_PATHS_NAMED)
        self.assertTrue(isinstance(directories, int) and 1 <= directories <= MOST_DIRECTORIES_NAMED)

    def test_a_message_joining_every_unlisted_path_is_found(self) -> None:
        self.assertEqual(["demo1_build_secret_unlisted"], JOIN_OF.findall("{{ demo1_build_secret_unlisted | join(', ') }}"))
        self.assertEqual(["x_shown"], JOIN_OF.findall("{{ x_shown | join(', ') }}"))

    def test_the_shown_diff_of_the_copied_files_is_inside_the_budget(self) -> None:
        total, sized = shown_diff_bytes(ROOT, demo1_role_names())
        largest = "\n".join(f"{size:>8} {where}" for size, where in sized[:8])
        self.assertGreater(len(sized), 5, "the walk found no copied file")
        self.assertLessEqual(
            total, SHOWN_DIFF_BUDGET, f"{total} bytes of diff are shown; the largest:\n{largest}"
        )

    def test_a_source_over_the_ansible_limit_is_not_counted(self) -> None:
        _total, sized = shown_diff_bytes(ROOT, demo1_role_names())
        self.assertTrue(all(size <= ANSIBLE_DIFF_LIMIT for size, _ in sized))
        self.assertFalse(any(where.endswith("pull_trigger.py") for _, where in sized))


if __name__ == "__main__":
    unittest.main()
