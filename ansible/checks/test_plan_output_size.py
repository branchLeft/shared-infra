"""The size of demo1's plan must not grow with the host, and its shown diff stays under the cap.

The plan job of the gated apply reads one host's check-mode output and withholds all of it when it
is over 300,000 bytes (900,000 in all) or matches the secret scan. demo1's plan was once
1,029,385 bytes, far more than the files its roles ship, so two things are held here:

- a task of demo1's roles loops over nothing the host decides. A loop prints one line per item in
  every run, and a list made by a command on the host (the links under the scanned roots) has as
  many items as the host has links. A loop over a fixed list or a registered result of one is
  bounded by the role, and is not a finding. The one loop over a host list that remains is named in
  BOUNDED_HOST_LOOPS with the reason it is small.
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
