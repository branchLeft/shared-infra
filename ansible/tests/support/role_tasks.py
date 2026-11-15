"""Read a role's tasks/main.yml as text: each task's name and body, in file order.

This is the one home of the task-name parser that the role unit tests import.
"""

import re
from pathlib import Path

TASK_LINE = re.compile(r"^- name: (.+)$")
NESTED_TASK_LINE = re.compile(r"^\s*- name: (.+)$")


def _split(tasks_file: Path, pattern: re.Pattern[str]) -> list[tuple[str, list[str]]]:
    tasks: list[tuple[str, list[str]]] = []
    for line in tasks_file.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            tasks.append((match.group(1).strip(), []))
        elif tasks:
            tasks[-1][1].append(line)
    return tasks


def task_lines(tasks_file: Path) -> list[tuple[str, list[str]]]:
    """Return (name, body lines) for every top-level task in tasks_file, in file order."""
    return _split(tasks_file, TASK_LINE)


def all_task_lines(tasks_file: Path) -> list[tuple[str, list[str]]]:
    """Return (name, body lines) for every task at any depth, in file order.

    A task inside a block or an always section is found too. A block's own body ends
    at its first inner task, so its inner tasks are listed after it, not inside it.
    """
    return _split(tasks_file, NESTED_TASK_LINE)
