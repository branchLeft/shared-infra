"""Read a role's tasks/main.yml as text: each task's name and body, in file order.

This is the one home of the task-name parser that the role unit tests import.
"""

import re
from pathlib import Path

TASK_LINE = re.compile(r"^- name: (.+)$")


def task_lines(tasks_file: Path) -> list[tuple[str, list[str]]]:
    """Return (name, body lines) for every task in tasks_file, in file order."""
    tasks: list[tuple[str, list[str]]] = []
    for line in tasks_file.read_text(encoding="utf-8").splitlines():
        match = TASK_LINE.match(line)
        if match:
            tasks.append((match.group(1).strip(), []))
        elif tasks:
            tasks[-1][1].append(line)
    return tasks
