"""The role's handler flush runs only after the isolation and the watch have been applied.

The policy program runs as root, and on a class-app host the handler that runs it fires at the
first flush. A flush placed before the post-write checks, the sudoers checks or the includes of
_isolation.yml and _watch.yml would run the program before those files are checked. These tests
read the role's task list only.
"""

from __future__ import annotations

import unittest
from collections.abc import Callable
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
MAIN = ROLE / "tasks" / "main.yml"
FLUSH = "ansible.builtin.meta"
INCLUDE = "ansible.builtin.include_tasks"
ISOLATION = "_isolation.yml"
WATCH = "_watch.yml"


def _tasks() -> list[dict[str, object]]:
    raw = yaml.safe_load(MAIN.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        return []
    return [{str(k): v for k, v in entry.items()} for entry in raw if isinstance(entry, dict)]


def _indices(predicate: Callable[[dict[str, object]], bool]) -> list[int]:
    return [i for i, task in enumerate(_tasks()) if predicate(task)]


def _is_flush(task: dict[str, object]) -> bool:
    return task.get(FLUSH) == "flush_handlers"


def _includes(path: str) -> list[int]:
    return _indices(lambda task: task.get(INCLUDE) == path)


class FlushOrder(unittest.TestCase):
    def test_the_isolation_and_watch_includes_exist_once(self) -> None:
        self.assertEqual(len(_includes(ISOLATION)), 1)
        self.assertEqual(len(_includes(WATCH)), 1)

    def test_there_is_one_flush_and_it_follows_both_includes(self) -> None:
        flushes = _indices(_is_flush)
        self.assertEqual(
            len(flushes), 1, "tasks/main.yml must hold exactly one flush_handlers task"
        )
        isolation_at = _includes(ISOLATION)[0]
        watch_at = _includes(WATCH)[0]
        self.assertGreater(
            flushes[0],
            isolation_at,
            "flush_handlers runs before _isolation.yml: the policy program would run unchecked",
        )
        self.assertGreater(
            flushes[0],
            watch_at,
            "flush_handlers runs before _watch.yml: the policy program would run unchecked",
        )

    def test_the_flush_is_the_last_task_of_the_role(self) -> None:
        flushes = _indices(_is_flush)
        self.assertEqual(flushes[0], len(_tasks()) - 2, "the enable loop follows the flush")


if __name__ == "__main__":
    unittest.main()
