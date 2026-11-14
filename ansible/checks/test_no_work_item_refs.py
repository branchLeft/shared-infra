"""No shipped file under ansible/ names a work item (standards CMT-1..3).

A work item is named as the tracker's reference form, ``workspace#N``. Every text file under
``ansible/`` is read, so a reference cannot be shipped in a README, a test fixture or a role's
comments and slip past a check that only looks at one role. The pattern is written with an
escaped ``#`` so that this file does not contain the literal it forbids.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ANSIBLE = Path(__file__).resolve().parent.parent
WORK_ITEM = re.compile(r"(?i)workspace(?:\#|/issues/)\d")


def work_item_problems(root: Path) -> list[str]:
    """Return ``path:line`` for every line under ``root`` that names a work item."""
    problems: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if WORK_ITEM.search(line):
                problems.append(f"{path.relative_to(root)}:{number}")
    return problems


class NoWorkItemReferenceTests(unittest.TestCase):
    def test_no_file_under_ansible_names_a_work_item(self) -> None:
        self.assertEqual([], work_item_problems(ANSIBLE))

    def test_the_check_finds_a_reference_when_one_is_planted(self) -> None:
        # Built at run time so this file never holds the literal it forbids.
        tag = "work" + "space" + "#"
        self.assertTrue(WORK_ITEM.search("see branchLeft/" + tag + "2531"))
        self.assertTrue(WORK_ITEM.search(tag.upper() + "7"))
        self.assertFalse(WORK_ITEM.search("workspace\\#7 and no number"))


if __name__ == "__main__":
    unittest.main()
