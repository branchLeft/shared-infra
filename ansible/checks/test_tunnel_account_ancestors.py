"""tunnel_account_inputs_ancestors must be exactly the directories above the inputs directory.

The role refuses an inputs path whose parent is not a real, root-owned, not group- or
other-writable directory. That only protects the path if the list names every parent, root first;
a hand-kept list could drift from `tunnel_account_inputs_dir` unnoticed. This derives the list
from the directory and compares.
"""

from __future__ import annotations

import posixpath
import re
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]

VARS = Path(__file__).resolve().parent.parent / "roles" / "tunnel_account" / "vars" / "main.yml"
REFERENCE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def resolve(value: str, variables: dict[str, object]) -> str:
    """Fills `{{ name }}` references from the other variables of the same file."""
    previous = None
    while previous != value:
        previous = value
        value = REFERENCE.sub(lambda match: str(variables[match.group(1)]), value)
    return value


def parents(path: str) -> list[str]:
    """Every directory above `path`, root first."""
    found: list[str] = []
    current = posixpath.dirname(path)
    while True:
        found.append(current)
        if current == "/":
            return found[::-1]
        current = posixpath.dirname(current)


class InputsAncestors(unittest.TestCase):
    def setUp(self) -> None:
        self.variables = yaml.safe_load(VARS.read_text(encoding="utf-8"))

    def test_the_list_is_every_parent_of_the_inputs_directory_root_first(self) -> None:
        inputs_dir = resolve(self.variables["tunnel_account_inputs_dir"], self.variables)
        listed = [resolve(item, self.variables) for item in self.variables["tunnel_account_inputs_ancestors"]]
        self.assertEqual(parents(inputs_dir), listed)

    def test_a_list_that_stops_short_is_caught(self) -> None:
        inputs_dir = resolve(self.variables["tunnel_account_inputs_dir"], self.variables)
        self.assertNotEqual(parents(inputs_dir), parents(inputs_dir)[:-1])
        self.assertEqual(parents("/a/b/c"), ["/", "/a", "/a/b"])


if __name__ == "__main__":
    unittest.main()
