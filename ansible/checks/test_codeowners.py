"""Tests that the file which reads the lock for the pin gate is owner-reviewed.

ansible/checks/check_pins.py is the pin gate, and it loads the lock reader and the allowed
marker set from the role's install program (install_runtime.py), which keeps no second copy.
A pull request that edits only that program, on a role path, would change what the gate reads
and need nothing but the reviewer App's approval, unless CODEOWNERS names the file. This test
reads .github/CODEOWNERS the way GitHub does (the last matching line wins) and fails when the
file is not the owner's.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import check_pins
import pathspec

ROOT = Path(__file__).resolve().parents[2]
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
OWNER = "@branchLeft/branchleft-admin"
INSTALL_PROGRAM = "ansible/roles/ansible_runtime/files/install_runtime.py"
# A file in the same role that is merged on the reviewer App's approval alone, so that a
# matcher that called everything owned would be seen.
UNOWNED_NEIGHBOUR = "ansible/roles/ansible_runtime/README.md"


def parse_rules(text: str) -> list[tuple[str, list[str]]]:
    """Return each line of a CODEOWNERS file as its pattern and its owners, in file order."""
    rules: list[tuple[str, list[str]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, *owners = line.split()
        rules.append((pattern, owners))
    return rules


def owners_of(path: str, rules: list[tuple[str, list[str]]]) -> list[str]:
    """Return the owners of ``path``: those of the last rule that matches it, or none."""
    owners: list[str] = []
    for pattern, rule_owners in rules:
        if pathspec.GitIgnoreSpec.from_lines([pattern]).match_file(path):
            owners = rule_owners
    return owners


class CodeownersTests(unittest.TestCase):
    """The install program is the owner's, and the matcher can tell an owned file from not."""

    def setUp(self) -> None:
        self.rules = parse_rules(CODEOWNERS.read_text(encoding="utf-8"))

    def test_the_install_program_is_owned_by_the_owner(self) -> None:
        self.assertEqual([OWNER], owners_of(INSTALL_PROGRAM, self.rules))

    def test_the_program_is_the_file_check_pins_loads(self) -> None:
        # The path above is the one the gate reads, so the owner line cannot name another file.
        self.assertEqual(INSTALL_PROGRAM, check_pins.RUNTIME_PROGRAM.relative_to(ROOT).as_posix())

    def test_a_neighbouring_role_file_is_not_the_owners(self) -> None:
        self.assertEqual([], owners_of(UNOWNED_NEIGHBOUR, self.rules))

    def test_the_host_role_lists_and_their_check_are_the_owners(self) -> None:
        # The list decides which roles a pulled playbook may run as root, so only the owner
        # merges an edit to it, to the check that reads it, or to the tests that hold the check.
        for path in (
            "ansible/checks/host_roles.yml",
            "ansible/checks/check_enrolment.py",
            "ansible/checks/test_check_host_roles.py",
        ):
            with self.subTest(path=path):
                self.assertEqual([OWNER], owners_of(path, self.rules))

    def test_the_last_matching_line_wins(self) -> None:
        rules = [("/a/", [OWNER]), ("/a/b.py", ["@someone-else"])]
        self.assertEqual(["@someone-else"], owners_of("a/b.py", rules))
        self.assertEqual([OWNER], owners_of("a/c.py", rules))
        self.assertEqual([], owners_of("z/c.py", rules))


if __name__ == "__main__":
    unittest.main()
