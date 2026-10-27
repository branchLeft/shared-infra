"""Tests for check_tunnel_account_ancestors: the real role passes, and a drifted copy fails.

Each case edits a copy of the real vars file and asserts that the check names the drift.
A case whose edit matched nothing fails, so a sabotage that changed nothing cannot pass.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from check_tunnel_account_ancestors import VARS, check

INPUTS_LINE = "tunnel_account_inputs_dir: '{{ tunnel_account_key_dir }}/inputs'"
ANCESTOR_LINE = "  - '{{ tunnel_account_key_dir }}'\n"


class RealRole(unittest.TestCase):
    def test_the_ancestor_list_is_the_inputs_directory_parents(self) -> None:
        self.assertEqual([], check(VARS))


class Drift(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.copy = Path(temp.name) / "main.yml"
        shutil.copy(VARS, self.copy)
        self.text = self.copy.read_text(encoding="utf-8")

    def _edit(self, old: str, new: str) -> None:
        self.assertEqual(1, self.text.count(old), f"sabotage did not match exactly once: {old!r}")
        self.copy.write_text(self.text.replace(old, new), encoding="utf-8")

    def test_a_directory_level_added_to_the_inputs_path_fails(self) -> None:
        self._edit(INPUTS_LINE, "tunnel_account_inputs_dir: '{{ tunnel_account_key_dir }}/x/inputs'")
        findings = check(self.copy)
        self.assertEqual(1, len(findings))
        self.assertIn("/etc/branchleft/db-tunnel/x", findings[0])

    def test_an_ancestor_removed_from_the_list_fails(self) -> None:
        self._edit(ANCESTOR_LINE, "")
        findings = check(self.copy)
        self.assertEqual(1, len(findings))
        self.assertIn("/etc/branchleft/db-tunnel", findings[0])

    def test_an_ancestor_added_to_the_list_fails(self) -> None:
        self._edit(ANCESTOR_LINE, ANCESTOR_LINE + "  - /home\n")
        self.assertEqual(1, len(check(self.copy)))

    def test_a_reordered_list_fails(self) -> None:
        self._edit("  - /etc\n  - /etc/branchleft\n", "  - /etc/branchleft\n  - /etc\n")
        self.assertEqual(1, len(check(self.copy)))


if __name__ == "__main__":
    unittest.main()
