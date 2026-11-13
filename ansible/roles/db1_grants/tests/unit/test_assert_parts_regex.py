"""Offline test of the verify-skip regex in molecule/default/tasks/assert_parts.yml.

The guard refuses a scenario whose skip-steps.txt leaves out the verify step. The harness
strips each line before it reads it, so the guard must match a verify line that is indented
too. This test reads the regex from the task file itself and checks it against lines a
harness could see. It needs no network.

Red then green: before the fix the indented "  verify" case fails, because the pattern
anchors at column zero. After the fix every case passes.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
ASSERT_PARTS = ROLE / "molecule" / "default" / "tasks" / "assert_parts.yml"


def guard_pattern() -> str:
    text = ASSERT_PARTS.read_text(encoding="utf-8")
    found = re.findall(r"regex_search\('(\(\?m\)[^']*)'\)", text)
    if len(found) != 1:
        raise AssertionError(f"expected one verify-skip regex in {ASSERT_PARTS}, found {len(found)}")
    return found[0]


def leaves_out_verify(skip_file_text: str) -> bool:
    """Return True when the guard sees that a skip file leaves out the verify step."""
    return re.search(guard_pattern(), skip_file_text) is not None


class VerifySkipGuard(unittest.TestCase):
    def test_a_verify_line_at_column_zero_is_refused(self) -> None:
        self.assertTrue(leaves_out_verify("verify\n"))

    def test_an_indented_verify_line_is_refused(self) -> None:
        self.assertTrue(leaves_out_verify("  verify\n"))

    def test_a_tab_indented_verify_line_is_refused(self) -> None:
        self.assertTrue(leaves_out_verify("\tverify\n"))

    def test_an_indented_verify_after_another_step_is_refused(self) -> None:
        self.assertTrue(leaves_out_verify("idempotence\n   verify   \n"))

    def test_a_commented_verify_line_is_not_refused(self) -> None:
        self.assertFalse(leaves_out_verify("# verify\n"))

    def test_a_different_step_name_is_not_refused(self) -> None:
        self.assertFalse(leaves_out_verify("idempotence\ncheck-fresh\n"))
        self.assertFalse(leaves_out_verify("unverify\nverify-more\n"))


if __name__ == "__main__":
    unittest.main()
