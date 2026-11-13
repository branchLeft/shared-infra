"""Pins on the Molecule "scenario leaves verify out" guard, which every role copies.

A role that shares its Molecule steps between scenarios has an `assert_parts.yml` that refuses
a scenario whose `skip-steps.txt` leaves out `verify`. No role imports another (ANS-12), so each
role carries its own copy of the pattern, and this test is the one place that holds them equal.
It also holds the pattern to the harness's reading of the file (`read_skips` in
`ansible/harness/run_harness.py`): the harness splits the text with `str.splitlines()`, strips each
line, and drops blank lines and lines that start with `#`. A line is a verify line to the harness
exactly when it strips to `verify`, so the guard must see the same lines, including the ones
`splitlines()` breaks on besides LF: CR, VT, FF, FS, GS, RS, NEL, LS and PS.

The pattern is held in a single-quoted YAML scalar named `*verify_skip_pattern` in the task's
`vars`, and the task passes that variable to `regex_search`. A single-quoted scalar keeps every
backslash, so the regex sees the text the file holds, and the test runs that text.

Sabotage, the CI-runnable red and then green: put the narrow `(?m)^verify\\s*$` back in any copy,
or change one character of one copy, and `test_every_copy_is_the_one_guard` or the harness
comparison fails; restore the file and they pass.
"""

from __future__ import annotations

import itertools
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
ASSERT_PARTS = "molecule/default/tasks/assert_parts.yml"
# The one text every copy holds, as it is written in the YAML file (before Jinja decodes it).
GUARD = (
    r"(?:\A|(?<=[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]))\s*verify\s*"
    r"(?=[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]|\Z)"
)
PATTERN_VAR = re.compile(r"^\s+(?:\w+_)?verify_skip_pattern: '([^']*)'$", re.MULTILINE)
SEARCH_CALL = re.compile(r"regex_search\(([^)]*)\)")
# Every character str.splitlines() breaks a line on, as the harness reads skip-steps.txt.
LINE_BREAKS = ("\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def copies() -> dict[str, list[str]]:
    """Return the verify-skip pattern of every role's assert_parts.yml, as written in the file."""
    found: dict[str, list[str]] = {}
    for path in sorted(ROLES.glob(f"*/{ASSERT_PARTS}")):
        found[str(path.relative_to(ROOT))] = PATTERN_VAR.findall(path.read_text(encoding="utf-8"))
    return found


def search_calls() -> dict[str, list[str]]:
    """Return what each role's assert_parts.yml hands to regex_search: it must be the pattern variable, never a literal."""
    return {
        str(path.relative_to(ROOT)): SEARCH_CALL.findall(path.read_text(encoding="utf-8"))
        for path in sorted(ROLES.glob(f"*/{ASSERT_PARTS}"))
    }


def guard_refuses(skip_file_text: str, pattern: str = GUARD) -> bool:
    """Return True when the guard sees that a skip file leaves out the verify step."""
    return re.search(pattern, skip_file_text) is not None


def harness_skips_verify(skip_file_text: str) -> bool:
    """Return True when run_harness.read_skips would leave verify out for this file's text."""
    lines = (line.strip() for line in skip_file_text.splitlines())
    return "verify" in {line for line in lines if line and not line.startswith("#")}


class VerifyGuardCopies(unittest.TestCase):
    def test_some_role_has_the_guard(self) -> None:
        self.assertGreaterEqual(len(copies()), 3, "db1_grants, db1_stack and edge_stack carry the guard")

    def test_every_copy_is_the_one_guard(self) -> None:
        for path, found in copies().items():
            with self.subTest(path=path):
                self.assertEqual(found, [GUARD], f"{path} holds {len(found)} verify-skip pattern(s); expected the shared one")


class VerifyGuardIsWhatTheTaskRuns(unittest.TestCase):
    def test_the_task_searches_with_the_pattern_variable_only(self) -> None:
        for path, calls in search_calls().items():
            with self.subTest(path=path):
                self.assertEqual(len(calls), 1, f"{path} must call regex_search once")
                self.assertRegex(calls[0], r"^\w*verify_skip_pattern$", f"{path} must pass the pattern variable, not a literal")


class VerifyGuardReadsLikeTheHarness(unittest.TestCase):
    def test_a_verify_line_is_refused_however_it_is_padded(self) -> None:
        for text in ("verify\n", "  verify\n", "\tverify\n", " \t verify \t\n", "verify", "verify\r\n", "idempotence\n   verify   \n"):
            with self.subTest(text=text):
                self.assertTrue(guard_refuses(text))

    def test_a_verify_line_is_refused_after_any_line_break_the_harness_splits_on(self) -> None:
        for sep in LINE_BREAKS:
            for text in (f"idempotence{sep}verify", f"verify{sep}idempotence", f"idempotence{sep}  verify  {sep}check-fresh"):
                with self.subTest(sep=repr(sep), text=text):
                    self.assertTrue(guard_refuses(text))

    def test_a_line_that_is_not_verify_is_not_refused(self) -> None:
        for text in (
            "",
            "# verify\n",
            "#verify\n",
            "  # verify\n",
            "unverify\n",
            "verify-more\n",
            "verify more\n",
            "verify # x\n",
            "- verify\n",
            "'verify'\n",
            "VERIFY\n",
            "x verify\n",
            "verify:\n",
            "idempotence\ncheck-fresh\n",
        ):
            with self.subTest(text=text):
                self.assertFalse(guard_refuses(text))

    def test_the_guard_and_the_harness_agree_on_every_short_file(self) -> None:
        # Every file of up to three pieces drawn from words, padding and every line break.
        pieces = ("verify", "verifyx", "#", "# verify", "idempotence", " ", "\t", *LINE_BREAKS)
        for count in range(4):
            for combo in itertools.product(pieces, repeat=count):
                text = "".join(combo)
                with self.subTest(text=text):
                    self.assertEqual(guard_refuses(text), harness_skips_verify(text), repr(text))

    def test_the_narrow_pattern_is_caught(self) -> None:
        narrow = r"(?m)^verify\s*$"
        self.assertFalse(guard_refuses("  verify\n", narrow), "the narrow pattern misses an indented verify")
        self.assertFalse(guard_refuses("idempotence\rverify\n", narrow), "the narrow pattern misses a bare CR")
        self.assertTrue(harness_skips_verify("  verify\n"))
        self.assertTrue(harness_skips_verify("idempotence\rverify\n"))


if __name__ == "__main__":
    unittest.main()
