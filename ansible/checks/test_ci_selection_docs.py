"""Tests that the prose on which changes run every shard matches ci_select.py.

EVERY_SHARD in ci_select.py is the one home of that rule. The header of
.github/workflows/ansible.yml and the "What runs" row of ansible/README.md describe it in
prose. A sentence that names the checks folder as a whole, or leaves out one of the checks
files the shards read, describes a gate wrongly, so these tests fail on it.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import ci_select

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"
README = ROOT / "ansible" / "README.md"
# The files under ansible/checks/ that every shard reads: EVERY_SHARD names each one.
SHARD_INPUTS = tuple(
    entry.rsplit("/", 1)[1]
    for entry in ci_select.EVERY_SHARD
    if entry.startswith("ansible/checks/") and not entry.endswith("/")
)
# The wording the stale claim used: the whole folder, and the list that named it.
STALE = ("the checks,", "checks, lock")


def flat(text: str) -> str:
    """Return ``text`` with comment marks, line breaks and runs of spaces removed."""
    return " ".join(" ".join(line.lstrip("#") for line in text.splitlines()).split())


def header_clause() -> str:
    """Return the sentence of the workflow header that says what runs every shard."""
    text = flat(WORKFLOW.read_text(encoding="utf-8"))
    start = text.index("change to the harness")
    return text[start : text.index("lint job only", start) + len("lint job only")]


def readme_clause() -> str:
    """Return the Shards cell of the pull request row in the README's What runs table."""
    row = next(
        line
        for line in README.read_text(encoding="utf-8").splitlines()
        if line.startswith("| pull request")
    )
    return row[row.index("every shard if") :]


class EveryShardProse(unittest.TestCase):
    def test_the_shard_inputs_are_found(self) -> None:
        self.assertTrue(SHARD_INPUTS)

    def test_header_names_each_checks_file_that_runs_every_shard(self) -> None:
        clause = header_clause()
        for name in SHARD_INPUTS:
            self.assertIn(name, clause)

    def test_header_drops_the_stale_wording(self) -> None:
        clause = header_clause()
        for phrase in STALE:
            self.assertNotIn(phrase, clause)

    def test_header_says_the_rest_of_checks_runs_lint_only(self) -> None:
        self.assertIn("ansible/checks/", ci_select.LINT_ONLY)
        self.assertIn(
            "Any other file under ansible/checks/ runs the lint job only", header_clause()
        )

    def test_readme_row_names_each_checks_file_that_runs_every_shard(self) -> None:
        clause = readme_clause()
        for name in SHARD_INPUTS:
            self.assertIn(name, clause)

    def test_readme_row_drops_the_stale_wording(self) -> None:
        clause = readme_clause()
        for phrase in STALE:
            self.assertNotIn(phrase, clause)


if __name__ == "__main__":
    unittest.main()
