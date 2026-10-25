"""Tests for the Ansible path filter.

The filter in .github/workflows/ansible.yml decides whether the Ansible lint job runs, and
ci_select.py decides which shards run. A role test that reads a file outside ansible/ must
run when that file changes, so every such path has to be inside what the filter watches. The
scan that finds those paths is ci_select.reads_by_path, the one the shard choice uses, so the
filter and the choice cannot disagree about what a role reads. These tests fail when a path
a role reads is outside the filter.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import ci_select

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"
FILTER = re.compile(r"watched=\(\n(.*?)\n\s*\)", re.DOTALL)
# The directories watched whole, whatever they hold now or later.
WHOLE = ("ansible/", "hetzner/")


def parse_watched(workflow_text: str) -> list[str]:
    """Return the entries of the watched=( ... ) array, or [] when the array is absent."""
    match = FILTER.search(workflow_text)
    if match is None:
        return []
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def uncovered(reads: set[str], watched: list[str]) -> list[str]:
    """Return the reads the filter does not name.

    A read is named when the filter lists it exactly, lists a directory that holds it, or
    lists files under it (a directory a verify step only reads the parts of).
    """
    names = {entry.rstrip("/") for entry in watched}
    dirs = {entry.rstrip("/") for entry in watched if entry.endswith("/")}
    missing = []
    for read in sorted(reads):
        if read in names:
            continue
        if any(read.startswith(d + "/") for d in dirs):
            continue
        if any(name.startswith(read + "/") for name in names):
            continue
        missing.append(read)
    return missing


class WatchedPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.watched = parse_watched(WORKFLOW.read_text(encoding="utf-8"))
        self.reads = ci_select.reads_by_path(ROOT)

    def test_every_outside_path_a_role_reads_is_watched(self) -> None:
        self.assertTrue(self.watched, "the workflow has no watched=( ... ) array")
        missing = uncovered(set(self.reads), self.watched)
        detail = [f"{path} (read by {', '.join(sorted(self.reads[path]))})" for path in missing]
        self.assertEqual([], detail, "these paths are read by role tests but not in the filter")

    def test_ansible_and_hetzner_are_watched_whole(self) -> None:
        # A file named one by one is a file the next edit forgets to name.
        for directory in WHOLE:
            with self.subTest(directory=directory):
                self.assertIn(directory, self.watched)

    def test_the_lint_files_and_the_two_files_the_tools_read_are_watched(self) -> None:
        for path in (
            ".ansible-lint",
            ".yamllint",
            ".github/workflows/ansible.yml",
            ".github/workflows/ansible-delivery.yml",
            "hetzner-host/cloudInit.ts",
            "hetzner-host/pullBootstrapFixed.json",
        ):
            with self.subTest(path=path):
                self.assertIn(path, self.watched)
                self.assertTrue((ROOT / path).is_file(), path)

    def test_everything_that_runs_every_shard_is_watched(self) -> None:
        # A change the shard choice treats as deciding every role must start the workflow's
        # work at all, or it would pass in silence.
        self.assertEqual([], uncovered(set(ci_select.EVERY_SHARD), self.watched))

    def test_scanner_finds_known_reads(self) -> None:
        # A control: the scan must see the reads it is meant to find, or a clean result
        # proves nothing.
        self.assertIn("hetzner/monitoring/stack", self.reads)
        self.assertIn("hetzner/provision/branchleft-nat.service", self.reads)
        self.assertIn("hetzner/provision/branchleft-db-tunnel.service", self.reads)
        # Read through a symlink in files/, not through a path in molecule/ or tests/.
        self.assertIn("hetzner/control-plane/stack", self.reads)

    def test_a_read_with_no_entry_is_reported(self) -> None:
        watched = ["ansible/", "hetzner-host/cloudInit.ts"]
        self.assertEqual(
            ["hetzner/provision/branchleft-nat.service"],
            uncovered({"hetzner/provision/branchleft-nat.service"}, watched),
        )

    def test_a_directory_entry_covers_the_files_under_it(self) -> None:
        self.assertEqual(
            [], uncovered({"hetzner/monitoring/stack/snds/x.py"}, ["hetzner/monitoring/stack/"])
        )
        self.assertEqual(
            ["hetzner/monitoring/stack"],
            uncovered(
                {"hetzner/monitoring/stack"},
                ["hetzner/monitoring/systemd/monitoring.override.conf"],
            ),
        )


if __name__ == "__main__":
    unittest.main()
