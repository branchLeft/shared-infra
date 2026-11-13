#!/usr/bin/env python3
"""The retired GCP estate is named only where it is labelled as history.

The operating documents below describe how this repo works today, so none may
name the retired cloud. The one runbook that still tells the migration off it
must open with a history banner, so a finished procedure never reads as a task.

Run: python3 -m unittest hetzner.test_gcp_residue -v (from the repository root).
"""

import pathlib
import re
import unittest

HETZNER = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HETZNER.parent

# Operating documents and config comments: the present tense of the repo.
OPERATING_FILES = (
    "README.md",
    ".gitignore",
    "hetzner/Pulumi.yaml",
    "hetzner/RUNBOOK-new-stack.md",
    "hetzner/RUNBOOK-provision-host.md",
)

RETIRED_CLOUD = re.compile(r"\bGCP\b|Cloud Run|Cloud Armor|Google Cloud|gcloud", re.IGNORECASE)

MIGRATION_RUNBOOK = "hetzner/RUNBOOK-existing-stack-migration.md"
HISTORY_BANNER = "> **History: this migration is finished.**"
BANNER_WITHIN_LINES = 5


def residue(relpath: str, text: str) -> list[str]:
    """Each line of `text` that names the retired cloud, as `path:line: text`."""
    return [
        f"{relpath}:{number}: {line.strip()}"
        for number, line in enumerate(text.splitlines(), start=1)
        if RETIRED_CLOUD.search(line)
    ]


def banner_problems(text: str) -> list[str]:
    """Empty when the history banner opens the migration runbook."""
    head = text.splitlines()[:BANNER_WITHIN_LINES]
    if any(line.startswith(HISTORY_BANNER) for line in head):
        return []
    return [
        f"{MIGRATION_RUNBOOK}: the first {BANNER_WITHIN_LINES} lines must carry "
        f"the banner {HISTORY_BANNER!r}"
    ]


class RetiredCloudTests(unittest.TestCase):
    def test_operating_files_do_not_name_the_retired_cloud(self) -> None:
        found: list[str] = []
        for relpath in OPERATING_FILES:
            found += residue(relpath, (REPO_ROOT / relpath).read_text(encoding="utf-8"))
        self.assertEqual(found, [])

    def test_the_residue_scan_sees_a_named_line(self) -> None:
        sample = "fine\nthe GCP stacks used WIF\n"
        self.assertEqual(residue("x.md", sample), ["x.md:2: the GCP stacks used WIF"])

    def test_the_migration_runbook_opens_with_its_history_banner(self) -> None:
        text = (REPO_ROOT / MIGRATION_RUNBOOK).read_text(encoding="utf-8")
        self.assertEqual(banner_problems(text), [])

    def test_a_runbook_without_the_banner_is_caught(self) -> None:
        text = (REPO_ROOT / MIGRATION_RUNBOOK).read_text(encoding="utf-8")
        stripped = "\n".join(line for line in text.splitlines() if not line.startswith(HISTORY_BANNER))
        self.assertEqual(len(banner_problems(stripped)), 1)


if __name__ == "__main__":
    unittest.main()
