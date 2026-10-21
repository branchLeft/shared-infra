#!/usr/bin/env python3
"""Pin tests: a pull_request run is grouped per pull request, and only those runs cancel.

Every workflow that runs on pull_request carries one top-level concurrency
block. Its group is keyed on the pull request number, and falls back to the
run id for every other event, so a push to main and a merge_group run each
form their own group. cancel-in-progress is true only for pull_request, so no
other run is cancelled, and no run is queued behind an apply paused for
approval.

The checks read the workflow text the way test_ci_apply_environments.py does:
standard library only, no YAML parser. Each check fails closed: a trigger that
is not in block form raises, and every cancel-in-progress value must be one of
the two allowed spellings, whatever its form.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from test_merge_group_triggers import on_block

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

PR_EXPRESSION = "${{ github.event_name == 'pull_request' }}"
PR_BLOCK = (
    "concurrency:\n"
    "  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}\n"
    f"  cancel-in-progress: {PR_EXPRESSION}\n"
)
ALLOWED_CANCEL = {"false", PR_EXPRESSION}

PR_TRIGGER = re.compile(r"(?m)^[ \t]+pull_request(_target)?:")
# A column-0 concurrency key, in any form, with the indented lines under it.
TOP_CONCURRENCY = re.compile(r"(?m)^concurrency\b[^\n]*\n(?:[ \t]+[^\n]*\n|[ \t]*\n)*")
CANCEL = re.compile(r"cancel-in-progress:[ \t]*([^\n]*)")


def workflow_files() -> list[pathlib.Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


class WorkflowConcurrencyTests(unittest.TestCase):
    def test_every_workflow_file_is_walked(self):
        names = {path.name for path in workflow_files()}
        self.assertIn("ci.yml", names)
        self.assertIn("ansible.yml", names)
        self.assertIn("docs-lint.yml", names)
        self.assertIn("standards.yml", names)

    def test_every_pull_request_workflow_carries_the_run_keyed_block(self):
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding="utf-8")
                if not PR_TRIGGER.search(on_block(text)):
                    continue
                found = TOP_CONCURRENCY.findall(text)
                self.assertEqual(
                    len(found),
                    1,
                    f"{path.name}: want one top-level concurrency block, found {len(found)}",
                )
                self.assertEqual(
                    found[0].rstrip("\n") + "\n",
                    PR_BLOCK,
                    f"{path.name}: top-level concurrency block is not the run-keyed block",
                )

    def test_no_non_pull_request_run_can_be_cancelled(self):
        for path in workflow_files():
            text = path.read_text(encoding="utf-8")
            for match in CANCEL.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                value = match.group(1).strip()
                with self.subTest(workflow=path.name, line=line):
                    self.assertIn(
                        value,
                        ALLOWED_CANCEL,
                        f"{path.name}:{line} cancel-in-progress: {value} may cancel a non-pull_request run",
                    )

    def test_merge_group_runs_are_keyed_on_the_run_not_the_ref(self):
        # A merge_group event carries no pull_request, so its group falls back
        # to the run id. Keyed on the ref or the workflow name alone, every
        # queued check run would share one group and replace one another.
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding="utf-8")
                if "merge_group" not in on_block(text):
                    continue
                found = TOP_CONCURRENCY.search(text)
                self.assertIsNotNone(found, f"{path.name}: no top-level concurrency block")
                group = re.search(r"^  group: (.*)$", found.group(0), re.M)
                self.assertIsNotNone(group, f"{path.name}: concurrency block has no group")
                self.assertIn("github.run_id", group.group(1))
                self.assertNotIn("github.ref", group.group(1))


if __name__ == "__main__":
    unittest.main()
