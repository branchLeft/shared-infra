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

# The trigger name in any spelling inside the on: block: a mapping key, a
# block-sequence item, quoted or bare. Matching the name, not a key shape,
# leaves no spelling for a pull_request workflow to skip the check.
PR_TRIGGER = re.compile(r"\bpull_request(?:_target)?\b")
# A column-0 concurrency key, in any form, with the indented lines under it.
TOP_CONCURRENCY = re.compile(r"(?m)^concurrency\b[^\n]*\n(?:[ \t]+[^\n]*\n|[ \t]*\n)*")
# Every mention of the key, quoted or bare, whatever follows it on the line.
CANCEL_KEY = re.compile(r"cancel-in-progress([^\n]*)")


def workflow_files() -> list[pathlib.Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def triggers_pull_request(text: str) -> bool:
    return PR_TRIGGER.search(on_block(text)) is not None


def cancel_values(text: str) -> list[tuple[int, str]]:
    """(line, value) for each cancel-in-progress. The value is what follows its colon.

    A key with no colon after it yields the rest of the line, which is never an
    allowed value, so the check fails closed on it. A key after a `#` on its
    line is a YAML comment and is not read.
    """
    values = []
    for match in CANCEL_KEY.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        if "#" in text[line_start : match.start()]:
            continue
        line = text.count("\n", 0, match.start()) + 1
        rest = match.group(1)
        value = re.sub(r"""^["']?[ \t]*:""", "", rest, count=1).strip()
        values.append((line, value))
    return values


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
                if not triggers_pull_request(text):
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
            for line, value in cancel_values(text):
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


class DetectorTests(unittest.TestCase):
    """The detectors catch the evasions the pin tests above must not miss."""

    def test_block_sequence_trigger_counts_as_pull_request(self):
        text = "on:\n  - push\n  - pull_request\njobs: {}\n"
        self.assertTrue(triggers_pull_request(text))

    def test_quoted_trigger_key_counts_as_pull_request(self):
        text = 'on:\n  "pull_request":\n    types: [opened]\njobs: {}\n'
        self.assertTrue(triggers_pull_request(text))

    def test_pull_request_target_counts_as_pull_request(self):
        text = "on:\n  pull_request_target:\njobs: {}\n"
        self.assertTrue(triggers_pull_request(text))

    def test_push_only_workflow_is_not_pull_request(self):
        text = "on:\n  push:\n    branches: [main]\njobs: {}\n"
        self.assertFalse(triggers_pull_request(text))

    def test_quoted_cancel_key_is_seen(self):
        text = 'on: push\nconcurrency:\n  group: deploy\n  "cancel-in-progress": true\n'
        self.assertEqual(cancel_values(text), [(4, "true")])

    def test_bare_cancel_key_value_is_read(self):
        text = "concurrency:\n  cancel-in-progress: false\n"
        self.assertEqual(cancel_values(text), [(2, "false")])

    def test_cancel_key_in_a_comment_is_not_read(self):
        text = "  # its cancel-in-progress is\n  cancel-in-progress: false # note\n"
        self.assertEqual(cancel_values(text), [(2, "false # note")])

    def test_cancel_key_without_colon_fails_closed(self):
        text = "concurrency:\n  cancel-in-progress true\n"
        values = cancel_values(text)
        self.assertEqual(len(values), 1)
        self.assertNotIn(values[0][1], ALLOWED_CANCEL)


if __name__ == "__main__":
    unittest.main()
