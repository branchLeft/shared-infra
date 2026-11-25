#!/usr/bin/env python3
"""Unit tests for queue_proof.py: a push may skip a check only on proof of the queue's own green run."""

from __future__ import annotations

import unittest

from queue_proof import judge

SHA = "a" * 40
WF = ".github/workflows/docs-lint.yml"


def run(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "path": WF,
        "event": "merge_group",
        "head_sha": SHA,
        "head_branch": "gh-readonly-queue/main/pr-1-" + SHA,
        "status": "completed",
        "conclusion": "success",
    }
    base.update(overrides)
    return base


def answer(*runs: object, total: int | None = None) -> dict[str, object]:
    return {"total_count": len(runs) if total is None else total, "workflow_runs": list(runs)}


class JudgeTests(unittest.TestCase):
    def test_a_green_queue_run_proves_the_commit(self) -> None:
        tested, _ = judge(answer(run()), WF, SHA)
        self.assertTrue(tested)

    def test_a_push_run_of_the_same_commit_is_not_proof(self) -> None:
        tested, _ = judge(answer(run(event="push", head_branch="main")), WF, SHA)
        self.assertFalse(tested)

    def test_a_queue_run_of_another_workflow_is_not_proof(self) -> None:
        tested, _ = judge(answer(run(path=".github/workflows/standards.yml")), WF, SHA)
        self.assertFalse(tested)

    def test_a_queue_run_of_another_commit_is_not_proof(self) -> None:
        tested, _ = judge(answer(run(head_sha="b" * 40)), WF, SHA)
        self.assertFalse(tested)

    def test_a_queue_run_not_on_a_queue_branch_is_not_proof(self) -> None:
        tested, _ = judge(answer(run(head_branch="main")), WF, SHA)
        self.assertFalse(tested)

    def test_an_incomplete_queue_run_is_not_proof(self) -> None:
        tested, _ = judge(answer(run(status="in_progress", conclusion=None)), WF, SHA)
        self.assertFalse(tested)

    def test_a_failed_queue_run_is_not_proof(self) -> None:
        tested, _ = judge(answer(run(conclusion="failure")), WF, SHA)
        self.assertFalse(tested)

    def test_one_proving_queue_run_is_enough_beside_bad_runs(self) -> None:
        tested, _ = judge(answer(run(conclusion="failure"), run()), WF, SHA)
        self.assertTrue(tested)

    def test_only_bad_runs_are_not_proof(self) -> None:
        tested, _ = judge(answer(run(conclusion="failure"), run(event="push")), WF, SHA)
        self.assertFalse(tested)

    def test_a_truncated_answer_is_not_proof(self) -> None:
        tested, reason = judge(answer(run(), total=2), WF, SHA)
        self.assertFalse(tested)
        self.assertIn("truncated", reason)

    def test_an_unreadable_answer_is_not_proof(self) -> None:
        for document in (None, [], "x", {"workflow_runs": "no"}, {"workflow_runs": []}):
            with self.subTest(document=document):
                tested, _ = judge(document, WF, SHA)
                self.assertFalse(tested)

    def test_a_malformed_sha_is_not_proof(self) -> None:
        tested, _ = judge(answer(run()), WF, "A" * 40)
        self.assertFalse(tested)


if __name__ == "__main__":
    unittest.main()
