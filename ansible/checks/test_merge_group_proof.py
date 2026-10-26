"""Tests for the proof that the merge queue passed the commit a delivery would ship.

The fixtures are shaped like the live answer of the runs call of ``ansible.yml``. The one
green case is a completed, successful ``merge_group`` run on the exact commit, from the Ansible
workflow, on a queue branch; every other case drops exactly one of those clauses, so a check
that has gone blind to one clause fails its own test here and not in a review.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

import merge_group_proof

SHA = "7ad2c8178cfd76e72cd4b6969f86ecc1e5086be9"
OTHER_SHA = "92eb6a22093740f326233b6260def94067104254"
QUEUE_BRANCH = "gh-readonly-queue/main/pr-428-2624db1fa356d1382079f76ccf1076f88e0627ae"


def queue_run(**changes: object) -> dict[str, object]:
    """Return the merge queue run of ``SHA`` as the API shows it, with ``changes`` applied."""
    run: dict[str, object] = {
        "id": 40407465946,
        "name": "Ansible",
        "event": "merge_group",
        "head_sha": SHA,
        "head_branch": QUEUE_BRANCH,
        "path": ".github/workflows/ansible.yml",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
    }
    run.update(changes)
    return run


def push_run(**changes: object) -> dict[str, object]:
    """Return the push run main gets for the same commit: green, from a job with no diff."""
    return queue_run(
        id=40407999999,
        event="push",
        head_branch="main",
        **changes,
    )


def answer(*runs: object, total: object = None) -> dict[str, object]:
    """Return the runs call's answer for ``runs``; ``total`` overrides ``total_count``."""
    return {
        "total_count": len(runs) if total is None else total,
        "workflow_runs": list(runs),
    }


def verdict(document: object, sha: str = SHA) -> bool:
    """Return only whether ``document`` proves the queue passed ``sha``."""
    return merge_group_proof.judge(copy.deepcopy(document), sha)[0]


class ProofTests(unittest.TestCase):
    """A delivery may skip its re-test only on a successful merge queue run of this commit."""

    def test_a_successful_queue_run_of_the_exact_commit_is_proof(self) -> None:
        tested, reason = merge_group_proof.judge(answer(queue_run()), SHA)
        self.assertTrue(tested, reason)

    def test_the_push_run_beside_the_queue_run_changes_nothing(self) -> None:
        # After a squash queue main carries both runs under one name; the queue run is the proof.
        self.assertTrue(verdict(answer(push_run(), queue_run())))
        self.assertTrue(verdict(answer(queue_run(), push_run())))

    def test_a_failed_attempt_beside_a_passing_one_is_proof(self) -> None:
        self.assertTrue(verdict(answer(queue_run(conclusion="failure", id=1), queue_run())))

    # (a) A push run is green too, and a merge that skipped the queue has no queue run at all.
    def test_a_green_push_run_and_no_queue_run_is_not_proof(self) -> None:
        self.assertFalse(verdict(answer(push_run())))

    def test_no_run_at_all_is_not_proof(self) -> None:
        self.assertFalse(verdict(answer()))

    def test_a_run_of_another_event_is_not_proof(self) -> None:
        # Each is otherwise exact, including a queue-looking branch, so only the event differs.
        for event in ("push", "pull_request", "schedule", "workflow_dispatch", "merge-group", ""):
            with self.subTest(event=event):
                self.assertFalse(verdict(answer(queue_run(event=event))))
        self.assertFalse(verdict(answer(queue_run(event=None))))

    # (b) A queue run that did not succeed.
    def test_a_queue_run_that_did_not_succeed_is_not_proof(self) -> None:
        for conclusion in ("failure", "cancelled", "skipped", "timed_out", "neutral", "", None):
            with self.subTest(conclusion=conclusion):
                self.assertFalse(verdict(answer(queue_run(conclusion=conclusion))))

    def test_a_queue_run_that_has_not_completed_is_not_proof(self) -> None:
        # A stale success conclusion on a run that is running again must not count.
        for status in ("queued", "in_progress", "waiting", "requested", "pending", "", None):
            with self.subTest(status=status):
                self.assertFalse(verdict(answer(queue_run(status=status))))

    def test_a_running_queue_run_as_the_api_shows_it_is_not_proof(self) -> None:
        self.assertFalse(verdict(answer(queue_run(status="in_progress", conclusion=None))))

    # (c) A successful queue run of another commit.
    def test_a_successful_queue_run_of_a_different_commit_is_not_proof(self) -> None:
        self.assertFalse(verdict(answer(queue_run(head_sha=OTHER_SHA))))

    def test_a_commit_that_differs_in_any_way_is_not_proof(self) -> None:
        for head in (SHA.upper(), SHA[:-1], SHA[:7], SHA + "0", " " + SHA, SHA + "\n", "", None):
            with self.subTest(head=head):
                self.assertFalse(verdict(answer(queue_run(head_sha=head))))

    def test_the_wanted_commit_must_be_a_full_lowercase_sha(self) -> None:
        # A run that matches a malformed wanted value is still no proof.
        for sha in (SHA.upper(), SHA[:7], SHA + "0", "", "main", SHA + "\n", "x" * 40):
            with self.subTest(sha=sha):
                self.assertFalse(verdict(answer(queue_run(head_sha=sha)), sha))

    def test_the_run_must_be_of_the_ansible_workflow(self) -> None:
        for path in (
            ".github/workflows/ansible-delivery.yml",
            ".github/workflows/other.yml",
            ".github/workflows/ansible.yml@refs/heads/main",
            "ansible.yml",
            "",
            None,
        ):
            with self.subTest(path=path):
                self.assertFalse(verdict(answer(queue_run(path=path))))

    def test_the_run_must_be_on_a_queue_branch(self) -> None:
        for branch in (
            "main",
            "feature/gh-readonly-queue/main",
            "GH-READONLY-QUEUE/main",
            "gh-readonly-queue",
            "",
            None,
            7,
        ):
            with self.subTest(branch=branch):
                self.assertFalse(verdict(answer(queue_run(head_branch=branch))))

    def test_a_truncated_answer_is_not_proof(self) -> None:
        # The answer says more runs exist than it holds, so what is missing is unknown.
        self.assertFalse(verdict(answer(queue_run(), total=101)))
        self.assertFalse(verdict(answer(queue_run(), total=2)))

    def test_an_answer_that_cannot_be_read_is_not_proof(self) -> None:
        good = answer(queue_run())
        broken: dict[str, object] = {
            "none": None,
            "a list": [queue_run()],
            "a string": "success",
            "an empty mapping": {},
            "a message": {"message": "Not Found", "status": "404"},
            "runs missing": {"total_count": 1},
            "runs not a list": {"total_count": 1, "workflow_runs": queue_run()},
            "runs a string": {"total_count": 1, "workflow_runs": "x"},
            "total missing": {"workflow_runs": [queue_run()]},
            "total a string": {"total_count": "1", "workflow_runs": [queue_run()]},
            "total a bool": {"total_count": True, "workflow_runs": [queue_run()]},
            "total None": {"total_count": None, "workflow_runs": [queue_run()]},
            "runs not mappings": {"total_count": 2, "workflow_runs": [None, "success"]},
        }
        self.assertTrue(verdict(good))
        for name, document in broken.items():
            with self.subTest(name=name):
                self.assertFalse(verdict(document))

    def test_a_reason_is_one_line_with_no_value_from_the_answer(self) -> None:
        hostile = queue_run(head_branch=QUEUE_BRANCH + "\ntested=true", conclusion="x\ntested=true")
        for document in (answer(hostile), answer(push_run()), None, answer(queue_run())):
            _, reason = merge_group_proof.judge(document, SHA)
            self.assertNotIn("\n", reason)
            self.assertNotIn("\r", reason)
            self.assertTrue(reason)


class CommandTests(unittest.TestCase):
    """The command prints the two output lines and exits 0 for any input."""

    def run_main(self, text: str | None, sha: str = SHA) -> tuple[int, list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.json"
            if text is not None:
                path.write_text(text, encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = merge_group_proof.main(["--runs", str(path), "--sha", sha])
        return code, out.getvalue().splitlines()

    def test_a_proving_answer_prints_true(self) -> None:
        code, lines = self.run_main(json.dumps(answer(queue_run())))
        self.assertEqual(0, code)
        self.assertEqual("tested=true", lines[0])
        self.assertEqual(2, len(lines))
        self.assertTrue(lines[1].startswith("reason="))

    def test_the_answer_of_a_push_alone_prints_false(self) -> None:
        code, lines = self.run_main(json.dumps(answer(push_run())))
        self.assertEqual(0, code)
        self.assertEqual("tested=false", lines[0])

    def test_unreadable_input_prints_false_and_exits_zero(self) -> None:
        cases: dict[str, Callable[[], tuple[int, list[str]]]] = {
            "a missing file": lambda: self.run_main(None),
            "an empty file": lambda: self.run_main(""),
            "not json": lambda: self.run_main("<html>502</html>"),
            "json null": lambda: self.run_main("null"),
        }
        for name, call in cases.items():
            with self.subTest(name=name):
                code, lines = call()
                self.assertEqual(0, code)
                self.assertEqual("tested=false", lines[0])
                self.assertEqual(2, len(lines))


if __name__ == "__main__":
    unittest.main()
