"""Tests for the one preparation of a delivery (delivery_prepare.py).

The answer joins two that were jobs of their own: whether the merge queue passed the commit
(``merge_group_proof.py``) and which shards run (``delivery_select.py``). Each half fails toward
testing, and the tests here break each half in turn and read the answer.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import delivery_prepare
import delivery_select
import merge_group_proof
from test_delivery_select import BEFORE, SHA, outputs_of

ROOT = Path(__file__).resolve().parents[2]
QUEUE_BRANCH = f"gh-readonly-queue/main/pr-7-{'c' * 40}"
FULL = "\n".join(delivery_select.FULL_DIRECTORIES)


def queue_run(**changes: object) -> dict[str, object]:
    """Return the merge queue run of ``SHA`` as the API shows it, with ``changes`` applied."""
    run: dict[str, object] = {
        "event": "merge_group",
        "head_sha": SHA,
        "head_branch": QUEUE_BRANCH,
        "path": merge_group_proof.WORKFLOW_PATH,
        "status": "completed",
        "conclusion": "success",
    }
    run.update(changes)
    return run


def answer(*runs: dict[str, object]) -> dict[str, object]:
    """Return the runs call's answer for ``runs``."""
    return {"total_count": len(runs), "workflow_runs": list(runs)}


class Calls:
    """Answers the runs call from a document, or fails, and keeps what was asked."""

    def __init__(self, document: object = None, error: Exception | None = None) -> None:
        self.document = document
        self.error = error
        self.asked: list[tuple[str, dict[str, str]]] = []

    def __call__(self, path: str, fields: dict[str, str]) -> object:
        self.asked.append((path, fields))
        if self.error is not None:
            raise self.error
        return self.document


class ProveTest(unittest.TestCase):
    def test_a_green_queue_run_of_the_commit_is_tested(self) -> None:
        calls = Calls(answer(queue_run()))
        tested, _ = delivery_prepare.prove(calls, SHA)
        self.assertTrue(tested)

    def test_it_asks_for_the_runs_of_the_ansible_gate_workflow_for_that_commit(self) -> None:
        calls = Calls(answer(queue_run()))
        delivery_prepare.prove(calls, SHA)
        self.assertEqual(
            [("actions/workflows/ansible.yml/runs", {"head_sha": SHA, "per_page": "100"})],
            calls.asked,
        )

    def test_a_push_run_of_the_same_commit_is_not_proof(self) -> None:
        push = queue_run(event="push", head_branch="main")
        self.assertFalse(delivery_prepare.prove(Calls(answer(push)), SHA)[0])

    def test_a_run_of_another_commit_is_not_proof(self) -> None:
        other = queue_run(head_sha="d" * 40)
        self.assertFalse(delivery_prepare.prove(Calls(answer(other)), SHA)[0])

    def test_an_unreadable_answer_is_not_proof(self) -> None:
        unreadable: list[object] = [None, {}, [], "text", {"workflow_runs": "x", "total_count": 1}]
        for document in unreadable:
            with self.subTest(document=document):
                self.assertFalse(delivery_prepare.prove(Calls(document), SHA)[0])

    def test_a_failed_read_is_not_proof_whatever_failed(self) -> None:
        for error in (
            delivery_select.SelectionError("gh api failed"),
            OSError("no gh"),
            RuntimeError("anything"),
        ):
            with self.subTest(error=error):
                tested, reason = delivery_prepare.prove(Calls(error=error), SHA)
                self.assertFalse(tested)
                self.assertIn("could not be read", reason)


class RenderTest(unittest.TestCase):
    def test_the_answer_has_the_proof_and_the_selection_in_the_output_file_format(self) -> None:
        selection = delivery_select.Selection(False, delivery_select.FULL_DIRECTORIES, "why")
        self.assertEqual(
            {"tested": "true", "shards": "false", "directories": FULL},
            outputs_of(delivery_prepare.render(True, selection)),
        )

    def test_an_unproven_commit_prints_false_and_a_chosen_shard_list_passes_through(self) -> None:
        selection = delivery_select.Selection(True, ("roles/a",), "why")
        self.assertEqual(
            {"tested": "false", "shards": "true", "directories": "roles/a"},
            outputs_of(delivery_prepare.render(False, selection)),
        )


class MainTest(unittest.TestCase):
    """The program as the workflow runs it: arguments in, the answer on standard output."""

    def run_main(self, *argv: str) -> tuple[int, dict[str, str]]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = delivery_prepare.main(argv)
        return code, outputs_of(out.getvalue())

    def test_a_run_that_cannot_read_github_or_history_tests_everything(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, found = self.run_main(
                "--before", BEFORE, "--sha", SHA, "--repository", "", "--root", directory
            )
        self.assertEqual(0, code)
        self.assertEqual({"tested": "false", "shards": "true", "directories": FULL}, found)

    def test_unreadable_arguments_test_everything_and_still_exit_zero(self) -> None:
        code, found = self.run_main("--nonsense")
        self.assertEqual(0, code)
        self.assertEqual({"tested": "false", "shards": "true", "directories": FULL}, found)

    def test_the_committed_program_run_on_its_own_prints_a_usable_answer(self) -> None:
        # Not a stub: the committed program with no way to read GitHub, as a process, must print
        # both lines the step of the reusable workflow requires, and exit 0.
        with tempfile.TemporaryDirectory() as directory:
            done = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(ROOT / "ansible/checks/delivery_prepare.py"),
                    "--before",
                    BEFORE,
                    "--sha",
                    SHA,
                    "--root",
                    directory,
                ],
                capture_output=True,
                check=False,
                text=True,
                env={"PATH": "/nonexistent", "HOME": directory},
            )
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual(
            {"tested": "false", "shards": "true", "directories": FULL}, outputs_of(done.stdout)
        )


if __name__ == "__main__":
    unittest.main()
