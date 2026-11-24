#!/usr/bin/env python3
"""Tests for cancel-superseded-ansible-delivery: an older delivery waiting for approval
is cancelled by a newer push, and nothing that started or is not an ancestor is.

Each test names the rule it proves. The last class pins the workflow that runs the script.
"""

from __future__ import annotations

import pathlib
import subprocess
import unittest
from typing import Any, Dict, List, Sequence

import yaml

SCRIPTS = pathlib.Path(__file__).resolve().parent
WORKFLOW = SCRIPTS.parent / ".github" / "workflows" / "ansible-supersede.yml"


from script_loader import load_script


script = load_script(
    SCRIPTS / "cancel-superseded-ansible-delivery.py",
    "cancel_superseded_ansible_delivery",
)

APPLY = "delivery / Apply the planned commit (after approval)"
PLAN = "delivery / Plan the apply (check mode on each host)"
GATE = "delivery / Ansible checks passed"


def job(name: str, status: str, conclusion: str = "") -> Dict[str, Any]:
    return {"name": name, "status": status, "conclusion": conclusion or None}


# The job shape of run 44075269897 while its apply waited.
WAITING_JOBS = [
    job(PLAN, "completed", "success"),
    job(APPLY, "waiting"),
    job(GATE, "queued"),
]


class Decide(unittest.TestCase):
    def test_cancels_a_waiting_apply_of_an_ancestor_commit(self) -> None:
        verdict, reason = script.decide(WAITING_JOBS, "ahead")
        self.assertEqual(verdict, "cancel", reason)

    def test_keeps_a_commit_that_is_not_an_ancestor(self) -> None:
        for relation in ("identical", "behind", "diverged", "None"):
            verdict, reason = script.decide(WAITING_JOBS, relation)
            self.assertEqual(verdict, "keep", relation)
            self.assertIn(repr(relation), reason)

    def test_keeps_a_run_with_a_job_in_progress(self) -> None:
        jobs = [job(PLAN, "in_progress"), job(APPLY, "waiting")]
        verdict, reason = script.decide(jobs, "ahead")
        self.assertEqual(verdict, "keep")
        self.assertIn(PLAN, reason)

    def test_keeps_a_run_whose_apply_has_started(self) -> None:
        jobs = [job(PLAN, "completed", "success"), job(APPLY, "in_progress")]
        verdict, _ = script.decide(jobs, "ahead")
        self.assertEqual(verdict, "keep")

    def test_keeps_a_run_whose_apply_is_not_waiting(self) -> None:
        for status in ("queued", "pending", "completed"):
            verdict, reason = script.decide([job(PLAN, "completed"), job(APPLY, status)], "ahead")
            self.assertEqual(verdict, "keep", status)
            self.assertIn(status, reason)

    def test_keeps_a_run_with_no_apply_job(self) -> None:
        verdict, _ = script.decide([job(PLAN, "completed", "success")], "ahead")
        self.assertEqual(verdict, "keep")

    def test_keeps_a_run_with_two_apply_jobs(self) -> None:
        verdict, _ = script.decide([job(APPLY, "waiting"), job(APPLY, "waiting")], "ahead")
        self.assertEqual(verdict, "keep")


class FakeGh:
    """The `gh api` the script calls, over a table of runs, compares and jobs."""

    def __init__(self, runs: List[Dict[str, Any]], relation: Dict[str, str],
                 jobs: Dict[str, List[Dict[str, Any]]]) -> None:
        self.runs, self.relation, self.jobs = runs, relation, jobs
        self.cancelled: List[str] = []
        self.unreadable: List[str] = []

    def __call__(self, args: Sequence[str]) -> Any:
        path = next(a for a in args if a.startswith("repos/"))
        if path.endswith("/runs") and "status=waiting" in args:
            return {"workflow_runs": self.runs}
        if "/compare/" in path:
            older = path.split("/compare/")[1].split("...")[0]
            return {"status": self.relation[older]}
        if path.endswith("/cancel"):
            self.cancelled.append(path.split("/runs/")[1].split("/")[0])
            return None
        run_id = path.split("/runs/")[1].split("/")[0]
        if run_id in self.unreadable:
            raise subprocess.CalledProcessError(1, "gh api")
        return {"jobs": self.jobs[run_id]}


NEW = "n" * 40


class TwoRunsWaiting(unittest.TestCase):
    """The 17 Nov case: an older run's apply waits, a newer commit is pushed."""

    def run_script(self, gh: FakeGh) -> List[str]:
        lines: List[str] = []
        self.code = script.supersede(gh, "org/repo", NEW, lines.append)
        return lines

    def test_cancels_the_older_waiting_run_and_names_it(self) -> None:
        gh = FakeGh([{"id": 111, "head_sha": "a" * 40}], {"a" * 40: "ahead"},
                    {"111": WAITING_JOBS})
        lines = self.run_script(gh)
        self.assertEqual(gh.cancelled, ["111"])
        self.assertEqual(self.code, 0)
        self.assertTrue(lines[0].startswith("cancelled run 111 at "), lines)

    def test_cancels_every_older_waiting_run(self) -> None:
        gh = FakeGh(
            [{"id": 111, "head_sha": "a" * 40}, {"id": 222, "head_sha": "b" * 40}],
            {"a" * 40: "ahead", "b" * 40: "ahead"},
            {"111": WAITING_JOBS, "222": WAITING_JOBS},
        )
        self.run_script(gh)
        self.assertEqual(gh.cancelled, ["111", "222"])

    def test_keeps_a_waiting_run_of_a_commit_that_is_not_an_ancestor(self) -> None:
        gh = FakeGh([{"id": 111, "head_sha": "a" * 40}], {"a" * 40: "diverged"},
                    {"111": WAITING_JOBS})
        lines = self.run_script(gh)
        self.assertEqual(gh.cancelled, [])
        self.assertIn("kept run 111", lines[0])

    def test_never_cancels_the_pushed_commits_own_run(self) -> None:
        gh = FakeGh([{"id": 333, "head_sha": NEW}], {}, {"333": WAITING_JOBS})
        lines = self.run_script(gh)
        self.assertEqual(gh.cancelled, [])
        self.assertIn("kept run 333", lines[0])

    def test_keeps_a_run_whose_apply_started(self) -> None:
        jobs = [job(PLAN, "completed", "success"), job(APPLY, "in_progress")]
        gh = FakeGh([{"id": 111, "head_sha": "a" * 40}], {"a" * 40: "ahead"}, {"111": jobs})
        self.run_script(gh)
        self.assertEqual(gh.cancelled, [])

    def test_an_unreadable_run_is_kept_and_the_step_fails_naming_it(self) -> None:
        gh = FakeGh([{"id": 111, "head_sha": "a" * 40}, {"id": 222, "head_sha": "b" * 40}],
                    {"a" * 40: "ahead", "b" * 40: "ahead"},
                    {"111": WAITING_JOBS, "222": WAITING_JOBS})
        gh.unreadable = ["111"]
        lines = self.run_script(gh)
        self.assertEqual(gh.cancelled, ["222"])
        self.assertEqual(self.code, 1)
        self.assertIn("kept run 111: it could not be read", lines[0])


class WorkflowShape(unittest.TestCase):
    """The workflow runs the script on a push to main, with actions: write on its one job only."""

    def setUp(self) -> None:
        self.flow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        self.job = self.flow["jobs"]["supersede"]

    def test_triggers_on_a_push_to_main_and_nothing_else(self) -> None:
        # PyYAML reads the key `on` as the boolean True.
        triggers = self.flow.get("on", self.flow.get(True))
        self.assertEqual(triggers, {"push": {"branches": ["main"]}})

    def test_the_workflow_token_is_read_only_and_the_job_alone_may_write_actions(self) -> None:
        self.assertEqual(self.flow["permissions"], {"contents": "read"})
        self.assertEqual(self.job["permissions"], {"contents": "read", "actions": "write"})

    def test_runs_the_script_on_the_pushed_commit_and_declares_no_environment(self) -> None:
        self.assertNotIn("environment", self.job)
        self.assertNotIn("secrets", self.job)
        run = self.job["steps"][-1]["run"]
        self.assertIn("scripts/cancel-superseded-ansible-delivery.py", run)
        self.assertIn('--sha "$SHA"', run)
        self.assertEqual(self.job["steps"][-1]["env"]["SHA"], "${{ github.sha }}")

    def test_the_script_names_the_delivery_workflow_and_its_apply_job(self) -> None:
        delivery = yaml.safe_load(
            (WORKFLOW.parent / "ansible-delivery.yml").read_text(encoding="utf-8"))
        self.assertEqual(script.WORKFLOW, "ansible-delivery.yml")
        self.assertIn("delivery", delivery["jobs"])


if __name__ == "__main__":
    unittest.main()
