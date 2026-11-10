"""Tests for queue_skip.py: which container shards the merge queue may skip.

A shard is skipped only when the pull request's own Ansible run passed that exact shard on a
commit with the same tree as the queued commit. Every other answer runs the shard, so each
test below is one way the evidence can be missing, wrong or unreadable.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import queue_skip

PR_HEAD = "1" * 40
QUEUE_SHA = "2" * 40
TREE = "3" * 40
OTHER_TREE = "4" * 40
QUEUE_REF = f"refs/heads/gh-readonly-queue/main/pr-41-{'5' * 40}"
SUITE = 900
OTHER_SUITE = 901

Entry = dict[str, str]
SHARD_A: Entry = {
    "name": "alpha",
    "path": "ansible/roles/alpha",
    "scenario": "default",
    "kind": "role",
}
SHARD_B: Entry = {
    "name": "beta",
    "path": "ansible/roles/beta",
    "scenario": "default",
    "kind": "role",
}
ENTRIES: list[Entry] = [SHARD_A, SHARD_B]


def check(name: str, conclusion: str | None = "success", **changes: object) -> dict[str, object]:
    """Return one check run as the API reports it, from the Ansible pull request run."""
    run: dict[str, object] = {
        "name": f"Harness: {name}",
        "status": "completed",
        "conclusion": conclusion,
        "app": {"slug": "github-actions"},
        "check_suite": {"id": SUITE},
    }
    run.update(changes)
    return run


class FakeApi:
    """Answers the four reads the queue check makes, from data a test sets."""

    def __init__(self) -> None:
        self.state = "open"
        self.head = PR_HEAD
        self.trees = {PR_HEAD: TREE}
        self.runs: list[dict[str, object]] = [
            {
                "event": "pull_request",
                "path": queue_skip.WORKFLOW_PATH,
                "head_sha": PR_HEAD,
                "check_suite_id": SUITE,
            }
        ]
        self.checks: list[dict[str, object]] = [check("alpha"), check("beta")]
        self.calls: list[str] = []
        self.fail: str | None = None

    def maybe_fail(self, name: str) -> None:
        self.calls.append(name)
        if self.fail == name:
            raise queue_skip.ApiError(name)

    def pull_request(self, number: int) -> dict[str, object]:
        self.maybe_fail("pull_request")
        return {"number": number, "state": self.state, "head": {"sha": self.head}}

    def commit_tree(self, sha: str) -> str:
        self.maybe_fail("commit_tree")
        return self.trees[sha]

    def pull_request_runs(self, sha: str) -> list[dict[str, object]]:
        self.maybe_fail("pull_request_runs")
        return self.runs

    def check_runs(self, sha: str) -> list[dict[str, object]]:
        self.maybe_fail("check_runs")
        return self.checks


def plan(
    api: FakeApi,
    *,
    event: str = "merge_group",
    entries: list[Entry] | None = None,
    local_tree: str = TREE,
) -> queue_skip.Plan:
    """Return the plan for the default queue entry, with the given API and checkout."""
    return queue_skip.plan(
        event=event,
        entries=list(ENTRIES if entries is None else entries),
        queue_ref=QUEUE_REF,
        queue_sha=QUEUE_SHA,
        local_head=QUEUE_SHA,
        local_tree=local_tree,
        api=api,
    )


class SkipOnlyWithEvidenceTest(unittest.TestCase):
    def test_every_shard_the_pull_request_passed_on_the_same_tree_is_skipped(self) -> None:
        result = plan(FakeApi())
        self.assertEqual([], result.keep)
        self.assertEqual([SHARD_A, SHARD_B], result.skipped)

    def test_a_shard_that_failed_on_the_pull_request_runs_again(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha"), check("beta", conclusion="failure")]
        result = plan(api)
        self.assertEqual([SHARD_B], result.keep)
        self.assertEqual([SHARD_A], result.skipped)

    def test_a_shard_that_was_cancelled_on_the_pull_request_runs_again(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha", conclusion="cancelled"), check("beta")]
        self.assertEqual([SHARD_A], plan(api).keep)

    def test_a_shard_still_running_on_the_pull_request_runs_again(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha", status="in_progress", conclusion=None), check("beta")]
        self.assertEqual([SHARD_A], plan(api).keep)

    def test_a_shard_with_no_check_run_on_the_pull_request_runs(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha")]
        self.assertEqual([SHARD_B], plan(api).keep)

    def test_a_failed_rerun_of_a_shard_keeps_it_on_the_run(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha"), check("alpha", conclusion="failure"), check("beta")]
        self.assertEqual([SHARD_A], plan(api).keep)

    def test_a_check_run_from_another_app_with_the_same_name_does_not_count(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha", app={"slug": "someone-else"}), check("beta")]
        self.assertEqual([SHARD_A], plan(api).keep)

    def test_a_check_run_from_a_run_that_was_not_a_pull_request_does_not_count(self) -> None:
        api = FakeApi()
        api.checks = [check("alpha", check_suite={"id": OTHER_SUITE}), check("beta")]
        self.assertEqual([SHARD_A], plan(api).keep)

    def test_a_run_with_no_check_suite_id_vouches_for_nothing(self) -> None:
        api = FakeApi()
        api.runs = [
            {"event": "pull_request", "path": queue_skip.WORKFLOW_PATH, "head_sha": PR_HEAD}
        ]
        api.checks = [
            {
                "name": "Harness: alpha",
                "status": "completed",
                "conclusion": "success",
                "app": {"slug": "github-actions"},
                "check_suite": {},
            },
            check("beta"),
        ]
        result = plan(api)
        self.assertEqual(ENTRIES, result.keep)

    def test_nothing_is_skipped_when_no_pull_request_run_of_this_workflow_exists(self) -> None:
        api = FakeApi()
        api.runs = []
        result = plan(api)
        self.assertEqual(ENTRIES, result.keep)
        self.assertEqual([], result.skipped)


class DoubtRunsEverythingTest(unittest.TestCase):
    def keep_everything(self, api: FakeApi, local_tree: str = TREE) -> None:
        result = plan(api, local_tree=local_tree)
        self.assertEqual(ENTRIES, result.keep, result.reason)
        self.assertEqual([], result.skipped)

    def test_a_tree_that_differs_from_the_pull_request_head_runs_every_shard(self) -> None:
        # Another entry ahead in the queue changed the tree, so the pull request's pass says
        # nothing about the queued commit.
        api = FakeApi()
        self.keep_everything(api, local_tree=OTHER_TREE)
        self.assertIn("tree", plan(api, local_tree=OTHER_TREE).reason)

    def test_a_pull_request_head_that_moved_since_the_queue_read_it_runs_every_shard(self) -> None:
        api = FakeApi()
        api.head = "6" * 40
        api.trees["6" * 40] = TREE
        api.checks = []
        self.keep_everything(api)

    def test_a_pull_request_that_is_not_open_runs_every_shard(self) -> None:
        api = FakeApi()
        api.state = "closed"
        self.keep_everything(api)

    def test_a_checkout_that_is_not_the_queued_commit_runs_every_shard(self) -> None:
        result = queue_skip.plan(
            event="merge_group",
            entries=list(ENTRIES),
            queue_ref=QUEUE_REF,
            queue_sha=QUEUE_SHA,
            local_head="7" * 40,
            local_tree=TREE,
            api=FakeApi(),
        )
        self.assertEqual(ENTRIES, result.keep)

    def test_a_queue_branch_name_that_is_not_read_runs_every_shard(self) -> None:
        result = queue_skip.plan(
            event="merge_group",
            entries=list(ENTRIES),
            queue_ref="refs/heads/main",
            queue_sha=QUEUE_SHA,
            local_head=QUEUE_SHA,
            local_tree=TREE,
            api=FakeApi(),
        )
        self.assertEqual(ENTRIES, result.keep)

    def test_an_api_error_on_any_read_runs_every_shard(self) -> None:
        for name in ("pull_request", "commit_tree", "pull_request_runs", "check_runs"):
            api = FakeApi()
            api.fail = name
            with self.subTest(read=name):
                result = plan(api)
                self.assertEqual(ENTRIES, result.keep)
                self.assertEqual([], result.skipped)

    def test_a_malformed_answer_runs_every_shard(self) -> None:
        api = FakeApi()
        api.checks = [{"name": "Harness: alpha"}, check("beta")]
        self.assertEqual(ENTRIES[:1], plan(api).keep)


class OtherEventsTest(unittest.TestCase):
    def test_a_pull_request_never_skips_a_shard_and_never_asks_the_api(self) -> None:
        api = FakeApi()
        result = plan(api, event="pull_request")
        self.assertEqual(ENTRIES, result.keep)
        self.assertEqual([], api.calls)

    def test_the_weekly_and_manual_runs_never_skip_a_shard(self) -> None:
        for event in ("schedule", "workflow_dispatch", "push"):
            api = FakeApi()
            with self.subTest(event=event):
                self.assertEqual(ENTRIES, plan(api, event=event).keep)
                self.assertEqual([], api.calls)

    def test_a_queue_entry_with_no_chosen_shard_asks_nothing(self) -> None:
        api = FakeApi()
        result = plan(api, entries=[])
        self.assertEqual([], result.keep)
        self.assertEqual([], api.calls)


def matrix_of(*names: str) -> str:
    """Return the matrix line ci_select.py writes for the named shards."""
    include = [
        {"name": name, "path": f"ansible/roles/{name}", "scenario": "default", "kind": "role"}
        for name in names
    ]
    return json.dumps({"include": include}, separators=(",", ":"))


class ReadAndWriteTest(unittest.TestCase):
    def selection(self, directory: str, shards: str, matrix: str) -> Path:
        path = Path(directory) / "selected.txt"
        path.write_text(f"shards={shards}\nmatrix={matrix}\n", encoding="utf-8")
        return path

    def test_the_outputs_name_only_the_shards_that_still_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selected = self.selection(directory, "true", matrix_of("alpha", "beta"))
            api = FakeApi()
            api.checks = [check("alpha"), check("beta", conclusion="failure")]
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = queue_skip.main(
                    [
                        "--event",
                        "merge_group",
                        "--selected",
                        str(selected),
                        "--queue-ref",
                        QUEUE_REF,
                        "--queue-sha",
                        QUEUE_SHA,
                    ],
                    api=api,
                    local=(QUEUE_SHA, TREE),
                )
        self.assertEqual(0, code)
        self.assertIn("shards=true\n", out.getvalue())
        self.assertIn('"name":"beta"', out.getvalue())
        self.assertNotIn('"name":"alpha"', out.getvalue())
        self.assertIn("skipped", err.getvalue())

    def test_no_shard_left_writes_the_no_shard_entry_and_shards_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selected = self.selection(directory, "true", matrix_of("alpha"))
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                queue_skip.main(
                    [
                        "--event",
                        "merge_group",
                        "--selected",
                        str(selected),
                        "--queue-ref",
                        QUEUE_REF,
                        "--queue-sha",
                        QUEUE_SHA,
                    ],
                    api=FakeApi(),
                    local=(QUEUE_SHA, TREE),
                )
        self.assertIn("shards=false\n", out.getvalue())
        self.assertIn('"kind":"none"', out.getvalue())

    def test_a_pull_request_passes_the_selection_through_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selected = self.selection(directory, "true", matrix_of("alpha"))
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                queue_skip.main(
                    ["--event", "pull_request", "--selected", str(selected)],
                    api=FakeApi(),
                    local=(QUEUE_SHA, TREE),
                )
        self.assertIn('"name":"alpha"', out.getvalue())
        self.assertIn("shards=true\n", out.getvalue())


class UnreadableCheckoutTest(unittest.TestCase):
    """A checkout or environment that cannot be read is a doubt, so every shard runs."""

    def run_main(self, api: FakeApi | None) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            selected = ReadAndWriteTest().selection(directory, "true", matrix_of("alpha", "beta"))
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = queue_skip.main(
                    [
                        "--event",
                        "merge_group",
                        "--selected",
                        str(selected),
                        "--queue-ref",
                        QUEUE_REF,
                        "--queue-sha",
                        QUEUE_SHA,
                    ],
                    api=api,
                )
        return code, out.getvalue()

    def test_a_checkout_git_cannot_read_keeps_every_shard(self) -> None:
        def unreadable() -> tuple[str, str]:
            raise subprocess.CalledProcessError(128, "git")

        with mock.patch.object(queue_skip, "local_head_and_tree", unreadable):
            code, out = self.run_main(FakeApi())
        self.assertEqual(0, code)
        self.assertIn("shards=true\n", out)
        self.assertIn('"name":"alpha"', out)
        self.assertIn('"name":"beta"', out)

    def test_a_runner_without_a_repository_name_keeps_every_shard(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            code, out = self.run_main(None)
        self.assertEqual(0, code)
        self.assertIn('"name":"alpha"', out)
        self.assertIn('"name":"beta"', out)


class ChecksPagingTest(unittest.TestCase):
    def test_the_check_runs_are_read_page_by_page_until_a_short_page(self) -> None:
        pages = [[check("alpha")] * 100, [check("beta")]]
        asked: list[str] = []

        def fake_gh(endpoint: str) -> object:
            asked.append(endpoint)
            return {"check_runs": pages[len(asked) - 1]}

        reader = queue_skip.GhCli("branchLeft/shared-infra", gh=fake_gh)
        self.assertEqual(101, len(reader.check_runs(PR_HEAD)))
        self.assertEqual(2, len(asked))
        self.assertIn("page=2", asked[1])

    def test_a_run_list_that_is_truncated_is_an_error_not_a_short_answer(self) -> None:
        def fake_gh(endpoint: str) -> object:
            return {"total_count": 150, "workflow_runs": [{"event": "pull_request"}]}

        reader = queue_skip.GhCli("branchLeft/shared-infra", gh=fake_gh)
        with self.assertRaises(queue_skip.ApiError):
            reader.pull_request_runs(PR_HEAD)


if __name__ == "__main__":
    unittest.main()
