"""Tests for the choice of Molecule shards of a delivery run (delivery_select.py).

A shard wrongly left out is a role that reaches a host without its container test, so these
tests are written from that side. They show, on the real tree, that a role or pattern change
selects that role and that a document change selects nothing; that the base of the diff is the
last delivery that finished green and not the commit before the push (a delivery that the next
push cancelled has tested nothing); and that every failure, in the program or in the shell step
that runs it, ends in every role and pattern and never in none.

Each control is also shown able to fail: the sabotage tests break the selection or the base and
require the guard to go red, so a guard that has gone blind fails here.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import check_delivery
import ci_select
import delivery_select
from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / check_delivery.CALLER
SHA = "a" * 40
BEFORE = "b" * 40
OLDER = "c" * 40
OLDEST = "d" * 40
RUN_PATH = delivery_select.WORKFLOW_PATH

# One role, one pattern and one document that exist on the real tree, named once.
ROLE_FILE = "ansible/roles/ci_login/tasks/main.yml"
PATTERN_FILE = "ansible/patterns/files_and_units/README.md"
DOCUMENT = "docs/ansible-handbook.md"
COMMENT_ONLY = "ansible/playbooks/demo1.yml"


def real_shards() -> list[dict[str, str]]:
    """Return the shards of the real tree, listed by the program the workflow runs."""
    return delivery_select.listed_shards(ROOT)


def job(
    name: str, conclusion: str | None, steps: list[dict[str, object]] | None = None
) -> dict[str, object]:
    """Return one job of a delivery run, named as the reusable workflow's jobs are."""
    entry: dict[str, object] = {"name": f"delivery / {name}", "conclusion": conclusion}
    if steps is not None:
        entry["steps"] = steps
    return entry


def discover(confirm: str | None) -> dict[str, object]:
    """Return the discover job of a run whose confirm step ended as ``confirm``."""
    return job(
        delivery_select.DISCOVER_JOB,
        "success",
        [
            {"name": "Checkout", "conclusion": "success"},
            {"name": delivery_select.CONFIRM_STEP, "conclusion": confirm},
        ],
    )


def green_run() -> list[object]:
    """Return the jobs of a delivery run whose lint and shards all passed."""
    return [
        job(delivery_select.DISCOVER_JOB, "success"),
        job(delivery_select.LINT_JOB, "success"),
        job("Molecule: ansible/roles/a", "success"),
        job("Molecule: ansible/roles/b", "success"),
        job("Plan the apply (check mode on each host)", None),
    ]


def run_entry(run_id: int, sha: str) -> dict[str, object]:
    """Return one entry of the run list of the delivery workflow."""
    return {
        "id": run_id,
        "head_sha": sha,
        "path": RUN_PATH,
        "event": "push",
        "head_branch": "main",
    }


class FakeGitHub:
    """Answers the two calls the program makes from a table, and counts them."""

    def __init__(
        self, runs: dict[str, list[dict[str, object]]], jobs: dict[int, list[object]]
    ) -> None:
        self.runs = runs
        self.jobs = jobs
        self.calls: list[str] = []

    def __call__(self, path: str, fields: dict[str, str]) -> object:
        self.calls.append(path)
        if path == "actions/workflows/ansible-delivery.yml/runs":
            listed = self.runs.get(fields["head_sha"], [])
            return {"total_count": len(listed), "workflow_runs": listed}
        prefix = "actions/runs/"
        if path.startswith(prefix) and path.endswith("/jobs"):
            everything = self.jobs[int(path[len(prefix) : -len("/jobs")])]
            page = int(fields["page"])
            size = int(fields["per_page"])
            return {
                "total_count": len(everything),
                "jobs": everything[(page - 1) * size : page * size],
            }
        message = f"unexpected call {path}"
        raise AssertionError(message)


def failing(path: str, fields: dict[str, str]) -> object:
    """Stand in for GitHub when it cannot be reached.

    Raises:
        SelectionError: always.
    """
    message = f"gh api {path} failed {fields}"
    raise delivery_select.SelectionError(message)


def outputs_of(text: str) -> dict[str, str]:
    """Parse text in the format of ``$GITHUB_OUTPUT``: ``name=value`` and ``name<<END`` blocks."""
    found: dict[str, str] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if "<<" in line:
            name, delimiter = line.split("<<", 1)
            block: list[str] = []
            index += 1
            while lines[index] != delimiter:
                block.append(lines[index])
                index += 1
            found[name] = "\n".join(block)
        elif "=" in line:
            name, value = line.split("=", 1)
            found[name] = value
        index += 1
    return found


FULL = "\n".join(delivery_select.FULL_DIRECTORIES)


class ChooseTest(unittest.TestCase):
    """What the pull request rules, applied to the diff since the base, ask the delivery to run."""

    shards: list[dict[str, str]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.shards = real_shards()

    def choose(self, *changed: str) -> delivery_select.Selection:
        return delivery_select.choose(list(changed), self.shards, ROOT)

    def test_a_role_change_selects_that_role_and_nothing_wider(self) -> None:
        selection = self.choose(ROLE_FILE)
        self.assertTrue(selection.run_shards)
        self.assertIn("roles/ci_login", selection.directories)
        self.assertLess(len(selection.directories), 10)

    def test_a_pattern_change_selects_that_pattern(self) -> None:
        selection = self.choose(PATTERN_FILE)
        self.assertTrue(selection.run_shards)
        self.assertIn("patterns/files_and_units", selection.directories)

    def test_a_document_or_comment_only_change_selects_no_shard(self) -> None:
        for path in (DOCUMENT, COMMENT_ONLY):
            with self.subTest(path=path):
                selection = self.choose(path)
                self.assertFalse(selection.run_shards)
                # The reusable workflow still lists its shards, so the globs stay full.
                self.assertEqual(delivery_select.FULL_DIRECTORIES, selection.directories)

    def test_a_change_to_the_harness_or_the_lock_selects_every_shard(self) -> None:
        for path in ("ansible/harness/run_harness.py", "ansible/requirements.txt"):
            with self.subTest(path=path):
                selection = self.choose(path)
                self.assertTrue(selection.run_shards)
                self.assertEqual(delivery_select.FULL_DIRECTORIES, selection.directories)

    def test_a_change_to_the_delivery_caller_or_this_program_selects_every_shard(self) -> None:
        for path in delivery_select.EVERY_SHARD:
            with self.subTest(path=path):
                selection = self.choose(DOCUMENT, path)
                self.assertTrue(selection.run_shards)
                self.assertEqual(delivery_select.FULL_DIRECTORIES, selection.directories)

    def test_an_unknown_file_under_ansible_selects_every_shard(self) -> None:
        selection = self.choose("ansible/new_kind_of_file.cfg")
        self.assertTrue(selection.run_shards)
        self.assertEqual(delivery_select.FULL_DIRECTORIES, selection.directories)

    def test_a_change_only_to_the_skeleton_selects_no_delivery_shard(self) -> None:
        # The delivery's globs (roles/*, patterns/*) never matched the skeleton, so it is not
        # a shard the delivery ran before this program either.
        selection = self.choose("ansible/role_skeleton/tasks/main.yml")
        self.assertFalse(selection.run_shards)

    def test_every_selected_directory_is_one_the_reusable_workflow_accepts(self) -> None:
        for path in (ROLE_FILE, PATTERN_FILE):
            for name in self.choose(path).directories:
                self.assertRegex(name, delivery_select.DIRECTORY.pattern)
                self.assertTrue((ROOT / "ansible" / name).is_dir(), name)

    def test_the_full_directories_are_the_globs_the_delivery_checker_pins(self) -> None:
        self.assertEqual(
            list(delivery_select.FULL_DIRECTORIES), list(check_delivery.ROLE_DIRECTORIES)
        )


class SabotageTest(unittest.TestCase):
    """The guards above go red when the selection is broken, so they are not blind."""

    def guard_role_change_runs_its_shard(self) -> None:
        """The guard: a role change must select that role.

        Raises:
            AssertionError: the role change selected nothing.
        """
        shards = real_shards()
        selection = delivery_select.choose([ROLE_FILE], shards, ROOT)
        if "roles/ci_login" not in selection.directories or not selection.run_shards:
            message = "a role change selected nothing"
            raise AssertionError(message)

    def test_the_guard_passes_on_the_real_selection(self) -> None:
        self.guard_role_change_runs_its_shard()

    def test_the_guard_fails_when_the_selection_selects_nothing(self) -> None:
        with mock.patch.object(ci_select, "select", lambda *_: []):
            with self.assertRaises(AssertionError):
                self.guard_role_change_runs_its_shard()

    def test_the_guard_fails_when_the_selection_forgets_the_role(self) -> None:
        def only_patterns(
            _event: str, _changed: object, shards: list[dict[str, str]], _root: Path
        ) -> list[dict[str, str]]:
            return [shard for shard in shards if shard["kind"] != "role"]

        with mock.patch.object(ci_select, "select", only_patterns):
            with self.assertRaises(AssertionError):
                self.guard_role_change_runs_its_shard()


class ChecksPassedTest(unittest.TestCase):
    """Which delivery runs count as having tested their tree."""

    def test_a_run_whose_lint_and_every_shard_passed_counts(self) -> None:
        self.assertTrue(delivery_select.checks_passed(green_run()))

    def test_a_run_that_the_next_push_cancelled_does_not_count(self) -> None:
        cancelled = [
            job(delivery_select.DISCOVER_JOB, "cancelled"),
            job(delivery_select.LINT_JOB, "skipped"),
            job("Molecule: ${{ matrix.name }}", "skipped"),
        ]
        self.assertFalse(delivery_select.checks_passed(cancelled))

    def test_a_run_with_a_shard_that_failed_was_cancelled_or_still_runs_does_not_count(
        self,
    ) -> None:
        for result in ("failure", "cancelled", None, "skipped", "timed_out"):
            with self.subTest(result=result):
                jobs = [*green_run(), job("Molecule: ansible/roles/c", result)]
                self.assertFalse(delivery_select.checks_passed(jobs))

    def test_a_run_whose_lint_did_not_pass_does_not_count(self) -> None:
        for result in ("failure", "cancelled", None):
            with self.subTest(result=result):
                jobs = [
                    job(delivery_select.DISCOVER_JOB, "success"),
                    job(delivery_select.LINT_JOB, result),
                ]
                jobs.append(job("Molecule: ansible/roles/a", "success"))
                self.assertFalse(delivery_select.checks_passed(jobs))

    def test_a_run_with_a_lint_but_no_shard_listed_does_not_count(self) -> None:
        jobs = [
            job(delivery_select.DISCOVER_JOB, "success"),
            job(delivery_select.LINT_JOB, "success"),
        ]
        self.assertFalse(delivery_select.checks_passed(jobs))

    def test_a_run_the_merge_queue_vouched_for_counts(self) -> None:
        jobs = [
            discover("success"),
            job(delivery_select.LINT_JOB, "skipped"),
            job("Molecule: ${{ matrix.name }}", "skipped"),
        ]
        self.assertTrue(delivery_select.checks_passed(jobs))

    def test_a_queue_vouched_run_whose_confirm_step_did_not_succeed_does_not_count(self) -> None:
        for result in ("skipped", "failure", "cancelled", None):
            with self.subTest(result=result):
                jobs = [
                    discover(result),
                    job(delivery_select.LINT_JOB, "skipped"),
                    job("Molecule: ${{ matrix.name }}", "skipped"),
                ]
                self.assertFalse(delivery_select.checks_passed(jobs))

    def test_a_queue_vouched_run_whose_confirm_step_is_missing_or_unreadable_does_not_count(
        self,
    ) -> None:
        confirm = {"name": delivery_select.CONFIRM_STEP, "conclusion": "success"}
        other = {"name": "Checkout", "conclusion": "success"}
        cases: dict[str, list[object]] = {
            "no steps key": [],
            "no steps listed": [[]],
            "other steps only": [[other]],
            "steps not a list": ["success"],
            "a step that is not a mapping": [[confirm, "x"]],
            "the step twice": [[confirm, confirm]],
        }
        for label, steps in cases.items():
            with self.subTest(label=label):
                entry = job(delivery_select.DISCOVER_JOB, "success")
                if label != "no steps key":
                    entry["steps"] = steps[0]
                jobs = [entry, job(delivery_select.LINT_JOB, "skipped")]
                self.assertFalse(delivery_select.checks_passed(jobs))

    def test_a_fully_tested_run_counts_though_its_confirm_step_was_skipped(self) -> None:
        for result in ("skipped", None):
            with self.subTest(result=result):
                jobs = [discover(result), *green_run()[1:]]
                self.assertTrue(delivery_select.checks_passed(jobs))

    def test_a_run_missing_its_discover_or_lint_job_does_not_count(self) -> None:
        self.assertFalse(delivery_select.checks_passed([job("Molecule: x", "success")]))
        self.assertFalse(
            delivery_select.checks_passed([job(delivery_select.DISCOVER_JOB, "success")])
        )
        self.assertFalse(delivery_select.checks_passed([]))

    def test_a_job_that_is_not_a_mapping_does_not_count(self) -> None:
        self.assertFalse(delivery_select.checks_passed([*green_run(), "x"]))


class BaseTest(unittest.TestCase):
    """The base is the nearest ancestor whose delivery finished green."""

    def test_the_previous_tip_is_the_base_when_its_delivery_passed(self) -> None:
        api = FakeGitHub({BEFORE: [run_entry(1, BEFORE)]}, {1: green_run()})
        self.assertEqual(BEFORE, delivery_select.tested_base(api, [BEFORE, OLDER]))

    def test_a_cancelled_delivery_is_walked_past_to_the_last_tested_one(self) -> None:
        cancelled: list[object] = [job(delivery_select.DISCOVER_JOB, "cancelled")]
        api = FakeGitHub(
            {BEFORE: [run_entry(1, BEFORE)], OLDER: [run_entry(2, OLDER)]},
            {1: cancelled, 2: green_run()},
        )
        self.assertEqual(OLDER, delivery_select.tested_base(api, [BEFORE, OLDER, OLDEST]))

    def test_a_commit_with_no_delivery_run_is_walked_past(self) -> None:
        api = FakeGitHub({OLDER: [run_entry(2, OLDER)]}, {2: green_run()})
        self.assertEqual(OLDER, delivery_select.tested_base(api, [BEFORE, OLDER]))

    def test_a_run_of_another_commit_workflow_event_or_branch_is_not_evidence(self) -> None:
        wrong: list[dict[str, object]] = [
            {**run_entry(1, BEFORE), "head_sha": OLDER},
            {**run_entry(1, BEFORE), "path": ".github/workflows/ansible.yml"},
            {**run_entry(1, BEFORE), "event": "merge_group"},
            {**run_entry(1, BEFORE), "head_branch": "gh-readonly-queue/main/x"},
            {**run_entry(1, BEFORE), "id": "1"},
        ]
        for entry in wrong:
            with self.subTest(entry=entry):
                api = FakeGitHub({BEFORE: [entry]}, {1: green_run()})
                self.assertIsNone(delivery_select.tested_base(api, [BEFORE]))

    def test_a_history_with_no_tested_delivery_has_no_base(self) -> None:
        self.assertIsNone(delivery_select.tested_base(FakeGitHub({}, {}), [BEFORE, OLDER]))

    def test_the_walk_stops_at_the_limit(self) -> None:
        api = FakeGitHub({}, {})
        history = [f"{n:040x}" for n in range(1, delivery_select.MAX_WALK + 20)]
        self.assertIsNone(delivery_select.tested_base(api, history))
        self.assertEqual(delivery_select.MAX_WALK, len(api.calls))

    def test_a_value_that_is_not_a_commit_id_is_never_a_base(self) -> None:
        api = FakeGitHub({"main": [run_entry(1, "main")]}, {1: green_run()})
        self.assertIsNone(delivery_select.tested_base(api, ["main", "0" * 40]))

    def test_jobs_are_read_across_pages(self) -> None:
        many = [job(f"Molecule: ansible/roles/r{n}", "success") for n in range(150)]
        jobs = [
            job(delivery_select.DISCOVER_JOB, "success"),
            job(delivery_select.LINT_JOB, "success"),
        ]
        api = FakeGitHub({BEFORE: [run_entry(1, BEFORE)]}, {1: [*jobs, *many]})
        self.assertEqual(BEFORE, delivery_select.tested_base(api, [BEFORE]))
        self.assertEqual(152, len(delivery_select.read_jobs(api, 1)))

    def test_an_unreadable_answer_raises_so_the_caller_runs_everything(self) -> None:
        with self.assertRaises(delivery_select.SelectionError):
            delivery_select.tested_base(failing, [BEFORE])
        with self.assertRaises(delivery_select.SelectionError):
            delivery_select.read_jobs(lambda *_: {"jobs": "x", "total_count": 1}, 1)


class SelectDeliveryTest(unittest.TestCase):
    """The whole choice, with the git and GitHub reads replaced."""

    def run_selection(
        self,
        api: Callable[[str, dict[str, str]], object],
        changed: list[str] | Exception,
        *,
        history: list[str] | Exception | None = None,
    ) -> tuple[delivery_select.Selection, list[tuple[str, str]]]:
        diffs: list[tuple[str, str]] = []

        def fake_diff(_root: Path, base: str, sha: str) -> list[str]:
            diffs.append((base, sha))
            if isinstance(changed, Exception):
                raise changed
            return changed

        def fake_history(_root: Path, before: str) -> list[str]:
            if isinstance(history, Exception):
                raise history
            return history if history is not None else [before, OLDER]

        with (
            mock.patch.object(delivery_select, "changed_since", fake_diff),
            mock.patch.object(delivery_select, "history_of", fake_history),
        ):
            return delivery_select.select_delivery(ROOT, BEFORE, SHA, api), diffs

    def tested(self, sha: str = BEFORE) -> FakeGitHub:
        return FakeGitHub({sha: [run_entry(1, sha)]}, {1: green_run()})

    def test_a_document_merge_after_a_tested_delivery_runs_no_shard(self) -> None:
        selection, diffs = self.run_selection(self.tested(), [DOCUMENT])
        self.assertFalse(selection.run_shards)
        self.assertEqual([(BEFORE, SHA)], diffs)

    def test_a_role_merge_after_a_tested_delivery_runs_that_role(self) -> None:
        selection, _ = self.run_selection(self.tested(), [ROLE_FILE])
        self.assertTrue(selection.run_shards)
        self.assertIn("roles/ci_login", selection.directories)

    def test_the_diff_starts_at_the_last_tested_delivery_not_at_the_commit_before(self) -> None:
        # The delivery of BEFORE was cancelled by this push, so a role changed in BEFORE has had
        # no shard run. Diffing from BEFORE would miss it: the diff must start at OLDER.
        api = FakeGitHub(
            {BEFORE: [run_entry(1, BEFORE)], OLDER: [run_entry(2, OLDER)]},
            {1: [job(delivery_select.DISCOVER_JOB, "cancelled")], 2: green_run()},
        )
        _, diffs = self.run_selection(api, [DOCUMENT])
        self.assertEqual([(OLDER, SHA)], diffs)

    def test_the_sabotage_of_diffing_from_the_previous_tip_is_caught(self) -> None:
        # Break the base: take the commit before the push whatever its delivery did. The guard
        # above then fails, so a role that a cancelled delivery never tested is not missed
        # silently.
        with mock.patch.object(delivery_select, "tested_base", lambda _api, history: history[0]):
            api = FakeGitHub(
                {BEFORE: [run_entry(1, BEFORE)], OLDER: [run_entry(2, OLDER)]},
                {1: [job(delivery_select.DISCOVER_JOB, "cancelled")], 2: green_run()},
            )
            _, diffs = self.run_selection(api, [DOCUMENT])
        with self.assertRaises(AssertionError):
            self.assertEqual([(OLDER, SHA)], diffs)

    def assert_full(self, selection: delivery_select.Selection) -> None:
        self.assertTrue(selection.run_shards)
        self.assertEqual(delivery_select.FULL_DIRECTORIES, selection.directories)

    def test_a_github_that_cannot_be_read_runs_every_shard(self) -> None:
        selection, _ = self.run_selection(failing, [DOCUMENT])
        self.assert_full(selection)

    def test_no_tested_delivery_in_reach_runs_every_shard(self) -> None:
        selection, _ = self.run_selection(FakeGitHub({}, {}), [DOCUMENT])
        self.assert_full(selection)

    def test_a_diff_that_fails_runs_every_shard(self) -> None:
        selection, _ = self.run_selection(self.tested(), delivery_select.SelectionError("diff"))
        self.assert_full(selection)

    def test_an_unexpected_error_of_any_kind_runs_every_shard(self) -> None:
        selection, _ = self.run_selection(self.tested(), KeyError("surprise"))
        self.assert_full(selection)

    def test_a_missing_or_null_previous_tip_runs_every_shard(self) -> None:
        for before in ("", "0" * 40, "main", "Z" * 40):
            with self.subTest(before=before):
                selection = delivery_select.select_delivery(ROOT, before, SHA, FakeGitHub({}, {}))
                self.assert_full(selection)

    def test_a_shard_list_that_cannot_be_made_runs_every_shard(self) -> None:
        def broken(_root: Path) -> list[dict[str, str]]:
            message = "the shard list is empty or malformed"
            raise delivery_select.SelectionError(message)

        with mock.patch.object(delivery_select, "listed_shards", broken):
            selection, _ = self.run_selection(self.tested(), [DOCUMENT])
        self.assert_full(selection)

    def test_the_selection_rules_failing_runs_every_shard(self) -> None:
        def broken(*_args: object) -> object:
            message = "rules broke"
            raise RuntimeError(message)

        with mock.patch.object(ci_select, "select", broken):
            selection, _ = self.run_selection(self.tested(), [ROLE_FILE])
        self.assert_full(selection)

    def test_the_program_prints_the_full_answer_and_exits_zero_whatever_fails(self) -> None:
        for argv in (
            [],
            ["--before", BEFORE],
            ["--before", "x", "--sha", "y", "--root", "/nowhere"],
        ):
            with self.subTest(argv=argv):
                out = io.StringIO()
                with redirect_stdout(out), redirect_stderr(io.StringIO()):
                    code = delivery_select.main(argv)
                self.assertEqual(0, code)
                answer = outputs_of(out.getvalue())
                self.assertEqual("true", answer["shards"])
                self.assertEqual(FULL, answer["directories"])


class RenderTest(unittest.TestCase):
    def test_a_selection_prints_in_the_output_file_format(self) -> None:
        text = delivery_select.render(
            delivery_select.Selection(True, ("patterns/b", "roles/a"), "why")
        )
        self.assertEqual({"shards": "true", "directories": "patterns/b\nroles/a"}, outputs_of(text))

    def test_a_none_selection_still_carries_the_globs_the_workflow_needs(self) -> None:
        none = delivery_select.Selection(False, delivery_select.FULL_DIRECTORIES, "why")
        self.assertEqual(
            {"shards": "false", "directories": FULL}, outputs_of(delivery_select.render(none))
        )

    def test_a_directory_that_is_not_in_the_accepted_shape_prints_the_full_answer(self) -> None:
        for bad in ("../roles/a", "roles/a b", "roles/a\nroles/b", "/etc", "roles/*/x", ""):
            with self.subTest(bad=bad):
                text = delivery_select.render(delivery_select.Selection(True, (bad,), "why"))
                self.assertEqual({"shards": "true", "directories": FULL}, outputs_of(text))

    def test_an_empty_list_prints_the_full_answer(self) -> None:
        text = delivery_select.render(delivery_select.Selection(False, (), "why"))
        self.assertEqual({"shards": "true", "directories": FULL}, outputs_of(text))


class GitTest(unittest.TestCase):
    """The two git reads, on a repository made here."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.shas: list[str] = []
        self.git("init", "-q", "-b", "main")
        for number, name in enumerate(("a", "b with space", "c")):
            (self.root / name).write_text(str(number), encoding="utf-8")
            self.git("add", "-A")
            self.git(
                "-c", "user.name=t", "-c", "user.email=t@example.test",
                "-c", "commit.gpgsign=false", "commit", "-q", "-m", name,
            )  # fmt: skip
            self.shas.append(self.git("rev-parse", "HEAD").strip())

    def git(self, *args: str) -> str:
        done = subprocess.run(  # noqa: S603
            ["git", "-C", str(self.root), *args],  # noqa: S607
            capture_output=True,
            check=True,
            text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )
        return done.stdout

    def test_the_history_is_newest_first(self) -> None:
        self.assertEqual(self.shas[::-1], delivery_select.history_of(self.root, self.shas[2]))

    def test_the_diff_lists_every_file_between_the_base_and_the_push(self) -> None:
        names = delivery_select.changed_since(self.root, self.shas[0], self.shas[2])
        self.assertEqual(["b with space", "c"], sorted(names))

    def test_an_unknown_commit_raises(self) -> None:
        with self.assertRaises(delivery_select.SelectionError):
            delivery_select.history_of(self.root, "e" * 40)
        with self.assertRaises(delivery_select.SelectionError):
            delivery_select.changed_since(self.root, "e" * 40, self.shas[2])


class StepFallbackTest(unittest.TestCase):
    """The shell step of ansible-delivery.yml, run as written, with the program replaced."""

    def step_text(self) -> str:
        document, problem = load_yaml(WORKFLOW)
        self.assertIsNone(problem)
        jobs = document["jobs"] if isinstance(document, dict) else {}
        steps = jobs[check_delivery.SELECT_JOB]["steps"]
        for step in steps:
            if step.get("id") == check_delivery.SELECT_STEP:
                return str(step["run"])
        message = "the select step is not in the workflow"
        raise AssertionError(message)

    def run_step(self, program: str) -> dict[str, str]:
        """Run the step in a directory whose delivery_select.py is ``program``."""
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "ansible" / "checks").mkdir(parents=True)
            (work / "ansible" / "checks" / "delivery_select.py").write_text(program, "utf-8")
            output = work / "github_output"
            output.write_text("", encoding="utf-8")
            done = subprocess.run(  # noqa: S603
                ["bash", "-c", self.step_text()],  # noqa: S607
                cwd=work,
                capture_output=True,
                check=False,
                text=True,
                env={
                    "PATH": os.environ["PATH"],
                    "RUNNER_TEMP": directory,
                    "GITHUB_OUTPUT": str(output),
                    "BEFORE": BEFORE,
                    "SHA": SHA,
                    "REPO": "o/r",
                    "GH_TOKEN": "x",
                },
            )
            self.assertEqual(0, done.returncode, done.stderr)
            return outputs_of(output.read_text(encoding="utf-8"))

    def assert_every_shard(self, answer: dict[str, str]) -> None:
        self.assertEqual({"shards": "true", "directories": FULL}, answer)

    def test_a_program_that_exits_with_an_error_runs_every_shard(self) -> None:
        self.assert_every_shard(self.run_step("import sys\nsys.exit(3)\n"))

    def test_a_program_that_crashes_runs_every_shard(self) -> None:
        self.assert_every_shard(self.run_step("raise RuntimeError('boom')\n"))

    def test_a_program_that_cannot_be_parsed_runs_every_shard(self) -> None:
        self.assert_every_shard(self.run_step("def (:\n"))

    def test_a_program_that_prints_nothing_runs_every_shard(self) -> None:
        self.assert_every_shard(self.run_step("pass\n"))

    def test_a_program_that_prints_no_directories_runs_every_shard(self) -> None:
        self.assert_every_shard(self.run_step("print('shards=false')\n"))

    def test_a_program_that_prints_a_garbled_verdict_runs_every_shard(self) -> None:
        self.assert_every_shard(
            self.run_step(
                "print('shards=maybe')\nprint('directories<<E')\nprint('roles/a')\nprint('E')\n"
            )
        )

    def test_a_missing_program_runs_every_shard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            output = work / "github_output"
            output.write_text("", encoding="utf-8")
            done = subprocess.run(  # noqa: S603
                ["bash", "-c", self.step_text()],  # noqa: S607
                cwd=work,
                capture_output=True,
                check=False,
                text=True,
                env={
                    "PATH": os.environ["PATH"],
                    "RUNNER_TEMP": directory,
                    "GITHUB_OUTPUT": str(output),
                    "BEFORE": BEFORE,
                    "SHA": SHA,
                },
            )
            self.assertEqual(0, done.returncode, done.stderr)
            self.assert_every_shard(outputs_of(output.read_text(encoding="utf-8")))

    def test_a_good_answer_passes_through_unchanged(self) -> None:
        program = (
            "print('shards=true')\nprint('directories<<DIRECTORIES_END')\n"
            "print('roles/a')\nprint('DIRECTORIES_END')\n"
        )
        self.assertEqual({"shards": "true", "directories": "roles/a"}, self.run_step(program))

    def test_a_none_answer_passes_through_so_the_savings_are_real(self) -> None:
        program = (
            "print('shards=false')\nprint('directories<<DIRECTORIES_END')\n"
            "print('roles/*')\nprint('patterns/*')\nprint('DIRECTORIES_END')\n"
        )
        self.assertEqual({"shards": "false", "directories": FULL}, self.run_step(program))

    def test_the_real_program_run_by_the_step_answers_in_the_format_the_step_accepts(self) -> None:
        # Not a stub: the committed program, with no way to read GitHub, must give the full
        # answer through the step.
        source = Path(delivery_select.__file__).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in ("delivery_select.py", "ci_select.py"):
                (work / "ansible" / "checks").mkdir(parents=True, exist_ok=True)
                (work / "ansible" / "checks" / name).write_text(
                    source if name == "delivery_select.py"
                    else (ROOT / "ansible" / "checks" / "ci_select.py").read_text("utf-8"),
                    encoding="utf-8",
                )  # fmt: skip
            output = work / "github_output"
            output.write_text("", encoding="utf-8")
            done = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(work / "ansible/checks/delivery_select.py"),
                    "--before",
                    BEFORE,
                    "--sha",
                    SHA,
                    "--root",
                    str(work),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(0, done.returncode, done.stderr)
        self.assert_every_shard(outputs_of(done.stdout))


if __name__ == "__main__":
    unittest.main()
