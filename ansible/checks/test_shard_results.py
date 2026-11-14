"""The step summary, the pass counter and the daily issue, run offline on recorded answers."""

from __future__ import annotations

import contextlib
import datetime
import io
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

import advisory_passes
import daily_red_issue
import shard_results
from shard_results import ADVISORY_PREFIX, BLOCKING_PREFIX, ShardResult

FIXTURE = Path(__file__).with_name("advisory_passes_fixture.json")
TODAY = datetime.date(2026, 11, 10)


def job(name: str, conclusion: str | None, number: int = 1) -> dict[str, object]:
    """Return a job document in the shape of the Actions API."""
    return {
        "name": name,
        "conclusion": conclusion,
        "html_url": f"https://example.invalid/job/{number}",
    }


class FakeSource:
    """Runs and jobs held in memory, newest run first."""

    def __init__(self, runs: Sequence[Sequence[dict[str, object]]]) -> None:
        self.runs = list(runs)

    def schedule_runs(self, limit: int) -> list[Mapping[str, object]]:
        runs: list[Mapping[str, object]] = [
            {"id": index + 1, "html_url": f"https://example.invalid/run/{index + 1}"}
            for index in range(len(self.runs))
        ]
        return runs[:limit]

    def run_jobs(self, run_id: int) -> list[Mapping[str, object]]:
        return list(self.runs[run_id - 1])


class ResultsTest(unittest.TestCase):
    JOBS = [
        job("Discover the Ansible shards", "success"),
        job(f"{BLOCKING_PREFIX}ansible/roles/a", "success"),
        job(f"{BLOCKING_PREFIX}ansible/roles/b", "failure"),
        job(f"{ADVISORY_PREFIX}ansible/roles/c", "success"),
        job(f"{ADVISORY_PREFIX}ansible/roles/d", "failure"),
        job(f"{ADVISORY_PREFIX}ansible/roles/e", "cancelled"),
        job(f"{ADVISORY_PREFIX}ansible/roles/f", "skipped"),
        job(f"{BLOCKING_PREFIX}${{{{ matrix.name }}}}", "skipped"),
    ]

    def test_only_shard_jobs_become_results_and_an_unexpanded_matrix_name_is_dropped(self) -> None:
        results = shard_results.shard_results(self.JOBS)
        self.assertEqual(
            ["ansible/roles/" + letter for letter in "abcdef"], [item.shard for item in results]
        )
        self.assertEqual([True, True, False, False, False, False], [i.blocking for i in results])

    def test_the_counts_split_by_kind(self) -> None:
        results = shard_results.shard_results(self.JOBS)
        self.assertEqual((1, 1, 0), shard_results.count(results, blocking=True))
        self.assertEqual((1, 2, 1), shard_results.count(results, blocking=False))

    def test_the_summary_lists_every_red_shard_in_one_table_and_nothing_green(self) -> None:
        text = shard_results.summary(shard_results.shard_results(self.JOBS))
        self.assertIn("| Blocking (the required check fails with these) | 1 | 1 | 0 |", text)
        self.assertIn("| Advisory (the required check does not wait for these) | 1 | 2 | 1 |", text)
        for red in "bde":
            self.assertIn(f"| `ansible/roles/{red}` |", text)
        for quiet in "acf":
            self.assertNotIn(f"`ansible/roles/{quiet}`", text)
        self.assertEqual(1, text.count("| Shard | Kind | Result | Job |"))
        self.assertLess(text.index("roles/b"), text.index("roles/d"), "blocking first")

    def test_a_run_with_nothing_red_says_so(self) -> None:
        results = shard_results.shard_results([job(f"{ADVISORY_PREFIX}ansible/roles/c", "success")])
        self.assertIn("No container test is red.", shard_results.summary(results))

    def test_the_report_command_prints_the_summary_from_a_recording(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = shard_results.main(
                ["report", "--run-id", "42612239123", "--fixture", str(FIXTURE)]
            )
        self.assertEqual(0, code)
        self.assertIn(
            "| Blocking (the required check fails with these) | 4 | 0 | 0 |", out.getvalue()
        )
        self.assertIn("No container test is red.", out.getvalue())


class FixtureTest(unittest.TestCase):
    def test_the_recording_is_real_run_data_in_the_shape_the_reader_expects(self) -> None:
        source = shard_results.FixtureSource.from_file(FIXTURE)
        self.assertEqual(2, len(source.schedule_runs(5)))
        names = [str(item.get("name")) for item in source.run_jobs(42612239123)]
        self.assertIn("Harness: ansible/roles/host_baseline", names)


class PassCounterTest(unittest.TestCase):
    SHARD = "ansible/roles/x"

    def runs(self, *conclusions: str | None) -> FakeSource:
        """One run per conclusion, newest first, each with the shard's job ending that way."""
        return FakeSource(
            [
                [job(f"{BLOCKING_PREFIX}{self.SHARD}", conclusion)]
                if conclusion != "absent"
                else [job("Discover the Ansible shards", "success")]
                for conclusion in conclusions
            ]
        )

    def streak(self, *conclusions: str | None, n: int = 5) -> int:
        return advisory_passes.streak(
            advisory_passes.examine(self.runs(*conclusions), self.SHARD, n)
        )

    def test_five_passes_in_a_row_count_five(self) -> None:
        self.assertEqual(5, self.streak(*["success"] * 5))

    def test_the_streak_stops_at_the_first_failure_from_the_newest(self) -> None:
        self.assertEqual(2, self.streak("success", "success", "failure", "success", "success"))

    def test_a_newest_failure_makes_the_streak_zero(self) -> None:
        self.assertEqual(0, self.streak("failure", "success", "success", "success", "success"))

    def test_a_cancelled_skipped_or_missing_job_is_not_a_pass(self) -> None:
        for broken in ("cancelled", "skipped", "absent", None):
            with self.subTest(broken=broken):
                self.assertEqual(1, self.streak("success", broken, "success", "success", "success"))

    def test_only_the_newest_n_runs_are_read(self) -> None:
        self.assertEqual(3, self.streak(*["success"] * 9, n=3))

    def test_an_advisory_named_job_is_not_a_daily_result(self) -> None:
        source = FakeSource([[job(f"{ADVISORY_PREFIX}{self.SHARD}", "success")]])
        examined = advisory_passes.examine(source, self.SHARD, 1)
        self.assertEqual(0, advisory_passes.streak(examined))

    def run_command(self, *argv: str) -> tuple[int, list[str]]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = advisory_passes.main([*argv, "--fixture", str(FIXTURE)])
        return code, out.getvalue().splitlines()

    def test_the_command_prints_the_streak_and_the_run_urls_and_exits_zero_at_n(self) -> None:
        code, lines = self.run_command("ansible/roles/host_baseline", "--n", "2")
        self.assertEqual(0, code)
        self.assertEqual("PASS-STREAK=2", lines[0])
        self.assertIn(
            "success https://github.com/branchLeft/shared-infra/actions/runs/42612239123", lines
        )

    def test_the_command_exits_one_below_n_and_says_how_many_runs_exist(self) -> None:
        code, lines = self.run_command("ansible/roles/host_baseline", "--n", "5")
        self.assertEqual(1, code)
        self.assertEqual("PASS-STREAK=2", lines[0])
        self.assertTrue(
            any("Only 2 completed daily run(s) exist; 5 are needed." in line for line in lines)
        )

    def test_the_command_counts_a_shard_missing_from_an_older_run_as_a_break(self) -> None:
        code, lines = self.run_command("ansible/roles/ci_jump", "--n", "2")
        self.assertEqual(1, code)
        self.assertEqual("PASS-STREAK=1", lines[0])
        self.assertTrue(any(line.startswith("absent ") for line in lines))


class FakeIssues:
    """The calls the program makes, recorded."""

    def __init__(self, open_issues: list[tuple[int, str]]) -> None:
        self.open = open_issues
        self.labelled = 0
        self.created: list[tuple[str, str]] = []
        self.commented: list[tuple[int, str]] = []

    def ensure_label(self) -> None:
        self.labelled += 1

    def open_issues(self) -> list[tuple[int, str]]:
        return self.open

    def create(self, title: str, body: str) -> int:
        self.created.append((title, body))
        return 77

    def comment(self, number: int, body: str) -> None:
        self.commented.append((number, body))


class DailyIssueTest(unittest.TestCase):
    RUN = "https://github.com/branchLeft/shared-infra/actions/runs/9"

    def test_a_red_day_with_no_open_issue_opens_one_with_the_date_the_link_and_the_ids(
        self,
    ) -> None:
        issues = FakeIssues([])
        done = daily_red_issue.report(
            issues, self.RUN, ["ansible/roles/b", "ansible/roles/a"], TODAY
        )
        self.assertEqual(("opened", 77), done)
        self.assertEqual(1, len(issues.created))
        title, body = issues.created[0]
        self.assertEqual([], issues.commented)
        self.assertEqual("Daily container tests red: 2026-11-10", title)
        self.assertIn(self.RUN, body)
        self.assertIn("`ansible/roles/a`", body)
        self.assertIn("`ansible/roles/b`", body)

    def test_while_an_issue_is_open_the_run_comments_on_it_and_opens_no_second_one(self) -> None:
        issues = FakeIssues([(5, "Unrelated"), (6, "Daily container tests red: 2026-11-09")])
        done = daily_red_issue.report(issues, self.RUN, ["ansible/roles/a"], TODAY)
        self.assertEqual(("commented", 6), done)
        self.assertEqual(1, issues.labelled)
        self.assertEqual([], issues.created)
        self.assertEqual([6], [number for number, _ in issues.commented])

    def test_an_open_issue_with_another_title_does_not_stop_a_new_one(self) -> None:
        issues = FakeIssues([(5, "Unrelated")])
        self.assertEqual("opened", daily_red_issue.report(issues, self.RUN, [], TODAY)[0])

    def test_the_text_names_no_one_and_asks_nothing_of_anyone(self) -> None:
        text = daily_red_issue.text(self.RUN, ["ansible/roles/@someone"])
        self.assertNotIn("@", text)

    def test_a_run_with_no_failed_shard_says_a_job_that_is_not_a_test_failed(self) -> None:
        self.assertIn(daily_red_issue.NO_FAILED_SHARD, daily_red_issue.text(self.RUN, []))

    def test_the_failed_ids_come_from_the_red_shard_jobs_only(self) -> None:
        results = shard_results.shard_results(
            [
                job(f"{BLOCKING_PREFIX}ansible/roles/b", "failure"),
                job(f"{BLOCKING_PREFIX}ansible/roles/a", "failure"),
                job(f"{BLOCKING_PREFIX}ansible/roles/ok", "success"),
                job(f"{BLOCKING_PREFIX}ansible/roles/skipped", "skipped"),
                job("Lint the Ansible inputs", "failure"),
            ]
        )
        self.assertEqual(
            ["ansible/roles/a", "ansible/roles/b"], daily_red_issue.failed_shards(results)
        )

    def test_the_summary_has_the_date_the_link_and_the_ids_and_names_no_one(self) -> None:
        body = daily_red_issue.summary(self.RUN, ["ansible/roles/a", "ansible/roles/@b"], TODAY)
        self.assertIn("2026-11-10", body)
        self.assertIn(self.RUN, body)
        self.assertIn("`ansible/roles/a`", body)
        self.assertNotIn("@", body)

    def test_a_summary_with_no_failed_shard_says_a_job_that_is_not_a_test_failed(self) -> None:
        self.assertIn(daily_red_issue.NO_FAILED_SHARD, daily_red_issue.summary(self.RUN, [], TODAY))

    def test_the_label_is_the_one_plain_label(self) -> None:
        self.assertEqual("ci-red-daily", daily_red_issue.LABEL)

    def test_a_result_that_is_still_running_is_not_red(self) -> None:
        self.assertFalse(ShardResult("s", True, "", "").failed)


if __name__ == "__main__":
    unittest.main()
