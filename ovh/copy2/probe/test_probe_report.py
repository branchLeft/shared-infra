"""The summary table says what happened: a check that did not pass is never shown as one."""

from __future__ import annotations

import unittest

from probe_report import (
    EXPECTED_CODES,
    CheckResult,
    Leftover,
    Status,
    all_passed,
    render_cleanup,
    render_table,
    scrub,
)


def passing() -> list[CheckResult]:
    return [
        CheckResult(code, f"title {code}", Status.PASS, "ok") for code in EXPECTED_CODES
    ]


class TableTests(unittest.TestCase):
    def test_all_passing_has_six_pass_rows_and_the_verdict(self) -> None:
        table = render_table(passing())
        self.assertEqual(6, table.count("**PASS**"))
        self.assertIn("ALL CHECKS PASSED: 6 of 6 passed.", table)

    def test_a_failed_check_is_shown_as_failed_and_the_verdict_is_negative(
        self,
    ) -> None:
        results = passing()
        results[2] = CheckResult(
            "P3", "title P3", Status.FAIL, "the plain delete was NOT refused"
        )
        table = render_table(results)
        self.assertIn("| P3 | title P3 | **FAIL** |", table)
        self.assertEqual(5, table.count("**PASS**"))
        self.assertIn("NOT ALL CHECKS PASSED: 5 of 6 passed.", table)
        self.assertFalse(all_passed(results))

    def test_an_error_row_is_never_a_pass(self) -> None:
        results = passing()
        results[0] = CheckResult("P1", "title P1", Status.ERROR, "timeout")
        self.assertIn("**ERROR**", render_table(results))
        self.assertFalse(all_passed(results))

    def test_a_check_that_never_reported_is_an_error_row(self) -> None:
        table = render_table(passing()[:4])
        self.assertIn("| P5 | (no result) | **ERROR** |", table)
        self.assertIn("| P6 | (no result) | **ERROR** |", table)
        self.assertFalse(all_passed(passing()[:5]))

    def test_an_empty_run_is_not_a_pass(self) -> None:
        self.assertFalse(all_passed([]))
        self.assertIn("NOT ALL CHECKS PASSED: 0 of 6 passed.", render_table([]))

    def test_a_pipe_or_newline_in_a_cell_cannot_break_the_table(self) -> None:
        results = passing()
        results[0] = CheckResult("P1", "t", Status.FAIL, "a | b\nc")
        row = next(
            line
            for line in render_table(results).splitlines()
            if line.startswith("| P1")
        )
        self.assertIn("a \\| b c", row)

    def test_the_first_result_for_a_code_wins_so_a_pass_cannot_follow_a_fail(
        self,
    ) -> None:
        results = [
            CheckResult("P1", "t", Status.FAIL, "x"),
            CheckResult("P1", "t", Status.PASS, "y"),
        ]
        self.assertFalse(all_passed(results + passing()[1:]))


class ScrubTests(unittest.TestCase):
    def test_every_secret_is_replaced_longest_first(self) -> None:
        text = "key abcd1234 and abcd1234-long and tiny"
        self.assertEqual(
            "key *** and *** and tiny", scrub(text, ["abcd1234", "abcd1234-long", "ti"])
        )

    def test_no_secrets_changes_nothing(self) -> None:
        self.assertEqual("plain", scrub("plain", []))


class CleanupTests(unittest.TestCase):
    def test_all_gone_says_so(self) -> None:
        text = render_cleanup(["bucket-a", "user-x"], [])
        self.assertIn(
            "Everything was destroyed: 2 resource(s) removed, none remain.", text
        )
        self.assertNotIn("NOT EVERYTHING", text)

    def test_leftovers_are_named_and_the_text_says_not_everything(self) -> None:
        text = render_cleanup(["user-x"], [Leftover("bucket", "zz-probe-a-r1a1")])
        self.assertIn("NOT EVERYTHING WAS DESTROYED: 1 resource(s) remain.", text)
        self.assertIn("| bucket | zz-probe-a-r1a1 |", text)
        self.assertNotIn("Everything was destroyed", text)


if __name__ == "__main__":
    unittest.main()
