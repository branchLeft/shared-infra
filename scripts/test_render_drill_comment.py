#!/usr/bin/env python3
"""Unit tests for render-drill-comment.

This script only ever handles the *outcome labels and static detail
strings* `verify-archive-passphrase.py --json` produces -- never a
passphrase, a salt, or anything decrypted. The tests below exercise its
rendering and exit-code logic; they do not (and do not need to) touch
Pulumi or a passphrase at all.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
import unittest
from contextlib import redirect_stdout


def _load_module():
    path = pathlib.Path(__file__).resolve().parent / "render-drill-comment.py"
    spec = importlib.util.spec_from_file_location("render_drill_comment", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render_mod = _load_module()


def result(stack: str, outcome: str, exit_code: int, detail: str = "detail") -> dict:
    return {"stack": stack, "outcome": outcome, "exit_code": exit_code, "detail": detail}


class WorstOutcomeTests(unittest.TestCase):
    def test_all_pass_is_pass(self):
        results = [result("a", "PASS", 0), result("b", "PASS", 0)]
        self.assertEqual(render_mod.worst_outcome(results), render_mod.EXIT_PASS)

    def test_a_single_fail_among_passes_wins(self):
        results = [result("a", "PASS", 0), result("b", "FAIL", 1), result("c", "PASS", 0)]
        self.assertEqual(render_mod.worst_outcome(results), 1)

    def test_fail_outranks_archive_and_inconclusive(self):
        results = [result("a", "INCONCLUSIVE", 4), result("b", "ARCHIVE", 3), result("c", "FAIL", 1)]
        self.assertEqual(render_mod.worst_outcome(results), 1)

    def test_archive_outranks_inconclusive_with_no_fail_present(self):
        results = [result("a", "INCONCLUSIVE", 4), result("b", "ARCHIVE", 3)]
        self.assertEqual(render_mod.worst_outcome(results), 3)


class RenderTests(unittest.TestCase):
    def test_a_clean_run_names_every_stack_and_says_all_pass(self):
        results = [result("mail", "PASS", 0, "passphrase opens this archive")]
        body = render_mod.render("2026-09-13", "branchLeft/shared-infra", results)
        self.assertIn("2026-09-13", body)
        self.assertIn("mail", body)
        self.assertIn("PASS", body)
        self.assertIn("All 1 stack in branchLeft/shared-infra opened", body)

    def test_a_failure_is_named_without_being_smoothed_over(self):
        results = [
            result("mail", "PASS", 0),
            result("hetzner-network", "FAIL", 1, "passphrase does not decrypt this archive"),
        ]
        body = render_mod.render("2026-09-13", "branchLeft/shared-infra", results)
        self.assertIn("hetzner-network", body)
        self.assertIn("FAIL", body)
        self.assertIn("1 stack in branchLeft/shared-infra did not PASS", body)

    def test_empty_results_is_a_programming_error_not_a_silent_pass(self):
        with self.assertRaises(ValueError):
            render_mod.render("2026-09-13", "branchLeft/shared-infra", [])

    def test_rendered_body_never_carries_a_field_other_than_the_known_ones(self):
        # A passphrase or salt has no way to reach this script (nothing
        # upstream of it ever puts one in a result dict) -- but if some
        # future caller did put extra fields on a result, this proves they
        # are not silently interpolated into the body.
        results = [result("mail", "PASS", 0, "safe detail")]
        results[0]["not_a_real_field"] = "should never appear"
        body = render_mod.render("2026-09-13", "branchLeft/shared-infra", results)
        self.assertNotIn("should never appear", body)


class MainTests(unittest.TestCase):
    def _run(self, results, date="2026-09-13", repo_label="branchLeft/shared-infra"):
        stdin = io.StringIO(json.dumps(results))
        stdout = io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            with redirect_stdout(stdout):
                rc = render_mod.main(["--date", date, "--repo-label", repo_label])
        finally:
            sys.stdin = old_stdin
        return rc, stdout.getvalue()

    def test_a_clean_run_exits_zero(self):
        rc, out = self._run([result("hosts", "PASS", 0)])
        self.assertEqual(rc, 0)
        self.assertIn("hosts", out)

    def test_a_failure_exits_with_its_own_code(self):
        rc, out = self._run([result("hosts", "FAIL", 1)])
        self.assertEqual(rc, 1)

    def test_malformed_stdin_is_a_usage_error_not_a_silent_pass(self):
        stdin = io.StringIO("not json")
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            rc = render_mod.main(["--date", "2026-09-13", "--repo-label", "x"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(rc, 2)

    def test_an_empty_array_is_a_usage_error_not_a_silent_pass(self):
        stdin = io.StringIO("[]")
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            rc = render_mod.main(["--date", "2026-09-13", "--repo-label", "x"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(rc, 2)

    def test_a_result_missing_a_field_is_a_usage_error(self):
        stdin = io.StringIO(json.dumps([{"stack": "mail", "outcome": "PASS"}]))
        old_stdin = sys.stdin
        sys.stdin = stdin
        try:
            rc = render_mod.main(["--date", "2026-09-13", "--repo-label", "x"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
