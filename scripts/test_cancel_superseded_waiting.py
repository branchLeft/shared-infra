#!/usr/bin/env python3
"""Fixture tests for cancel-superseded-waiting: the keep-or-clear decision.

The job shapes are the ones the cancel step reads from the jobs listing of an
older push run of ci.yml. Each test names the rule it proves."""

import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "cancel-superseded-waiting.py"
    spec = importlib.util.spec_from_file_location("cancel_superseded_waiting", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


superseded = _load_module()

MAIL = "Apply (mail, pulumi up)"
NETWORK = "Apply (hetzner network, pulumi up)"
ESTATE = "Apply (hetzner estate, pulumi up)"
PLAN_MAIL = "Plan (mail, pulumi preview)"


def job(name, status, conclusion=None):
    return {"name": name, "status": status, "conclusion": conclusion}


def planned(mail=False, network=False, estate=False):
    return {"mail": mail, "hetzner_network": network, "hetzner_estate": estate}


class RunThirtyEightMillionShape(unittest.TestCase):
    """Run 38425376153's job shape: one apply success, one cancelled, one
    waiting on a stack this push planned. The old rule kept it on the success."""

    JOBS = [
        job(PLAN_MAIL, "completed", "success"),
        job(MAIL, "completed", "cancelled"),
        job(NETWORK, "completed", "success"),
        job(ESTATE, "waiting"),
    ]

    def test_clears_a_waiting_apply_whose_sibling_applies_finished(self):
        verdict, reason = superseded.decide(
            self.JOBS, planned(mail=False, network=False, estate=True)
        )
        self.assertEqual(verdict, "cancel", reason)
        self.assertIn(ESTATE, reason)

    def test_clears_when_every_stack_was_planned(self):
        verdict, _ = superseded.decide(
            self.JOBS, planned(mail=True, network=True, estate=True)
        )
        self.assertEqual(verdict, "cancel")


class KeepRules(unittest.TestCase):
    def test_keeps_a_run_with_a_job_in_progress(self):
        jobs = [job(MAIL, "in_progress"), job(ESTATE, "waiting")]
        verdict, reason = superseded.decide(jobs, planned(estate=True))
        self.assertEqual(verdict, "keep")
        self.assertIn("in progress", reason)
        self.assertIn(MAIL, reason)

    def test_keeps_a_run_with_a_job_in_progress_that_is_not_an_apply(self):
        jobs = [job("Plan (hetzner estate, pulumi preview)", "in_progress"), job(ESTATE, "waiting")]
        verdict, _ = superseded.decide(jobs, planned(estate=True))
        self.assertEqual(verdict, "keep")

    def test_keeps_a_waiting_apply_on_a_stack_this_push_did_not_plan(self):
        jobs = [job(MAIL, "waiting"), job(NETWORK, "waiting")]
        verdict, reason = superseded.decide(jobs, planned(mail=True, network=False))
        self.assertEqual(verdict, "keep")
        self.assertIn(NETWORK, reason)
        self.assertIn("did not plan", reason)

    def test_keeps_a_run_with_no_apply_waiting(self):
        jobs = [job(MAIL, "completed", "skipped"), job(ESTATE, "queued")]
        verdict, reason = superseded.decide(jobs, planned(mail=True, estate=True))
        self.assertEqual(verdict, "keep")
        self.assertIn("no apply is waiting", reason)

    def test_keeps_a_run_with_no_apply_job(self):
        verdict, reason = superseded.decide([job(PLAN_MAIL, "waiting")], planned(mail=True))
        self.assertEqual(verdict, "keep")
        self.assertIn("no apply job", reason)

    def test_keeps_an_unrecognised_apply_name(self):
        jobs = [job("Apply (somewhere else, pulumi up)", "waiting")]
        verdict, _ = superseded.decide(jobs, planned(mail=True, network=True, estate=True))
        self.assertEqual(verdict, "keep")


class ListingReading(unittest.TestCase):
    def run_main(self, text):
        argv = ["--mail", "true", "--network", "false", "--estate", "true"]
        out = io.StringIO()
        original = sys.stdin
        sys.stdin = io.StringIO(text)
        try:
            with contextlib.redirect_stdout(out):
                code = superseded.main(argv)
        finally:
            sys.stdin = original
        return code, out.getvalue()

    def test_prints_the_verdict_and_the_reason(self):
        listing = '{"jobs": [{"name": "%s", "status": "waiting"}]}' % ESTATE
        code, out = self.run_main(listing)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("cancel: "), out)

    def test_an_unreadable_listing_exits_nonzero_and_prints_nothing(self):
        code, out = self.run_main("not json")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")

    def test_a_listing_without_a_jobs_list_exits_nonzero(self):
        code, out = self.run_main('{"message": "Resource not accessible"}')
        self.assertEqual(code, 1)
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
