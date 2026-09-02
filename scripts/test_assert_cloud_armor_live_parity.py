#!/usr/bin/env python3
"""Unit tests for assert-cloud-armor-live-parity.

This checker exists because two silent partial applies already reached
production before anything caught them (CLOUD-ARMOR-BASELINE.md's Findings
#1 and #2, RUNBOOK-edge-state-move.md appendix A): `pulumi up` reported
success while the live Cloud Armor policy diverged from what the checkpoint
and the code both recorded. A diff that reports "clean" regardless of its
input is worse than no diff at all -- every test below is built around a
divergence shaped like one of those two incidents, or a shape the compare
could plausibly get wrong (a rule dropped entirely, an extra undeclared
rule, a field flip, two divergences at once, malformed priorities), not
around the identical-input happy path alone.

Run directly:
    python3 -m unittest scripts/test_assert_cloud_armor_live_parity.py -v

Also picked up by `python3 -m unittest discover -s scripts -p 'test_*.py'`,
which the `scripts-tests` pre-commit hook and CI job both run.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest


def _load_module():
    """Import the script by path -- its filename has hyphens, so a plain
    `import` cannot name it. Registered in `sys.modules` before execution:
    `Divergence` is a `@dataclass`, and `dataclasses` resolves its owning
    module via `sys.modules[cls.__module__]` while the class body runs."""
    path = pathlib.Path(__file__).resolve().parent / "assert-cloud-armor-live-parity.py"
    spec = importlib.util.spec_from_file_location("assert_cloud_armor_live_parity", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


live_parity = _load_module()


def _clean_policy() -> dict:
    """A minimal but realistic normalized policy: two rules, sorted by
    priority, no volatile fields -- what `normalize-cloud-armor-baseline.py`
    would actually hand this script."""
    return {
        "name": "branchleft-edge-armor",
        "type": "CLOUD_ARMOR",
        "rules": [
            {
                "priority": 1000,
                "description": "sqli-v33-stable",
                "action": "deny(403)",
                "preview": False,
                "match": {"config": {"srcIpRanges": ["*"]}},
            },
            {
                "priority": 1003,
                "description": "lfi-v33-stable",
                "action": "deny(403)",
                "preview": False,
                "match": {"config": {"srcIpRanges": ["*"]}},
            },
            {"priority": 2147483647, "description": "default-allow", "action": "allow"},
        ],
    }


class DiffNormalizedPoliciesTests(unittest.TestCase):
    def test_identical_policies_have_no_divergence(self):
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        self.assertEqual(live_parity.diff_normalized_policies(baseline, captured), [])

    def test_a_dropped_rule_is_named_by_priority_not_silently_absorbed_by_length(self):
        # The 2026-08-04 shape: `lfi` vanished from the deployed policy while
        # state and code both kept it. A compare keyed by list position
        # rather than priority would see "3 rules vs 2 rules" and could stop
        # there, or worse, compare priority=1003 against priority=2147483647
        # positionally and report a confusing default-allow divergence
        # instead of naming the rule that actually went missing.
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["rules"] = [r for r in captured["rules"] if r["priority"] != 1003]

        divergences = live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(len(divergences), 1)
        self.assertIn("priority=1003", divergences[0].label)
        self.assertIn("lfi-v33-stable", divergences[0].label)
        self.assertEqual(divergences[0].captured_value, "absent from live capture")

    def test_an_undeclared_live_rule_is_named(self):
        # Cloud Armor evaluates by ascending priority and stops at the first
        # match, so a rule present live but not in the baseline can silently
        # override every rule below it -- this must never pass as "no
        # divergence" just because every baseline rule still has a match.
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["rules"].append({"priority": 500, "action": "allow", "description": "undeclared"})

        divergences = live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(len(divergences), 1)
        self.assertIn("priority=500", divergences[0].label)
        self.assertEqual(divergences[0].baseline_value, "absent from baseline")

    def test_a_single_flipped_rule_field_is_named_precisely(self):
        # The 2026-08-11 shape: a `patchRule` call silently did nothing, so
        # `preview` stayed True live (enforcing nothing) while state and
        # edge.ts both correctly recorded False. This is the incident the
        # whole gate exists to catch, so the diff must name the exact field
        # and exact values, not just "rule priority=1000 differs".
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["rules"][0]["preview"] = True

        divergences = live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(len(divergences), 1)
        divergence = divergences[0]
        self.assertIn("priority=1000", divergence.label)
        self.assertEqual(divergence.field, "preview")
        self.assertIs(divergence.baseline_value, False)
        self.assertIs(divergence.captured_value, True)

    def test_a_nested_match_expression_field_is_named_by_its_full_path(self):
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["rules"][0]["match"]["config"]["srcIpRanges"] = ["203.0.113.0/24"]

        divergences = live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(len(divergences), 1)
        self.assertEqual(divergences[0].field, "match.config.srcIpRanges[0]")

    def test_a_policy_level_field_is_attributed_to_the_policy_not_a_rule(self):
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["type"] = "CLOUD_ARMOR_EDGE"

        divergences = live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(len(divergences), 1)
        self.assertEqual(divergences[0].label, "policy")
        self.assertEqual(divergences[0].field, "type")

    def test_two_simultaneous_divergences_are_both_reported(self):
        # A diff that returns on its first finding would silently hide a
        # second, independent partial-apply symptom landing in the same run.
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["rules"][0]["preview"] = True
        captured["name"] = "branchleft-edge-armor-typo"

        divergences = live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(len(divergences), 2)
        fields = {d.field for d in divergences}
        self.assertEqual(fields, {"preview", "name"})

    def test_a_duplicate_priority_in_the_live_capture_fails_closed(self):
        baseline = _clean_policy()
        captured = {"rules": [{"priority": 1000, "action": "deny(403)"}, {"priority": 1000, "action": "allow"}]}
        with self.assertRaises(ValueError):
            live_parity.diff_normalized_policies(baseline, captured)

    def test_a_rule_with_no_priority_fails_closed_rather_than_being_dropped(self):
        baseline = _clean_policy()
        captured = {"rules": [{"action": "allow"}]}
        with self.assertRaises(ValueError):
            live_parity.diff_normalized_policies(baseline, captured)

    def test_a_boolean_is_never_accepted_as_a_priority(self):
        # bool is a subclass of int in Python; True/False must not silently
        # key a rule at priority 1/0.
        baseline = _clean_policy()
        captured = {"rules": [{"priority": True, "action": "allow"}]}
        with self.assertRaises(ValueError):
            live_parity.diff_normalized_policies(baseline, captured)

    def test_does_not_mutate_its_inputs(self):
        baseline = _clean_policy()
        captured = copy.deepcopy(baseline)
        captured["rules"][0]["preview"] = True
        before_baseline = json.dumps(baseline, sort_keys=True)
        before_captured = json.dumps(captured, sort_keys=True)

        live_parity.diff_normalized_policies(baseline, captured)

        self.assertEqual(json.dumps(baseline, sort_keys=True), before_baseline)
        self.assertEqual(json.dumps(captured, sort_keys=True), before_captured)


class MainCliTests(unittest.TestCase):
    """End-to-end through `main()` against real files on disk, not just the
    comparison function -- the CLI's argument handling, exit codes and
    stdout framing are exactly what a CI step actually depends on."""

    def _run(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = live_parity.main(argv)
        return exit_code, stdout.getvalue()

    def _write(self, tmp: pathlib.Path, name: str, content) -> str:
        path = tmp / name
        path.write_text(json.dumps(content), encoding="utf-8")
        return str(path)

    def test_matching_captures_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            policy = _clean_policy()
            baseline_path = self._write(tmp, "baseline.json", policy)
            captured_path = self._write(tmp, "captured.json", copy.deepcopy(policy))

            exit_code, output = self._run(["prog", baseline_path, captured_path])

            self.assertEqual(exit_code, 0)
            self.assertIn("OK", output)

    def test_a_divergence_exits_one_and_names_the_diverging_rule(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            baseline = _clean_policy()
            captured = copy.deepcopy(baseline)
            captured["rules"][0]["preview"] = True
            baseline_path = self._write(tmp, "baseline.json", baseline)
            captured_path = self._write(tmp, "captured.json", captured)

            exit_code, output = self._run(["prog", baseline_path, captured_path])

            self.assertEqual(exit_code, 1)
            self.assertIn("priority=1000", output)
            self.assertIn("preview", output)

    def test_a_malformed_capture_exits_one_not_zero_and_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            baseline_path = self._write(tmp, "baseline.json", _clean_policy())
            captured_path = self._write(tmp, "captured.json", {"rules": [{"action": "allow"}]})

            exit_code, output = self._run(["prog", baseline_path, captured_path])

            self.assertEqual(exit_code, 1)
            self.assertIn("error", output.lower())

    def test_a_missing_file_exits_one(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            baseline_path = self._write(tmp, "baseline.json", _clean_policy())

            exit_code, _output = self._run(["prog", baseline_path, str(tmp / "does-not-exist.json")])

            self.assertEqual(exit_code, 1)

    def test_invalid_json_exits_one(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = pathlib.Path(tmp_str)
            baseline_path = self._write(tmp, "baseline.json", _clean_policy())
            captured_path = tmp / "captured.json"
            captured_path.write_text("{not json", encoding="utf-8")

            exit_code, _output = self._run(["prog", baseline_path, str(captured_path)])

            self.assertEqual(exit_code, 1)

    def test_wrong_argument_count_exits_two_and_prints_usage(self):
        exit_code, output = self._run(["prog", "only-one-arg"])
        self.assertEqual(exit_code, 2)
        self.assertIn("Usage", output)

    def test_self_test_flag_runs_the_embedded_self_test(self):
        exit_code, output = self._run(["prog", "--self-test"])
        self.assertEqual(exit_code, 0)
        self.assertIn("self-test passed", output)


if __name__ == "__main__":
    unittest.main()
