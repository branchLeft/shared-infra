#!/usr/bin/env python3
"""Diff a freshly normalized live Cloud Armor capture against the committed baseline.

Usage:
    assert-cloud-armor-live-parity.py <baseline.normalized.json> <live-capture.normalized.json>
    assert-cloud-armor-live-parity.py --self-test

Both inputs must already be the output of `normalize-cloud-armor-baseline.py`
-- this script does not capture, normalize or redact anything itself, so the
normalizer's IP-redaction refusal still governs whatever CI captures, exactly
as it does for a hand-run recapture. This script's only job is the compare:
exit 1, naming every diverging field, if the two normalized policies are not
identical; exit 0 if they are; exit 2 on a usage error.

Unlike assert-cloud-armor-baseline-parity.py (which checks the baseline
against what `edge.ts` declares, and deliberately skips fields `edge.ts`
does not build), this is a whole-document compare of two captures already
in the same normalized shape -- policy-level fields and every rule, field
for field. A `pulumi up` that reports success is not evidence the resulting
policy matches the code (RUNBOOK-edge-state-move.md appendix A); this is the
independent read-and-compare step that appendix's A.5 says has to run every
time, not be remembered.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Divergence:
    label: str
    field: str
    baseline_value: object
    captured_value: object

    @property
    def message(self) -> str:
        return f"{self.label}: field '{self.field}' -- baseline={self.baseline_value!r} live={self.captured_value!r}"


def _diff_paths(baseline: object, captured: object, path: str = "") -> list[tuple[str, object, object]]:
    """Every leaf path where `baseline` and `captured` differ.

    A type mismatch (e.g. an object replaced by a string) is reported at
    that field directly rather than recursed into -- the two sides have
    nothing further in common to compare at that point.
    """
    if isinstance(baseline, dict) and isinstance(captured, dict):
        diffs: list[tuple[str, object, object]] = []
        for key in sorted(set(baseline) | set(captured)):
            sub_path = f"{path}.{key}" if path else key
            if key not in baseline:
                diffs.append((sub_path, "<absent>", captured[key]))
            elif key not in captured:
                diffs.append((sub_path, baseline[key], "<absent>"))
            else:
                diffs.extend(_diff_paths(baseline[key], captured[key], sub_path))
        return diffs
    if isinstance(baseline, list) and isinstance(captured, list):
        if len(baseline) != len(captured):
            return [(f"{path}[]", f"<{len(baseline)} items>", f"<{len(captured)} items>")]
        diffs = []
        for i, (b_item, c_item) in enumerate(zip(baseline, captured)):
            diffs.extend(_diff_paths(b_item, c_item, f"{path}[{i}]"))
        return diffs
    if baseline != captured:
        return [(path or "<root>", baseline, captured)]
    return []


def _rules_by_priority(policy: dict, source: str) -> dict[int, dict]:
    """Index a normalized policy's rules by integer priority.

    Fails closed on anything a priority-keyed compare can't safely handle --
    a non-object rule, a missing/non-integer priority, or a duplicate
    priority -- rather than silently dropping or overwriting the rule the
    compare below would then never see.
    """
    by_priority: dict[int, dict] = {}
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict):
            raise ValueError(f"{source}: a rule entry is not an object: {rule!r}")
        priority = rule.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError(f"{source}: rule has a missing or non-integer priority: {rule!r}")
        if priority in by_priority:
            raise ValueError(f"{source}: duplicate rule priority {priority}")
        by_priority[priority] = rule
    return by_priority


def _rule_label(priority: int, rule: dict) -> str:
    description = rule.get("description")
    tag = f" ({description})" if isinstance(description, str) and description else ""
    return f"rule priority={priority}{tag}"


def diff_normalized_policies(baseline: dict, captured: dict) -> list[Divergence]:
    """Every field on which two already-normalized policies disagree.

    Raises ValueError if either side's `rules` cannot be safely indexed by
    priority (see `_rules_by_priority`) -- a rule this can't key is a rule
    no part of the compare below can see, so it fails rather than skips it.
    """
    divergences: list[Divergence] = []

    baseline_top = {k: v for k, v in baseline.items() if k != "rules"}
    captured_top = {k: v for k, v in captured.items() if k != "rules"}
    for field, baseline_value, captured_value in _diff_paths(baseline_top, captured_top):
        divergences.append(Divergence("policy", field, baseline_value, captured_value))

    baseline_rules = _rules_by_priority(baseline, "baseline")
    captured_rules = _rules_by_priority(captured, "live capture")

    for priority in sorted(set(baseline_rules) - set(captured_rules)):
        label = _rule_label(priority, baseline_rules[priority])
        divergences.append(Divergence(label, "<rule>", "present in baseline", "absent from live capture"))

    for priority in sorted(set(captured_rules) - set(baseline_rules)):
        label = _rule_label(priority, captured_rules[priority])
        divergences.append(Divergence(label, "<rule>", "absent from baseline", "present in live capture"))

    for priority in sorted(set(baseline_rules) & set(captured_rules)):
        label = _rule_label(priority, baseline_rules[priority])
        for field, baseline_value, captured_value in _diff_paths(
            baseline_rules[priority], captured_rules[priority]
        ):
            divergences.append(Divergence(label, field, baseline_value, captured_value))

    return divergences


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()

    positional = argv[1:]
    if len(positional) != 2:
        print(__doc__)
        return 2

    baseline_path, captured_path = (Path(p) for p in positional)
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        captured = json.loads(captured_path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"::error::could not read input: {error}")
        return 1
    except json.JSONDecodeError as error:
        print(f"::error::input is not valid JSON: {error}")
        return 1

    try:
        divergences = diff_normalized_policies(baseline, captured)
    except ValueError as error:
        print(f"::error::{error}")
        return 1

    if divergences:
        print(
            f"::error::the live Cloud Armor policy diverges from the committed "
            f"baseline in {len(divergences)} way(s):"
        )
        for divergence in divergences:
            print(f"  - {divergence.message}")
        print(
            "A deploy that changed the policy in a way the baseline does not "
            "reflect is either a partial apply or an un-recaptured intentional "
            "change; both must stop here. If this is an intentional change, "
            "re-run 'Reproducing this capture' in CLOUD-ARMOR-BASELINE.md and "
            "commit the refreshed baseline in the same PR as the code change "
            "that caused it."
        )
        return 1

    print("OK: the live Cloud Armor policy matches the committed baseline")
    return 0


def self_test() -> int:
    failed = False

    def check(condition: bool, message: str) -> None:
        nonlocal failed
        if not condition:
            print(f"FAIL: {message}")
            failed = True

    base_rule = {"priority": 1000, "description": "sqli-v33-stable", "action": "deny(403)", "preview": False}
    policy = {"name": "branchleft-edge-armor", "type": "CLOUD_ARMOR", "rules": [dict(base_rule)]}

    # Identical captures diverge nowhere.
    identical = json.loads(json.dumps(policy))
    check(diff_normalized_policies(policy, identical) == [], "identical policies were reported as diverging")

    # A single differing rule field is named, by priority and field path --
    # this is the 2026-08-11 shape: a `patchRule` silently did nothing, so
    # `preview` stayed True live while the baseline (and edge.ts) said False.
    drifted_flag = json.loads(json.dumps(policy))
    drifted_flag["rules"][0]["preview"] = True
    divergences = diff_normalized_policies(policy, drifted_flag)
    check(
        len(divergences) == 1
        and divergences[0].field == "preview"
        and "priority=1000" in divergences[0].label
        and divergences[0].baseline_value is False
        and divergences[0].captured_value is True,
        f"a single flipped rule field was not reported precisely: {divergences}",
    )

    # A rule missing from the live capture entirely (the 2026-08-04 shape:
    # `lfi` dropped from the deployed policy while state and code kept it)
    # is named as absent, not silently skipped because the sides have
    # different lengths.
    missing_rule = {"name": "branchleft-edge-armor", "type": "CLOUD_ARMOR", "rules": []}
    divergences = diff_normalized_policies(policy, missing_rule)
    check(
        len(divergences) == 1 and "priority=1000" in divergences[0].label and "absent from live capture" in divergences[0].captured_value,
        f"a rule missing from the live capture was not named: {divergences}",
    )

    # A rule present live but not in the baseline -- Cloud Armor evaluates
    # by ascending priority and stops at the first match, so an undeclared
    # rule can silently override every rule below it.
    extra_rule = json.loads(json.dumps(policy))
    extra_rule["rules"].append({"priority": 500, "action": "allow"})
    divergences = diff_normalized_policies(policy, extra_rule)
    check(
        len(divergences) == 1 and "priority=500" in divergences[0].label and "present in live capture" in divergences[0].captured_value,
        f"a rule with no baseline counterpart was not named: {divergences}",
    )

    # A policy-level field (not inside any rule) diverging is reported
    # against 'policy', not attributed to a rule it has nothing to do with.
    policy_level_drift = json.loads(json.dumps(policy))
    policy_level_drift["type"] = "CLOUD_ARMOR_EDGE"
    divergences = diff_normalized_policies(policy, policy_level_drift)
    check(
        len(divergences) == 1 and divergences[0].label == "policy" and divergences[0].field == "type",
        f"a policy-level divergence was not attributed correctly: {divergences}",
    )

    # Two simultaneous divergences are both reported -- this must not stop
    # at the first difference it finds.
    double_drift = json.loads(json.dumps(policy))
    double_drift["rules"][0]["preview"] = True
    double_drift["type"] = "CLOUD_ARMOR_EDGE"
    check(
        len(diff_normalized_policies(policy, double_drift)) == 2,
        "two simultaneous divergences were not both reported",
    )

    # Fails closed, rather than silently dropping the rule, on the shapes a
    # priority-keyed compare cannot safely handle.
    try:
        diff_normalized_policies(policy, {"rules": [{"priority": 1000}, {"priority": 1000}]})
        check(False, "a duplicate live-capture priority did not raise")
    except ValueError:
        pass

    try:
        diff_normalized_policies(policy, {"rules": [{"action": "allow"}]})
        check(False, "a rule with no priority at all did not raise")
    except ValueError:
        pass

    if failed:
        print("\nassert-cloud-armor-live-parity.py self-test FAILED")
    else:
        print("OK: assert-cloud-armor-live-parity.py self-test passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
