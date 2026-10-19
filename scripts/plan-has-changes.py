#!/usr/bin/env python3
"""Decide whether a Pulumi plan changes anything, so a no-op apply can be skipped.

Run in a CI plan job, after `pulumi preview --json` (the file the delete guard
reads) and `pulumi preview --save-plan` (the update plan) have both written
their files. The plan job publishes the answer as its `has_changes` output and
the apply job runs, and so asks its environment for approval, only when that
output is `true`.

Usage:
    plan-has-changes.py <preview-json> <plan-file>
        [--github-output FILE] [--github-summary FILE]

The answer is `false` only when ALL of these hold; anything else is `true`, so
a plan this script does not understand always reaches the approval gate:

1. The preview JSON parsed, every step in it has op `same`, and exactly one
   step is the root stack (`pulumi:pulumi:Stack`).
2. The preview's `changeSummary` is an object whose counts are all zero except
   `same`.
3. The plan file parsed, holds exactly one root stack entry, every resource
   step it lists is `same`, and the root stack's `goal.outputDiff` is present,
   made only of the keys `adds`, `updates` and `deletes`, and empty.

Why two files. `pulumi preview --json` lists the root stack step on every run,
but a change that touches only stack outputs leaves that step `same`, carries
no outputs on it, and the digest has no outputs section, so the JSON alone
cannot see it. The update plan records the root stack's output diff, computed
inside the CLI on the decrypted values, so an unchanged secret output is no
diff and a changed one is a diff. Nothing here reads or decrypts a value.

Nothing the plan file holds is printed. It can carry resource inputs and
secrets-provider ciphertext; this script reads it and reports only a boolean,
a count and a reason code.

What this cannot see, both limits real and the same as today's apply:

1. `pulumi preview` does not refresh, so drift outside Pulumi reads as `same`.
   The apply does not refresh either.
2. It sees what the preview sees. A plan shape from a Pulumi CLI that this
   script has not met falls back to `true`: it costs an approval, never a skip.

Exit status is 0 whenever an answer was produced, including `true` for an
unreadable plan, 1 if an output file cannot be written, 2 on a usage error.
"""

import argparse
import json
import sys
from typing import NamedTuple

ROOT_STACK_TYPE = "pulumi:pulumi:Stack"
SAME = "same"

# The only keys the root stack's `outputDiff` may carry, with the JSON type of
# each. Anything else is a shape this script has not met.
OUTPUT_DIFF_KEYS = {"adds": dict, "updates": dict, "deletes": list}

HEADLINE_NO_CHANGES = "No changes: the apply job is skipped and no approval is requested"
HEADLINE_NOT_UNDERSTOOD = "Plan not understood, treated as changes: approval required"

# Reason codes that carry a meaningful change count.
COUNTED_REASONS = {"steps-changed", "summary-changed", "output-changed"}


class Verdict(NamedTuple):
    has_changes: bool
    count: int
    reason: str


NO_CHANGES = Verdict(False, 0, "no-changes")


class Unclear(Exception):
    """An input is not a shape this script understands. `reason` is its code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Unclear(reason)


def _as_dict(value: object, reason: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise Unclear(reason)
    return value


def _load(path: str, reason: str) -> object:
    """Parse a JSON file, or raise Unclear for every way it can fail."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, RecursionError) as error:
        raise Unclear(reason) from error


def _type_of(urn: object, reason: str) -> str:
    """The leaf type token of a Pulumi URN, as the delete guard reads it."""
    _require(isinstance(urn, str), reason)
    parts = str(urn).rsplit("::", 2)
    _require(len(parts) == 3, reason)
    return parts[1].rsplit("$", 1)[-1]


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _preview_ops(doc: dict[str, object]) -> list[tuple[str, str]]:
    """(op, type token) for every step of a preview JSON document."""
    steps = doc.get("steps")
    if not isinstance(steps, list) or not steps:
        raise Unclear("preview-shape")
    found = []
    for step in steps:
        entry = _as_dict(step, "preview-shape")
        op = entry.get("op")
        if not isinstance(op, str):
            raise Unclear("preview-shape")
        found.append((op, _type_of(entry.get("urn"), "preview-shape")))
    return found


def _summary_changes(doc: dict[str, object]) -> int:
    """The largest non-`same` count in the change summary."""
    summary = _as_dict(doc.get("changeSummary"), "preview-shape")
    counts = []
    for key, value in summary.items():
        if not isinstance(value, int) or not _is_count(value):
            raise Unclear("preview-shape")
        if key != SAME:
            counts.append(value)
    return max(counts, default=0)


def _preview_verdict(path: str) -> Verdict | None:
    """A `true` verdict if the preview JSON shows anything but a clean no-op."""
    doc = _as_dict(_load(path, "preview-unreadable"), "preview-shape")
    ops = _preview_ops(doc)
    changed = sum(1 for op, _ in ops if op != SAME)
    if changed:
        return Verdict(True, changed, "steps-changed")
    if sum(1 for _, type_token in ops if type_token == ROOT_STACK_TYPE) != 1:
        return Verdict(True, 0, "no-root-stack")
    summary_changes = _summary_changes(doc)
    if summary_changes:
        return Verdict(True, summary_changes, "summary-changed")
    _require(not doc.get("maybeCorrupt"), "preview-shape")
    return None


def _plan_entries(doc: object) -> dict[str, dict[str, object]]:
    """The plan file's per-resource entries, keyed by URN."""
    plans = _as_dict(_as_dict(doc, "plan-shape").get("resourcePlans"), "plan-shape")
    _require(bool(plans), "plan-shape")
    return {urn: _as_dict(entry, "plan-shape") for urn, entry in plans.items()}


def _changed_plan_steps(entry: dict[str, object]) -> int:
    """How many of one resource's planned steps are not `same`."""
    steps = entry.get("steps")
    if steps is None:
        return 0
    if not isinstance(steps, list) or not all(isinstance(op, str) for op in steps):
        raise Unclear("plan-shape")
    return sum(1 for op in steps if op != SAME)


def _root_entry(entries: dict[str, dict[str, object]]) -> dict[str, object]:
    roots = [e for urn, e in entries.items() if _type_of(urn, "plan-shape") == ROOT_STACK_TYPE]
    _require(len(roots) == 1, "plan-shape")
    return roots[0]


def _output_changes(root: dict[str, object]) -> int:
    """How many output keys the root stack's output diff adds, updates or deletes."""
    goal = _as_dict(root.get("goal"), "plan-shape")
    diff = _as_dict(goal.get("outputDiff"), "plan-shape")
    _require(set(diff) <= set(OUTPUT_DIFF_KEYS), "plan-shape")
    total = 0
    for key, kind in OUTPUT_DIFF_KEYS.items():
        value = diff.get(key)
        if value is None:
            continue
        if not isinstance(value, kind) or not isinstance(value, (dict, list)):
            raise Unclear("plan-shape")
        total += len(value)
    return total


def _plan_verdict(path: str) -> Verdict:
    """The verdict from the update plan: output diff and per-resource ops."""
    entries = _plan_entries(_load(path, "plan-unreadable"))
    changed_steps = sum(_changed_plan_steps(entry) for entry in entries.values())
    output_changes = _output_changes(_root_entry(entries))
    if output_changes:
        return Verdict(True, output_changes, "output-changed")
    if changed_steps:
        return Verdict(True, changed_steps, "steps-changed")
    return NO_CHANGES


def evaluate(preview_path: str, plan_path: str) -> Verdict:
    """The verdict for a preview JSON file and its saved plan file.

    Fails closed: an input that is not understood is a `true` with its reason
    code, and so is an unexpected error, never an exception that a caller could
    mistake for an answer.
    """
    try:
        verdict = _preview_verdict(preview_path)
        if verdict is not None:
            return verdict
        return _plan_verdict(plan_path)
    except Unclear as unclear:
        return Verdict(True, 0, unclear.reason)
    except Exception:  # noqa: BLE001 -- every failure must reach the gate
        return Verdict(True, 0, "internal-error")


def headline(verdict: Verdict) -> str:
    """The first line of the plan job's summary."""
    if not verdict.has_changes:
        return HEADLINE_NO_CHANGES
    if verdict.reason in COUNTED_REASONS and verdict.count > 0:
        noun = "change" if verdict.count == 1 else "changes"
        return f"{verdict.count} {noun}: approval required"
    return HEADLINE_NOT_UNDERSTOOD


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="plan-has-changes.py", description=__doc__.split("\n")[0])
    parser.add_argument("preview_json")
    parser.add_argument("plan_file")
    parser.add_argument("--github-output", help="append has_changes=<bool> to this file")
    parser.add_argument("--github-summary", help="append the headline to this file")
    args = parser.parse_args(argv[1:])

    verdict = evaluate(args.preview_json, args.plan_file)
    text = "true" if verdict.has_changes else "false"

    try:
        if args.github_output:
            with open(args.github_output, "a", encoding="utf-8") as handle:
                handle.write(f"has_changes={text}\n")
        if args.github_summary:
            with open(args.github_summary, "a", encoding="utf-8") as handle:
                handle.write(f"{headline(verdict)}\n\n")
    except OSError as error:
        print(f"::error::cannot write the plan verdict: {type(error).__name__}")
        return 1

    print(f"has_changes={text} reason={verdict.reason} count={verdict.count}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
