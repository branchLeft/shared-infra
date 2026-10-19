#!/usr/bin/env python3
"""Decide whether a Pulumi plan changes anything: only a clean plan is `false`.
The rules and their reasons are in plan-has-changes.md beside this file."""

import argparse
import json
import os
import sys
from typing import NamedTuple

ROOT_STACK_TYPE = "pulumi:pulumi:Stack"
SAME = "same"
MAX_DEPTH = 500

# The only top-level keys each input file has been seen to carry.
PREVIEW_KEYS = frozenset({"config", "steps", "duration", "changeSummary", "diagnostics", "maybeCorrupt"})
PLAN_KEYS = frozenset({"manifest", "config", "resourcePlans"})

# A `same` step that carries any of these, non-empty, is not a no-op.
STEP_DIFF_KEYS = ("diffs", "detailedDiff", "diffReasons", "replaceReasons")
# What the output diff and the input diff may carry, with each JSON type.
DIFF_KEYS = {"adds": dict, "updates": dict, "deletes": list}

HEADLINE_NO_CHANGES = "No changes: the apply job is skipped and no approval is requested"
HEADLINE_NOT_UNDERSTOOD = "Plan not understood, treated as changes: approval required"
COUNTED_REASONS = {"steps-changed", "summary-changed", "output-changed"}


class Verdict(NamedTuple):
    has_changes: bool
    count: int
    reason: str


class Urn(NamedTuple):
    stack: str
    project: str
    type: str
    name: str


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


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constant(name: str) -> object:
    raise ValueError(name)


def _too_deep(doc: object) -> bool:
    """Whether the document nests deeper than MAX_DEPTH, measured without recursion."""
    stack = [(doc, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > MAX_DEPTH:
                return True
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    return False


def _load(path: str, reason: str) -> object:
    """Parse a JSON file, or raise Unclear for every way it can fail."""
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (OSError, ValueError, RecursionError) as error:
        raise Unclear(reason) from error
    _require(not _too_deep(doc), reason)
    return doc


def _parse_urn(urn: object, reason: str) -> Urn:
    """Split `urn:pulumi:<stack>::<project>::<type>::<name>`; a `::` in the name is refused."""
    _require(isinstance(urn, str), reason)
    parts = str(urn).split("::", 3)
    _require(len(parts) == 4 and parts[0].startswith("urn:pulumi:"), reason)
    _require("::" not in parts[3], reason)
    return Urn(parts[0][len("urn:pulumi:") :], parts[1], parts[2], parts[3])


def _is_root(urn: Urn) -> bool:
    """The stack's own root: the exact root type, named `<project>-<stack>`."""
    return urn.type == ROOT_STACK_TYPE and urn.name == f"{urn.project}-{urn.stack}"


def _has_one_root(urns: list[Urn]) -> bool:
    """Exactly one stack-typed resource, and it is the root: a second one is anomalous."""
    stacks = [urn for urn in urns if urn.type == ROOT_STACK_TYPE]
    return len(stacks) == 1 and _is_root(stacks[0])


def _leaf_type(urn: Urn) -> str:
    return urn.type.rsplit("$", 1)[-1]


def _check_keys(doc: dict[str, object], known: frozenset[str], reason: str) -> None:
    _require(set(doc) <= known, reason)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _same_step_differs(step: dict[str, object]) -> bool:
    """Whether a `same` step carries its own evidence of a difference."""
    if any(step.get(key) for key in STEP_DIFF_KEYS):
        return True
    old, new = step.get("oldState"), step.get("newState")
    if isinstance(old, dict) and isinstance(new, dict):
        return any(key in old and key in new and old[key] != new[key] for key in ("inputs", "outputs"))
    return False


def _preview_steps(doc: dict[str, object]) -> list[tuple[str, Urn, dict[str, object]]]:
    steps = doc.get("steps")
    if not isinstance(steps, list) or not steps:
        raise Unclear("preview-shape")
    found = []
    for step in steps:
        entry = _as_dict(step, "preview-shape")
        op = entry.get("op")
        _require(isinstance(op, str), "preview-shape")
        found.append((str(op), _parse_urn(entry.get("urn"), "preview-shape"), entry))
    return found


def _summary_verdict(doc: dict[str, object], same_steps: int) -> Verdict | None:
    """The change summary must count nothing but `same`, and at least the `same` steps listed."""
    summary = _as_dict(doc.get("changeSummary"), "preview-shape")
    for value in summary.values():
        _require(_is_count(value), "preview-shape")
    changed = max((int(v) for k, v in summary.items() if k != SAME and isinstance(v, int)), default=0)
    if changed:
        return Verdict(True, changed, "summary-changed")
    same_count = summary.get(SAME, 0)
    _require(isinstance(same_count, int) and same_count >= same_steps, "preview-shape")
    return None


def _preview_verdict(path: str) -> Verdict | None:
    """A `true` verdict if the preview JSON shows anything but a clean no-op."""
    doc = _as_dict(_load(path, "preview-unreadable"), "preview-shape")
    _check_keys(doc, PREVIEW_KEYS, "preview-shape")
    steps = _preview_steps(doc)
    changed = sum(1 for op, _, _ in steps if op != SAME)
    if changed:
        return Verdict(True, changed, "steps-changed")
    differing = sum(1 for _, _, step in steps if _same_step_differs(step))
    if differing:
        return Verdict(True, differing, "steps-changed")
    if not _has_one_root([urn for _, urn, _ in steps]):
        return Verdict(True, 0, "no-root-stack")
    verdict = _summary_verdict(doc, len(steps))
    _require(not doc.get("maybeCorrupt"), "preview-shape")
    return verdict


def _diff_size(diff: object) -> int:
    """How many keys an adds/updates/deletes diff holds; null or odd types are Unclear."""
    entries = _as_dict(diff, "plan-shape")
    _check_keys(entries, frozenset(DIFF_KEYS), "plan-shape")
    total = 0
    for key, kind in DIFF_KEYS.items():
        if key in entries:
            value = entries[key]
            _require(isinstance(value, kind), "plan-shape")
            total += len(value)  # type: ignore[arg-type]
    return total


def _planned_steps(entry: dict[str, object]) -> int:
    """How many of an entry's planned steps are not `same`; absent or empty is Unclear."""
    steps = entry.get("steps")
    _require(isinstance(steps, list) and bool(steps), "plan-shape")
    _require(all(isinstance(op, str) for op in steps), "plan-shape")  # type: ignore[union-attr]
    return sum(1 for op in steps if op != SAME)  # type: ignore[union-attr]


def _entry_changes(urn: Urn, entry: dict[str, object]) -> tuple[int, int]:
    """(output changes, other changes) for one planned resource."""
    other = _planned_steps(entry)
    goal = _as_dict(entry.get("goal"), "plan-shape")
    if "type" in goal:
        _require(goal["type"] == _leaf_type(urn), "plan-shape")
    if "inputDiff" in goal:
        other += _diff_size(goal["inputDiff"])
    if "outputDiff" in goal:
        return _diff_size(goal["outputDiff"]), other
    _require(not _is_root(urn), "plan-shape")
    return 0, other


def _plan_verdict(path: str) -> Verdict:
    """The verdict from the update plan, every entry checked, the root stack's included."""
    doc = _as_dict(_load(path, "plan-unreadable"), "plan-shape")
    _check_keys(doc, PLAN_KEYS, "plan-shape")
    plans = _as_dict(doc.get("resourcePlans"), "plan-shape")
    _require(bool(plans), "plan-shape")
    entries = [(_parse_urn(key, "plan-shape"), _as_dict(value, "plan-shape")) for key, value in plans.items()]
    _require(_has_one_root([urn for urn, _ in entries]), "plan-shape")
    results = [_entry_changes(urn, entry) for urn, entry in entries]
    outputs = sum(out for out, _ in results)
    other = sum(rest for _, rest in results)
    if outputs:
        return Verdict(True, outputs, "output-changed")
    if other:
        return Verdict(True, other, "steps-changed")
    return NO_CHANGES


def _same_file(first: str, second: str) -> bool:
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def evaluate(preview_path: str, plan_path: str) -> Verdict:
    """The verdict for a preview JSON file and its saved plan file.

    Fails closed: a shape not understood, or any error, is a `true` with a reason code."""
    try:
        if _same_file(preview_path, plan_path):
            return Verdict(True, 0, "same-file")
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
    parser.add_argument("--github-output", required=True, help="append has_changes=<bool> to this file")
    parser.add_argument("--github-summary", required=True, help="append the headline to this file")
    args = parser.parse_args(argv[1:])

    for flag, value in (("--github-output", args.github_output), ("--github-summary", args.github_summary)):
        if not value:
            print(f"::error::{flag} names no file, so the plan verdict cannot be published")
            return 1

    verdict = evaluate(args.preview_json, args.plan_file)
    text = "true" if verdict.has_changes else "false"
    try:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write(f"has_changes={text}\n")
        with open(args.github_summary, "a", encoding="utf-8") as handle:
            handle.write(f"{headline(verdict)}\n\n")
    except OSError as error:
        print(f"::error::cannot write the plan verdict: {type(error).__name__}")
        return 1

    print(f"has_changes={text} reason={verdict.reason} count={verdict.count}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
