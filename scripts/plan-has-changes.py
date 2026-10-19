#!/usr/bin/env python3
"""Decide whether a Pulumi plan changes anything: only a clean plan is `false`.
The rules and their reasons are in plan-has-changes.md beside this file."""

import argparse
import json
import math
import os
import stat
import sys
from typing import NamedTuple

ROOT_STACK_TYPE = "pulumi:pulumi:Stack"
SAME = "same"
MAX_DEPTH = 500

# The keys each level of the two files may carry: those seen in a real plan and
# preview, plus the preview step's own fields. Any other key is a shape change.
PREVIEW_KEYS = frozenset({"config", "steps", "duration", "changeSummary", "diagnostics", "maybeCorrupt"})
PLAN_KEYS = frozenset({"manifest", "config", "resourcePlans"})
STEP_KEYS = frozenset({"op", "urn", "provider", "oldState", "newState", "detailedDiff", "diffReasons", "replaceReasons"})
ENTRY_KEYS = frozenset({"goal", "steps", "state", "seed"})
GOAL_KEYS = frozenset(
    {"type", "name", "custom", "inputDiff", "outputDiff", "parent", "protect", "provider", "propertyDependencies", "customTimeouts"}
)

# A `same` step that carries any of these, non-empty, is not a no-op.
STEP_DIFF_KEYS = ("detailedDiff", "diffReasons", "replaceReasons")
# State keys that must match exactly; a missing one reads as null, so a value
# on one side only differs. Outputs, id and provider are compared only when
# both sides hold them: a real new state is read before it copies the old ones.
STRICT_STATE_KEYS = ("inputs", "parent")
LENIENT_STATE_KEYS = ("outputs", "id", "provider")
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


def _finite(text: str) -> float:
    """A JSON number that overflows to infinity is refused, like `NaN` and `Infinity`."""
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(text)
    return value


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
            doc = json.load(
                handle, object_pairs_hook=_no_duplicates, parse_constant=_no_constant, parse_float=_finite
            )
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


def _leaf_type(urn: Urn) -> str:
    return urn.type.rsplit("$", 1)[-1]


def _stacks(urns: list[Urn]) -> list[Urn]:
    """Every resource whose own type is the stack type, nested under a parent type or not."""
    return [urn for urn in urns if _leaf_type(urn) == ROOT_STACK_TYPE]


def _has_one_root(urns: list[Urn]) -> bool:
    """Exactly one stack-typed resource, and it is the root: a second one is anomalous."""
    stacks = _stacks(urns)
    return len(stacks) == 1 and _is_root(stacks[0])


def _check_keys(doc: dict[str, object], known: frozenset[str], reason: str) -> None:
    _require(set(doc) <= known, reason)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _evidence(value: object) -> bool:
    """Absent, null and empty hold no evidence; non-empty does; any other type is Unclear."""
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return bool(value)
    raise Unclear("preview-shape")


def _states_differ(old: dict[str, object], new: dict[str, object]) -> bool:
    """Whether a `same` step's old and new state disagree."""
    for key in STRICT_STATE_KEYS:
        if old.get(key) != new.get(key):
            return True
    return any(key in old and key in new and old[key] != new[key] for key in LENIENT_STATE_KEYS)


def _same_step_differs(step: dict[str, object]) -> bool:
    """Whether a `same` step carries its own evidence of a difference."""
    _check_keys(step, STEP_KEYS, "preview-shape")
    evidence = [_evidence(step.get(key)) for key in STEP_DIFF_KEYS]
    old, new = step.get("oldState"), step.get("newState")
    if not (isinstance(old, dict) and isinstance(new, dict)):
        raise Unclear("preview-shape")
    return any(evidence) or _states_differ(old, new)


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


def _preview_verdict(path: str) -> tuple[Verdict | None, Urn | None]:
    """(a `true` verdict, None) if the preview JSON shows anything but a clean no-op,
    else (None, the root stack's URN)."""
    doc = _as_dict(_load(path, "preview-unreadable"), "preview-shape")
    _check_keys(doc, PREVIEW_KEYS, "preview-shape")
    steps = _preview_steps(doc)
    changed = sum(1 for op, _, _ in steps if op != SAME)
    if changed:
        return Verdict(True, changed, "steps-changed"), None
    differing = sum(1 for _, _, step in steps if _same_step_differs(step))
    if differing:
        return Verdict(True, differing, "steps-changed"), None
    urns = [urn for _, urn, _ in steps]
    if not _has_one_root(urns):
        return Verdict(True, 0, "no-root-stack"), None
    diagnostics = doc.get("diagnostics")
    _require(diagnostics is None or (isinstance(diagnostics, list) and not diagnostics), "preview-diagnostics")
    corrupt = doc.get("maybeCorrupt")
    _require(corrupt is None or corrupt is False, "preview-shape")
    return _summary_verdict(doc, len(steps)), _stacks(urns)[0]


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
    _check_keys(entry, ENTRY_KEYS, "plan-shape")
    other = _planned_steps(entry)
    goal = _as_dict(entry.get("goal"), "plan-shape")
    _check_keys(goal, GOAL_KEYS, "plan-shape")
    _require("outputDiff" in goal, "plan-shape")
    if "type" in goal:
        _require(goal["type"] == _leaf_type(urn), "plan-shape")
    if "inputDiff" in goal:
        other += _diff_size(goal["inputDiff"])
    return _diff_size(goal["outputDiff"]), other


def _plan_verdict(path: str, root: Urn | None) -> Verdict:
    """The verdict from the update plan, every entry checked, the root stack's included.

    `root` is the preview's root stack: the plan must be for the same stack."""
    doc = _as_dict(_load(path, "plan-unreadable"), "plan-shape")
    _check_keys(doc, PLAN_KEYS, "plan-shape")
    plans = _as_dict(doc.get("resourcePlans"), "plan-shape")
    _require(bool(plans), "plan-shape")
    entries = [(_parse_urn(key, "plan-shape"), _as_dict(value, "plan-shape")) for key, value in plans.items()]
    urns = [urn for urn, _ in entries]
    _require(_has_one_root(urns), "plan-shape")
    _require(_stacks(urns)[0] == root, "stack-mismatch")
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
        verdict, root = _preview_verdict(preview_path)
        if verdict is not None:
            return verdict
        return _plan_verdict(plan_path, root)
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


def _path_problem(flag: str, path: str) -> str | None:
    """Why an output path cannot carry the verdict: blank, or an existing non-regular file."""
    if not path.strip():
        return f"{flag} names no file, so the plan verdict cannot be published"
    if os.path.exists(path) and not stat.S_ISREG(os.stat(path).st_mode):
        return f"{flag} is not a regular file, so the plan verdict cannot be published"
    return None


def _output_problem(output: str, summary: str) -> str | None:
    """Why the two output paths cannot be written, or None."""
    problem = _path_problem("--github-output", output) or _path_problem("--github-summary", summary)
    if problem is None and os.path.realpath(output) == os.path.realpath(summary):
        return "--github-output and --github-summary name the same file, so the verdict would be mangled"
    return problem


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="plan-has-changes.py", description=__doc__.split("\n")[0])
    parser.add_argument("preview_json")
    parser.add_argument("plan_file")
    parser.add_argument("--github-output", required=True, help="append has_changes=<bool> to this file")
    parser.add_argument("--github-summary", required=True, help="append the headline to this file")
    args = parser.parse_args(argv[1:])

    problem = _output_problem(args.github_output, args.github_summary)
    if problem:
        print(f"::error::{problem}")
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
