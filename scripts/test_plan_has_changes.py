#!/usr/bin/env python3
"""Unit tests for plan-has-changes.

This script decides whether the owner is asked to approve an apply. The
failure that matters is a `false` over a plan that changes something: the
change is then never applied and nobody is asked. Every test is aimed at that
shape: an op the rule waves through, an output-only change nothing else would
see, or an input that cannot be read yet is treated as clean.

The fixtures follow what the Pulumi CLI wrote when run against a throwaway
local stack: a `create` plan whose root stack output diff has `adds`, a
resource whose output diff is the empty object, the secrets-provider
ciphertext shape for a secret output, and the sentinel string an unknown value
is written as.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "plan-has-changes.py"
    spec = importlib.util.spec_from_file_location("plan_has_changes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


noop = _load_module()

_STACK = "urn:pulumi:production::branchleft-mail::"
_ROOT = f"{_STACK}pulumi:pulumi:Stack::branchleft-mail-production"
_SERVER = f"{_STACK}hcloud:index/server:Server::mx1"
_FIREWALL = f"{_STACK}hcloud:index/firewall:Firewall::mail-firewall"

# What an unknown value is written as in a saved plan.
UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
# The shape a secret output takes in a saved plan: the secrets provider's
# ciphertext, never the value.
SECRET = {
    "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
    "ciphertext": "v1:CIPHERTEXT_PLACEHOLDER",
}
MARKER = "VALUE_MARKER_MUST_NOT_BE_PRINTED"


def preview(*steps, summary=None, **extra):
    """A preview JSON document: (op, urn) steps and a change summary."""
    doc = {
        "steps": [{"op": op, "urn": urn} for op, urn in steps],
        "duration": 1,
        "changeSummary": summary if summary is not None else {"same": 3},
    }
    doc.update(extra)
    return doc


def no_op_preview():
    return preview(("same", _ROOT))


def plan(output_diff=None, root=_ROOT, root_steps=("same",), others=None, goal=None):
    """A saved plan file: a root stack entry and any other resource entries."""
    root_goal = goal if goal is not None else {"type": "pulumi:pulumi:Stack"}
    if goal is None:
        root_goal["outputDiff"] = {} if output_diff is None else output_diff
    plans = {root: {"goal": root_goal, "steps": list(root_steps), "state": {"k": MARKER}}}
    for urn, steps in (others or {}).items():
        plans[urn] = {"goal": {"outputDiff": {}}, "steps": list(steps)}
    return {"manifest": {"version": "v0"}, "config": {"k": MARKER}, "resourcePlans": plans}


class Files:
    """A temp directory holding the two input files."""

    def __init__(self, testcase):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="plan-has-changes-"))
        testcase.addCleanup(self._cleanup)

    def _cleanup(self):
        for child in self.dir.iterdir():
            child.unlink()
        self.dir.rmdir()

    def write(self, name, content):
        path = self.dir / name
        path.write_text(
            content if isinstance(content, str) else json.dumps(content), encoding="utf-8"
        )
        return str(path)

    def missing(self, name):
        return str(self.dir / name)


class VerdictCase(unittest.TestCase):
    def setUp(self):
        self.files = Files(self)

    def verdict(self, preview_doc, plan_doc):
        return noop.evaluate(
            self.files.write("preview.json", preview_doc),
            self.files.write("plan.json", plan_doc),
        )

    def assertAsks(self, verdict, reason):
        self.assertTrue(verdict.has_changes, verdict)
        self.assertEqual(verdict.reason, reason)


class SameOnlyTests(VerdictCase):
    def test_a_same_only_plan_with_an_empty_output_diff_is_no_change(self):
        verdict = self.verdict(no_op_preview(), plan())
        self.assertFalse(verdict.has_changes)
        self.assertEqual(verdict, noop.NO_CHANGES)

    def test_a_same_only_plan_that_also_lists_same_resources_is_no_change(self):
        verdict = self.verdict(
            preview(("same", _ROOT), ("same", _SERVER)),
            plan(others={_SERVER: ["same"], _FIREWALL: ["same"]}),
        )
        self.assertFalse(verdict.has_changes)

    def test_an_output_diff_of_empty_collections_is_no_change(self):
        verdict = self.verdict(
            no_op_preview(), plan({"adds": {}, "updates": {}, "deletes": []})
        )
        self.assertFalse(verdict.has_changes)


class StepOpTests(VerdictCase):
    def test_every_changing_op_is_a_change(self):
        for op in (
            "create",
            "update",
            "delete",
            "replace",
            "create-replacement",
            "delete-replaced",
            "read",
            "refresh",
            "import",
        ):
            with self.subTest(op=op):
                verdict = self.verdict(
                    preview(("same", _ROOT), (op, _SERVER), summary={"same": 2, op: 1}),
                    plan(),
                )
                self.assertAsks(verdict, "steps-changed")
                self.assertEqual(verdict.count, 1)

    def test_an_unknown_op_is_a_change(self):
        verdict = self.verdict(preview(("same", _ROOT), ("frobnicate", _SERVER)), plan())
        self.assertAsks(verdict, "steps-changed")

    def test_the_root_stack_step_itself_changing_is_a_change(self):
        verdict = self.verdict(preview(("update", _ROOT)), plan())
        self.assertAsks(verdict, "steps-changed")

    def test_the_count_is_the_number_of_changing_steps(self):
        verdict = self.verdict(
            preview(("same", _ROOT), ("create", _SERVER), ("update", _FIREWALL)), plan()
        )
        self.assertEqual(verdict.count, 2)

    def test_a_non_same_op_in_the_plan_file_alone_is_a_change(self):
        verdict = self.verdict(
            no_op_preview(), plan(others={_SERVER: ["same", "update"]})
        )
        self.assertAsks(verdict, "steps-changed")


class OutputOnlyTests(VerdictCase):
    def test_an_added_output_is_a_change(self):
        verdict = self.verdict(no_op_preview(), plan({"adds": {"greeting": "hello"}}))
        self.assertAsks(verdict, "output-changed")
        self.assertEqual(verdict.count, 1)

    def test_an_updated_output_is_a_change(self):
        verdict = self.verdict(no_op_preview(), plan({"updates": {"a": "x", "b": "y"}}))
        self.assertAsks(verdict, "output-changed")
        self.assertEqual(verdict.count, 2)

    def test_a_deleted_output_is_a_change(self):
        verdict = self.verdict(no_op_preview(), plan({"deletes": ["gone"]}))
        self.assertAsks(verdict, "output-changed")

    def test_a_changed_secret_output_is_a_change(self):
        # The secret arrives as ciphertext; the diff itself was computed on the
        # decrypted values inside the CLI, so an entry here means it changed.
        verdict = self.verdict(no_op_preview(), plan({"updates": {"secret_one": SECRET}}))
        self.assertAsks(verdict, "output-changed")

    def test_an_output_unknown_at_preview_time_is_a_change(self):
        verdict = self.verdict(no_op_preview(), plan({"adds": {"id": UNKNOWN}}))
        self.assertAsks(verdict, "output-changed")

    def test_an_output_change_in_a_non_root_resource_is_not_read(self):
        # Only the root stack's output diff is the stack's outputs.
        doc = plan(others={_SERVER: ["same"]})
        doc["resourcePlans"][_SERVER]["goal"]["outputDiff"] = {"adds": {"k": "v"}}
        self.assertFalse(self.verdict(no_op_preview(), doc).has_changes)


class PlanFileShapeTests(VerdictCase):
    """A plan file this script does not understand reaches the gate."""

    def test_a_missing_plan_file(self):
        verdict = noop.evaluate(
            self.files.write("preview.json", no_op_preview()), self.files.missing("plan.json")
        )
        self.assertAsks(verdict, "plan-unreadable")

    def test_an_empty_plan_file(self):
        verdict = self.verdict(no_op_preview(), "")
        self.assertAsks(verdict, "plan-unreadable")

    def test_an_invalid_json_plan_file(self):
        verdict = self.verdict(no_op_preview(), "{not json")
        self.assertAsks(verdict, "plan-unreadable")

    def test_a_non_utf8_plan_file(self):
        path = self.files.dir / "plan.json"
        path.write_bytes(b"\xff\xfe\x00")
        verdict = noop.evaluate(self.files.write("preview.json", no_op_preview()), str(path))
        self.assertAsks(verdict, "plan-unreadable")

    def test_a_plan_file_that_is_not_an_object(self):
        for content in ([], "null", '"text"', "3"):
            with self.subTest(content=content):
                self.assertAsks(self.verdict(no_op_preview(), content), "plan-shape")

    def test_no_resource_plans_key(self):
        self.assertAsks(self.verdict(no_op_preview(), {"manifest": {}}), "plan-shape")

    def test_empty_resource_plans(self):
        self.assertAsks(self.verdict(no_op_preview(), {"resourcePlans": {}}), "plan-shape")

    def test_resource_plans_that_is_a_list(self):
        self.assertAsks(self.verdict(no_op_preview(), {"resourcePlans": []}), "plan-shape")

    def test_no_root_stack_entry(self):
        doc = plan(root=_SERVER)
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_two_root_stack_entries(self):
        doc = plan()
        doc["resourcePlans"][_ROOT.replace("mail", "other")] = {"goal": {"outputDiff": {}}}
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_a_non_urn_key(self):
        doc = plan()
        doc["resourcePlans"]["not-a-urn"] = {"goal": {"outputDiff": {}}}
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_an_entry_that_is_not_an_object(self):
        doc = plan()
        doc["resourcePlans"][_SERVER] = "nope"
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_root_entry_with_no_goal(self):
        doc = plan()
        del doc["resourcePlans"][_ROOT]["goal"]
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_goal_with_no_output_diff_key(self):
        doc = plan(goal={"type": "pulumi:pulumi:Stack"})
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_output_diff_that_is_not_an_object(self):
        for value in (None, [], "x", 0):
            with self.subTest(value=value):
                doc = plan(goal={"outputDiff": value})
                self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_output_diff_with_an_unrecognised_key(self):
        doc = plan({"renames": {"a": "b"}})
        self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")

    def test_output_diff_collections_of_the_wrong_type(self):
        for diff in ({"adds": []}, {"updates": "x"}, {"deletes": {}}, {"adds": 3}):
            with self.subTest(diff=diff):
                self.assertAsks(self.verdict(no_op_preview(), plan(diff)), "plan-shape")

    def test_plan_steps_that_are_not_a_list_of_strings(self):
        for steps in ("same", [1], {"a": "same"}):
            with self.subTest(steps=steps):
                doc = plan()
                doc["resourcePlans"][_ROOT]["steps"] = steps
                self.assertAsks(self.verdict(no_op_preview(), doc), "plan-shape")


class PreviewShapeTests(VerdictCase):
    """A preview JSON this script does not understand reaches the gate."""

    def test_a_missing_preview_file(self):
        verdict = noop.evaluate(
            self.files.missing("preview.json"), self.files.write("plan.json", plan())
        )
        self.assertAsks(verdict, "preview-unreadable")

    def test_an_empty_preview_file(self):
        self.assertAsks(self.verdict("", plan()), "preview-unreadable")

    def test_an_unparseable_preview_file(self):
        self.assertAsks(self.verdict("{not json", plan()), "preview-unreadable")
        self.assertAsks(self.verdict('{"steps": [', plan()), "preview-unreadable")

    def test_a_non_utf8_preview_file(self):
        path = self.files.dir / "preview.json"
        path.write_bytes(b"\xff\xfe\x00")
        verdict = noop.evaluate(str(path), self.files.write("plan.json", plan()))
        self.assertAsks(verdict, "preview-unreadable")

    def test_a_preview_that_is_not_an_object(self):
        for content in ([], "null", "3"):
            with self.subTest(content=content):
                self.assertAsks(self.verdict(content, plan()), "preview-shape")

    def test_no_steps_key(self):
        self.assertAsks(self.verdict({"changeSummary": {"same": 1}}, plan()), "preview-shape")

    def test_steps_that_is_not_a_list(self):
        self.assertAsks(self.verdict({"steps": "nope"}, plan()), "preview-shape")

    def test_an_empty_steps_list(self):
        self.assertAsks(self.verdict(preview(), plan()), "preview-shape")

    def test_a_step_missing_its_op_or_urn(self):
        for step in ({"urn": _ROOT}, {"op": "same"}, {"op": 1, "urn": _ROOT}, "same"):
            with self.subTest(step=step):
                doc = no_op_preview()
                doc["steps"] = [step]
                self.assertAsks(self.verdict(doc, plan()), "preview-shape")

    def test_a_step_whose_urn_is_not_a_urn(self):
        doc = no_op_preview()
        doc["steps"][0]["urn"] = "urn:pulumi:x"
        self.assertAsks(self.verdict(doc, plan()), "preview-shape")

    def test_no_root_stack_step(self):
        self.assertAsks(self.verdict(preview(("same", _SERVER)), plan()), "no-root-stack")

    def test_two_root_stack_steps(self):
        doc = preview(("same", _ROOT), ("same", _ROOT.replace("mail", "other")))
        self.assertAsks(self.verdict(doc, plan()), "no-root-stack")

    def test_no_change_summary(self):
        doc = no_op_preview()
        del doc["changeSummary"]
        self.assertAsks(self.verdict(doc, plan()), "preview-shape")

    def test_a_change_summary_that_counts_a_change_over_same_steps(self):
        doc = preview(("same", _ROOT), summary={"same": 2, "update": 1})
        verdict = self.verdict(doc, plan())
        self.assertAsks(verdict, "summary-changed")
        self.assertEqual(verdict.count, 1)

    def test_a_change_summary_with_a_bad_count(self):
        for summary in ({"same": "3"}, {"same": True}, {"same": -1}, {"same": None}, []):
            with self.subTest(summary=summary):
                doc = no_op_preview()
                doc["changeSummary"] = summary
                self.assertAsks(self.verdict(doc, plan()), "preview-shape")

    def test_a_maybe_corrupt_preview(self):
        doc = preview(("same", _ROOT), maybeCorrupt=True)
        self.assertAsks(self.verdict(doc, plan()), "preview-shape")

    def test_a_change_summary_of_zero_counts_other_than_same_is_fine(self):
        doc = preview(("same", _ROOT), summary={"same": 3, "create": 0})
        self.assertFalse(self.verdict(doc, plan()).has_changes)


class FailClosedTests(VerdictCase):
    def test_an_unexpected_error_is_a_change(self):
        original = noop._preview_verdict

        def boom(path):
            raise RuntimeError("unexpected")

        noop._preview_verdict = boom
        try:
            verdict = self.verdict(no_op_preview(), plan())
        finally:
            noop._preview_verdict = original
        self.assertAsks(verdict, "internal-error")

    def test_a_deeply_nested_file_is_a_change_not_a_crash(self):
        verdict = self.verdict("[" * 100000, plan())
        self.assertTrue(verdict.has_changes)


class HeadlineTests(unittest.TestCase):
    def test_no_changes_headline(self):
        self.assertEqual(
            noop.headline(noop.NO_CHANGES),
            "No changes: the apply job is skipped and no approval is requested",
        )

    def test_counted_headlines(self):
        for reason in ("steps-changed", "summary-changed", "output-changed"):
            with self.subTest(reason=reason):
                self.assertEqual(
                    noop.headline(noop.Verdict(True, 3, reason)), "3 changes: approval required"
                )
                self.assertEqual(
                    noop.headline(noop.Verdict(True, 1, reason)), "1 change: approval required"
                )

    def test_a_plan_not_understood_says_so(self):
        for reason in ("plan-unreadable", "preview-shape", "internal-error", "no-root-stack"):
            with self.subTest(reason=reason):
                self.assertEqual(
                    noop.headline(noop.Verdict(True, 0, reason)),
                    "Plan not understood, treated as changes: approval required",
                )


class MainTests(unittest.TestCase):
    def setUp(self):
        self.files = Files(self)

    def run_main(self, preview_doc, plan_doc, outputs=True):
        argv = [
            "plan-has-changes.py",
            self.files.write("preview.json", preview_doc),
            self.files.write("plan.json", plan_doc),
        ]
        out = self.files.dir / "output"
        summary = self.files.dir / "summary"
        if outputs:
            argv += ["--github-output", str(out), "--github-summary", str(summary)]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = noop.main(argv)
        read = lambda p: p.read_text(encoding="utf-8") if p.exists() else ""  # noqa: E731
        return code, buffer.getvalue(), read(out), read(summary)

    def test_a_no_op_writes_false_and_the_no_change_headline_first(self):
        code, stdout, out, summary = self.run_main(no_op_preview(), plan())
        self.assertEqual(code, 0)
        self.assertEqual(out, "has_changes=false\n")
        self.assertEqual(
            summary.splitlines()[0],
            "No changes: the apply job is skipped and no approval is requested",
        )
        self.assertIn("has_changes=false", stdout)

    def test_a_change_writes_true_and_the_count_headline_first(self):
        code, _, out, summary = self.run_main(
            preview(("same", _ROOT), ("create", _SERVER), summary={"same": 1, "create": 1}),
            plan(),
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, "has_changes=true\n")
        self.assertEqual(summary.splitlines()[0], "1 change: approval required")

    def test_an_output_only_change_writes_true(self):
        _, _, out, summary = self.run_main(no_op_preview(), plan({"adds": {"a": 1, "b": 2}}))
        self.assertEqual(out, "has_changes=true\n")
        self.assertEqual(summary.splitlines()[0], "2 changes: approval required")

    def test_an_unreadable_plan_still_exits_zero_with_true(self):
        code, _, out, summary = self.run_main(no_op_preview(), "{not json")
        self.assertEqual(code, 0)
        self.assertEqual(out, "has_changes=true\n")
        self.assertEqual(
            summary.splitlines()[0],
            "Plan not understood, treated as changes: approval required",
        )

    def test_stdout_carries_no_plan_values(self):
        for plan_doc in (
            plan(),
            plan({"adds": {"k": MARKER, "secret_one": SECRET}}),
            "{not json " + MARKER,
        ):
            with self.subTest(plan=str(plan_doc)[:20]):
                _, stdout, out, summary = self.run_main(no_op_preview(), plan_doc)
                for text in (stdout, out, summary):
                    self.assertNotIn(MARKER, text)
                    self.assertNotIn("CIPHERTEXT_PLACEHOLDER", text)

    def test_an_unwritable_output_file_exits_one(self):
        argv = [
            "plan-has-changes.py",
            self.files.write("preview.json", no_op_preview()),
            self.files.write("plan.json", plan()),
            "--github-output",
            str(self.files.dir / "no-such-dir" / "output"),
        ]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(noop.main(argv), 1)

    def test_a_usage_error_exits_two(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                noop.main(["plan-has-changes.py"])
        self.assertEqual(raised.exception.code, 2)

    def test_the_output_files_are_appended_to_not_replaced(self):
        out = self.files.dir / "output"
        out.write_text("earlier=1\n", encoding="utf-8")
        argv = [
            "plan-has-changes.py",
            self.files.write("preview.json", no_op_preview()),
            self.files.write("plan.json", plan()),
            "--github-output",
            str(out),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            noop.main(argv)
        self.assertEqual(out.read_text(encoding="utf-8"), "earlier=1\nhas_changes=false\n")


if __name__ == "__main__":
    unittest.main()
