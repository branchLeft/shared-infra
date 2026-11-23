"""The list of blocking container tests, the split it drives, and what the gate does with it.

Each test's name states the rule it holds; the reasons are in ansible/checks/blocking_shards.md.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

import blocking_shards
from ci_select import NO_SHARD
from test_ci_gate_order import ANSIBLE_WORKFLOW, get, run_gate, script

ROOT = Path(__file__).resolve().parents[2]
LIST_SHARDS = ROOT / "ansible" / "harness" / "list_shards.py"

# The lock-out roles: the ones whose break can cut the operator or the pipeline off a host.
# Their shards are blocking and stay blocking. Taking one off the list is a decision for the
# owner, so it needs an owner-approved edit to THIS test as well as to the list. A shard of
# one of these paths (a new scenario included) must be on the list.
LOCKOUT_PATHS = (
    "ansible/roles/pull_trigger",
    "ansible/roles/ci_jump",
    "ansible/roles/breakglass_mint_host",
    "ansible/roles/host_baseline",
    "ansible/roles/tunnel_account",
    "ansible/roles/edge_firewall",
    "ansible/roles/egress_nat",
    "ansible/roles/deploy_tooling",
)
# The lock-out paths that have no directory in this tree yet, and may be absent. None now: every
# lock-out role is merged, so a path that goes missing is a failure.
NOT_MERGED_YET: tuple[str, ...] = ()

FULL_RUN_EVENTS = ("schedule", "workflow_dispatch")
EVENTS = ("pull_request", "merge_group", *FULL_RUN_EVENTS)
RESULTS = ("success", "failure", "cancelled", "skipped")
ONE_SHARD = {
    "name": "ansible/roles/example",
    "path": "ansible/roles/example",
    "scenario": "default",
    "kind": "role",
}


def real_shards() -> list[dict[str, str]]:
    """Return the shards of the real tree, listed by the program the workflow runs.

    Raises:
        AssertionError: list_shards.py cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location("list_shards_for_blocking", LIST_SHARDS)
    if spec is None or spec.loader is None:
        message = "list_shards.py cannot be loaded"
        raise AssertionError(message)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    listed: list[dict[str, str]] = module.shards(ROOT)
    return listed


def expected_to_pass(event: str, listed: bool, result: str) -> bool:
    """Say whether the required check passes, written out by rule and not by the code's route.

    A full run (scheduled or manual) needs every shard to succeed. On a pull request or in the
    queue an unlisted shard never decides. A listed shard must succeed, except that the queue
    does not run the shards and so accepts a skip.
    """
    if event in FULL_RUN_EVENTS:
        return result == "success"
    if not listed:
        return True
    if event == "merge_group":
        return result in ("success", "skipped")
    return result == "success"


def gate_exit(event: str, listed: bool, result: str) -> int:
    """Return the exit status of the workflow's own gate script for one shard in one situation.

    The split decides which shard job the shard is in. The gate sees only the blocking job:
    the shard's result when it is in that job, and nothing from an advisory job.
    """
    blocking, _ = blocking_shards.partition(
        event, [ONE_SHARD], frozenset({ONE_SHARD["name"]} if listed else ())
    )
    gate_script = str(get(ANSIBLE_WORKFLOW, "jobs", "roles", "steps", 0, "run"))
    return run_gate(
        gate_script,
        {
            "EVENT": event,
            "BLOCKING": "true" if blocking else "false",
            "BLOCKING_RESULT": result if blocking else "skipped",
        },
    )


class TheListTest(unittest.TestCase):
    listed = blocking_shards.read_list()
    shards = real_shards()
    names = [shard["name"] for shard in shards]

    def test_the_list_names_only_shards_that_exist_once_each_in_order(self) -> None:
        self.assertEqual([], blocking_shards.problems(self.listed, self.names))

    def test_the_list_file_has_the_one_key_and_nothing_else(self) -> None:
        document = json.loads(blocking_shards.LIST_FILE.read_text(encoding="utf-8"))
        self.assertEqual({"blocking"}, set(document))

    def test_every_shard_of_a_lockout_role_is_on_the_list(self) -> None:
        # Removing one is a decision for the owner: it needs an owner-approved edit to
        # LOCKOUT_PATHS in this test as well as to the list.
        for path in LOCKOUT_PATHS:
            shards = [shard["name"] for shard in self.shards if shard["path"] == path]
            with self.subTest(role=path):
                if not shards:
                    self.assertIn(path, NOT_MERGED_YET, f"{path} has no shard in this tree")
                for name in shards:
                    self.assertIn(
                        name,
                        self.listed,
                        f"{name} is a lock-out role shard and stays blocking: taking it off "
                        "needs an owner-approved edit to LOCKOUT_PATHS in this test as well "
                        "as to the list",
                    )

    def test_every_one_of_the_eight_lockout_roles_exists_here(self) -> None:
        # A control: an emptied LOCKOUT_PATHS, or a tree read that found nothing, would pass
        # the test above.
        present = {shard["path"] for shard in self.shards} & set(LOCKOUT_PATHS)
        self.assertEqual(8, len(present))
        self.assertEqual(8, len(LOCKOUT_PATHS))

    def test_the_list_is_not_the_whole_tree(self) -> None:
        # A list naming every shard would make advisory mean nothing.
        self.assertLess(len(self.listed), len(self.names) // 2)


class ProblemsTest(unittest.TestCase):
    KNOWN = ("a", "b", "c")

    def test_an_unknown_id_is_found(self) -> None:
        self.assertEqual(["unknown shard id: 'z'"], blocking_shards.problems(["z"], self.KNOWN))

    def test_a_duplicate_is_found(self) -> None:
        self.assertIn("duplicate shard id: 'a'", blocking_shards.problems(["a", "a"], self.KNOWN))

    def test_an_unsorted_list_is_found(self) -> None:
        self.assertEqual(
            ["the list is not sorted (plain string order)"],
            blocking_shards.problems(["b", "a"], self.KNOWN),
        )

    def test_a_clean_list_has_no_problem(self) -> None:
        self.assertEqual([], blocking_shards.problems(["a", "c"], self.KNOWN))


class ReadListTest(unittest.TestCase):
    def read(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "list.json"
            path.write_text(text, encoding="utf-8")
            return blocking_shards.read_list(path)

    def refused(self, text: str) -> None:
        with self.assertRaises(blocking_shards.ListError):
            self.read(text)

    def test_an_unknown_key_is_refused(self) -> None:
        self.refused('{"blocking": [], "advisory": []}')

    def test_a_missing_key_is_refused(self) -> None:
        self.refused("{}")

    def test_a_list_of_something_else_is_refused(self) -> None:
        self.refused('{"blocking": [1]}')
        self.refused('{"blocking": "a"}')

    def test_something_that_is_not_json_is_refused(self) -> None:
        self.refused("blocking: [a]")

    def test_a_good_file_is_read_in_order(self) -> None:
        self.assertEqual(["a", "b"], self.read('{"blocking": ["a", "b"]}'))


class SplitTest(unittest.TestCase):
    SELECTED = [
        {"name": "x", "path": "p/x", "scenario": "default", "kind": "role"},
        {"name": "y", "path": "p/y", "scenario": "default", "kind": "role"},
    ]

    def names(self, shards: Sequence[Mapping[str, str]]) -> list[str]:
        return [shard["name"] for shard in shards]

    def test_a_pull_request_splits_by_the_list(self) -> None:
        blocking, advisory = blocking_shards.partition(
            "pull_request", self.SELECTED, frozenset({"x"})
        )
        self.assertEqual(["x"], self.names(blocking))
        self.assertEqual(["y"], self.names(advisory))

    def test_a_full_run_makes_every_shard_blocking(self) -> None:
        for event in (*FULL_RUN_EVENTS, "", "something_new"):
            with self.subTest(event=event):
                blocking, advisory = blocking_shards.partition(event, self.SELECTED, frozenset())
                self.assertEqual(["x", "y"], self.names(blocking))
                self.assertEqual([], advisory)

    def test_an_empty_side_is_one_entry_that_stands_for_no_shard(self) -> None:
        lines = blocking_shards.matrix_lines("advisory", [])
        self.assertEqual("advisory=false", lines[0])
        self.assertEqual({"include": [NO_SHARD]}, json.loads(lines[1].split("=", 1)[1]))

    def test_the_selection_is_read_without_the_no_shard_entry(self) -> None:
        none = "shards=false\nmatrix=" + json.dumps({"include": [NO_SHARD]})
        self.assertEqual([], blocking_shards.selected_from(none))
        some = "shards=true\nmatrix=" + json.dumps({"include": self.SELECTED})
        self.assertEqual(["x", "y"], self.names(blocking_shards.selected_from(some)))

    def test_a_selection_with_no_matrix_is_refused(self) -> None:
        with self.assertRaises(blocking_shards.ListError):
            blocking_shards.selected_from("shards=true\n")

    def run_split(self, listed: list[str], event: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "list.json").write_text(json.dumps({"blocking": listed}), encoding="utf-8")
            (base / "all.json").write_text(json.dumps({"include": self.SELECTED}), encoding="utf-8")
            (base / "sel.txt").write_text(
                "shards=true\nmatrix=" + json.dumps({"include": self.SELECTED}), encoding="utf-8"
            )
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = blocking_shards.main(
                    [
                        "split",
                        "--event",
                        event,
                        "--all-file",
                        str(base / "all.json"),
                        "--selection-file",
                        str(base / "sel.txt"),
                        "--list-file",
                        str(base / "list.json"),
                    ]
                )
            return code, out.getvalue()

    def test_the_command_prints_the_four_outputs(self) -> None:
        code, out = self.run_split(["x"], "pull_request")
        self.assertEqual(0, code)
        keys = [line.split("=", 1)[0] for line in out.splitlines()]
        self.assertEqual(["blocking", "blocking_matrix", "advisory", "advisory_matrix"], keys)
        self.assertIn("blocking=true", out)
        self.assertIn("advisory=true", out)

    def test_the_command_refuses_a_list_that_names_an_unknown_shard(self) -> None:
        code, out = self.run_split(["x", "zzz"], "pull_request")
        self.assertEqual(1, code)
        self.assertEqual("", out, "a refused list must print no output for the job to use")


class DeferralTest(unittest.TestCase):
    """On a pull request that changed a run-everything file, own-file shards run, the rest wait."""

    ADVISORY = [
        {"name": "x", "path": "p/x", "scenario": "default", "kind": "role"},
        {"name": "y", "path": "p/y", "scenario": "default", "kind": "role"},
        {"name": "z", "path": "p/z", "scenario": "default", "kind": "role"},
    ]

    def names(self, shards: Sequence[Mapping[str, str]]) -> list[str]:
        return [shard["name"] for shard in shards]

    def test_the_advisory_shards_the_pull_request_does_not_select_are_deferred(self) -> None:
        run, left = blocking_shards.defer_advisory("pull_request", self.ADVISORY, ["y"])
        self.assertEqual(["y"], self.names(run))
        self.assertEqual(["x", "z"], self.names(left))

    def test_no_direct_line_defers_nothing(self) -> None:
        run, left = blocking_shards.defer_advisory("pull_request", self.ADVISORY, None)
        self.assertEqual(["x", "y", "z"], self.names(run))
        self.assertEqual([], left)

    def test_an_empty_direct_list_defers_every_advisory_shard(self) -> None:
        run, left = blocking_shards.defer_advisory("pull_request", self.ADVISORY, [])
        self.assertEqual([], run)
        self.assertEqual(["x", "y", "z"], self.names(left))

    def test_no_other_event_defers_anything(self) -> None:
        for event in ("merge_group", *FULL_RUN_EVENTS, "", "something_new"):
            with self.subTest(event=event):
                run, left = blocking_shards.defer_advisory(event, self.ADVISORY, [])
                self.assertEqual(["x", "y", "z"], self.names(run))
                self.assertEqual([], left)

    def test_a_line_that_is_not_a_list_of_strings_reads_as_absent(self) -> None:
        for text in ("direct=", "direct=not json", 'direct={"a": 1}', "direct=[1]", "other=[]"):
            with self.subTest(text=text):
                self.assertIsNone(blocking_shards.listed_in(text, "direct"))
        self.assertEqual(["a"], blocking_shards.listed_in('x=1\ndirect=["a"]\n', "direct"))
        self.assertEqual([], blocking_shards.listed_in("direct=[]", "direct"))

    def test_the_note_says_which_shards_wait_why_and_for_what(self) -> None:
        note = blocking_shards.deferral_note(self.ADVISORY[:2], [".yamllint"])
        self.assertIn("2 advisory shard(s) left to the nightly run", note)
        self.assertIn("`.yamllint`", note)
        self.assertIn("cron 41 2 * * *", note)
        self.assertIn("- x\n- y\n", note)
        self.assertEqual("", blocking_shards.deferral_note([], [".yamllint"]))

    def test_a_long_list_is_cut_and_says_how_many_more(self) -> None:
        many = [{"name": f"s{n}", "path": "", "scenario": "", "kind": "role"} for n in range(50)]
        note = blocking_shards.deferral_note(many, [f"f{n}" for n in range(9)])
        self.assertIn("- and 10 more", note)
        self.assertNotIn("`f5`", note)

    def test_the_nightly_name_is_the_schedule_the_workflow_has(self) -> None:
        cron = str(get(ANSIBLE_WORKFLOW, "on", "schedule", 0, "cron"))
        self.assertEqual(blocking_shards.NIGHTLY, f"cron {cron}")


class DeferralCommandTest(unittest.TestCase):
    SELECTED = SplitTest.SELECTED + [
        {"name": "w", "path": "p/w", "scenario": "default", "kind": "role"},
    ]

    def run_split(
        self, event: str, extra: list[str], listed: list[str] | None = None
    ) -> tuple[int, str, str, str]:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "list.json").write_text(
                json.dumps({"blocking": listed if listed is not None else ["x"]}), encoding="utf-8"
            )
            (base / "all.json").write_text(json.dumps({"include": self.SELECTED}), encoding="utf-8")
            lines = ["shards=true", "matrix=" + json.dumps({"include": self.SELECTED}), *extra]
            (base / "sel.txt").write_text("\n".join(lines), encoding="utf-8")
            summary = base / "summary.md"
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = blocking_shards.main(
                    [
                        "split",
                        "--event",
                        event,
                        "--all-file",
                        str(base / "all.json"),
                        "--selection-file",
                        str(base / "sel.txt"),
                        "--list-file",
                        str(base / "list.json"),
                        "--summary-file",
                        str(summary),
                    ]
                )
            written = summary.read_text(encoding="utf-8") if summary.exists() else ""
            return code, out.getvalue(), err.getvalue(), written

    def advisory_names(self, out: str) -> list[str]:
        line = next(line for line in out.splitlines() if line.startswith("advisory_matrix="))
        return [entry["name"] for entry in json.loads(line.split("=", 1)[1])["include"]]

    def test_a_run_everything_pull_request_runs_blocking_and_own_shards_only(self) -> None:
        extra = ['direct=["y"]', 'run_everything_files=[".yamllint"]']
        code, out, err, summary = self.run_split("pull_request", extra)
        self.assertEqual(0, code)
        self.assertEqual(["y"], self.advisory_names(out))
        self.assertIn("blocking=true", out)
        self.assertIn("1 blocking and 1 advisory shard(s)", err)
        for text in (err, summary):
            self.assertIn("1 advisory shard(s) left to the nightly run", text)
            self.assertIn("- w", text)
            self.assertIn("`.yamllint`", text)
        self.assertNotIn("- y", summary)

    def test_every_advisory_shard_deferred_leaves_the_advisory_job_with_nothing(self) -> None:
        extra = ["direct=[]", 'run_everything_files=["ansible/requirements.txt"]']
        _, out, _, _ = self.run_split("pull_request", extra)
        self.assertIn("advisory=false", out)

    def test_without_the_direct_line_every_advisory_shard_runs_and_nothing_is_written(self) -> None:
        _, out, err, summary = self.run_split("pull_request", [])
        self.assertEqual(["y", "w"], self.advisory_names(out))
        self.assertEqual("", summary)
        self.assertNotIn("nightly", err)

    def test_the_sweep_ignores_a_direct_line_and_runs_every_shard_blocking(self) -> None:
        _, out, _, summary = self.run_split("schedule", ["direct=[]"])
        self.assertIn("advisory=false", out)
        self.assertIn("blocking=true", out)
        self.assertEqual("", summary)

    def test_a_blocking_shard_is_never_deferred(self) -> None:
        _, out, _, _ = self.run_split("pull_request", ["direct=[]"], listed=["w", "x", "y"])
        blocking = next(line for line in out.splitlines() if line.startswith("blocking_matrix="))
        names = [e["name"] for e in json.loads(blocking.split("=", 1)[1])["include"]]
        self.assertEqual(["x", "y", "w"], names)

    def test_a_summary_file_that_cannot_be_written_does_not_fail_the_split(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / "list.json").write_text('{"blocking": ["x"]}', encoding="utf-8")
            (base / "all.json").write_text(json.dumps({"include": self.SELECTED}), encoding="utf-8")
            lines = ["matrix=" + json.dumps({"include": self.SELECTED}), "direct=[]"]
            (base / "sel.txt").write_text("\n".join(lines), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = blocking_shards.main(
                    [
                        "split",
                        "--event",
                        "pull_request",
                        "--all-file",
                        str(base / "all.json"),
                        "--selection-file",
                        str(base / "sel.txt"),
                        "--list-file",
                        str(base / "list.json"),
                        "--summary-file",
                        str(base / "no-such-folder" / "summary.md"),
                    ]
                )
        self.assertEqual(0, code)
        self.assertIn("the step summary cannot be written", err.getvalue())
        self.assertIn("advisory=false", out.getvalue())

    def test_the_workflow_passes_the_step_summary_to_the_split(self) -> None:
        step = str(get(ANSIBLE_WORKFLOW, "jobs", "discover", "steps", 3, "run"))
        self.assertIn('--summary-file "$GITHUB_STEP_SUMMARY"', step)


class TruthTableTest(unittest.TestCase):
    def test_the_required_check_follows_the_list_for_every_event_and_result(self) -> None:
        # event x listed/unlisted x the shard's result, through the split and the real gate.
        for event in EVENTS:
            for listed in (True, False):
                for result in RESULTS:
                    with self.subTest(event=event, listed=listed, result=result):
                        want = 0 if expected_to_pass(event, listed, result) else 1
                        self.assertEqual(want, gate_exit(event, listed, result))

    def test_the_table_has_a_row_that_fails_and_a_row_that_passes_for_each_listed_state(
        self,
    ) -> None:
        # A control: a gate that always passes, or always fails, would not be told apart above.
        outcomes = {
            (listed, gate_exit("pull_request", listed, result) == 0)
            for listed in (True, False)
            for result in RESULTS
        }
        self.assertEqual({(True, True), (True, False), (False, True)}, outcomes)

    def test_an_unlisted_failure_on_a_pull_request_passes_and_a_listed_one_fails(self) -> None:
        self.assertEqual(0, gate_exit("pull_request", False, "failure"))
        self.assertEqual(1, gate_exit("pull_request", True, "failure"))

    def test_an_unlisted_failure_in_a_full_run_fails(self) -> None:
        for event in FULL_RUN_EVENTS:
            self.assertEqual(1, gate_exit(event, False, "failure"), event)


class TheWorkflowSplitsByTheListTest(unittest.TestCase):
    def test_the_gate_reads_no_advisory_result(self) -> None:
        gate = get(ANSIBLE_WORKFLOW, "jobs", "roles")
        self.assertNotIn("advisory", script(gate).lower().replace("no blocking shard", ""))
        self.assertNotIn("shard-advisory", str(get(gate, "needs")))
        self.assertNotIn("advisory", str(get(gate, "steps", 0, "env")))


if __name__ == "__main__":
    unittest.main()
