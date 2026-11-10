"""The list of blocking container tests, the split it drives, and what the gate does with it.

Each test's name states the rule it holds; the reasons are in ansible/checks/README.md.
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
# one of these paths (a new scenario included) must be on the list. `edge_firewall` is named
# here before its role is merged; the day its directory exists, its shards must be listed.
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
# The lock-out paths that have no directory in this tree yet, and may be absent.
NOT_MERGED_YET = ("ansible/roles/edge_firewall",)

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

    def test_the_lockout_roles_that_exist_here_are_most_of_the_eight(self) -> None:
        # A control: an emptied LOCKOUT_PATHS, or a tree read that found nothing, would pass
        # the test above.
        present = {shard["path"] for shard in self.shards} & set(LOCKOUT_PATHS)
        self.assertEqual(7, len(present))
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
