"""Unit tests for the pass program: which approvals it runs, and which it never runs again.

Each control that a test names was run red on a sabotaged copy and green on the file as shipped
(the pull request records both). The program is imported as a module, and the executor is a
recording stand-in handed in as the runner, so nothing is started.
"""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

import provisioning_controller_pass as program


def line(approval: str, event: str) -> str:
    """Return one state record as the executor writes it."""
    return json.dumps({"at": "2026-01-01T00:00:00Z", "approvalId": approval, "event": event}) + "\n"


class Case(unittest.TestCase):
    """A directory with a ledger and a state file, and a runner that records its calls."""

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        self.approvals = self.root / "approvals.json"
        self.state = self.root / "run-state.jsonl"
        self.settings = program.Settings(
            "/exec", "/config.json", str(self.approvals), str(self.state)
        )
        self.calls: list[list[str]] = []
        self.codes: dict[str, int] = {}

    def ledger(self, *ids: str, mode: int = 0o600) -> None:
        """Write a ledger holding these approvals."""
        body = {"approvals": [{"approvalId": i} for i in ids]}
        self.approvals.write_text(json.dumps(body), encoding="utf-8")
        self.approvals.chmod(mode)

    def history(self, text: str, mode: int = 0o600) -> None:
        """Write the state file."""
        self.state.write_text(text, encoding="utf-8")
        self.state.chmod(mode)

    def runner(self, argv: Sequence[str], env: dict[str, str]) -> int:
        """Record the call and answer with the code set for its approval, 0 by default."""
        self.assertEqual(env, {"PATH": program.FIXED_PATH})
        self.calls.append(list(argv))
        return self.codes.get(argv[-1], 0)

    def run_pass(self) -> int:
        """Run one pass with the recording runner."""
        return program.run_pass(self.settings, self.runner)


class PendingTests(Case):
    """Which approvals a pass runs."""

    def test_no_ledger_is_a_clean_pass_that_runs_nothing(self) -> None:
        self.assertEqual(self.run_pass(), program.EXIT_OK)
        self.assertEqual(self.calls, [])

    def test_an_empty_ledger_is_a_clean_pass_that_runs_nothing(self) -> None:
        self.ledger()
        self.assertEqual(self.run_pass(), program.EXIT_OK)
        self.assertEqual(self.calls, [])

    def test_a_recorded_approval_is_run_with_its_id_and_nothing_typed(self) -> None:
        self.ledger("appr-1")
        self.assertEqual(self.run_pass(), program.EXIT_OK)
        self.assertEqual(
            self.calls, [["/exec", "--config", "/config.json", "--approval-id", "appr-1"]]
        )

    def test_a_complete_approval_is_never_run_again(self) -> None:
        """The guard: a run-complete record takes an approval out of the pass."""
        self.ledger("appr-1", "appr-2")
        self.history(line("appr-1", "run-complete"))
        self.assertEqual(self.run_pass(), program.EXIT_OK)
        self.assertEqual([c[-1] for c in self.calls], ["appr-2"])

    def test_an_approval_that_only_started_or_halted_is_run_again(self) -> None:
        self.ledger("appr-1", "appr-2")
        self.history(line("appr-1", "run-halted") + line("appr-2", "step-started"))
        self.run_pass()
        self.assertEqual([c[-1] for c in self.calls], ["appr-1", "appr-2"])

    def test_a_torn_last_line_is_ignored_as_the_executor_ignores_it(self) -> None:
        self.ledger("appr-1")
        self.history(line("appr-1", "run-complete")[:-1])
        self.run_pass()
        self.assertEqual([c[-1] for c in self.calls], ["appr-1"])

    def test_a_stopped_run_ends_the_pass_with_a_failure_and_the_others_still_run(self) -> None:
        self.ledger("appr-1", "appr-2")
        self.codes["appr-1"] = 1
        self.assertEqual(self.run_pass(), program.EXIT_STOPPED)
        self.assertEqual([c[-1] for c in self.calls], ["appr-1", "appr-2"])

    def test_a_program_that_cannot_be_started_is_its_own_status(self) -> None:
        self.ledger("appr-1")

        def missing(argv: Sequence[str], env: dict[str, str]) -> int:
            raise FileNotFoundError(argv[0])

        self.assertEqual(program.run_pass(self.settings, missing), program.EXIT_NOT_STARTED)

    def test_a_run_that_times_out_is_a_stopped_run(self) -> None:
        self.ledger("appr-1")

        def slow(argv: Sequence[str], env: dict[str, str]) -> int:
            raise subprocess.TimeoutExpired(list(argv), 1)

        self.assertEqual(program.run_pass(self.settings, slow), program.EXIT_STOPPED)


class RefusalTests(Case):
    """Files the pass will not act on."""

    def refused(self) -> None:
        """Run a pass and require it to refuse and to run nothing."""
        self.assertEqual(self.run_pass(), program.EXIT_REFUSED)
        self.assertEqual(self.calls, [])

    def test_a_ledger_others_can_write(self) -> None:
        self.ledger("appr-1", mode=0o666)
        self.refused()

    def test_a_ledger_that_is_a_link(self) -> None:
        real = self.root / "real.json"
        real.write_text('{"approvals": []}', encoding="utf-8")
        self.approvals.symlink_to(real)
        self.refused()

    def test_a_ledger_that_is_not_json_or_has_no_list(self) -> None:
        for text in ("not json", "[]", '{"approvals": 3}', '{"approvals": [3]}'):
            with self.subTest(text):
                self.approvals.write_text(text, encoding="utf-8")
                self.approvals.chmod(0o600)
                self.refused()

    def test_an_approval_id_the_executor_would_refuse(self) -> None:
        for bad in ("", "-x", "a b", "a/b", "x" * 129, "line\nbreak"):
            with self.subTest(bad):
                self.ledger(bad)
                self.refused()

    def test_an_id_twice(self) -> None:
        self.ledger("appr-1", "appr-1")
        self.refused()

    def test_a_state_file_other_users_can_read(self) -> None:
        self.ledger("appr-1")
        self.history(line("appr-1", "run-complete"), mode=0o644)
        self.refused()

    def test_a_damaged_state_file_stops_every_run(self) -> None:
        self.ledger("appr-1")
        self.history("not json\n")
        self.refused()

    def test_a_fifo_in_the_ledger_place_does_not_hang_the_pass(self) -> None:
        os.mkfifo(self.approvals)
        self.assertTrue(stat.S_ISFIFO(self.approvals.stat().st_mode))
        self.refused()

    def test_a_ledger_that_is_too_big(self) -> None:
        self.approvals.write_text(" " * (program.MAX_FILE_BYTES + 1), encoding="utf-8")
        self.approvals.chmod(0o600)
        self.refused()

    def test_the_refusal_names_a_code_and_a_path_and_no_content(self) -> None:
        self.approvals.write_text(
            '{"approvals": [{"approvalId": "PLANTED-TEXT"}]', encoding="utf-8"
        )
        self.approvals.chmod(0o600)
        with self.assertRaises(program.RefusalError) as caught:
            program.pending(self.settings)
        self.assertNotIn("PLANTED-TEXT", str(caught.exception))
        self.assertEqual(str(caught.exception), f"E-LEDGER-FORM: {self.approvals}")


class CommandLineTests(Case):
    """The four paths are required and absolute."""

    def test_a_relative_path_is_refused_before_anything_is_read(self) -> None:
        argv = ["--program", "exec", "--config", "/c", "--approvals", "/a", "--state", "/s"]
        self.assertEqual(program.main(argv), program.EXIT_REFUSED)

    def test_a_missing_option_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit):
            program.main(["--program", "/exec"])


if __name__ == "__main__":
    unittest.main()
