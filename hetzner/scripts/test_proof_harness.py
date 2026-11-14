#!/usr/bin/env python3
"""Unit tests for the shared harness of the Docker proofs.

The harness decides what a proof reports: which checks pass, which fail, how
the summary reads and what exit code comes out. Those are driven here with
fake checks. The stand-in's command line and the counters that read iptables
output are checked too. No docker, no network.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from lib import proof_harness
from lib.proof_harness import (
    ProofAbort,
    StandIn,
    Tally,
    count_lines_containing,
    keep_containers,
    packet_count,
    wait_until,
)


def captured(action) -> str:  # type: ignore[no-untyped-def]
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        action()
    return buffer.getvalue()


class Expectations(unittest.TestCase):
    def test_expect_reach_passes_when_the_check_holds(self) -> None:
        tally = Tally()
        text = captured(lambda: tally.expect_reach("reaches", lambda: True))
        self.assertEqual(text, "PASS: reaches\n")
        self.assertEqual((tally.passes, tally.failures), (1, 0))

    def test_expect_reach_fails_when_the_check_does_not_hold(self) -> None:
        tally = Tally()
        text = captured(lambda: tally.expect_reach("reaches", lambda: False))
        self.assertEqual(text, "FAIL: reaches\n")
        self.assertEqual((tally.passes, tally.failures), (0, 1))

    def test_expect_blocked_is_the_inverse(self) -> None:
        tally = Tally()
        captured(lambda: tally.expect_blocked("refused", lambda: False))
        captured(lambda: tally.expect_blocked("not refused", lambda: True))
        self.assertEqual((tally.passes, tally.failures), (1, 1))

    def test_the_summary_reads_the_counts_and_exits_zero_only_without_failures(
        self,
    ) -> None:
        clean = Tally()
        captured(lambda: clean.passed("one"))
        text = captured(lambda: self.assertEqual(clean.summary(), 0))
        self.assertTrue(text.endswith("\n1 passed, 0 failed\n"))

        dirty = Tally()
        captured(lambda: dirty.passed("one"))
        captured(lambda: dirty.failed("two"))
        text = captured(lambda: self.assertEqual(dirty.summary(), 1))
        self.assertTrue(text.endswith("\n1 passed, 1 failed\n"))

    def test_a_heading_prints_the_double_equals_form(self) -> None:
        text = captured(lambda: Tally().heading("the policy"))
        self.assertEqual(text, "== the policy\n")


class WaitUntil(unittest.TestCase):
    def test_returns_as_soon_as_ready_holds(self) -> None:
        answers = iter([False, False, True])
        pauses: list[float] = []
        with mock.patch.object(proof_harness.time, "sleep", side_effect=pauses.append):
            wait_until(lambda: next(answers), limit=10, message="never")
        self.assertEqual(len(pauses), 2)

    def test_aborts_with_the_message_on_the_limit_th_failure(self) -> None:
        pauses: list[float] = []
        with (
            mock.patch.object(proof_harness.time, "sleep", side_effect=pauses.append),
            self.assertRaises(ProofAbort) as raised,
        ):
            wait_until(lambda: False, limit=5, message="never came up")
        self.assertEqual(str(raised.exception), "never came up")
        self.assertEqual(len(pauses), 4)


class Counters(unittest.TestCase):
    def test_grep_c_counts_lines_not_occurrences(self) -> None:
        text = "-A DOCKER-USER ctorigdstport 8300\n-A DOCKER-USER ctorigdstport 8301\nother line\n"
        self.assertEqual(count_lines_containing(text, "ctorigdstport"), 2)
        self.assertEqual(count_lines_containing("", "ctorigdstport"), 0)

    def test_a_packet_count_is_one_whole_number(self) -> None:
        self.assertEqual(packet_count("1\n"), 1)
        self.assertEqual(packet_count("  42 "), 42)

    def test_anything_else_is_not_a_packet_count(self) -> None:
        self.assertIsNone(packet_count(""))
        self.assertIsNone(packet_count("Chain DOCKER-USER\npkts\n3"))
        self.assertIsNone(packet_count("-3"))


class StandInCommands(unittest.TestCase):
    def test_a_command_runs_in_the_container_through_sh(self) -> None:
        host = StandIn("proof-host")
        self.assertEqual(
            host._argv("docker info"),
            ["docker", "exec", "proof-host", "sh", "-c", "docker info"],
        )

    def test_once_dockerd_path_is_known_the_command_carries_it(self) -> None:
        host = StandIn("proof-host")
        host.dockerd_path = "/usr/local/sbin:/usr/bin"
        self.assertEqual(
            host._argv("iptables-save"),
            [
                "docker",
                "exec",
                "-e",
                "PATH=/usr/local/sbin:/usr/bin",
                "proof-host",
                "sh",
                "-c",
                "iptables-save",
            ],
        )


class KeepContainers(unittest.TestCase):
    def test_an_empty_variable_does_not_keep_them(self) -> None:
        with mock.patch.dict("os.environ", {"KEEP_PROOF_CONTAINERS": ""}):
            self.assertFalse(keep_containers())

    def test_any_value_keeps_them(self) -> None:
        with mock.patch.dict("os.environ", {"KEEP_PROOF_CONTAINERS": "1"}):
            self.assertTrue(keep_containers())


if __name__ == "__main__":
    unittest.main()
