"""The forced command's request parsing, readiness checks, lock and the argument list it builds.

The bundler, Docker and the real sshd are not run here: a stand-in takes the place of the program's
runner and records what it was given. The forced command as a real sshd serves it, with a stand-in
for Node, is the Molecule `entry` scenario's.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import export_entry as entry
from export_entry import Paths, RefusalError

RECIPIENT = "age1" + "q" * 58
REFERENCE = "grant/consent-2026-11-27#1"
GOOD = f"export-demo demo-3 {RECIPIENT} 2027-03-01 18123 {REFERENCE}"


class Recorder:
    """A stand-in for the runner: records every call and returns a chosen status."""

    def __init__(self, status: int = 0) -> None:
        self.status = status
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(self, argv: Sequence[str], environment: Mapping[str, str]) -> int:
        self.calls.append((list(argv), dict(environment)))
        return self.status


class Scratch(unittest.TestCase):
    """A scratch tree laid out as the role and the owner leave the host."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.paths = Paths(
            node=str(self.root / "node"),
            bundler_dir=str(self.root / "bundler"),
            state_dir=str(self.root / "state"),
            lock=str(self.root / "lock"),
            owner_uid=os.getuid(),
        )
        (self.root / "bundler" / "dist").mkdir(parents=True)
        (self.root / "state").mkdir()
        self.make(self.root / "node", 0o755)
        self.make(self.root / "bundler" / "dist" / "cli.js", 0o600)
        self.make(self.root / "state" / "demo-3.descriptor.json", 0o600)
        self.log: list[str] = []

    @staticmethod
    def make(path: Path, mode: int) -> None:
        path.write_text("x", encoding="utf-8")
        path.chmod(mode)

    def serve(self, original: str | None, runner: Recorder | None = None) -> int:
        environment: dict[str, str] = {} if original is None else {"SSH_ORIGINAL_COMMAND": original}
        return entry.serve(environment, self.paths, runner or Recorder(), self.log.append)

    def refusal(self, original: str | None) -> RefusalError:
        runner = Recorder()
        with self.assertRaises(RefusalError) as caught:
            self.serve(original, runner)
        self.assertEqual([], runner.calls, "a refused request must run nothing")
        return caught.exception


class ParseTests(unittest.TestCase):
    def test_the_one_shape_is_accepted(self) -> None:
        self.assertEqual(
            entry.Request("demo-3", RECIPIENT, "2027-03-01", 18123, REFERENCE),
            entry.parse_request(GOOD),
        )

    def test_every_slot_name_of_one_or_two_digits_is_accepted(self) -> None:
        for slot in ("demo-0", "demo-6", "demo-12"):
            with self.subTest(slot):
                self.assertEqual(slot, entry.parse_request(GOOD.replace("demo-3", slot)).slot)

    HOSTILE = (
        ("a shell", "/bin/sh"),
        ("no words", ""),
        ("another command", "id"),
        ("the program itself", "/usr/local/sbin/branchleft-export-entry"),
        ("sudo", "sudo -n /bin/true"),
        ("the word alone", "export-demo"),
        ("the word and a space", "export-demo "),
        ("upper case", GOOD.replace("export-demo", "EXPORT-DEMO")),
        ("a second command", GOOD + "; touch /tmp/MARKER"),
        ("a command substitution", GOOD + " $(touch /tmp/MARKER)"),
        ("a backtick", GOOD + " `touch /tmp/MARKER`"),
        ("a pipe", GOOD + " | cat"),
        ("a redirect", GOOD + " > /tmp/MARKER"),
        ("an and", GOOD + " && id"),
        ("a line break after", GOOD + "\ntouch /tmp/MARKER"),
        ("a trailing line break", GOOD + "\n"),
        ("a line break inside", GOOD.replace(" 18123 ", "\n18123 ")),
        ("an extra word", GOOD + " extra"),
        ("a flag in the reference", GOOD.replace(REFERENCE, "--audit-log")),
        ("a flag as a word", GOOD + " --audit-log /tmp/MARKER"),
        ("a reference with a space", GOOD.replace(REFERENCE, "a b")),
        ("a reference with a quote", GOOD.replace(REFERENCE, "a'b")),
        ("a reference starting with a hyphen", GOOD.replace(REFERENCE, "-x")),
        ("a reference with a backslash", GOOD.replace(REFERENCE, "a\\b")),
        ("a slot that is a path", GOOD.replace("demo-3", "demo-3/../x")),
        ("a slot with three digits", GOOD.replace("demo-3", "demo-123")),
        ("a slot that is a tenant", GOOD.replace("demo-3", "my-blog")),
        ("a slot in upper case", GOOD.replace("demo-3", "DEMO-3")),
        ("an Arabic-Indic digit in the slot", GOOD.replace("demo-3", "demo-٣")),
        ("a recipient that is a private identity", GOOD.replace(RECIPIENT, "AGE-SECRET-KEY-1QQQ")),
        ("a recipient with a bad character", GOOD.replace(RECIPIENT, "age1" + "q" * 57 + "b")),
        ("a recipient one short", GOOD.replace(RECIPIENT, "age1" + "q" * 57)),
        ("a recipient one long", GOOD.replace(RECIPIENT, "age1" + "q" * 59)),
        ("a recipient in upper case", GOOD.replace(RECIPIENT, "AGE1" + "Q" * 58)),
        ("a date in another form", GOOD.replace("2027-03-01", "01/03/2027")),
        ("a date with unicode digits", GOOD.replace("2027-03-01", "٢027-03-01")),
        ("a port with a leading zero", GOOD.replace("18123", "018123")),
        ("a port with letters", GOOD.replace("18123", "18a23")),
        ("a negative port", GOOD.replace("18123", "-1812")),
        ("two spaces", GOOD.replace("demo-3 ", "demo-3  ")),
        ("a tab", GOOD.replace("demo-3 ", "demo-3\t")),
    )

    def test_everything_but_the_one_shape_is_refused_before_anything_runs(self) -> None:
        for label, original in self.HOSTILE:
            with self.subTest(label), self.assertRaises(RefusalError) as caught:
                entry.parse_request(original)
            self.assertEqual(entry.EXIT_REFUSED, caught.exception.status, label)

    def test_no_request_at_all_is_refused_as_such(self) -> None:
        with self.assertRaises(RefusalError) as caught:
            entry.parse_request(None)
        self.assertEqual("no-command", caught.exception.reason)

    def test_a_long_request_is_refused_before_it_is_matched(self) -> None:
        with self.assertRaises(RefusalError) as caught:
            entry.parse_request(GOOD + " " + "a" * entry.MAX_REQUEST_LENGTH)
        self.assertEqual("request-too-long", caught.exception.reason)

    def test_a_date_that_is_not_on_the_calendar_is_refused(self) -> None:
        for date in ("2027-02-30", "2027-13-01", "2027-00-10", "0000-01-01"):
            with self.subTest(date), self.assertRaises(RefusalError) as caught:
                entry.parse_request(GOOD.replace("2027-03-01", date))
            self.assertEqual("bad-date", caught.exception.reason)

    def test_a_port_outside_the_unprivileged_range_is_refused(self) -> None:
        for port in ("1000", "1023", "65536", "99999"):
            with self.subTest(port), self.assertRaises(RefusalError) as caught:
                entry.parse_request(GOOD.replace("18123", port))
            self.assertEqual("bad-port", caught.exception.reason)

    def test_the_edges_of_the_port_range_are_accepted(self) -> None:
        for port in (1024, 65535):
            self.assertEqual(port, entry.parse_request(GOOD.replace("18123", str(port))).port)


class ArgumentListTests(Scratch):
    def test_the_whole_argument_list_is_the_one_the_program_builds(self) -> None:
        recorder = Recorder()
        self.assertEqual(0, self.serve(GOOD, recorder))
        state = self.paths.state_dir
        self.assertEqual(
            [
                [
                    self.paths.node,
                    f"{self.paths.bundler_dir}/dist/cli.js",
                    "--grant-lane",
                    "consented",
                    "--grant-reference",
                    REFERENCE,
                    "--descriptor",
                    f"{state}/demo-3.descriptor.json",
                    "--age-recipient",
                    RECIPIENT,
                    "--promotion-recipient",
                    RECIPIENT,
                    "--requested-by",
                    "promotion-controller",
                    "--delivered-to",
                    "ops1",
                    "--dest-dir",
                    f"{state}/out",
                    "--flag-dir",
                    f"{state}/flags",
                    "--audit-log",
                    f"{state}/audit.jsonl",
                    "--loopback-port",
                    "18123",
                    "--erasure-date",
                    "2027-03-01",
                    "--carry-media-files",
                ]
            ],
            [argv for argv, _ in recorder.calls],
        )

    def test_the_lane_is_always_consented_and_the_media_always_carried(self) -> None:
        recorder = Recorder()
        self.serve(GOOD, recorder)
        argv = recorder.calls[0][0]
        self.assertEqual("consented", argv[argv.index("--grant-lane") + 1])
        self.assertIn("--carry-media-files", argv)
        self.assertNotIn("incident", argv)

    def test_the_child_gets_a_fixed_environment_and_nothing_from_the_caller(self) -> None:
        recorder = Recorder()
        environment = {
            "SSH_ORIGINAL_COMMAND": GOOD,
            "LD_PRELOAD": "/tmp/EVIL.so",
            "NODE_OPTIONS": "--require /tmp/EVIL.js",
            "PATH": "/tmp/EVIL",
        }
        entry.serve(environment, self.paths, recorder, self.log.append)
        self.assertEqual(dict(entry.CHILD_ENVIRONMENT), recorder.calls[0][1])
        # The values themselves, so that a change to the constant is a change to this test.
        self.assertEqual(
            {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"},
            recorder.calls[0][1],
        )

    def test_the_request_fills_five_values_and_adds_no_flag(self) -> None:
        recorder = Recorder()
        self.serve(GOOD, recorder)
        flags = [item for item in recorder.calls[0][0] if item.startswith("--")]
        self.assertEqual(
            [
                "--grant-lane",
                "--grant-reference",
                "--descriptor",
                "--age-recipient",
                "--promotion-recipient",
                "--requested-by",
                "--delivered-to",
                "--dest-dir",
                "--flag-dir",
                "--audit-log",
                "--loopback-port",
                "--erasure-date",
                "--carry-media-files",
            ],
            flags,
        )


class ReadinessTests(Scratch):
    def test_a_missing_node_is_not_ready(self) -> None:
        (self.root / "node").unlink()
        self.assertEqual(("no-node", entry.EXIT_NOT_READY), self._why())

    def test_a_node_that_others_can_write_is_not_ready(self) -> None:
        (self.root / "node").chmod(0o777)
        self.assertEqual(("no-node", entry.EXIT_NOT_READY), self._why())

    def test_a_node_that_is_a_link_is_not_ready(self) -> None:
        (self.root / "node").unlink()
        (self.root / "node").symlink_to(self.root / "state")
        self.assertEqual(("no-node", entry.EXIT_NOT_READY), self._why())

    def test_a_missing_bundler_is_not_ready(self) -> None:
        (self.root / "bundler" / "dist" / "cli.js").unlink()
        self.assertEqual(("no-bundler", entry.EXIT_NOT_READY), self._why())

    def test_a_bundler_that_others_can_read_is_not_ready(self) -> None:
        (self.root / "bundler" / "dist" / "cli.js").chmod(0o644)
        self.assertEqual(("no-bundler", entry.EXIT_NOT_READY), self._why())

    def test_a_missing_descriptor_is_not_ready(self) -> None:
        (self.root / "state" / "demo-3.descriptor.json").unlink()
        self.assertEqual(("no-descriptor", entry.EXIT_NOT_READY), self._why())

    def test_a_descriptor_that_is_a_link_is_not_ready(self) -> None:
        link = self.root / "state" / "demo-3.descriptor.json"
        link.unlink()
        self.make(self.root / "elsewhere.json", 0o600)
        link.symlink_to(self.root / "elsewhere.json")
        self.assertEqual(("no-descriptor", entry.EXIT_NOT_READY), self._why())

    def test_a_descriptor_that_others_can_read_is_not_ready(self) -> None:
        (self.root / "state" / "demo-3.descriptor.json").chmod(0o640)
        self.assertEqual(("no-descriptor", entry.EXIT_NOT_READY), self._why())

    def test_files_owned_by_someone_else_are_not_ready(self) -> None:
        other = replace(self.paths, owner_uid=os.getuid() + 1)
        runner = Recorder()
        with self.assertRaises(RefusalError) as caught:
            entry.serve({"SSH_ORIGINAL_COMMAND": GOOD}, other, runner, self.log.append)
        self.assertEqual("no-node", caught.exception.reason)
        self.assertEqual([], runner.calls)

    def test_another_slots_descriptor_is_not_this_slots(self) -> None:
        refused = self.refusal(GOOD.replace("demo-3", "demo-4"))
        self.assertEqual("no-descriptor", refused.reason)

    def _why(self) -> tuple[str, int]:
        refused = self.refusal(GOOD)
        return refused.reason, refused.status


class LockAndStatusTests(Scratch):
    def test_a_second_export_while_one_runs_is_refused_as_busy(self) -> None:
        held = entry.take_lock(self.paths.lock)
        self.addCleanup(os.close, held)
        refused = self.refusal(GOOD)
        self.assertEqual(("busy", entry.EXIT_BUSY), (refused.reason, refused.status))

    def test_the_lock_is_released_when_the_export_ends(self) -> None:
        self.assertEqual(0, self.serve(GOOD))
        os.close(entry.take_lock(self.paths.lock))

    def test_the_lock_is_released_when_the_runner_raises(self) -> None:
        def boom(_argv: Sequence[str], _environment: Mapping[str, str]) -> int:
            raise OSError("stand-in")

        with self.assertRaises(OSError):
            entry.serve({"SSH_ORIGINAL_COMMAND": GOOD}, self.paths, boom, self.log.append)
        os.close(entry.take_lock(self.paths.lock))

    def test_the_bundlers_statuses_are_reduced_to_three(self) -> None:
        cases = ((0, 0), (1, 1), (2, 1), (3, 1), (4, 1), (70, 70), (-15, 1), (137, 1))
        for child, expected in cases:
            with self.subTest(child):
                self.assertEqual(expected, self.serve(GOOD, Recorder(child)))

    def test_the_log_names_the_slot_and_never_the_request(self) -> None:
        self.serve(GOOD)
        self.assertEqual(["started slot=demo-3", "finished slot=demo-3 status=0"], self.log)
        joined = " ".join(self.log)
        for value in (RECIPIENT, "grant/consent", "2027-03-01", "18123"):
            self.assertNotIn(value, joined)

    def test_a_refusal_holds_no_lock_and_logs_no_start(self) -> None:
        self.refusal("id")
        self.assertEqual([], self.log)
        os.close(entry.take_lock(self.paths.lock))


if __name__ == "__main__":
    unittest.main()
