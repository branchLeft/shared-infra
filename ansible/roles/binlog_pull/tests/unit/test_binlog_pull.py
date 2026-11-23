"""Unit tests for the binary-log pull program: what it fetches, proves, seals, ships and refuses.

The program's commands run for real in Python with every outside effect replaced by a fake that
records what it was asked: the database host, age and the object store. A log is a real binary-log
byte string made here with the same event header the server writes. No test reaches a database, a
host or a bucket. A control is proven by sabotage: each refusal and each coverage rule below goes
red when the line that makes it is broken (the role README lists the edits).
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
import uuid
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

import branchleft_binlog_pull as program
import yaml

ROLE = Path(__file__).resolve().parents[2]
SERVER = "0b1e2f3a-4c5d-6e7f-8091-a2b3c4d5e6f7"
OTHER_SERVER = "11111111-2222-3333-4444-555555555555"
RECIPIENT = "age1" + "q" * 58
SEALED_PREFIX = b"age-encryption.org/v1\n-> X25519 abcdefgh\nbody\n--- mac\n"
NOW = 1_795_060_000
PLAIN_LOGIN = "EXAMPLEONLYloginvalue0000"


def make_log(
    start: int, transactions: Sequence[tuple[int, int]], *, end: int | None = None
) -> bytes:
    """A whole binary log: format description, one GTID event per transaction, a closing rotate."""

    def event(kind: int, stamp: int, body: bytes, position: int) -> bytes:
        length = program.EVENT_HEADER.size + len(body)
        head = program.EVENT_HEADER.pack(stamp, kind, 2, length, position + length, 0)
        return head + body

    data = program.BINLOG_MAGIC
    data += event(program.FORMAT_DESCRIPTION_EVENT, start, b"\x04\x00" + b"\x00" * 55, len(data))
    sid = uuid.UUID(SERVER).bytes
    for stamp, gno in transactions:
        body = b"\x01" + sid + gno.to_bytes(8, "little") + b"\x00" * 16
        data += event(program.GTID_EVENT, stamp, body, len(data))
    last = end if end is not None else max([start, *(s for s, _ in transactions)])
    data += event(4, last, b"\x04\x00\x00\x00\x00\x00\x00\x00mysql-bin.999999", len(data))
    return data


def log_name(seq: int) -> str:
    return f"mysql-bin.{seq:06d}"


def timed_logs(count: int, *, first: int = 1, start: int = 1_795_000_000) -> dict[int, bytes]:
    """`count` consecutive logs, each 900 seconds long, the next beginning where the last ends."""
    logs: dict[int, bytes] = {}
    for offset in range(count):
        seq = first + offset
        begin = start + offset * 900
        logs[seq] = make_log(begin, [(begin + 100, seq * 10)], end=begin + 900)
    return logs


class FakeSource:
    """The database host: closed logs, one open log, and a knob for each way a fetch fails."""

    def __init__(
        self, logs: dict[int, bytes], *, server: str = SERVER, fail: set[int] | None = None
    ) -> None:
        self.logs = dict(logs)
        self.server = server
        self.failing = set(fail or ())
        self.flushes = 0
        self.fetched: list[str] = []
        self.next_open = max(logs, default=0) + 1
        self.size_lie: dict[int, int] = {}

    def server_uuid(self) -> str:
        return self.server

    def flush(self) -> None:
        self.flushes += 1
        self.next_open += 1
        top = max(self.logs, default=0)
        self.logs[top + 1] = make_log(1_795_000_000 + top * 900, [])

    def binary_logs(self) -> list[program.LogFile]:
        rows = [
            program.LogFile(log_name(s), self.size_lie.get(s, len(b)))
            for s, b in sorted(self.logs.items())
        ]
        rows.append(program.LogFile(log_name(self.next_open), 0))
        return rows

    def fetch(self, name: str, directory: Path) -> Path:
        seq = program.sequence_of(name)
        self.fetched.append(name)
        if seq in self.failing:
            program.fail(f"mysqlbinlog exited 1 for {name} (output withheld)")
        target = directory / name
        target.write_bytes(self.logs[seq])
        return target


class FakeStore:
    def __init__(self, fail_on: str | None = None) -> None:
        self.objects: dict[str, bytes] = {}
        self.fail_on = fail_on
        self.puts: list[str] = []

    def put(self, key: str, data: bytes) -> None:
        if self.fail_on is not None and self.fail_on in key:
            program.fail(f"the put of {key} to backup copy 1 failed (output withheld)")
        self.puts.append(key)
        self.objects[key] = data

    def get(self, key: str) -> bytes:
        if key not in self.objects:
            program.fail(f"the read of {key} from backup copy 1 failed (output withheld)")
        return self.objects[key]

    def list(self, prefix: str) -> list[str]:
        return sorted(k for k in self.objects if k.startswith(prefix))


def fake_seal(plain: Path, sealed: Path, recipient: str) -> None:
    """Stands in for age: a header with one recipient stanza, then the bytes (reversible)."""
    assert recipient == RECIPIENT
    sealed.write_bytes(SEALED_PREFIX + plain.read_bytes())


def fake_open(sealed: Path, plain: Path, identity: Path) -> None:
    assert identity.name == "identity.txt"
    plain.write_bytes(sealed.read_bytes().split(b"--- mac\n", 1)[1])


class Quiet:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    def text(self) -> str:
        return "\n".join(self.lines)


class WorkdirCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.ledger = self.tmp / "state" / "ledger.json"
        self.work = self.tmp / "work"
        self.say = Quiet()

    def do_pull(
        self, source: FakeSource, store: FakeStore, *, flush: bool = False
    ) -> program.PullReport:
        return program.pull(
            source=source,
            store=store,
            seal=fake_seal,
            recipient=RECIPIENT,
            ledger_path=self.ledger,
            work=self.work,
            flush=flush,
            now=lambda: float(NOW),
            say=self.say,
        )


class ReadSpanTests(WorkdirCase):
    def write(self, data: bytes) -> Path:
        path = self.tmp / "log"
        path.write_bytes(data)
        return path

    def test_a_whole_log_gives_its_times_and_its_gtids(self) -> None:
        span = program.read_span(self.write(make_log(1000, [(1010, 5), (1020, 6)], end=1030)))
        self.assertEqual((span.start, span.end, span.events), (1000, 1030, 4))
        self.assertEqual(span.first_gtid, f"{SERVER}:5")
        self.assertEqual(span.last_gtid, f"{SERVER}:6")

    def test_a_log_with_no_transaction_has_no_gtid(self) -> None:
        span = program.read_span(self.write(make_log(1000, [])))
        self.assertIsNone(span.first_gtid)

    def test_a_fetch_cut_inside_an_event_is_refused(self) -> None:
        whole = make_log(1000, [(1010, 5)])
        for cut in (len(whole) - 1, len(whole) - 30, 4 + 10):
            with self.subTest(cut=cut), self.assertRaises(program.CheckFailed):
                program.read_span(self.write(whole[:cut]))

    def test_a_file_that_is_not_a_binary_log_is_refused(self) -> None:
        with self.assertRaises(program.CheckFailed):
            program.read_span(self.write(b"not a binary log at all" * 5))

    def test_an_event_that_does_not_end_where_the_next_begins_is_refused(self) -> None:
        whole = bytearray(make_log(1000, [(1010, 5)]))
        # The format description's recorded end sits at bytes 4+13..4+17 of the file.
        whole[4 + 13 : 4 + 17] = (9999).to_bytes(4, "little")
        with self.assertRaises(program.CheckFailed):
            program.read_span(self.write(bytes(whole)))

    def test_a_log_that_does_not_open_with_a_format_description_is_refused(self) -> None:
        head = program.EVENT_HEADER.pack(1000, 2, 1, 19, 4 + 19, 0)
        with self.assertRaises(program.CheckFailed):
            program.read_span(self.write(program.BINLOG_MAGIC + head))

    def test_a_file_with_only_the_magic_holds_no_events(self) -> None:
        with self.assertRaises(program.CheckFailed):
            program.read_span(self.write(program.BINLOG_MAGIC))


class CoverageTests(unittest.TestCase):
    def test_every_closed_log_shipped_is_covered(self) -> None:
        cover = program.coverage({1, 2, 3}, {1, 2, 3})
        self.assertTrue(cover.ok)
        self.assertEqual(cover.gap_logs, 0)

    def test_a_skipped_log_between_two_shipped_ones_is_a_hole_the_server_still_holds(self) -> None:
        cover = program.coverage({1, 2, 4, 5}, {1, 2, 3, 4, 5})
        self.assertEqual(cover.holes, (3,))
        self.assertEqual(cover.unshipped, (3,))
        self.assertEqual(cover.lost, ())
        self.assertEqual(cover.gap_logs, 1)
        self.assertFalse(cover.ok)

    def test_a_skipped_log_the_server_has_dropped_is_lost_for_good(self) -> None:
        cover = program.coverage({1, 2, 4, 5}, {4, 5})
        self.assertEqual((cover.holes, cover.lost, cover.unshipped), ((3,), (3,), ()))
        self.assertEqual(cover.gap_logs, 1)

    def test_logs_that_aged_out_above_the_newest_shipped_are_lost(self) -> None:
        cover = program.coverage({1, 2}, {5, 6})
        self.assertEqual(cover.lost, (3, 4))
        self.assertEqual(cover.unshipped, (5, 6))

    def test_a_closed_log_not_yet_shipped_is_not_a_hole(self) -> None:
        cover = program.coverage({1, 2}, {1, 2, 3})
        self.assertEqual((cover.holes, cover.lost, cover.unshipped), ((), (), (3,)))
        self.assertEqual(cover.gap_logs, 0)
        self.assertFalse(cover.ok)

    def test_nothing_shipped_yet_means_every_closed_log_is_unshipped(self) -> None:
        cover = program.coverage(set(), {1, 2})
        self.assertEqual(cover.unshipped, (1, 2))
        self.assertEqual(cover.gap_logs, 0)


class PullTests(WorkdirCase):
    def test_it_ships_every_closed_log_and_never_the_open_one(self) -> None:
        source = FakeSource(timed_logs(3))
        store = FakeStore()
        report = self.do_pull(source, store)
        self.assertEqual(source.fetched, [log_name(1), log_name(2), log_name(3)])
        self.assertEqual(report.shipped, tuple(log_name(n) for n in (1, 2, 3)))
        self.assertTrue(report.cover.ok)
        self.assertNotIn(log_name(4), "".join(store.objects))

    def test_a_pull_with_one_log_open_and_none_closed_ships_nothing(self) -> None:
        source = FakeSource({})
        report = self.do_pull(source, FakeStore())
        self.assertEqual(report.shipped, ())
        self.assertTrue(report.cover.ok)

    def test_the_server_log_is_flushed_first_when_asked(self) -> None:
        source = FakeSource(timed_logs(1))
        report = self.do_pull(source, FakeStore(), flush=True)
        self.assertEqual(source.flushes, 1)
        # The log that was open is closed by the flush and shipped in the same run.
        self.assertEqual(report.shipped, (log_name(1), log_name(2)))

    def test_the_server_log_is_not_flushed_when_the_switch_is_off(self) -> None:
        source = FakeSource(timed_logs(2))
        self.do_pull(source, FakeStore(), flush=False)
        self.assertEqual(source.flushes, 0)

    def test_objects_are_ciphertext_under_the_server_incarnation_with_a_plain_manifest(
        self,
    ) -> None:
        logs = timed_logs(1)
        store = FakeStore()
        self.do_pull(FakeSource(logs), store)
        sealed = f"binlogs/{SERVER}/dbt1-mysql-bin.000001.age"
        manifest = f"binlogs/{SERVER}/dbt1-mysql-bin.000001.manifest.json"
        self.assertEqual(sorted(store.objects), [sealed, manifest])
        self.assertTrue(store.objects[sealed].startswith(b"age-encryption.org/v1\n"))
        document = json.loads(store.objects[manifest])
        self.assertEqual(
            document["sealed_sha256"], hashlib.sha256(store.objects[sealed]).hexdigest()
        )
        self.assertEqual(document["plain_sha256"], hashlib.sha256(logs[1]).hexdigest())
        self.assertEqual((document["sequence"], document["server_uuid"]), (1, SERVER))
        self.assertEqual(document["first_gtid"], f"{SERVER}:10")

    def test_the_ciphertext_is_put_before_its_manifest(self) -> None:
        store = FakeStore()
        self.do_pull(FakeSource(timed_logs(1)), store)
        self.assertTrue(store.puts[0].endswith(".age"))
        self.assertTrue(store.puts[1].endswith(".manifest.json"))

    def test_nothing_the_store_holds_carries_the_plain_log(self) -> None:
        logs = timed_logs(2)
        store = FakeStore()
        self.do_pull(FakeSource(logs), store)
        # The fake seal keeps the plain bytes after its header, so look only for the manifest:
        # the manifest is the one object that is not sealed, and it holds digests and times only.
        for key, body in store.objects.items():
            if key.endswith(".manifest.json"):
                self.assertNotIn(program.BINLOG_MAGIC, body)

    def test_a_second_pull_ships_nothing_it_already_shipped(self) -> None:
        store = FakeStore()
        self.do_pull(FakeSource(timed_logs(3)), store)
        before = list(store.puts)
        source = FakeSource(timed_logs(3))
        report = self.do_pull(source, store)
        self.assertEqual(report.shipped, ())
        self.assertEqual(source.fetched, [])
        self.assertEqual(store.puts, before)

    def test_a_new_closed_log_is_the_only_one_a_later_pull_ships(self) -> None:
        store = FakeStore()
        self.do_pull(FakeSource(timed_logs(2)), store)
        source = FakeSource(timed_logs(3))
        report = self.do_pull(source, store)
        self.assertEqual(report.shipped, (log_name(3),))

    def test_the_ledger_is_written_after_each_log_so_a_killed_run_keeps_what_it_shipped(
        self,
    ) -> None:
        store = FakeStore(fail_on="000003")
        report = self.do_pull(FakeSource(timed_logs(4)), store)
        held = program.load_ledger(self.ledger).shipped(SERVER)
        self.assertEqual(sorted(held), [1, 2, 4])
        self.assertEqual(len(report.failures), 1)

    def test_the_ledger_is_private_to_root(self) -> None:
        self.do_pull(FakeSource(timed_logs(1)), FakeStore())
        self.assertEqual(stat.S_IMODE(os.stat(self.ledger).st_mode), 0o600)

    def test_the_plain_log_is_gone_from_the_work_directory_after_each_log(self) -> None:
        self.do_pull(FakeSource(timed_logs(2)), FakeStore())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_the_plain_log_is_gone_even_when_the_put_fails(self) -> None:
        self.do_pull(FakeSource(timed_logs(2)), FakeStore(fail_on=".age"))
        self.assertEqual(list(self.work.iterdir()), [])

    def test_a_log_that_is_cut_short_is_not_shipped(self) -> None:
        logs = timed_logs(2)
        logs[1] = logs[1][:-5]
        store = FakeStore()
        report = self.do_pull(FakeSource(logs), store)
        self.assertEqual(report.shipped, (log_name(2),))
        self.assertNotIn(f"binlogs/{SERVER}/dbt1-mysql-bin.000001.age", store.objects)
        self.assertEqual(report.cover.unshipped, (1,))

    def test_a_seal_that_is_not_one_recipient_is_not_shipped(self) -> None:
        def two_recipients(plain: Path, sealed: Path, recipient: str) -> None:
            sealed.write_bytes(
                b"age-encryption.org/v1\n-> X25519 a\nb\n-> X25519 c\nd\n--- mac\n"
                + plain.read_bytes()
            )

        store = FakeStore()
        report = program.pull(
            source=FakeSource(timed_logs(1)),
            store=store,
            seal=two_recipients,
            recipient=RECIPIENT,
            ledger_path=self.ledger,
            work=self.work,
            flush=False,
            now=lambda: float(NOW),
            say=self.say,
        )
        self.assertEqual(store.objects, {})
        self.assertEqual(report.shipped, ())
        self.assertIn("2 recipient stanzas", report.failures[0])

    def test_a_log_over_the_size_the_program_holds_is_not_fetched(self) -> None:
        source = FakeSource(timed_logs(2))
        source.size_lie[1] = program.MAX_LOG_BYTES + 1
        report = self.do_pull(source, FakeStore())
        self.assertNotIn(log_name(1), source.fetched)
        self.assertEqual(report.shipped, (log_name(2),))

    def test_a_server_that_lists_no_log_means_binary_logging_is_off(self) -> None:
        class Silent(FakeSource):
            def binary_logs(self) -> list[program.LogFile]:
                return []

        with self.assertRaises(program.Precondition):
            self.do_pull(Silent({}), FakeStore())

    def test_a_new_incarnation_of_the_server_starts_its_own_series(self) -> None:
        store = FakeStore()
        self.do_pull(FakeSource(timed_logs(2)), store)
        report = self.do_pull(FakeSource(timed_logs(2), server=OTHER_SERVER), store)
        self.assertEqual(len(report.shipped), 2)
        self.assertIn(f"binlogs/{OTHER_SERVER}/dbt1-mysql-bin.000001.age", store.objects)
        self.assertIn(f"binlogs/{SERVER}/dbt1-mysql-bin.000001.age", store.objects)

    def test_entries_shipped_long_ago_are_forgotten_but_never_the_newest(self) -> None:
        ledger = program.Ledger()
        for seq, shipped in ((1, 0), (2, 0)):
            ledger.record(
                SERVER,
                program.Entry(seq, log_name(seq), "a" * 64, "b" * 64, 10, 1, 2, shipped),
            )
        ledger.prune(float(program.KEEP_LEDGER_SECONDS + 100))
        self.assertEqual(sorted(ledger.shipped(SERVER)), [2])


class SkippedLogScenario(WorkdirCase):
    """The control: skip one log in the pull; the check and the gauge go red."""

    def pull_with_log_three_skipped(self, store: FakeStore) -> program.PullReport:
        return self.do_pull(FakeSource(timed_logs(5), fail={3}), store)

    def test_the_skipped_log_is_a_hole_and_the_gap_gauge_says_one(self) -> None:
        report = self.pull_with_log_three_skipped(FakeStore())
        self.assertEqual(report.shipped, tuple(log_name(n) for n in (1, 2, 4, 5)))
        self.assertEqual(report.cover.holes, (3,))
        program.write_metrics(self.tmp / "metrics", report, now=float(NOW))
        gauges = (self.tmp / "metrics" / program.METRICS_FILE).read_text().splitlines()
        self.assertIn("binlog_pull_gap_logs 1", gauges)
        self.assertIn("binlog_pull_unshipped_logs 1", gauges)
        self.assertIn("binlog_pull_last_run_success 0", gauges)

    def test_the_coverage_check_is_red_while_the_log_is_skipped(self) -> None:
        self.pull_with_log_three_skipped(FakeStore())
        with self.assertRaises(program.CheckFailed) as caught:
            program.check(
                source=FakeSource(timed_logs(5), fail={3}), ledger_path=self.ledger, say=self.say
            )
        self.assertIn("[3]", str(caught.exception))

    def test_reverting_the_skip_turns_the_check_and_the_gauge_green(self) -> None:
        store = FakeStore()
        self.pull_with_log_three_skipped(store)
        report = self.do_pull(FakeSource(timed_logs(5)), store)
        self.assertEqual(report.shipped, (log_name(3),))
        self.assertTrue(report.cover.ok)
        program.check(source=FakeSource(timed_logs(5)), ledger_path=self.ledger, say=self.say)
        program.write_metrics(self.tmp / "metrics", report, now=float(NOW))
        gauges = (self.tmp / "metrics" / program.METRICS_FILE).read_text().splitlines()
        self.assertIn("binlog_pull_gap_logs 0", gauges)
        self.assertIn("binlog_pull_last_run_success 1", gauges)

    def test_a_log_the_server_drops_while_skipped_is_lost_and_stays_red(self) -> None:
        self.pull_with_log_three_skipped(FakeStore())
        remaining = {s: b for s, b in timed_logs(5).items() if s != 3}
        with self.assertRaises(program.CheckFailed):
            program.check(source=FakeSource(remaining), ledger_path=self.ledger, say=self.say)
        report = self.do_pull(FakeSource(remaining), FakeStore())
        self.assertEqual(report.cover.lost, (3,))
        self.assertEqual(report.cover.gap_logs, 1)


class MetricsTests(WorkdirCase):
    def read(self) -> list[str]:
        return (self.tmp / "m" / program.METRICS_FILE).read_text().splitlines()

    def test_a_clean_run_publishes_its_time_and_the_coverage(self) -> None:
        report = self.do_pull(FakeSource(timed_logs(2)), FakeStore())
        program.write_metrics(self.tmp / "m", report, now=float(NOW))
        lines = self.read()
        self.assertIn(f"binlog_pull_last_success_timestamp_seconds {NOW}", lines)
        self.assertIn("binlog_pull_last_run_success 1", lines)
        self.assertIn("binlog_pull_newest_shipped_sequence 2", lines)
        self.assertIn("binlog_pull_lost_logs 0", lines)

    def test_a_failed_run_carries_the_last_success_time_forward(self) -> None:
        good = self.do_pull(FakeSource(timed_logs(2)), FakeStore())
        program.write_metrics(self.tmp / "m", good, now=float(NOW))
        bad = self.do_pull(FakeSource(timed_logs(3), fail={3}), FakeStore())
        program.write_metrics(self.tmp / "m", bad, now=float(NOW + 900))
        lines = self.read()
        self.assertIn(f"binlog_pull_last_success_timestamp_seconds {NOW}", lines)
        self.assertIn("binlog_pull_last_run_success 0", lines)

    def test_a_run_that_never_succeeded_publishes_no_success_time(self) -> None:
        program.write_metrics(self.tmp / "m", None, now=float(NOW))
        lines = self.read()
        self.assertIn("binlog_pull_last_run_success 0", lines)
        self.assertFalse([ln for ln in lines if ln.startswith("binlog_pull_last_success")])

    def test_the_file_is_world_readable_for_the_exporter_and_written_whole(self) -> None:
        program.write_metrics(self.tmp / "m", None, now=float(NOW))
        self.assertEqual(
            stat.S_IMODE(os.stat(self.tmp / "m" / program.METRICS_FILE).st_mode), 0o644
        )
        self.assertEqual([p.name for p in (self.tmp / "m").iterdir()], [program.METRICS_FILE])


class ClientTests(unittest.TestCase):
    """The mysql and mysqlbinlog arguments, with a client that records them."""

    def source(self) -> tuple[program.MysqlSource, list[tuple[list[str], str]], list[bytes]]:
        calls: list[tuple[list[str], str]] = []
        answers: list[bytes] = [b""]

        def client(
            argv: Sequence[str], pw: str, timeout: float
        ) -> "subprocess.CompletedProcess[bytes]":
            calls.append((list(argv), pw))
            return subprocess.CompletedProcess(list(argv), 0, answers[0], b"")

        connection = program.Connection(
            "192.0.2.20", 3306, "binlog_example", PLAIN_LOGIN, "/ca.pem"
        )
        return program.MysqlSource(connection, client), calls, answers

    def test_every_call_is_over_tls_to_the_named_host_with_no_login_value_in_the_arguments(
        self,
    ) -> None:
        source, calls, answers = self.source()
        answers[0] = f"{SERVER}\n".encode()
        source.server_uuid()
        source.flush()
        answers[0] = b"mysql-bin.000001\t154\nmysql-bin.000002\t200\tNo\n"
        source.binary_logs()
        for argv, pw in calls:
            self.assertIn("--ssl-mode=VERIFY_CA", argv)
            self.assertEqual(argv[argv.index("--ssl-ca") + 1], "/ca.pem")
            self.assertEqual(argv[argv.index("--host") + 1], "192.0.2.20")
            self.assertEqual(argv[argv.index("--user") + 1], "binlog_example")
            self.assertEqual(pw, PLAIN_LOGIN)
            self.assertNotIn(PLAIN_LOGIN, " ".join(argv))
            self.assertFalse([a for a in argv if "defaults" in a])

    def test_the_three_statements_are_exactly_these(self) -> None:
        source, calls, answers = self.source()
        answers[0] = f"{SERVER}\n".encode()
        source.server_uuid()
        source.flush()
        answers[0] = b"mysql-bin.000001\t154\n"
        source.binary_logs()
        sent = [argv[argv.index("--execute") + 1] for argv, _ in calls]
        self.assertEqual(sent, ["SELECT @@server_uuid", "FLUSH BINARY LOGS", "SHOW BINARY LOGS"])

    def test_the_binary_log_list_is_read_with_its_sizes(self) -> None:
        source, _, answers = self.source()
        answers[0] = b"mysql-bin.000001\t154\nmysql-bin.000002\t200\tNo\n"
        self.assertEqual(
            source.binary_logs(),
            [program.LogFile("mysql-bin.000001", 154), program.LogFile("mysql-bin.000002", 200)],
        )

    def test_a_server_id_that_is_not_a_uuid_is_refused(self) -> None:
        source, _, answers = self.source()
        answers[0] = b"not-a-uuid\n"
        with self.assertRaises(program.CheckFailed):
            source.server_uuid()

    def test_a_fetch_is_a_raw_remote_read_of_one_named_log_into_a_directory(self) -> None:
        source, calls, _ = self.source()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "mysql-bin.000007").write_bytes(b"x")
            source.fetch("mysql-bin.000007", Path(tmp))
            argv = calls[0][0]
            self.assertEqual(argv[0], "mysqlbinlog")
            self.assertIn("--read-from-remote-server", argv)
            self.assertIn("--raw", argv)
            self.assertIn(f"--result-file={tmp}/", argv)
            self.assertEqual(argv[-1], "mysql-bin.000007")
            self.assertNotIn("--stop-never", argv)
            self.assertNotIn("--to-last-log", argv)

    def test_a_fetch_that_wrote_no_file_fails(self) -> None:
        source, _, _ = self.source()
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(program.CheckFailed):
            source.fetch("mysql-bin.000007", Path(tmp))

    def test_a_client_failure_names_the_server_error_code_and_nothing_else(self) -> None:
        def client(
            argv: Sequence[str], pw: str, timeout: float
        ) -> "subprocess.CompletedProcess[bytes]":
            return subprocess.CompletedProcess(
                list(argv), 1, b"", b"mysqlbinlog: ERROR 1045 (28000): Access denied for 'x'@'y'"
            )

        connection = program.Connection("192.0.2.20", 3306, "u", PLAIN_LOGIN, "/ca.pem")
        with self.assertRaises(program.CheckFailed) as caught:
            program.MysqlSource(connection, client).flush()
        self.assertIn("server error 1045 (28000)", str(caught.exception))
        self.assertNotIn("Access denied", str(caught.exception))

    def test_the_login_value_reaches_the_child_by_pipe_and_never_by_argument(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "show"
            script.write_text('#!/bin/sh\ncat "${1#--defaults-extra-file=}"\necho "ARGS: $*"\n')
            script.chmod(0o755)
            result = program.run_client([str(script), "--host", "h"], PLAIN_LOGIN, 20.0)
        out = result.stdout.decode()
        self.assertIn(f"[client]\n{program.OPTION_NAME}={PLAIN_LOGIN}\n", out)
        args_line = next(ln for ln in out.splitlines() if ln.startswith("ARGS:"))
        self.assertTrue(args_line.endswith("--host h"))
        self.assertNotIn(PLAIN_LOGIN, args_line)


class CiphertextTests(unittest.TestCase):
    def test_an_age_file_with_one_recipient_passes(self) -> None:
        program.require_ciphertext(SEALED_PREFIX + b"x")

    def test_anything_that_is_not_an_age_file_is_refused(self) -> None:
        for blob in (program.BINLOG_MAGIC + b"\x00" * 40, b"", b"-> X25519 a\n--- mac\n"):
            with self.subTest(blob=blob[:8]), self.assertRaises(program.CheckFailed):
                program.require_ciphertext(blob)

    def test_two_recipients_or_none_are_refused(self) -> None:
        for header in (b"", b"-> X25519 a\nb\n-> X25519 c\nd\n"):
            with self.subTest(header=header), self.assertRaises(program.CheckFailed):
                program.require_ciphertext(b"age-encryption.org/v1\n" + header + b"--- mac\nx")


class AuditTests(WorkdirCase):
    def shipped(self) -> FakeStore:
        store = FakeStore()
        self.do_pull(FakeSource(timed_logs(3)), store)
        return store

    def test_every_shipped_log_read_back_equals_what_was_shipped(self) -> None:
        store = self.shipped()
        program.audit(store=store, ledger_path=self.ledger, say=self.say)
        self.assertIn("3 logs read back", self.say.text())

    def test_a_log_missing_from_copy_1_is_red(self) -> None:
        store = self.shipped()
        del store.objects[f"binlogs/{SERVER}/dbt1-mysql-bin.000002.age"]
        with self.assertRaises(program.CheckFailed) as caught:
            program.audit(store=store, ledger_path=self.ledger, say=self.say)
        self.assertIn("mysql-bin.000002 is not on copy 1", str(caught.exception))

    def test_a_log_whose_bytes_changed_is_red(self) -> None:
        store = self.shipped()
        store.objects[f"binlogs/{SERVER}/dbt1-mysql-bin.000001.age"] = SEALED_PREFIX + b"other"
        with self.assertRaises(program.CheckFailed) as caught:
            program.audit(store=store, ledger_path=self.ledger, say=self.say)
        self.assertIn("another digest", str(caught.exception))

    def test_an_empty_ledger_is_a_precondition_not_a_pass(self) -> None:
        with self.assertRaises(program.Precondition):
            program.audit(store=FakeStore(), ledger_path=self.ledger, say=self.say)


class RestoreToATimeTests(WorkdirCase):
    """The replay check: which logs carry a restored copy to a time, and whether they open."""

    BASE = 1_795_000_000

    def manifests(self, store: FakeStore, count: int = 4) -> list[program.Manifest]:
        self.do_pull(FakeSource(timed_logs(count, start=self.BASE)), store)
        return program.manifests_from_store(store, SERVER)

    def test_a_window_inside_the_shipped_logs_names_the_logs_in_order(self) -> None:
        manifests = self.manifests(FakeStore())
        chosen = program.plan_replay(manifests, begin=self.BASE + 1000, stop=self.BASE + 2000)
        self.assertEqual([m.seq for m in chosen], [2, 3])

    def test_a_missing_log_inside_the_window_is_refused_and_named(self) -> None:
        manifests = [m for m in self.manifests(FakeStore()) if m.seq != 2]
        with self.assertRaises(program.CheckFailed) as caught:
            program.plan_replay(manifests, begin=self.BASE + 100, stop=self.BASE + 2000)
        self.assertIn("[2]", str(caught.exception))

    def test_a_stop_after_the_newest_shipped_log_is_refused(self) -> None:
        manifests = self.manifests(FakeStore())
        with self.assertRaises(program.CheckFailed) as caught:
            program.plan_replay(manifests, begin=self.BASE + 100, stop=self.BASE + 4 * 900 + 500)
        self.assertIn("log still open", str(caught.exception))

    def test_a_start_before_the_oldest_shipped_log_is_refused(self) -> None:
        manifests = self.manifests(FakeStore())
        with self.assertRaises(program.CheckFailed):
            program.plan_replay(manifests, begin=self.BASE - 1000, stop=self.BASE + 500)

    def test_a_stop_before_the_start_is_a_precondition(self) -> None:
        with self.assertRaises(program.Precondition):
            program.plan_replay([], begin=10, stop=5)

    def test_no_shipped_logs_is_red_not_empty_success(self) -> None:
        with self.assertRaises(program.CheckFailed):
            program.plan_replay([], begin=5, stop=10)

    def test_the_plan_from_this_hosts_ledger_equals_the_plan_from_copy_1(self) -> None:
        store = FakeStore()
        from_store = self.manifests(store)
        from_ledger = program.manifests_from_ledger(program.load_ledger(self.ledger), SERVER)
        window = {"begin": self.BASE + 1000, "stop": self.BASE + 2000}
        self.assertEqual(
            [m.name for m in program.plan_replay(from_store, **window)],
            [m.name for m in program.plan_replay(from_ledger, **window)],
        )

    def test_a_replay_dry_run_opens_every_log_and_touches_no_database(self) -> None:
        store = FakeStore()
        chosen = program.plan_replay(
            self.manifests(store), begin=self.BASE + 1000, stop=self.BASE + 2000
        )
        ran: list[Sequence[str]] = []

        def runner(reader: Sequence[str], writer: Sequence[str]) -> int:
            ran.append(reader)
            return 0

        program.replay(
            chosen=chosen,
            store=store,
            identity=self.tmp / "identity.txt",
            option_file=self.tmp / "scratch.cnf",
            stop=self.BASE + 2000,
            database=None,
            work=self.work,
            apply=False,
            say=self.say,
            opener=fake_open,
            runner=runner,
        )
        self.assertEqual(ran, [])
        self.assertIn("2 logs opened and checked", self.say.text())
        self.assertIn("dry run", self.say.text())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_an_applied_replay_pipes_the_logs_in_order_up_to_the_stop_time(self) -> None:
        store = FakeStore()
        chosen = program.plan_replay(
            self.manifests(store), begin=self.BASE + 1000, stop=self.BASE + 2000
        )
        seen: list[tuple[list[str], list[str]]] = []

        def runner(reader: Sequence[str], writer: Sequence[str]) -> int:
            seen.append((list(reader), list(writer)))
            return 0

        program.replay(
            chosen=chosen,
            store=store,
            identity=self.tmp / "identity.txt",
            option_file=self.tmp / "scratch.cnf",
            stop=self.BASE + 2000,
            database="tenant_db",
            work=self.work,
            apply=True,
            say=self.say,
            opener=fake_open,
            runner=runner,
        )
        reader, writer = seen[0]
        self.assertEqual(reader[0], "mysqlbinlog")
        self.assertIn("--stop-datetime=2026-11-18 11:40:00", reader)
        self.assertIn("--database=tenant_db", reader)
        names = [Path(a).name for a in reader if a.startswith(str(self.work))]
        self.assertEqual(names, [log_name(2), log_name(3)])
        self.assertEqual(writer[0], "mysql")
        self.assertIn(f"--defaults-extra-file={self.tmp / 'scratch.cnf'}", writer)

    def test_a_log_that_opens_to_other_bytes_than_were_shipped_stops_the_replay(self) -> None:
        store = FakeStore()
        chosen = program.plan_replay(
            self.manifests(store), begin=self.BASE + 1000, stop=self.BASE + 2000
        )

        def wrong(sealed: Path, plain: Path, identity: Path) -> None:
            plain.write_bytes(make_log(1, []))

        with self.assertRaises(program.CheckFailed) as caught:
            program.replay(
                chosen=chosen,
                store=store,
                identity=self.tmp / "identity.txt",
                option_file=self.tmp / "scratch.cnf",
                stop=self.BASE + 2000,
                database=None,
                work=self.work,
                apply=True,
                say=self.say,
                opener=wrong,
                runner=lambda reader, writer: 0,
            )
        self.assertIn("not the log that was shipped", str(caught.exception))

    def test_an_object_changed_on_copy_1_stops_the_replay_before_it_is_opened(self) -> None:
        store = FakeStore()
        chosen = program.plan_replay(
            self.manifests(store), begin=self.BASE + 1000, stop=self.BASE + 2000
        )
        store.objects[f"binlogs/{SERVER}/dbt1-mysql-bin.000002.age"] = SEALED_PREFIX + b"x"
        opened: list[Path] = []
        with self.assertRaises(program.CheckFailed):
            program.replay(
                chosen=chosen,
                store=store,
                identity=self.tmp / "identity.txt",
                option_file=self.tmp / "scratch.cnf",
                stop=self.BASE + 2000,
                database=None,
                work=self.work,
                apply=True,
                say=self.say,
                opener=lambda s, p, i: opened.append(s),
                runner=lambda reader, writer: 0,
            )
        self.assertEqual(opened, [])

    def test_a_failing_replay_is_red(self) -> None:
        store = FakeStore()
        chosen = program.plan_replay(
            self.manifests(store), begin=self.BASE + 1000, stop=self.BASE + 2000
        )
        with self.assertRaises(program.CheckFailed):
            program.replay(
                chosen=chosen,
                store=store,
                identity=self.tmp / "identity.txt",
                option_file=self.tmp / "scratch.cnf",
                stop=self.BASE + 2000,
                database=None,
                work=self.work,
                apply=True,
                say=self.say,
                opener=fake_open,
                runner=lambda reader, writer: 1,
            )

    def test_times_are_utc_only(self) -> None:
        self.assertEqual(program.parse_time("2026-11-19T03:10:00Z"), 1_795_057_800)
        self.assertEqual(program.parse_time("2026-11-19 03:10:00+00:00"), 1_795_057_800)
        for text in ("2026-11-19T03:10:00", "2026-11-19T03:10:00+01:00", "yesterday"):
            with self.subTest(text=text), self.assertRaises(program.Precondition):
                program.parse_time(text)
        self.assertEqual(program.mysqlbinlog_time(1_795_057_800), "2026-11-19 03:10:00")


class ConfigurationTests(unittest.TestCase):
    def env(self, **changes: str) -> dict[str, str]:
        base = {
            "BINLOG_PULL_DB_HOST": "192.0.2.20",
            "BINLOG_PULL_DB_USER": "binlog_example",
            "BINLOG_PULL_DB_PWD": PLAIN_LOGIN,
            "BINLOG_PULL_DB_CA_FILE": "/etc/branchleft/dbt1-ca.pem",
        }
        base.update(changes)
        return base

    def test_a_complete_environment_gives_a_connection_on_the_default_port(self) -> None:
        connection = program.connection_of(self.env())
        self.assertEqual(
            (connection.host, connection.port, connection.user),
            ("192.0.2.20", 3306, "binlog_example"),
        )

    def test_each_missing_or_malformed_value_is_a_precondition(self) -> None:
        for change in (
            {"BINLOG_PULL_DB_HOST": ""},
            {"BINLOG_PULL_DB_HOST": "a b"},
            {"BINLOG_PULL_DB_USER": "x;y"},
            {"BINLOG_PULL_DB_PWD": ""},
            {"BINLOG_PULL_DB_CA_FILE": ""},
            {"BINLOG_PULL_DB_PORT": "33x6"},
        ):
            with self.subTest(change=change), self.assertRaises(program.Precondition):
                program.connection_of(self.env(**change))

    def test_the_recipient_must_be_one_age_public_key_and_a_private_key_is_refused(self) -> None:
        self.assertEqual(program.recipient_of({"STATE_COPY_RECIPIENT": RECIPIENT}), RECIPIENT)
        for value in ("", "AGE-SECRET-KEY-1" + "Q" * 50, RECIPIENT + RECIPIENT):
            with self.subTest(value=value[:12]), self.assertRaises(program.Precondition):
                program.recipient_of({"STATE_COPY_RECIPIENT": value})

    def test_the_destination_needs_all_five_values_and_names_the_missing_ones(self) -> None:
        full = {f"STATE_COPY_DEST_{n}": "v" for n in program.DEST_NAMES}
        self.assertEqual(program.target_of(full, "STATE_COPY_DEST").bucket, "v")
        del full["STATE_COPY_DEST_REGION"]
        with self.assertRaises(program.Precondition) as caught:
            program.target_of(full, "STATE_COPY_DEST")
        self.assertIn("STATE_COPY_DEST_REGION", str(caught.exception))

    def test_a_missing_environment_file_is_named(self) -> None:
        with self.assertRaises(program.Precondition) as caught:
            program.load_env(Path("/nonexistent/x.env"))
        self.assertIn("/nonexistent/x.env is not there", str(caught.exception))


class MainTests(WorkdirCase):
    def args(self, *more: str) -> list[str]:
        return [
            "--env-file", str(self.tmp / "binlog.env"),
            "--copy-env-file", str(self.tmp / "copy.env"),
            "--state-dir", str(self.tmp / "state"),
            "--work-dir", str(self.work),
            "--metrics-dir", str(self.tmp / "m"),
            *more,
        ]  # fmt: skip

    def test_the_install_check_passes_and_touches_nothing(self) -> None:
        self.assertEqual(program.main(["--check"], say=self.say), 0)
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_a_pull_without_its_environment_stops_with_the_precondition_code(self) -> None:
        self.assertEqual(program.main(self.args("pull"), say=self.say), program.EXIT_PRECONDITION)
        self.assertIn("NOT RUN", self.say.text())

    def write_environment(self) -> None:
        (self.tmp / "binlog.env").write_text(
            f"BINLOG_PULL_DB_HOST=192.0.2.20\nBINLOG_PULL_DB_USER=binlog_example\n"
            f"BINLOG_PULL_DB_PWD={PLAIN_LOGIN}\nBINLOG_PULL_DB_CA_FILE=/ca.pem\n"
        )
        (self.tmp / "copy.env").write_text(f"STATE_COPY_RECIPIENT={RECIPIENT}\n")

    def test_a_pull_that_leaves_a_hole_exits_red_and_publishes_the_gap(self) -> None:
        self.write_environment()
        source = FakeSource(timed_logs(5), fail={3})
        with (
            mock.patch.object(program, "MysqlSource", return_value=source),
            mock.patch.object(program, "write_store", return_value=FakeStore()),
            mock.patch.object(program, "age_seal", fake_seal),
        ):
            code = program.main(self.args("pull"), say=self.say)
        self.assertEqual(code, program.EXIT_CHECK_FAILED)
        gauges = (self.tmp / "m" / program.METRICS_FILE).read_text().splitlines()
        self.assertIn("binlog_pull_gap_logs 1", gauges)
        self.assertNotIn(PLAIN_LOGIN, self.say.text())

    def test_a_pull_that_ships_everything_exits_green(self) -> None:
        self.write_environment()
        with (
            mock.patch.object(program, "MysqlSource", return_value=FakeSource(timed_logs(3))),
            mock.patch.object(program, "write_store", return_value=FakeStore()),
            mock.patch.object(program, "age_seal", fake_seal),
        ):
            code = program.main(self.args("pull"), say=self.say)
        self.assertEqual(code, program.EXIT_OK)
        gauges = (self.tmp / "m" / program.METRICS_FILE).read_text().splitlines()
        self.assertIn("binlog_pull_gap_logs 0", gauges)

    def test_the_check_command_is_red_on_an_unshipped_log_and_green_after_the_pull(self) -> None:
        self.write_environment()
        with mock.patch.object(program, "MysqlSource", return_value=FakeSource(timed_logs(2))):
            self.assertEqual(
                program.main(self.args("check"), say=self.say), program.EXIT_CHECK_FAILED
            )
        with (
            mock.patch.object(program, "MysqlSource", return_value=FakeSource(timed_logs(2))),
            mock.patch.object(program, "write_store", return_value=FakeStore()),
            mock.patch.object(program, "age_seal", fake_seal),
        ):
            self.assertEqual(program.main(self.args("pull"), say=self.say), program.EXIT_OK)
            self.assertEqual(program.main(self.args("check"), say=self.say), program.EXIT_OK)

    def test_a_second_run_while_one_holds_the_lock_stands_aside(self) -> None:
        self.write_environment()
        with (
            program.run_lock(self.tmp / "state") as first,
            mock.patch.object(program, "MysqlSource", return_value=FakeSource(timed_logs(2))),
            mock.patch.object(program, "write_store", return_value=FakeStore()),
        ):
            self.assertTrue(first)
            code = program.main(self.args("pull"), say=self.say)
        self.assertEqual(code, program.EXIT_OK)
        self.assertIn("stands aside", self.say.text())
        self.assertFalse((self.tmp / "m" / program.METRICS_FILE).exists())

    def test_a_precondition_during_a_pull_still_publishes_a_failed_run(self) -> None:
        self.write_environment()

        class Off(FakeSource):
            def binary_logs(self) -> list[program.LogFile]:
                return []

        with (
            mock.patch.object(program, "MysqlSource", return_value=Off({})),
            mock.patch.object(program, "write_store", return_value=FakeStore()),
        ):
            code = program.main(self.args("pull"), say=self.say)
        self.assertEqual(code, program.EXIT_PRECONDITION)
        self.assertIn(
            "binlog_pull_last_run_success 0", (self.tmp / "m" / program.METRICS_FILE).read_text()
        )

    def test_a_replay_from_the_ledger_is_refused_because_it_reads_copy_1(self) -> None:
        self.write_environment()
        store = FakeStore()
        self.do_pull(FakeSource(timed_logs(3, start=1_795_000_000)), store)
        (self.tmp / "state").mkdir(exist_ok=True)
        (self.tmp / "state" / "ledger.json").write_bytes(self.ledger.read_bytes())
        code = program.main(
            self.args(
                "replay", "--server-uuid", SERVER, "--from", "2026-11-18T10:30:00Z",
                "--to", "2026-11-18T10:50:00Z", "--from-ledger", "--identity", "/i",
                "--target-option-file", "/t",
            ),
            say=self.say,
        )  # fmt: skip
        self.assertEqual(code, program.EXIT_PRECONDITION)


class ProgramTextTests(unittest.TestCase):
    """The program text must read as plain code to the plan's secret scan, and as one program."""

    PROGRAM = (ROLE / "files" / "branchleft_binlog_pull.py").read_text()

    def test_no_line_reads_as_a_credential_assignment_to_the_plan_scan(self) -> None:
        # The credential-assignment pattern of the gated plan's scan, as ansible/checks holds it.
        scan = re.compile(
            r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
            r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
            re.IGNORECASE | re.ASCII,
        )
        hits = [n for n, line in enumerate(self.PROGRAM.splitlines(), 1) if scan.search(line)]
        self.assertEqual(hits, [], "these lines would withhold the host's whole plan")

    def test_the_program_prints_no_login_value_and_passes_none_as_an_argument(self) -> None:
        for forbidden in ("os.environ", "shell=True", "MYSQL_PWD", "--password"):
            self.assertNotIn(forbidden, self.PROGRAM)

    def test_the_program_fetches_only_closed_logs_by_name_and_never_streams(self) -> None:
        self.assertNotIn("--stop-never", self.PROGRAM)
        self.assertNotIn("--to-last-log", self.PROGRAM)
        self.assertIn("logs[:-1]", self.PROGRAM)

    def test_it_is_a_python_3_12_program_with_the_isolated_interpreter_line(self) -> None:
        self.assertTrue(self.PROGRAM.startswith("#!/usr/bin/python3 -I\n"))


class RoleContractTests(unittest.TestCase):
    """The role's files and the program agree on every path, name and number they share."""

    def load(self, relative: str) -> dict[str, object]:
        loaded = yaml.safe_load((ROLE / relative).read_text())
        assert isinstance(loaded, dict)
        return loaded

    def tasks(self) -> list[dict[str, object]]:
        loaded = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        assert isinstance(loaded, list)
        return loaded

    def test_the_paths_the_role_makes_are_the_paths_the_program_reads(self) -> None:
        constants = self.load("vars/main.yml")
        self.assertEqual(constants["binlog_pull_env_file"], str(program.ENV_FILE))
        self.assertEqual(constants["binlog_pull_state_dir"], str(program.STATE_DIR))
        self.assertEqual(constants["binlog_pull_copy_env_file"], str(program.COPY_ENV_FILE))
        self.assertEqual(
            constants["binlog_pull_release_client"],
            str(program.RELEASE_SCRIPTS / "shared_objectstorage.py"),
        )
        self.assertEqual(constants["binlog_pull_program_dir"], "/opt/branchleft/binlog-pull")
        self.assertEqual(constants["binlog_pull_ca_file"], "/etc/branchleft/dbt1-ca.pem")

    def test_the_environment_template_names_what_the_program_reads(self) -> None:
        template = (ROLE / "templates" / "binlog-pull.env.j2").read_text()
        names = [line.split("=", 1)[0] for line in template.splitlines()]
        self.assertEqual(
            names,
            [
                program.ENV_HOST,
                program.ENV_PORT,
                program.ENV_USER,
                program.ENV_PW,
                program.ENV_CA,
                program.ENV_FLUSH,
            ],
        )

    def test_the_service_runs_the_installed_program_and_the_work_directory_is_its_runtime_one(
        self,
    ) -> None:
        service = (ROLE / "files" / "branchleft-binlog-pull.service").read_text()
        self.assertIn(
            "ExecStart=/usr/bin/python3 -I "
            "/opt/branchleft/binlog-pull/branchleft_binlog_pull.py pull",
            service,
        )
        self.assertIn(f"RuntimeDirectory={program.WORK_DIR.name}", service)
        self.assertIn("RuntimeDirectoryMode=0700", service)
        self.assertIn("Type=oneshot", service)

    def test_the_timer_fires_every_15_minutes_and_the_run_is_bounded_under_it(self) -> None:
        timer = (ROLE / "files" / "branchleft-binlog-pull.timer").read_text()
        self.assertIn("OnUnitActiveSec=15min", timer)
        self.assertIn("OnBootSec=5min", timer)
        service = (ROLE / "files" / "branchleft-binlog-pull.service").read_text()
        self.assertIn("TimeoutStartSec=10min", service)

    def test_the_timer_is_off_by_default_and_never_disabled_by_default(self) -> None:
        defaults = self.load("defaults/main.yml")
        self.assertIs(defaults["binlog_pull_timer_enabled"], False)
        self.assertIs(defaults["binlog_pull_timer_may_disable"], False)

    def test_the_timer_task_is_gated_on_both_switches(self) -> None:
        hold = next(t for t in self.tasks() if str(t["name"]).startswith("Hold the timer"))
        conditions = hold["when"]
        assert isinstance(conditions, list)
        self.assertIn(
            "binlog_pull_timer_enabled | bool or binlog_pull_timer_may_disable | bool", conditions
        )

    def test_the_timer_is_refused_without_the_destination_file_and_the_staged_client(self) -> None:
        refusal = next(
            t for t in self.tasks() if str(t["name"]).startswith("Refuse the timer while")
        )
        self.assertEqual(refusal["when"], "binlog_pull_timer_enabled | bool")
        assert isinstance(refusal["ansible.builtin.assert"], dict)
        self.assertIn(
            "state-copy environment file", str(refusal["ansible.builtin.assert"]["fail_msg"])
        )

    def test_every_task_that_handles_a_login_value_or_the_ca_hides_it(self) -> None:
        by_name = {str(t["name"]): t for t in self.tasks()}
        for name in (
            "Install the database CA",
            "Create the environment file empty, closed to everyone but root",
            "Write the environment file from the inputs",
        ):
            self.assertIs(by_name[name]["no_log"], True, name)
            self.assertIs(by_name[name]["diff"], False, name)
        login = by_name[
            "Refuse a login value that is empty or cannot be one line of the environment file"
        ]
        self.assertIs(login["no_log"], True)
        # The value appears in no other task than the ones above and the argument spec's own.
        holders = [
            name
            for name, task in by_name.items()
            if "binlog_pull_db_password" in yaml.safe_dump(task)
        ]
        self.assertEqual(
            holders,
            ["Refuse a login value that is empty or cannot be one line of the environment file"],
        )

    def test_the_environment_file_is_closed_before_the_value_is_written(self) -> None:
        names = [str(t["name"]) for t in self.tasks()]
        create = names.index("Create the environment file empty, closed to everyone but root")
        attributes = names.index("Set the owner and mode of the environment file on every run")
        write = names.index("Write the environment file from the inputs")
        self.assertLess(create, attributes)
        self.assertLess(attributes, write)
        first = next(
            t for t in self.tasks() if str(t["name"]).startswith("Create the environment file")
        )
        copy = first["ansible.builtin.copy"]
        assert isinstance(copy, dict)
        self.assertEqual((copy["content"], copy["force"], copy["mode"]), ("", False, "0600"))

    def test_the_program_is_installed_only_after_its_own_check(self) -> None:
        install = next(t for t in self.tasks() if str(t["name"]).startswith("Install the program"))
        copy = install["ansible.builtin.copy"]
        assert isinstance(copy, dict)
        self.assertEqual(copy["validate"], "/usr/bin/python3 -I %s --check")
        self.assertEqual((copy["owner"], copy["group"], copy["mode"]), ("root", "root", "0755"))

    def test_the_argument_spec_holds_exactly_the_variables_the_tasks_and_template_read(
        self,
    ) -> None:
        spec = self.load("meta/argument_specs.yml")
        main = spec["argument_specs"]
        assert isinstance(main, dict)
        options = main["main"]["options"]
        self.assertEqual(
            sorted(options),
            sorted(
                [
                    "binlog_pull_db_host",
                    "binlog_pull_db_user",
                    "binlog_pull_db_password",
                    "binlog_pull_db_ca_pem",
                    "binlog_pull_db_port",
                    "binlog_pull_flush",
                    "binlog_pull_timer_enabled",
                    "binlog_pull_timer_may_disable",
                ]
            ),
        )
        for private in ("host", "user", "password", "ca_pem"):
            self.assertIs(options[f"binlog_pull_db_{private}"]["required"], True)
            self.assertNotIn("default", options[f"binlog_pull_db_{private}"])
        self.assertIs(options["binlog_pull_db_password"]["no_log"], True)
        defaults = self.load("defaults/main.yml")
        for name in (
            "binlog_pull_db_host",
            "binlog_pull_db_user",
            "binlog_pull_db_password",
            "binlog_pull_db_ca_pem",
        ):
            self.assertNotIn(name, defaults)

    def test_the_object_key_shape_is_the_one_the_database_runbook_restores_from(self) -> None:
        self.assertEqual(
            program.sealed_key(SERVER, "mysql-bin.000012"),
            f"binlogs/{SERVER}/dbt1-mysql-bin.000012.age",
        )

    def test_the_readme_names_every_command_and_the_owner_steps(self) -> None:
        readme = (ROLE / "README.md").read_text()
        for needle in (
            "`pull`",
            "`check`",
            "`audit`",
            "`plan`",
            "`replay`",
            "Owner steps",
            "Sabotage",
        ):
            self.assertIn(needle, readme)


if __name__ == "__main__":
    unittest.main()
