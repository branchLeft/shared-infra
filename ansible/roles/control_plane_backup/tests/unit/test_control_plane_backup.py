"""Unit tests for the control-plane backup program: what it takes, proves, refuses and ships.

The program's commands are run for real in Python with every outside effect replaced by a
fake that records what it was asked: the docker client, the psql session, pg_dump, the
throwaway restore, age and the object store. No test reaches a database, a host or a bucket.
A control is proven by sabotage: each refusal below goes red when the line that makes it is
broken (the role README lists the edits).
"""

import datetime
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from collections import deque
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import IO, cast
from unittest import mock

import branchleft_control_plane_backup as program
import yaml

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
IMAGE = "sha256:" + "a" * 64
RECIPIENT = "age1" + "q" * 58
SNAPSHOT = "00000003-0000001B-1"
GOOD_COUNTS: program.Counts = {
    "public.prospects": 120,
    "public.quotes": 40,
    "eventstore.events": 75,
}
AGE_FILE = b"age-encryption.org/v1\n-> X25519 abcdefgh\nbody\n--- mac\nciphertext"
STAMP = "20261111T024000Z"


def done(code: int = 0, out: str = "") -> "subprocess.CompletedProcess[str]":
    return subprocess.CompletedProcess([], code, out, "")


def count_lines(counts: program.Counts) -> str:
    return "".join(f"{table}|{rows}\n" for table, rows in counts.items())


class KeptInput(io.BytesIO):
    """A child's standard input that still tells what was written after the program closes it."""

    kept = b""

    def close(self) -> None:
        self.kept = self.getvalue()
        super().close()


class FakeProcess:
    """A finished child: its output is fixed, what is written to it is kept."""

    def __init__(
        self, out: bytes = b"", code: int = 0, on_wait: Callable[[bytes], None] | None = None
    ) -> None:
        self.stdin: IO[bytes] = KeptInput()
        self.stdout: IO[bytes] = io.BytesIO(out)
        self.code = code
        self.killed = False
        self._on_wait = on_wait

    def written(self) -> bytes:
        return cast(KeptInput, self.stdin).kept

    def wait(self, timeout: float | None = None) -> int:
        if self._on_wait is not None:
            self._on_wait(self.written())
            self._on_wait = None
        return self.code

    def poll(self) -> int | None:
        return self.code

    def kill(self) -> None:
        self.killed = True


class SessionProcess:
    """A psql child that answers each statement as the server would, one end mark per echo."""

    def __init__(
        self,
        counts: program.Counts,
        *,
        snapshot: str = SNAPSHOT,
        ends: bool = True,
        events: list[str] | None = None,
    ) -> None:
        self.events = events if events is not None else []
        self.counts = counts
        self.snapshot = snapshot
        self.ends = ends
        self.sent: list[str] = []
        self.queue: deque[bytes] = deque()
        self.stdin = cast(IO[bytes], self)
        self.stdout = cast(IO[bytes], self)
        self.code = 0

    def write(self, data: bytes) -> int:
        text = data.decode().strip()
        self.sent.append(text)
        if "pg_export_snapshot" in text:
            self.queue.append(f"{self.snapshot}\n".encode())
        elif text == program.COUNT_SQL:
            self.events.append("counts")
            self.queue.extend(line.encode() for line in count_lines(self.counts).splitlines(True))
        elif text.endswith(program.END_MARK) and self.ends:
            self.queue.append(f"{program.END_MARK}\n".encode())
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def readline(self) -> bytes:
        return self.queue.popleft() if self.queue else b""

    def wait(self, timeout: float | None = None) -> int:
        return self.code

    def poll(self) -> int | None:
        return self.code

    def kill(self) -> None:
        return None


class FakeSpawner:
    """Starts fakes in place of docker exec psql, pg_dump, the restore load and age."""

    def __init__(self, live: dict[str, program.Counts]) -> None:
        self.live = live
        self.calls: list[list[str]] = []
        self.dump_code = 0
        self.age_code = 0
        self.load_code = 0
        self.sessions: list[SessionProcess] = []
        self.loads: list[FakeProcess] = []
        self.age_input = b""
        self.snapshots_used: list[str] = []
        self.events: list[str] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        stdin: program.Stream = None,
        stdout: program.Stream = None,
        stderr: program.Stream = None,
    ) -> "subprocess.Popen[bytes]":
        args = list(argv)
        self.calls.append(args)
        if "pg_dump" in args:
            database = args[args.index("-d") + 1]
            self.events.append("dump")
            self.snapshots_used.append(next(a for a in args if a.startswith("--snapshot=")))
            return cast(
                "subprocess.Popen[bytes]",
                FakeProcess(f"-- dump of {database}\n".encode(), self.dump_code),
            )
        if args[0] == "age":
            sink = cast(IO[bytes], stdout)

            def finish(data: bytes) -> None:
                self.age_input = data
                sink.write(AGE_FILE)

            return cast("subprocess.Popen[bytes]", FakeProcess(b"", self.age_code, finish))
        if "psql" in args and "-tA" in args:
            database = args[args.index("-d") + 1]
            session = SessionProcess(self.live[database], events=self.events)
            self.sessions.append(session)
            return cast("subprocess.Popen[bytes]", session)
        load = FakeProcess(b"", self.load_code)
        self.loads.append(load)
        return cast("subprocess.Popen[bytes]", load)


class FakeDocker:
    """The docker client: containers, sizes, the throwaway server and what it counts."""

    def __init__(self, restored: dict[str, program.Counts] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.containers = ["abc123"]
        self.sizes = {"portal": 5000, "zitadel": 7000}
        self.restored = restored if restored is not None else {}
        self.created: list[str] = []
        self.ready = True
        self.refuse_run = False

    def __call__(self, argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
        args = list(argv)
        self.calls.append(args)
        if args[1:3] == ["ps", "-q"]:
            return done(out="\n".join(self.containers))
        if args[1] == "inspect":
            return done(out=IMAGE + "\n")
        if args[1] == "info":
            return done(out="/var/lib/docker\n")
        if args[1] == "run":
            return done(1 if self.refuse_run else 0, "containerid\n")
        if "pg_isready" in args:
            return done(0 if self.ready else 1)
        if "createdb" in args:
            self.created.append(args[-1])
            return done()
        if program.COUNT_SQL in args:
            database = args[args.index("-d") + 1]
            return done(out=count_lines(self.restored.get(database, {})))
        for database, size in self.sizes.items():
            if f"pg_database_size('{database}')" in " ".join(args):
                return done(out=f"{size}\n")
        return done()

    def removed(self) -> bool:
        return any(call[1:4] == ["rm", "-f", "-v"] for call in self.calls)


def roomy(path: Path) -> tuple[int, int, int]:
    return (100 * 2**30, 0, 90 * 2**30)


def cramped(path: Path) -> tuple[int, int, int]:
    return (2**30, 0, 2**30 + 1)


def make_backup(
    root: Path, live: dict[str, program.Counts] | None = None
) -> tuple[Path, FakeSpawner]:
    """A real backup directory made by `take` against fakes."""
    counts = live if live is not None else {"portal": GOOD_COUNTS, "zitadel": GOOD_COUNTS}
    spawner = FakeSpawner(counts)
    backup = program.take(
        root=root, runner=FakeDocker(), spawner=spawner, usage=roomy, say=lambda _: None
    )
    return backup, spawner


class TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "backups"


class CountsTests(unittest.TestCase):
    def test_a_table_and_a_number_per_line_is_read(self) -> None:
        self.assertEqual(
            program.parse_counts(["public.a|3", "eventstore.events|0"]),
            {"public.a": 3, "eventstore.events": 0},
        )

    def test_a_line_of_another_shape_is_refused_without_being_quoted(self) -> None:
        with self.assertRaises(program.CheckFailed) as caught:
            program.parse_counts(["alice@example.invalid|not-a-number"])
        self.assertNotIn("alice", str(caught.exception))

    def test_equal_counts_pass(self) -> None:
        program.compare_counts("portal", GOOD_COUNTS, dict(GOOD_COUNTS))

    def test_a_different_count_names_the_table(self) -> None:
        restored = {**GOOD_COUNTS, "public.quotes": 39}
        with self.assertRaisesRegex(program.CheckFailed, r"public\.quotes live=40 restored=39"):
            program.compare_counts("portal", GOOD_COUNTS, restored)

    def test_an_empty_restore_fails_against_a_live_database_with_tables(self) -> None:
        with self.assertRaisesRegex(program.CheckFailed, "restored database holds no tables"):
            program.compare_counts("portal", GOOD_COUNTS, {})

    def test_a_live_database_with_no_tables_proves_nothing(self) -> None:
        with self.assertRaisesRegex(program.CheckFailed, "equal counts prove nothing"):
            program.compare_counts("portal", {}, {})

    def test_a_missing_or_extra_table_fails(self) -> None:
        with self.assertRaisesRegex(program.CheckFailed, "1 missing"):
            program.compare_counts(
                "portal",
                GOOD_COUNTS,
                {k: v for k, v in GOOD_COUNTS.items() if k != "public.quotes"},
            )
        with self.assertRaisesRegex(program.CheckFailed, "1 not in the live copy"):
            program.compare_counts("portal", GOOD_COUNTS, {**GOOD_COUNTS, "public.extra": 1})

    def test_a_zero_row_table_is_a_table(self) -> None:
        program.compare_counts("portal", {"public.empty": 0}, {"public.empty": 0})


class CommandShapeTests(unittest.TestCase):
    def test_the_password_is_expanded_in_the_container_and_never_in_the_arguments(self) -> None:
        argv = program.pg_argv("abc123", ["psql", "-U", "postgres"])
        self.assertEqual(argv[:4], ["docker", "exec", "abc123", "sh"])
        self.assertIn("$POSTGRES_PASSWORD", argv[5])
        self.assertEqual(argv[-3:], ["psql", "-U", "postgres"])
        self.assertNotIn("-e", argv)

    def test_an_interactive_command_asks_docker_for_stdin(self) -> None:
        self.assertEqual(
            program.pg_argv("abc123", ["psql"], interactive=True)[:4],
            ["docker", "exec", "-i", "abc123"],
        )

    def test_a_database_name_that_is_not_plain_is_refused(self) -> None:
        for name in ("portal; drop", "Portal", "", "a" * 40, "po rtal"):
            with self.assertRaises(program.Precondition):
                program.database_name(name)

    def test_the_count_query_reads_no_row_and_writes_nothing(self) -> None:
        self.assertTrue(program.COUNT_SQL.startswith("SELECT"))
        self.assertIn("count(*)", program.COUNT_SQL)
        for word in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "COPY"):
            self.assertNotIn(word, program.COUNT_SQL.upper())


class SnapshotTests(unittest.TestCase):
    def session(self, **kwargs: object) -> tuple[program.Snapshot, SessionProcess]:
        process = SessionProcess(GOOD_COUNTS, **kwargs)  # type: ignore[arg-type]
        return program.Snapshot(cast("subprocess.Popen[bytes]", process)), process

    def test_open_returns_the_exported_snapshot_inside_a_read_only_transaction(self) -> None:
        snapshot, process = self.session()
        self.assertEqual(snapshot.open(), SNAPSHOT)
        self.assertEqual(process.sent[0], "BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;")
        self.assertEqual(process.sent[1], "SELECT pg_export_snapshot();")

    def test_counts_are_read_in_the_same_session(self) -> None:
        snapshot, _ = self.session()
        snapshot.open()
        self.assertEqual(snapshot.counts(), GOOD_COUNTS)

    def test_close_rolls_back(self) -> None:
        snapshot, process = self.session()
        snapshot.open()
        snapshot.close()
        self.assertEqual(process.sent[-1], "ROLLBACK;")

    def test_something_that_is_not_one_snapshot_id_is_refused(self) -> None:
        snapshot, _ = self.session(snapshot="not-a-snapshot")
        with self.assertRaisesRegex(program.CheckFailed, "one snapshot id"):
            snapshot.open()

    def test_a_session_that_ends_before_it_answers_fails_instead_of_waiting(self) -> None:
        snapshot, _ = self.session(ends=False)
        with self.assertRaisesRegex(program.CheckFailed, "ended before it answered"):
            snapshot.open()


class TakeTests(TmpCase):
    def test_a_take_writes_a_root_only_directory_with_a_dump_and_the_live_counts_of_each_database(
        self,
    ) -> None:
        backup, spawner = make_backup(self.root)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(
            sorted(p.name for p in backup.iterdir()),
            ["manifest.json", "portal.sql.gz", "zitadel.sql.gz"],
        )
        for path in backup.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        manifest = json.loads((backup / "manifest.json").read_text())
        self.assertEqual(manifest["image"], IMAGE)
        self.assertEqual(manifest["databases"]["portal"]["tables"], GOOD_COUNTS)
        digest = hashlib.sha256((backup / "portal.sql.gz").read_bytes()).hexdigest()
        self.assertEqual(manifest["databases"]["portal"]["sha256"], digest)
        self.assertEqual(
            gzip.decompress((backup / "portal.sql.gz").read_bytes()), b"-- dump of portal\n"
        )
        self.assertEqual(spawner.snapshots_used, [f"--snapshot={SNAPSHOT}"] * 2)

    def test_the_dump_reads_the_snapshot_the_counts_were_taken_in(self) -> None:
        _, spawner = make_backup(self.root)
        self.assertEqual(spawner.events, ["dump", "counts", "dump", "counts"])
        for session in spawner.sessions:
            self.assertLess(
                session.sent.index("SELECT pg_export_snapshot();"),
                session.sent.index(program.COUNT_SQL),
            )
            self.assertEqual(session.sent[-1], "ROLLBACK;")

    def test_a_failed_dump_leaves_no_directory_to_be_mistaken_for_a_backup(self) -> None:
        spawner = FakeSpawner({"portal": GOOD_COUNTS, "zitadel": GOOD_COUNTS})
        spawner.dump_code = 1
        with self.assertRaisesRegex(program.CheckFailed, "pg_dump of portal failed"):
            program.take(
                root=self.root,
                runner=FakeDocker(),
                spawner=spawner,
                usage=roomy,
                say=lambda _: None,
            )
        self.assertEqual(list(self.root.iterdir()), [])

    def test_a_database_with_no_tables_is_not_backed_up(self) -> None:
        spawner = FakeSpawner({"portal": GOOD_COUNTS, "zitadel": {}})
        with self.assertRaisesRegex(
            program.CheckFailed, "zitadel: the live database has no tables"
        ):
            program.take(
                root=self.root,
                runner=FakeDocker(),
                spawner=spawner,
                usage=roomy,
                say=lambda _: None,
            )
        self.assertEqual(list(self.root.iterdir()), [])

    def test_two_database_containers_are_refused(self) -> None:
        docker = FakeDocker()
        docker.containers = ["a", "b"]
        with self.assertRaisesRegex(program.Precondition, "found 2"):
            program.take(
                root=self.root,
                runner=docker,
                spawner=FakeSpawner({}),
                usage=roomy,
                say=lambda _: None,
            )

    def test_a_take_that_would_leave_under_a_gibibyte_is_refused_before_anything_is_written(
        self,
    ) -> None:
        with self.assertRaisesRegex(program.Precondition, "not enough free space"):
            program.take(
                root=self.root,
                runner=FakeDocker(),
                spawner=FakeSpawner({}),
                usage=cramped,
                say=lambda _: None,
            )
        self.assertEqual(list(self.root.iterdir()), [])

    def test_the_output_carries_names_and_counts_only(self) -> None:
        said: list[str] = []
        program.take(
            root=self.root,
            runner=FakeDocker(),
            spawner=FakeSpawner({"portal": GOOD_COUNTS, "zitadel": GOOD_COUNTS}),
            usage=roomy,
            say=said.append,
        )
        self.assertTrue(
            all("insert" not in line.lower() and "-- dump" not in line for line in said)
        )


class VerifyTests(TmpCase):
    def verify(self, backup: Path, docker: FakeDocker) -> list[str]:
        said: list[str] = []
        program.verify(
            backup,
            runner=docker,
            spawner=FakeSpawner({}),
            sleep=lambda _: None,
            usage=roomy,
            say=said.append,
        )
        return said

    def restored(self, **changes: program.Counts) -> dict[str, program.Counts]:
        return {"portal": dict(GOOD_COUNTS), "zitadel": dict(GOOD_COUNTS), **changes}

    def test_a_restore_with_the_same_counts_passes_and_the_throwaway_is_removed(self) -> None:
        backup, _ = make_backup(self.root)
        docker = FakeDocker(self.restored())
        said = self.verify(backup, docker)
        self.assertEqual(docker.created, ["portal", "zitadel"])
        self.assertTrue(docker.removed())
        self.assertEqual(len(said), 3)
        self.assertEqual(said[-1], f"proven {backup.name}: counted toward retention")

    def test_a_restore_that_passes_marks_the_copy_proven_and_one_that_fails_does_not(self) -> None:
        backup, _ = make_backup(self.root)
        self.assertFalse(program.is_proven(backup))
        with self.assertRaises(program.CheckFailed):
            self.verify(backup, FakeDocker(self.restored(portal={"public.prospects": 1})))
        self.assertFalse(program.is_proven(backup))
        self.assertFalse((self.root / f"{backup.name}{program.PROVEN_SUFFIX}").exists())
        self.verify(backup, FakeDocker(self.restored()))
        self.assertTrue(program.is_proven(backup))

    def test_the_throwaway_has_no_network_no_logs_and_a_trust_only_socket(self) -> None:
        backup, _ = make_backup(self.root)
        docker = FakeDocker(self.restored())
        self.verify(backup, docker)
        run = next(call for call in docker.calls if call[1] == "run")
        self.assertIn("none", run[run.index("--network") + 1 :][:1])
        self.assertIn("--log-driver", run)
        self.assertIn("--rm", run)
        self.assertEqual(run[-1], IMAGE)
        self.assertNotIn("-p", run)

    def test_a_restore_that_counts_differently_fails_and_still_removes_the_throwaway(self) -> None:
        backup, _ = make_backup(self.root)
        docker = FakeDocker(self.restored(zitadel={**GOOD_COUNTS, "public.prospects": 119}))
        with self.assertRaisesRegex(program.CheckFailed, "zitadel: count mismatch"):
            self.verify(backup, docker)
        self.assertTrue(docker.removed())

    def test_a_restore_into_an_empty_database_fails(self) -> None:
        backup, _ = make_backup(self.root)
        with self.assertRaisesRegex(
            program.CheckFailed, "portal: the restored database holds no tables"
        ):
            self.verify(backup, FakeDocker(self.restored(portal={})))

    def test_a_dump_changed_after_it_was_taken_is_refused_before_a_restore_starts(self) -> None:
        backup, _ = make_backup(self.root)
        with (backup / "portal.sql.gz").open("ab") as handle:
            handle.write(b"tamper")
        docker = FakeDocker(self.restored())
        with self.assertRaisesRegex(program.CheckFailed, "does not match the digest"):
            self.verify(backup, docker)
        self.assertFalse(any(call[1] == "run" for call in docker.calls))

    def test_a_missing_dump_is_refused(self) -> None:
        backup, _ = make_backup(self.root)
        (backup / "zitadel.sql.gz").unlink()
        with self.assertRaisesRegex(program.CheckFailed, "is missing"):
            self.verify(backup, FakeDocker(self.restored()))

    def test_a_manifest_that_does_not_name_both_databases_is_refused(self) -> None:
        backup, _ = make_backup(self.root)
        manifest = json.loads((backup / "manifest.json").read_text())
        del manifest["databases"]["zitadel"]
        (backup / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(program.CheckFailed, "does not record exactly the databases"):
            self.verify(backup, FakeDocker(self.restored()))

    def test_a_throwaway_that_never_becomes_ready_fails_and_is_removed(self) -> None:
        docker = FakeDocker()
        docker.ready = False
        ticks = iter(range(0, 1000, 60))
        target = program.Throwaway(docker, FakeSpawner({}), IMAGE, "256m")
        with self.assertRaisesRegex(program.CheckFailed, "not ready"), target:
            target.wait_ready(timeout=100.0, sleep=lambda _: None, clock=lambda: float(next(ticks)))
        self.assertTrue(docker.removed())

    def test_a_failed_restore_load_fails_the_check(self) -> None:
        backup, _ = make_backup(self.root)
        spawner = FakeSpawner({})
        spawner.load_code = 3
        with self.assertRaisesRegex(program.CheckFailed, "stopped on an error"):
            program.verify(
                backup,
                runner=FakeDocker(self.restored()),
                spawner=spawner,
                sleep=lambda _: None,
                usage=roomy,
                say=lambda _: None,
            )

    def test_a_restore_is_refused_when_the_docker_disk_is_short(self) -> None:
        backup, _ = make_backup(self.root)
        docker = FakeDocker(self.restored())
        with self.assertRaisesRegex(program.Precondition, "not enough free space"):
            program.verify(
                backup, runner=docker, spawner=FakeSpawner({}), usage=cramped, say=lambda _: None
            )
        self.assertFalse(any(call[1] == "run" for call in docker.calls))


class SealTests(TmpCase):
    def seal(self, backup: Path, spawner: FakeSpawner) -> Path:
        return program.seal(
            backup,
            RECIPIENT,
            spawner=spawner,
            which=lambda _: "/usr/bin/age",
            usage=roomy,
            say=lambda _: None,
        )

    def test_a_seal_is_one_age_file_beside_the_backup_with_its_digest(self) -> None:
        backup, _ = make_backup(self.root)
        spawner = FakeSpawner({})
        sealed = self.seal(backup, spawner)
        self.assertEqual(sealed, self.root / f"{backup.name}.tar.age")
        self.assertEqual(stat.S_IMODE(sealed.stat().st_mode), 0o600)
        self.assertEqual(sealed.read_bytes(), AGE_FILE)
        self.assertEqual(spawner.calls[0], ["age", "-r", RECIPIENT])
        digest = hashlib.sha256(AGE_FILE).hexdigest()
        self.assertEqual(
            (self.root / f"{sealed.name}.sha256").read_text(), f"{digest}  {sealed.name}\n"
        )

    def test_what_is_encrypted_is_the_whole_backup_directory(self) -> None:
        backup, _ = make_backup(self.root)
        spawner = FakeSpawner({})
        self.seal(backup, spawner)
        self.assertIn(f"{backup.name}/portal.sql.gz".encode(), spawner.age_input)
        self.assertIn(f"{backup.name}/manifest.json".encode(), spawner.age_input)

    def test_a_failed_age_leaves_no_sealed_file(self) -> None:
        backup, _ = make_backup(self.root)
        spawner = FakeSpawner({})
        spawner.age_code = 1
        with self.assertRaisesRegex(program.CheckFailed, "sealing failed"):
            self.seal(backup, spawner)
        self.assertFalse((self.root / f"{backup.name}.tar.age").exists())

    def test_without_age_nothing_is_sealed(self) -> None:
        backup, _ = make_backup(self.root)
        with self.assertRaisesRegex(program.Precondition, "age is not installed"):
            program.seal(
                backup,
                RECIPIENT,
                spawner=FakeSpawner({}),
                which=lambda _: None,
                usage=roomy,
                say=lambda _: None,
            )

    def test_an_existing_sealed_file_is_not_overwritten(self) -> None:
        backup, _ = make_backup(self.root)
        (self.root / f"{backup.name}.tar.age").write_bytes(b"x")
        with self.assertRaisesRegex(program.Precondition, "already exists"):
            self.seal(backup, FakeSpawner({}))

    def test_a_directory_this_program_did_not_take_is_not_sealed(self) -> None:
        stray = self.root / "stray"
        stray.mkdir(parents=True)
        with self.assertRaisesRegex(program.Precondition, "not a backup this program took"):
            self.seal(stray, FakeSpawner({}))


class CiphertextTests(unittest.TestCase):
    def test_an_age_file_with_one_recipient_passes(self) -> None:
        program.require_ciphertext(AGE_FILE)

    def test_a_plaintext_archive_is_refused(self) -> None:
        with self.assertRaisesRegex(program.CheckFailed, "does not start as an age file"):
            program.require_ciphertext(b"portal.sql.gz\x00" * 10)

    def test_two_recipients_are_refused(self) -> None:
        two = b"age-encryption.org/v1\n-> X25519 aaaa\nb\n-> X25519 cccc\nd\n--- mac\nx"
        with self.assertRaisesRegex(program.CheckFailed, "2 recipient stanzas"):
            program.require_ciphertext(two)

    def test_a_header_that_never_ends_is_refused(self) -> None:
        with self.assertRaisesRegex(program.CheckFailed, "0 recipient stanzas"):
            program.require_ciphertext(b"age-encryption.org/v1\n-> X25519 aaaa\nb\n")


class FakeStore(ModuleType):
    """The estate's object-store client: what it was asked to put and get, in memory."""

    class ObjectStorageError(Exception):
        pass

    def __init__(self) -> None:
        super().__init__("fake_store")
        self.objects: dict[str, bytes] = {}
        self.puts: list[dict[str, object]] = []
        self.fail_put = False

    def put_object(self, **kwargs: object) -> None:
        if self.fail_put:
            raise self.ObjectStorageError("403")
        self.puts.append(kwargs)
        self.objects[cast(str, kwargs["key"])] = cast(bytes, kwargs["data"])

    def get_object(self, **kwargs: object) -> bytes:
        key = cast(str, kwargs["key"])
        if key not in self.objects:
            raise self.ObjectStorageError("404")
        return self.objects[key]


DEST_ENV = (
    f"STATE_COPY_RECIPIENT={RECIPIENT}\n"
    "STATE_COPY_DEST_BUCKET=example-bucket\n"
    "STATE_COPY_DEST_ENDPOINT=s3.example.invalid\n"
    "STATE_COPY_DEST_REGION=example-1\n"
    "STATE_COPY_DEST_ACCESS_KEY_ID=EXAMPLEWRITE\n"
    "STATE_COPY_DEST_SECRET_ACCESS_KEY=EXAMPLEWRITESECRET\n"
)
READ_ENV = (
    "BACKUP_DRILL_COPY_PRIMARY_BUCKET=example-bucket\n"
    "BACKUP_DRILL_COPY_PRIMARY_ENDPOINT=s3.example.invalid\n"
    "BACKUP_DRILL_COPY_PRIMARY_REGION=example-1\n"
    "BACKUP_DRILL_COPY_PRIMARY_ACCESS_KEY_ID=EXAMPLEREAD\n"
    "BACKUP_DRILL_COPY_PRIMARY_SECRET_ACCESS_KEY=EXAMPLEREADSECRET\n"
)


class ShipTests(TmpCase):
    def setUp(self) -> None:
        super().setUp()
        self.root.mkdir(parents=True)
        self.env = self.root.parent / "state-copy.env"
        self.env.write_text(DEST_ENV)
        self.read_env = self.root.parent / "drill.env"
        self.read_env.write_text(READ_ENV)
        self.store = FakeStore()
        self.sealed = self.root / f"{STAMP}.tar.age"
        self.key = f"state/ops1-control-plane/generations/{STAMP}/control-plane.tar.age"

    def place(self, blob: bytes = AGE_FILE, digest: str | None = None) -> None:
        self.sealed.write_bytes(blob)
        recorded = digest if digest is not None else hashlib.sha256(blob).hexdigest()
        (self.root / f"{self.sealed.name}.sha256").write_text(f"{recorded}  {self.sealed.name}\n")

    def ship(self) -> str:
        return program.ship(
            self.sealed, env_file=self.env, scripts=self.root, store=self.store, say=lambda _: None
        )

    def test_a_sealed_backup_is_put_under_the_control_plane_prefix_with_copy_1s_put_key(
        self,
    ) -> None:
        self.place()
        self.assertEqual(self.ship(), self.key)
        self.assertEqual(self.store.objects, {self.key: AGE_FILE})
        put = self.store.puts[0]
        self.assertEqual(put["bucket"], "example-bucket")
        self.assertEqual(put["access_key"], "EXAMPLEWRITE")
        self.assertEqual(
            sorted(put), ["access_key", "bucket", "data", "endpoint", "key", "region", "secret_key"]
        )

    def test_nothing_that_is_not_an_age_file_leaves_the_host(self) -> None:
        self.place(b"portal.sql.gz plaintext archive")
        with self.assertRaisesRegex(program.CheckFailed, "does not start as an age file"):
            self.ship()
        self.assertEqual(self.store.puts, [])

    def test_a_file_changed_since_it_was_sealed_is_not_shipped(self) -> None:
        self.place(digest="0" * 64)
        with self.assertRaisesRegex(
            program.CheckFailed, "does not match the digest recorded when it was sealed"
        ):
            self.ship()
        self.assertEqual(self.store.puts, [])

    def test_a_missing_digest_file_stops_the_ship(self) -> None:
        self.sealed.write_bytes(AGE_FILE)
        with self.assertRaisesRegex(program.Precondition, "seal the backup first"):
            self.ship()

    def test_without_the_state_copy_file_nothing_is_shipped(self) -> None:
        self.place()
        self.env.unlink()
        with self.assertRaisesRegex(program.Precondition, "is not there"):
            self.ship()

    def test_a_missing_destination_name_is_named_and_its_value_is_not(self) -> None:
        self.place()
        self.env.write_text(DEST_ENV.replace("STATE_COPY_DEST_REGION=example-1\n", ""))
        with self.assertRaisesRegex(program.Precondition, "STATE_COPY_DEST_REGION") as caught:
            self.ship()
        self.assertNotIn("EXAMPLEWRITE", str(caught.exception))

    def test_a_name_that_is_not_one_this_program_made_is_refused(self) -> None:
        self.sealed = self.root / "not-a-stamp.tar.age"
        self.place()
        with self.assertRaisesRegex(program.Precondition, "not a sealed backup this program named"):
            self.ship()

    def test_a_failed_put_fails_the_ship_without_quoting_the_store(self) -> None:
        self.place()
        self.store.fail_put = True
        with self.assertRaisesRegex(
            program.CheckFailed, "the put to backup copy 1 failed"
        ) as caught:
            self.ship()
        self.assertNotIn("403", str(caught.exception))

    def test_an_estate_recipient_that_is_not_one_age_key_stops_the_seal(self) -> None:
        self.env.write_text(DEST_ENV.replace(RECIPIENT, "AGE-SECRET-KEY-1" + "Q" * 40))
        with self.assertRaisesRegex(program.Precondition, "not a single age1 recipient"):
            program.recipient_of(program.load_env(self.env))

    def check(self) -> None:
        program.offsite_check(
            self.sealed,
            read_env_file=self.read_env,
            scripts=self.root,
            store=self.store,
            say=lambda _: None,
        )

    def test_the_read_back_passes_when_the_object_is_the_sealed_file(self) -> None:
        self.place()
        self.ship()
        self.check()

    def test_the_read_back_fails_when_the_object_differs(self) -> None:
        self.place()
        self.ship()
        self.store.objects[self.key] = AGE_FILE + b"x"
        with self.assertRaisesRegex(program.CheckFailed, "not the one sealed on the host"):
            self.check()

    def test_the_read_back_fails_when_nothing_was_shipped(self) -> None:
        self.place()
        with self.assertRaisesRegex(program.CheckFailed, "read back from backup copy 1 failed"):
            self.check()

    def test_the_read_back_uses_the_read_key_and_never_the_put_key(self) -> None:
        self.place()
        self.ship()
        seen: list[dict[str, object]] = []
        original = self.store.get_object

        def spy(**kwargs: object) -> bytes:
            seen.append(kwargs)
            return original(**kwargs)

        self.store.get_object = spy  # type: ignore[method-assign]
        self.check()
        self.assertEqual(seen[0]["access_key"], "EXAMPLEREAD")

    def test_an_object_store_client_that_is_not_staged_stops_the_ship(self) -> None:
        self.place()
        with self.assertRaisesRegex(program.Precondition, "release must be staged"):
            program.ship(
                self.sealed, env_file=self.env, scripts=self.root / "absent", say=lambda _: None
            )


def found(pattern: str, text: str) -> "re.Match[str]":
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise AssertionError(f"{pattern!r} is not in the text")
    return match


NOW = datetime.datetime(2026, 11, 19, 12, 0, tzinfo=datetime.UTC)


def plant(root: Path, name: str, *, manifest: bool = True, proven: bool = True) -> Path:
    """A backup directory as `take` leaves it (manifest) and `verify` leaves it (mark)."""
    backup = root / name
    backup.mkdir(parents=True)
    (backup / "portal.sql.gz").write_bytes(b"x")
    if manifest:
        (backup / program.MANIFEST_FILE).write_text(json.dumps({"version": 1}) + "\n")
    if proven:
        program.mark_proven(backup)
    (root / f"{name}{program.SEALED_SUFFIX}").write_bytes(b"x")
    (root / f"{name}{program.SEALED_SUFFIX}.sha256").write_text("x")
    return backup


def nights(count: int) -> list[str]:
    """Stamps of `count` nights, oldest first, the newest two days before NOW."""
    first = NOW - datetime.timedelta(days=count + 1)
    return [(first + datetime.timedelta(days=n)).strftime("%Y%m%dT024000Z") for n in range(count)]


class PruneTests(TmpCase):
    def prune(self, keep: int, protect: Path, now: datetime.datetime = NOW) -> list[str]:
        said: list[str] = []
        program.prune(self.root, keep, protect=protect, now=now, say=said.append)
        return said

    def left(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_dir())

    def test_the_newest_proven_are_kept_and_the_protected_one_is_never_removed(self) -> None:
        names = nights(5)
        for name in names:
            plant(self.root, name)
        self.prune(2, self.root / names[0])
        self.assertEqual(self.left(), [names[0], names[3], names[4]])
        for gone in names[1:3]:
            self.assertFalse((self.root / f"{gone}.tar.age").exists())
            self.assertFalse((self.root / f"{gone}.tar.age.sha256").exists())
            self.assertFalse((self.root / f"{gone}{program.PROVEN_SUFFIX}").exists())
        self.assertTrue((self.root / f"{names[0]}.tar.age").exists())

    def test_a_directory_without_a_manifest_does_not_push_out_a_proven_copy(self) -> None:
        names = nights(9)
        proven, killed = names[:7], names[7:]
        for name in proven:
            plant(self.root, name)
        for name in killed:
            plant(self.root, name, manifest=False, proven=False)
        said = self.prune(7, self.root / proven[-1])
        self.assertEqual(self.left(), proven)
        self.assertEqual(said, ["swept 2 unproven directories"])

    def test_a_directory_that_lost_its_manifest_does_not_count_though_its_mark_is_there(
        self,
    ) -> None:
        names = nights(8)
        proven, lost = names[:7], names[7]
        for name in proven:
            plant(self.root, name)
        (plant(self.root, lost) / program.MANIFEST_FILE).unlink()
        self.prune(7, self.root / proven[-1])
        self.assertEqual(self.left(), proven)

    def test_a_directory_whose_restore_failed_does_not_count_either(self) -> None:
        names = nights(9)
        proven, unproven = names[:7], names[7:]
        for name in proven:
            plant(self.root, name)
        for name in unproven:
            plant(self.root, name, proven=False)
        self.prune(7, self.root / proven[-1])
        self.assertEqual(self.left(), proven)

    def test_a_directory_swept_for_want_of_proof_takes_its_sidecars(self) -> None:
        proven, killed = nights(2)
        plant(self.root, proven)
        plant(self.root, killed, manifest=False, proven=False)
        self.prune(1, self.root / proven)
        self.assertFalse((self.root / f"{killed}{program.SEALED_SUFFIX}").exists())
        self.assertFalse((self.root / f"{killed}{program.SEALED_SUFFIX}.sha256").exists())

    def test_a_take_still_running_is_left_alone(self) -> None:
        proven = nights(1)[0]
        plant(self.root, proven)
        running = (NOW - datetime.timedelta(hours=2, minutes=59)).strftime("%Y%m%dT%H%M%SZ")
        abandoned = (NOW - datetime.timedelta(hours=3)).strftime("%Y%m%dT%H%M%SZ")
        plant(self.root, running, manifest=False, proven=False)
        plant(self.root, abandoned, manifest=False, proven=False)
        self.prune(7, self.root / proven)
        self.assertEqual(self.left(), sorted([proven, running]))

    def test_a_stamp_from_the_future_is_not_swept(self) -> None:
        proven = nights(1)[0]
        plant(self.root, proven)
        future = (NOW + datetime.timedelta(days=1)).strftime("%Y%m%dT%H%M%SZ")
        plant(self.root, future, manifest=False, proven=False)
        self.prune(7, self.root / proven)
        self.assertIn(future, self.left())

    def test_a_stamp_that_is_not_a_date_is_left_alone(self) -> None:
        proven = nights(1)[0]
        plant(self.root, proven)
        odd = "20269999T999999Z"
        plant(self.root, odd, manifest=False, proven=False)
        self.prune(7, self.root / proven)
        self.assertIn(odd, self.left())

    def test_the_last_proven_copy_survives_whatever_else_is_there(self) -> None:
        names = nights(5)
        plant(self.root, names[0])
        for name in names[1:]:
            plant(self.root, name, proven=False)
        self.prune(1, self.root / names[0])
        self.assertEqual(self.left(), [names[0]])
        self.assertTrue(program.is_proven(self.root / names[0]))

    def test_a_proven_copy_is_kept_when_the_newest_directories_are_all_unproven(self) -> None:
        names = nights(4)
        plant(self.root, names[0])
        for name in names[1:]:
            plant(self.root, name, manifest=False, proven=False)
        # `protect` is a directory that was not proven; it stays, and so does the proven one.
        self.prune(1, self.root / names[3])
        self.assertEqual(self.left(), [names[0], names[3]])

    def test_a_manifest_changed_after_the_proof_is_no_longer_proven(self) -> None:
        backup = plant(self.root, nights(1)[0])
        self.assertTrue(program.is_proven(backup))
        (backup / program.MANIFEST_FILE).write_text(json.dumps({"version": 1, "x": 1}) + "\n")
        self.assertFalse(program.is_proven(backup))

    def test_a_mark_without_a_manifest_proves_nothing(self) -> None:
        backup = plant(self.root, nights(1)[0])
        (backup / program.MANIFEST_FILE).unlink()
        self.assertFalse(program.is_proven(backup))

    def test_a_mark_is_not_written_for_a_directory_without_a_manifest(self) -> None:
        backup = plant(self.root, nights(1)[0], manifest=False, proven=False)
        with self.assertRaises(program.CheckFailed):
            program.mark_proven(backup)
        self.assertFalse((self.root / f"{backup.name}{program.PROVEN_SUFFIX}").exists())

    def test_a_removal_that_stops_half_way_leaves_no_proven_copy(self) -> None:
        old, new = nights(2)
        half = plant(self.root, old)
        plant(self.root, new)
        with (
            mock.patch("shutil.rmtree", side_effect=OSError("disk error")),
            self.assertRaises(OSError),
        ):
            self.prune(1, self.root / new)
        self.assertTrue(half.is_dir())
        self.assertFalse(program.is_proven(half))

    def test_a_directory_that_is_not_a_stamp_is_left_alone(self) -> None:
        (self.root / "notes").mkdir(parents=True)
        newest = plant(self.root, "20261111T024000Z")
        self.prune(1, newest)
        self.assertTrue((self.root / "notes").is_dir())

    def test_a_link_named_like_a_stamp_is_left_alone(self) -> None:
        proven = nights(1)[0]
        plant(self.root, proven)
        elsewhere = Path(self._tmp.name) / "elsewhere"
        elsewhere.mkdir()
        link = self.root / "20200101T024000Z"
        link.symlink_to(elsewhere)
        self.prune(7, self.root / proven)
        self.assertTrue(elsewhere.is_dir())
        self.assertTrue(link.is_symlink())

    def test_keeping_none_is_refused(self) -> None:
        self.root.mkdir(parents=True)
        with self.assertRaises(program.Precondition):
            program.prune(self.root, 0, protect=self.root)

    def test_the_abandon_age_is_longer_than_the_service_allows_a_run(self) -> None:
        service = (ROLE / "files" / "branchleft-control-plane-backup.service").read_text()
        hours = int(found(r"^TimeoutStartSec=(\d+)h$", service)[1])
        self.assertGreater(program.ABANDONED_AFTER, datetime.timedelta(hours=hours))


class MetricsTests(TmpCase):
    def test_each_stage_keeps_its_own_time(self) -> None:
        program.record_success(self.root, "verified_on_host", now=100.0)
        program.record_success(self.root, "shipped_offsite", now=200.0)
        text = (self.root / program.METRICS_FILE).read_text()
        self.assertIn('{stage="verified_on_host"} 100', text)
        self.assertIn('{stage="shipped_offsite"} 200', text)
        program.record_success(self.root, "verified_on_host", now=300.0)
        again = (self.root / program.METRICS_FILE).read_text()
        self.assertIn('{stage="verified_on_host"} 300', again)
        self.assertIn('{stage="shipped_offsite"} 200', again)


class FailureMarkTests(TmpCase):
    def test_a_failure_writes_its_time_to_a_file_of_its_own(self) -> None:
        program.record_failure(self.root, now=1234.0)
        text = (self.root / program.FAILED_METRICS_FILE).read_text()
        self.assertIn(f"# TYPE {program.FAILURE_METRIC} gauge\n", text)
        self.assertIn(f"\n{program.FAILURE_METRIC} 1234\n", text)
        mode = (self.root / program.FAILED_METRICS_FILE).stat().st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o644)

    def test_a_later_failure_replaces_the_time(self) -> None:
        program.record_failure(self.root, now=100.0)
        program.record_failure(self.root, now=200.0)
        text = (self.root / program.FAILED_METRICS_FILE).read_text()
        self.assertIn(f"{program.FAILURE_METRIC} 200", text)
        self.assertNotIn(f"{program.FAILURE_METRIC} 100", text)

    def test_a_success_never_touches_the_failure_mark(self) -> None:
        program.record_failure(self.root, now=100.0)
        before = (self.root / program.FAILED_METRICS_FILE).read_text()
        program.record_success(self.root, "shipped_offsite", now=200.0)
        self.assertEqual((self.root / program.FAILED_METRICS_FILE).read_text(), before)
        self.assertNotIn(program.FAILURE_METRIC, (self.root / program.METRICS_FILE).read_text())

    def test_the_success_line_is_the_one_the_alert_reads(self) -> None:
        program.record_success(self.root, "shipped_offsite", now=200.0)
        line = f'{program.SUCCESS_METRIC}{{stage="shipped_offsite"}} 200'
        self.assertIn(line, (self.root / program.METRICS_FILE).read_text().splitlines())
        self.assertTrue(program.METRIC_LINE.match(line))

    def test_the_command_marks_the_failure_without_touching_docker_or_a_lock(self) -> None:
        said: list[str] = []
        code = program.main(["--metrics-dir", str(self.root), "mark-failed"], say=said.append)
        self.assertEqual(code, 0)
        self.assertTrue((self.root / program.FAILED_METRICS_FILE).is_file())
        self.assertEqual(said[-1], "OK")


class LockTests(TmpCase):
    def test_a_held_deploy_lock_stops_the_take(self) -> None:
        self.root.mkdir(parents=True)
        path = self.root / f"{program.PROJECT}.deploy.lock"
        holder = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX)
        with (
            self.assertRaisesRegex(program.Precondition, "a deploy of control-plane is running"),
            program.deploy_lock(self.root),
        ):
            self.fail("the lock was taken while held")

    def test_a_free_lock_is_taken_and_released(self) -> None:
        self.root.mkdir(parents=True)
        with program.deploy_lock(self.root):
            pass
        with program.deploy_lock(self.root):
            pass


class MainTests(TmpCase):
    def run_main(self, *args: str) -> tuple[int, list[str]]:
        said: list[str] = []
        return program.main(list(args), say=said.append), said

    def test_the_install_time_check_passes_and_touches_nothing(self) -> None:
        code, said = self.run_main("--check")
        self.assertEqual((code, said), (0, ["OK"]))

    def test_a_missing_precondition_exits_2_and_says_it_was_not_run(self) -> None:
        code, said = self.run_main(
            "--env-file", str(self.root / "absent.env"), "seal", str(self.root)
        )
        self.assertEqual(code, 2)
        self.assertTrue(said[0].startswith("NOT RUN: "))

    def test_a_failed_check_exits_1(self) -> None:
        self.root.mkdir(parents=True)
        code, said = self.run_main("verify", str(self.root))
        self.assertEqual(code, 1)
        self.assertTrue(said[0].startswith("FAIL: "))

    def test_offsite_check_without_a_read_file_is_not_run(self) -> None:
        code, said = self.run_main("offsite-check", str(self.root / f"{STAMP}.tar.age"))
        self.assertEqual(code, 2)
        self.assertIn("--read-env-file", said[0])

    def test_a_command_is_required(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            program.main([], say=lambda _: None)
        self.assertEqual(caught.exception.code, 2)


def load_yaml(path: Path) -> dict[str, object]:
    loaded = yaml.safe_load(path.read_text())
    if not isinstance(loaded, dict):
        raise AssertionError(f"{path} is not a mapping")
    return cast(dict[str, object], loaded)


def role_vars(role: str) -> dict[str, object]:
    return load_yaml(ROLES / role / "vars" / "main.yml")


class RoleContractTests(unittest.TestCase):
    """A constant the program holds must equal what its neighbours say."""

    def test_the_program_paths_are_the_roles(self) -> None:
        mine = role_vars("control_plane_backup")
        self.assertEqual(str(program.BACKUP_ROOT), mine["control_plane_backup_root"])
        self.assertEqual(str(program.ENV_FILE), mine["control_plane_backup_env_file"])
        directory = mine["control_plane_backup_program_dir"]
        installed = f"{directory}/{mine['control_plane_backup_program_name']}"
        service = (ROLE / "files" / "branchleft-control-plane-backup.service").read_text()
        self.assertIn(f"ExecStart=/usr/bin/python3 -I {installed} run\n", service)
        self.assertEqual(Path(installed).name, Path(program.__file__).name)

    def test_the_destination_file_is_the_one_backup_restore_writes(self) -> None:
        theirs = role_vars("backup_restore")
        self.assertEqual(str(program.ENV_FILE), theirs["backup_restore_state_copy_env_file"])
        names = cast(list[str], theirs["backup_restore_state_copy_env_names"])
        for name in (
            "STATE_COPY_RECIPIENT",
            *(
                f"STATE_COPY_DEST_{n}"
                for n in ("BUCKET", "ENDPOINT", "REGION", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY")
            ),
        ):
            self.assertIn(name, names)

    def test_the_object_store_client_is_where_backup_worker_stages_it(self) -> None:
        theirs = role_vars("backup_worker")
        staged = f"{theirs['backup_worker_current_link']}/infra/provisioning/scripts"
        self.assertEqual(str(program.RELEASE_SCRIPTS), staged)
        paths = [
            entry["path"]
            for entry in cast(
                list[dict[str, str]],
                load_yaml(ROLES / "backup_worker" / "defaults" / "main.yml")[
                    "backup_worker_release_files"
                ],
            )
        ]
        self.assertIn("infra/provisioning/scripts/shared_objectstorage.py", paths)
        self.assertIn("db/provision/objectstorage.py", paths)

    def test_the_stack_names_are_the_control_planes(self) -> None:
        control_plane = role_vars("control_plane")
        self.assertEqual(program.PROJECT, control_plane["control_plane_project_name"])
        db = role_vars("control_plane_db")
        self.assertEqual(
            f"{program.PROJECT}-{program.DB_SERVICE}-1", db["control_plane_db_hba_container"]
        )
        self.assertIn(db["control_plane_db_database_name"], program.DATABASES)

    def test_the_compose_file_has_the_database_service_and_the_sign_in_database(self) -> None:
        compose = (
            ROLES.parents[1] / "hetzner" / "control-plane" / "stack" / "compose.yml"
        ).read_text()
        self.assertIn("\n  db:\n", compose)
        self.assertIn("ZITADEL_DATABASE_POSTGRES_DATABASE: zitadel", compose)
        self.assertIn("name: control-plane", compose)

    def test_the_lock_is_the_one_the_deploy_tool_takes(self) -> None:
        tool = (ROLES.parents[1] / "hetzner" / "provision" / "branchleft_deploy.py").read_text()
        self.assertIn('f"{stack}.deploy.lock"', tool)

    def test_the_timer_sits_between_the_dump_worker_and_the_state_copy(self) -> None:
        timer = (ROLE / "files" / "branchleft-control-plane-backup.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 02:40:00\n", timer)
        self.assertIn("Persistent=true", timer)

    def test_a_failed_run_starts_the_unit_that_marks_it(self) -> None:
        mine = role_vars("control_plane_backup")
        failed = str(mine["control_plane_backup_failed_unit"])
        service = (ROLE / "files" / "branchleft-control-plane-backup.service").read_text()
        self.assertIn(f"\nOnFailure={failed}\n", service)
        # In [Unit], where systemd reads it; under [Service] it is ignored without a word.
        self.assertLess(service.index("OnFailure="), service.index("[Service]"))
        self.assertTrue((ROLE / "files" / failed).is_file())

    def test_the_failure_unit_runs_the_programs_mark_and_nothing_else(self) -> None:
        mine = role_vars("control_plane_backup")
        failed = (ROLE / "files" / str(mine["control_plane_backup_failed_unit"])).read_text()
        directory, name = (
            mine["control_plane_backup_program_dir"],
            mine["control_plane_backup_program_name"],
        )
        installed = f"{directory}/{name}"
        self.assertEqual(
            re.findall(r"^Exec\w+=.*$", failed, re.MULTILINE),
            [f"ExecStart=/usr/bin/python3 -I {installed} mark-failed"],
        )
        self.assertIn("\nType=oneshot\n", failed)
        # node_exporter reads the mark and is not root.
        self.assertIn("\nUMask=0022\n", failed)
        # A failure unit that itself named OnFailure= could start itself without end.
        self.assertEqual(re.findall(r"^OnFailure=", failed, re.MULTILINE), [])

    def test_the_failure_unit_is_installed_before_the_service_that_names_it(self) -> None:
        task = next(t for t in self.tasks() if "failure unit" in str(t["name"]))
        loop = cast(list[str], task["loop"])
        self.assertEqual(
            loop,
            [
                "{{ control_plane_backup_failed_unit }}",
                "{{ control_plane_backup_service_unit }}",
                "{{ control_plane_backup_timer_unit }}",
            ],
        )
        copy = cast(dict[str, object], task["ansible.builtin.copy"])
        self.assertEqual((copy["owner"], copy["mode"]), ("root", "0644"))

    def test_the_program_writes_where_the_monitoring_stacks_node_exporter_reads(self) -> None:
        unit = (ROLES.parents[1] / "hetzner" / "provision" / "node-exporter.service").read_text()
        self.assertIn(str(program.METRICS_DIR), unit)

    def test_the_alert_rules_read_the_names_the_program_writes(self) -> None:
        rules = (
            ROLES.parents[1] / "hetzner" / "monitoring" / "stack" / "prometheus" / "alerts.yml"
        ).read_text()
        self.assertIn(f'time() - {program.SUCCESS_METRIC}{{host="ops1"}} > 129600', rules)
        self.assertIn(f'{program.FAILURE_METRIC}{{host="ops1"}}', rules)
        self.assertIn(f'{program.SUCCESS_METRIC}{{host="ops1", stage="shipped_offsite"}}', rules)
        # The stage the failure rule clears on is one the program records, after the ship.
        source = Path(program.__file__).read_text()
        self.assertIn('record_success(args.metrics_dir, "shipped_offsite")', source)

    def test_the_stale_bound_leaves_days_before_copy_1_expires_the_last_object(self) -> None:
        rules = (
            ROLES.parents[1] / "hetzner" / "monitoring" / "stack" / "prometheus" / "alerts.yml"
        ).read_text()
        bound = int(found(rf'{program.SUCCESS_METRIC}\{{host="ops1"\}} > (\d+)', rules)[1])
        service = (ROLE / "files" / "branchleft-control-plane-backup.service").read_text()
        hours = int(found(r"^TimeoutStartSec=(\d+)h$", service)[1])
        # Past one healthy night (24h, the timer's 5m delay and a run that takes the whole timeout).
        self.assertGreater(bound, (24 + hours) * 3600 + 5 * 60)
        # Copy 1 expires a state/ object after 10 days (README); the alert leaves most of them.
        self.assertLess(bound, 5 * 24 * 3600)

    def tasks(self) -> list[dict[str, object]]:
        loaded = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
        return cast(list[dict[str, object]], loaded)

    def test_the_timer_task_is_gated_on_both_switches(self) -> None:
        task = next(t for t in self.tasks() if str(t["name"]).startswith("Hold the nightly timer"))
        conditions = " ".join(cast(list[str], task["when"]))
        self.assertIn(
            "control_plane_backup_timer_enabled | bool"
            " or control_plane_backup_timer_may_disable | bool",
            conditions,
        )

    def test_the_timer_defaults_to_off(self) -> None:
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        self.assertIs(defaults["control_plane_backup_timer_enabled"], False)
        self.assertIs(defaults["control_plane_backup_timer_may_disable"], False)

    def test_the_program_is_installed_only_after_its_own_check(self) -> None:
        task = next(t for t in self.tasks() if str(t["name"]).startswith("Install the program"))
        copy = cast(dict[str, object], task["ansible.builtin.copy"])
        self.assertEqual(copy["validate"], "/usr/bin/python3 -I %s --check")
        self.assertEqual(copy["mode"], "0755")

    def test_the_backup_directory_is_root_only(self) -> None:
        task = next(t for t in self.tasks() if "on-host backup directory" in str(t["name"]))
        spec = cast(dict[str, object], task["ansible.builtin.file"])
        self.assertEqual((spec["owner"], spec["mode"]), ("root", "0700"))

    def test_the_role_names_no_work_item_or_person(self) -> None:
        for path in ROLE.rglob("*"):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix in {".py", ".yml", ".md", ".service", ".timer", ".toml"}
            ):
                text = path.read_text()
                self.assertNotRegex(text, r"(?i)\b(?:workspace|issue)\s*#\s*\d+", str(path))


if __name__ == "__main__":
    unittest.main()
