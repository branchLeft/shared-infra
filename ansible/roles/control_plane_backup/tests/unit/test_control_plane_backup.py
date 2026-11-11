"""Unit tests for the control-plane backup program: what it takes, proves, refuses and ships.

The program's commands are run for real in Python with every outside effect replaced by a
fake that records what it was asked: the docker client, the psql session, pg_dump, the
throwaway restore, age and the object store. No test reaches a database, a host or a bucket.
A control is proven by sabotage: each refusal below goes red when the line that makes it is
broken (the role README lists the edits).
"""

import fcntl
import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from collections import deque
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import IO, cast

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
        self.assertEqual(len(said), 2)

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


class PruneTests(TmpCase):
    def test_the_newest_are_kept_and_the_protected_one_is_never_removed(self) -> None:
        names = [f"2026111{d}T024000Z" for d in range(1, 6)]
        for name in names:
            (self.root / name).mkdir(parents=True)
            (self.root / f"{name}.tar.age").write_bytes(b"x")
            (self.root / f"{name}.tar.age.sha256").write_text("x")
        program.prune(self.root, 2, protect=self.root / names[0], say=lambda _: None)
        left = sorted(p.name for p in self.root.iterdir() if p.is_dir())
        self.assertEqual(left, [names[0], names[3], names[4]])
        self.assertFalse((self.root / f"{names[1]}.tar.age").exists())
        self.assertTrue((self.root / f"{names[0]}.tar.age").exists())

    def test_a_directory_that_is_not_a_stamp_is_left_alone(self) -> None:
        (self.root / "notes").mkdir(parents=True)
        (self.root / "20261111T024000Z").mkdir()
        program.prune(self.root, 1, protect=self.root / "20261111T024000Z", say=lambda _: None)
        self.assertTrue((self.root / "notes").is_dir())

    def test_keeping_none_is_refused(self) -> None:
        self.root.mkdir(parents=True)
        with self.assertRaises(program.Precondition):
            program.prune(self.root, 0, protect=self.root)


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
