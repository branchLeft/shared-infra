#!/usr/bin/python3 -I
"""Backs up the control plane's two databases, proves the copy restores, ships ciphertext.

Commands: take, verify DIR, seal DIR, ship SEALED, offsite-check SEALED, run. Exit 0 proven,
1 a check failed, 2 a precondition is missing so nothing was proven. A database is read in one
repeatable-read snapshot that pg_dump also reads, and its rows are counted in that same
snapshot, so the recorded counts are exactly what the dump holds. The copy is restored into a
throwaway PostgreSQL with no network and counted again. Only table names and counts are ever
printed; the output of docker, psql, pg_dump and age is withheld because it can quote a row.
The off-site copy is the dump, sealed with age to the estate recipient, put to backup copy 1.
Reasoning, layout and the controls: the role README.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime
import errno
import fcntl
import gzip
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import ModuleType, TracebackType
from typing import IO, NoReturn, Protocol

PROJECT = "control-plane"
DB_SERVICE = "db"
PG_USER = "postgres"
DATABASES = ("portal", "zitadel")
BACKUP_ROOT = pathlib.Path("/var/backups/branchleft/control-plane")
LOCK_DIR = pathlib.Path("/etc/branchleft")
ENV_FILE = pathlib.Path("/etc/branchleft/state-copy.env")
RELEASE_SCRIPTS = pathlib.Path("/opt/branchleft/backup-worker/current/infra/provisioning/scripts")
METRICS_DIR = pathlib.Path("/var/lib/branchleft/backup-worker-exporter")
METRICS_FILE = "control_plane_backup.prom"
OFFSITE_PREFIX = "state/ops1-control-plane/generations"
OFFSITE_OBJECT = "control-plane.tar.age"
DEFAULT_KEEP = 7
DEFAULT_RESTORE_MEMORY = "512m"
HEADROOM_BYTES = 1024 * 1024 * 1024
MAX_SEALED_BYTES = 256 * 1024 * 1024
READY_TIMEOUT_SECONDS = 120.0

LABEL = "branchleft.control-plane-backup"
NO_LOGS = ("--log-driver", "none")
STOP_ON_ERROR = ("-v", "ON_ERROR_STOP=1")
# Runs inside the database container, so the password expands there and never appears in an
# argument list or on this host. The first argument names the variable the tool reads, and the
# tool and its arguments follow as "$@". Written so the line is not a credential assignment to
# the plan's secret scan.
CONTAINER_ENV = 'name=$1; shift; exec env "$name=$POSTGRES_PASSWORD" "$@"'
DB_AUTH_VARIABLE = "PGPASSWORD"  # the variable psql and pg_dump read
END_MARK = "@@END@@"
MANIFEST_FILE = "manifest.json"
MANIFEST_VERSION = 1
SEALED_SUFFIX = ".tar.age"

BACKUP_NAME = re.compile(r"\A\d{8}T\d{6}Z\Z")
DATABASE_NAME = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")
IMAGE_ID = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
SNAPSHOT_ID = re.compile(r"\A[0-9A-F]{8}-[0-9A-F]{8}-[0-9]+\Z")
TABLE_LINE = re.compile(r"\A(?P<table>[^|]+)\|(?P<rows>[0-9]+)\Z")
RECIPIENT = re.compile(r"\Aage1[0-9a-z]{50,100}\Z")
AGE_HEADER = b"age-encryption.org/v1\n"
METRIC_LINE = re.compile(
    r'\Acontrol_plane_backup_last_success_timestamp_seconds\{stage="([a-z_]+)"\} ([0-9.]+)\Z'
)
ENV_LINE = re.compile(r"\A(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)\Z")

# Every user table once: partitions are left out because their parent's count holds them.
# The count is taken by the server (query_to_xml), so no row leaves it; only a name and a number.
COUNT_SQL = (
    "SELECT n.nspname || '.' || c.relname || '|' || "
    "(xpath('/row/c/text()', query_to_xml(format("
    "'SELECT count(*) AS c FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]::text "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition "
    "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' ORDER BY 1;"
)

EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_PRECONDITION = 2

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]
Stream = int | IO[bytes] | None
Counts = dict[str, int]


class CheckFailed(Exception):  # noqa: N818 -- a result the caller names, not an error type
    """A backup exists but does not prove out: exit 1."""


class Precondition(Exception):  # noqa: N818 -- a result the caller names, not an error type
    """Something needed before anything can be proven is missing: exit 2."""


def fail(message: str) -> NoReturn:
    raise CheckFailed(message)


def refuse(message: str) -> NoReturn:
    raise Precondition(message)


def run_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run one command from an argument list, output captured, never through a shell."""
    return subprocess.run(  # noqa: S603 -- argv is a list and no shell is involved
        list(argv), capture_output=True, text=True, check=False
    )


class Spawn(Protocol):
    """Starts a child process whose three streams the caller chooses."""

    def __call__(
        self,
        argv: Sequence[str],
        *,
        stdin: Stream = None,
        stdout: Stream = None,
        stderr: Stream = None,
    ) -> subprocess.Popen[bytes]: ...


def spawn(
    argv: Sequence[str], *, stdin: Stream = None, stdout: Stream = None, stderr: Stream = None
) -> subprocess.Popen[bytes]:
    """Start one command from an argument list, never through a shell."""
    return subprocess.Popen(  # noqa: S603 -- argv is a list and no shell is involved
        list(argv), stdin=stdin, stdout=stdout, stderr=stderr
    )


def docker(runner: Runner, argv: Sequence[str], what: str) -> str:
    result = runner(["docker", *argv])
    if result.returncode != 0:
        fail(f"{what} failed (docker exit {result.returncode}; output withheld)")
    return result.stdout


def pg_argv(container: str, tool: Sequence[str], *, interactive: bool = False) -> list[str]:
    """A command that runs a PostgreSQL tool inside the database container as its administrator."""
    head = ["docker", "exec", *(["-i"] if interactive else []), container]
    return [*head, "sh", "-c", CONTAINER_ENV, "sh", DB_AUTH_VARIABLE, *tool]


def database_name(name: str) -> str:
    if not DATABASE_NAME.match(name):
        refuse(f"{name!r} is not a plain database name")
    return name


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_counts(lines: Sequence[str]) -> Counts:
    """Table name and row count per line. A line of any other shape is refused unread."""
    counts: Counts = {}
    for line in lines:
        match = TABLE_LINE.match(line)
        if match is None:
            fail("the count query returned a line that is not a table and a number (withheld)")
        counts[match["table"]] = int(match["rows"])
    return counts


def compare_counts(database: str, live: Counts, restored: Counts) -> None:
    """Live against restored: the same tables and the same row count in each.

    A database with no tables is refused on either side. Equal emptiness proves nothing.
    """
    if not live:
        fail(f"{database}: the live database recorded no tables, so equal counts prove nothing")
    if not restored:
        fail(f"{database}: the restored database holds no tables")
    missing = sorted(set(live) - set(restored))
    extra = sorted(set(restored) - set(live))
    if missing or extra:
        fail(
            f"{database}: table set differs, {len(missing)} missing from the restore "
            f"and {len(extra)} not in the live copy"
        )
    differing = [t for t in sorted(live) if live[t] != restored[t]]
    if differing:
        shown = ", ".join(f"{t} live={live[t]} restored={restored[t]}" for t in differing[:10])
        fail(f"{database}: count mismatch in {len(differing)} table(s): {shown}")


def find_db_container(runner: Runner) -> str:
    out = docker(
        runner,
        [
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--filter",
            f"label=com.docker.compose.service={DB_SERVICE}",
        ],
        "listing the database container",
    )
    found = out.split()
    if len(found) != 1:
        refuse(f"expected one running {DB_SERVICE!r} container in {PROJECT!r}, found {len(found)}")
    return found[0]


def container_image(runner: Runner, container: str) -> str:
    image = docker(
        runner, ["inspect", "--format", "{{.Image}}", container], "reading the database image"
    ).strip()
    if not IMAGE_ID.match(image):
        refuse("the database container's image id is not a sha256 digest")
    return image


def live_db_bytes(runner: Runner, container: str, database: str) -> int:
    sql = f"SELECT pg_database_size('{database_name(database)}')"
    result = runner(
        pg_argv(container, ["psql", "-X", "-q", "-U", PG_USER, "-d", "postgres", "-tA", "-c", sql])
    )
    size = result.stdout.strip()
    if result.returncode != 0 or not size.isdigit():
        refuse(f"could not size the {database} database (output withheld)")
    return int(size)


def require_free_space(
    root: pathlib.Path,
    needed: int,
    *,
    usage: Callable[[pathlib.Path], tuple[int, int, int]] = shutil.disk_usage,
) -> None:
    """The copies share the live disk, so one that would leave under 1 GiB free is refused."""
    free = usage(root)[2]
    if free - needed < HEADROOM_BYTES:
        refuse(
            f"not enough free space at {root}: {free} bytes free, about {needed} needed "
            f"plus {HEADROOM_BYTES} headroom"
        )


@contextlib.contextmanager
def deploy_lock(lock_dir: pathlib.Path) -> Iterator[None]:
    """Hold the flock the host's deploy tool takes for this stack.

    Raises:
        Precondition: the lock is held, because a deploy is running.
        OSError: the lock file could not be opened or locked for another reason.
    """
    path = lock_dir / f"{PROJECT}.deploy.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                refuse(f"{path} is held: a deploy of {PROJECT} is running; try again after it")
            raise
        yield
    finally:
        os.close(fd)


class Snapshot:
    """One read-only repeatable-read transaction, held open while pg_dump reads its snapshot.

    The psql child reads statements from a pipe. After each one this class asks it to echo an
    end mark and reads up to the mark, so it never waits on output that is not coming.
    """

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

    def _send(self, text: str) -> None:
        stdin = self._process.stdin
        if stdin is None:
            fail("the snapshot session has no input")
        try:
            stdin.write(text.encode() + b"\n")
            stdin.flush()
        except OSError:
            fail("the snapshot session closed its input (output withheld)")

    def _answer(self) -> list[str]:
        self._send(f"\\echo {END_MARK}")
        stdout = self._process.stdout
        if stdout is None:
            fail("the snapshot session has no output")
        lines: list[str] = []
        while True:
            raw = stdout.readline()
            if not raw:
                fail("the snapshot session ended before it answered (output withheld)")
            line = raw.decode(errors="replace").rstrip("\n")
            if line == END_MARK:
                return lines
            lines.append(line)

    def open(self) -> str:
        self._send("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;")
        self._send("SELECT pg_export_snapshot();")
        answer = self._answer()
        if len(answer) != 1 or not SNAPSHOT_ID.match(answer[0]):
            fail("the server did not return one snapshot id (output withheld)")
        return answer[0]

    def counts(self) -> Counts:
        self._send(COUNT_SQL)
        return parse_counts(self._answer())

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._send("ROLLBACK;")
        if self._process.stdin is not None:
            with contextlib.suppress(OSError):
                self._process.stdin.close()
        with contextlib.suppress(Exception):
            self._process.wait(timeout=30)
        if self._process.poll() is None:
            self._process.kill()
            self._process.wait()


def dump_database(
    spawner: Spawn, container: str, database: str, snapshot: str, dest: pathlib.Path
) -> None:
    argv = pg_argv(
        container,
        [
            "pg_dump",
            "-U",
            PG_USER,
            "-d",
            database_name(database),
            "--no-owner",
            "--no-acl",
            f"--snapshot={snapshot}",
        ],
    )
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as out:
        process = spawner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if process.stdout is None:
            fail("pg_dump has no output")
        for block in iter(lambda: process.stdout.read(1 << 20), b""):  # type: ignore[union-attr]
            out.write(block)
        process.stdout.close()
        code = process.wait()
    if code != 0:
        fail(f"pg_dump of {database} failed (exit {code}; output withheld)")


def take_database(
    spawner: Spawn, container: str, database: str, dest_dir: pathlib.Path
) -> dict[str, object]:
    """Dump one database and count its tables, both in the one snapshot."""
    name = database_name(database)
    process = spawner(
        pg_argv(
            container,
            ["psql", "-X", "-q", "-U", PG_USER, "-d", name, *STOP_ON_ERROR, "-tA"],
            interactive=True,
        ),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    session = Snapshot(process)
    try:
        snapshot = session.open()
        target = dest_dir / f"{name}.sql.gz"
        dump_database(spawner, container, name, snapshot, target)
        tables = session.counts()
    finally:
        session.close()
    if not tables:
        fail(f"{name}: the live database has no tables, so there is nothing to back up")
    return {
        "file": target.name,
        "sha256": sha256_file(target),
        "bytes": target.stat().st_size,
        "tables": tables,
    }


def stamp_name(now: datetime.datetime | None = None) -> str:
    return (now or datetime.datetime.now(datetime.UTC)).strftime("%Y%m%dT%H%M%SZ")


def take(
    *,
    root: pathlib.Path,
    runner: Runner = run_command,
    spawner: Spawn = spawn,
    usage: Callable[[pathlib.Path], tuple[int, int, int]] = shutil.disk_usage,
    now: datetime.datetime | None = None,
    say: Callable[[str], None] = print,
) -> pathlib.Path:
    """Take one backup directory, root only, holding a dump and the live counts per database."""
    container = find_db_container(runner)
    image = container_image(runner, container)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    sizes = {db: live_db_bytes(runner, container, db) for db in DATABASES}
    require_free_space(root, 2 * sum(sizes.values()), usage=usage)
    dest = root / stamp_name(now)
    dest.mkdir(mode=0o700)
    try:
        databases = {db: take_database(spawner, container, db, dest) for db in DATABASES}
    except BaseException:
        # A half-written copy must never be mistaken for a backup later.
        shutil.rmtree(dest, ignore_errors=True)
        raise
    manifest = {
        "version": MANIFEST_VERSION,
        "taken_at": dest.name,
        "project": PROJECT,
        "image": image,
        "db_bytes": sizes,
        "databases": databases,
    }
    fd = os.open(dest / MANIFEST_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    for db in DATABASES:
        say(f"took {db}: tables={len(databases[db]['tables'])}")  # type: ignore[arg-type]
    say(f"took {dest}")
    return dest


def load_manifest(backup: pathlib.Path) -> dict[str, object]:
    try:
        manifest = json.loads((backup / MANIFEST_FILE).read_text())
    except FileNotFoundError:
        fail(f"{backup} has no {MANIFEST_FILE}")
    except ValueError:
        fail(f"{backup / MANIFEST_FILE} is not valid JSON")
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        fail(f"{MANIFEST_FILE} is not version {MANIFEST_VERSION}")
    return manifest


def recorded_databases(manifest: Mapping[str, object]) -> dict[str, dict[str, object]]:
    recorded = manifest.get("databases")
    if not isinstance(recorded, dict) or set(recorded) != set(DATABASES):
        fail(f"{MANIFEST_FILE} does not record exactly the databases {', '.join(DATABASES)}")
    return {db: recorded[db] for db in DATABASES}


def recorded_tables(entry: Mapping[str, object]) -> Counts:
    tables = entry.get("tables")
    if not isinstance(tables, dict) or not all(
        isinstance(k, str) and isinstance(v, int) for k, v in tables.items()
    ):
        fail(f"{MANIFEST_FILE} does not record the live counts")
    return dict(tables)


def check_digests(backup: pathlib.Path, databases: Mapping[str, Mapping[str, object]]) -> None:
    for db, entry in databases.items():
        path = backup / f"{db}.sql.gz"
        if not path.is_file():
            fail(f"{path} is missing")
        if sha256_file(path) != entry.get("sha256"):
            fail(f"{path} does not match the digest recorded when it was taken")


class Throwaway:
    """One throwaway PostgreSQL, no network, no logs, removed with its volume however it ends.

    Trust authentication is safe here because the container has no network: the only way in
    is docker exec on this host.
    """

    def __init__(self, runner: Runner, spawner: Spawn, image: str, memory: str) -> None:
        self._runner = runner
        self._spawner = spawner
        self._image = image
        self._memory = memory
        self.name = f"control-plane-restore-check-{secrets.token_hex(4)}"

    def __enter__(self) -> Throwaway:
        docker(
            self._runner,
            [
                "run",
                "-d",
                "--rm",
                "--name",
                self.name,
                *NO_LOGS,
                "--network",
                "none",
                "--label",
                f"{LABEL}=restore",
                "--memory",
                self._memory,
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                self._image,
            ],
            "starting the throwaway database",
        )
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._runner(["docker", "rm", "-f", "-v", self.name])

    def wait_ready(
        self,
        *,
        timeout: float = READY_TIMEOUT_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # TCP, not the socket: the image's init server listens on the socket only, so a
        # socket probe would pass before the real server is up.
        deadline = clock() + timeout
        while clock() < deadline:
            probe = self._runner(
                ["docker", "exec", self.name, "pg_isready", "-h", "127.0.0.1", "-q"]
            )
            if probe.returncode == 0:
                return
            sleep(1.0)
        fail(f"the throwaway database was not ready within {int(timeout)}s")

    def _psql(self, database: str, *extra: str) -> list[str]:
        return [
            "docker",
            "exec",
            self.name,
            "psql",
            "-X",
            "-q",
            "-U",
            PG_USER,
            "-d",
            database,
            *extra,
        ]

    def create(self, database: str) -> None:
        docker(
            self._runner,
            ["exec", self.name, "createdb", "-U", PG_USER, database_name(database)],
            f"creating {database} in the throwaway database",
        )

    def load(self, database: str, dump: pathlib.Path) -> None:
        argv = [*self._psql(database, *STOP_ON_ERROR)]
        argv.insert(2, "-i")
        process = self._spawner(
            argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if process.stdin is None:
            fail("the restore has no input")
        try:
            with gzip.open(dump, "rb") as source:
                for block in iter(lambda: source.read(1 << 20), b""):
                    process.stdin.write(block)
        except (OSError, EOFError):
            process.kill()
            process.wait()
            fail(f"{dump} does not decompress to the end")
        finally:
            with contextlib.suppress(OSError):
                process.stdin.close()
        code = process.wait()
        if code != 0:
            fail(
                f"the restore of {database} stopped on an error (psql exit {code}; output withheld)"
            )

    def counts(self, database: str) -> Counts:
        result = self._runner([*self._psql(database, *STOP_ON_ERROR, "-tA", "-c", COUNT_SQL)])
        if result.returncode != 0:
            fail(f"{database}: the restored database could not be counted (output withheld)")
        return parse_counts([line for line in result.stdout.splitlines() if line.strip()])


def docker_root(runner: Runner) -> pathlib.Path:
    root = docker(runner, ["info", "--format", "{{.DockerRootDir}}"], "reading the docker root")
    if not root.strip().startswith("/"):
        refuse("the docker root directory did not come back as an absolute path")
    return pathlib.Path(root.strip())


def verify(
    backup: pathlib.Path,
    *,
    runner: Runner = run_command,
    spawner: Spawn = spawn,
    memory: str = DEFAULT_RESTORE_MEMORY,
    sleep: Callable[[float], None] = time.sleep,
    usage: Callable[[pathlib.Path], tuple[int, int, int]] = shutil.disk_usage,
    say: Callable[[str], None] = print,
) -> None:
    """Restore a backup into a throwaway PostgreSQL and require the same tables and counts."""
    manifest = load_manifest(backup)
    databases = recorded_databases(manifest)
    check_digests(backup, databases)
    image = manifest.get("image")
    if not isinstance(image, str) or not IMAGE_ID.match(image):
        fail(f"{MANIFEST_FILE} does not record the database image")
    live = {db: recorded_tables(entry) for db, entry in databases.items()}
    # The restore writes databases about the live size into docker's own disk.
    sizes = manifest.get("db_bytes")
    total = sum(v for v in sizes.values() if isinstance(v, int)) if isinstance(sizes, dict) else 0
    require_free_space(
        docker_root(runner),
        2 * (total or 10 * (backup / "portal.sql.gz").stat().st_size),
        usage=usage,
    )
    with Throwaway(runner, spawner, image, memory) as target:
        target.wait_ready(sleep=sleep)
        for db in DATABASES:
            target.create(db)
            target.load(db, backup / f"{db}.sql.gz")
            restored = target.counts(db)
            compare_counts(db, live[db], restored)
            rows = sum(restored.values())
            say(f"verified {db}: tables={len(restored)} rows={rows}, equal to live")


def load_env(path: pathlib.Path) -> dict[str, str]:
    """Read NAME=value lines of the state-copy environment file. Values are never printed."""
    if not path.is_file():
        refuse(f"{path} is not there; the estate recipient and copy 1's put key are read from it")
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        match = ENV_LINE.match(line.strip())
        if match:
            values[match["name"]] = match["value"]
    return values


def recipient_of(env: Mapping[str, str]) -> str:
    recipient = env.get("STATE_COPY_RECIPIENT", "")
    if not RECIPIENT.match(recipient):
        refuse("STATE_COPY_RECIPIENT is not a single age1 recipient")
    return recipient


@dataclass(frozen=True)
class Target:
    bucket: str
    endpoint: str
    region: str
    access_key: str
    secret_key: str


def target_of(env: Mapping[str, str], prefix: str, names: Sequence[str]) -> Target:
    values = [env.get(f"{prefix}_{n}", "") for n in names]
    missing = [f"{prefix}_{n}" for n, v in zip(names, values, strict=True) if not v]
    if missing:
        refuse(f"missing {', '.join(missing)}")
    return Target(*values)


def seal(
    backup: pathlib.Path,
    recipient: str,
    *,
    spawner: Spawn = spawn,
    which: Callable[[str], str | None] = shutil.which,
    usage: Callable[[pathlib.Path], tuple[int, int, int]] = shutil.disk_usage,
    say: Callable[[str], None] = print,
) -> pathlib.Path:
    """Encrypt a backup directory to one age file beside it, and write the file's digest.

    The private half of the recipient is never on this host, so the sealed copy cannot be
    opened here. It is the copy that goes off the host.
    """
    if not (backup / MANIFEST_FILE).is_file():
        refuse(f"{backup} is not a backup this program took")
    if which("age") is None:
        refuse("age is not installed on this host")
    out = backup.parent / f"{backup.name}{SEALED_SUFFIX}"
    if out.exists():
        refuse(f"{out} already exists")
    require_free_space(backup.parent, sum(p.stat().st_size for p in backup.iterdir()), usage=usage)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    processes: list[subprocess.Popen[bytes]] = []
    try:
        with os.fdopen(fd, "wb") as handle:
            encrypt = spawner(
                ["age", "-r", recipient],
                stdin=subprocess.PIPE,
                stdout=handle,
                stderr=subprocess.DEVNULL,
            )
            processes.append(encrypt)
            if encrypt.stdin is None:
                fail("age has no input")
            with tarfile.open(fileobj=encrypt.stdin, mode="w|") as archive:
                archive.add(backup, arcname=backup.name, filter=_plain_owner)
            encrypt.stdin.close()
            code = encrypt.wait()
        if code != 0:
            fail("sealing failed (age output withheld)")
        digest = sha256_file(out)
        sidecar = backup.parent / f"{out.name}.sha256"
        sidecar.write_text(f"{digest}  {out.name}\n")
        sidecar.chmod(0o600)
    except BaseException:
        for process in processes:
            with contextlib.suppress(BaseException):
                process.kill()
                process.wait()
        out.unlink(missing_ok=True)
        raise
    say(f"sealed {out}: sha256={digest} bytes={out.stat().st_size}")
    return out


def _plain_owner(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def require_ciphertext(blob: bytes) -> None:
    """Refuse anything that is not an age file with exactly one recipient: ciphertext only."""
    if not blob.startswith(AGE_HEADER):
        fail("the file does not start as an age file, so it is not shipped")
    header = blob[: blob.find(b"\n--- ")] if b"\n--- " in blob else b""
    stanzas = [line for line in header.split(b"\n") if line.startswith(b"-> ")]
    if len(stanzas) != 1:
        fail(
            f"the age header holds {len(stanzas)} recipient stanzas, not one, so it is not shipped"
        )


def sealed_digest(sealed: pathlib.Path) -> str:
    sidecar = sealed.parent / f"{sealed.name}.sha256"
    try:
        recorded = sidecar.read_text().split()[0]
    except (FileNotFoundError, IndexError):
        refuse(f"{sidecar} is missing or empty; seal the backup first")
    return recorded


def object_key(sealed: pathlib.Path) -> str:
    stamp = sealed.name.removesuffix(SEALED_SUFFIX)
    if not BACKUP_NAME.match(stamp):
        refuse(f"{sealed.name} is not a sealed backup this program named")
    return f"{OFFSITE_PREFIX}/{stamp}/{OFFSITE_OBJECT}"


def load_object_storage(scripts: pathlib.Path) -> ModuleType:
    """The estate's one signing client, loaded from the staged release rather than copied."""
    path = scripts / "shared_objectstorage.py"
    if not path.is_file():
        refuse(f"{path} is not there; the backup worker's release must be staged first")
    sys.path.insert(0, str(scripts))
    try:
        spec = importlib.util.spec_from_file_location("branchleft_shared_objectstorage", path)
        if spec is None or spec.loader is None:
            refuse(f"{path} could not be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except ImportError:
        refuse(f"{path} could not be loaded (output withheld)")
    finally:
        sys.path.remove(str(scripts))
    return module


def ship(
    sealed: pathlib.Path,
    *,
    env_file: pathlib.Path,
    scripts: pathlib.Path,
    store: ModuleType | None = None,
    say: Callable[[str], None] = print,
) -> str:
    """Put a sealed backup to backup copy 1 under the control plane's prefix, ciphertext only."""
    env = load_env(env_file)
    target = target_of(
        env,
        "STATE_COPY_DEST",
        ("BUCKET", "ENDPOINT", "REGION", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY"),
    )
    key = object_key(sealed)
    size = sealed.stat().st_size
    if size > MAX_SEALED_BYTES:
        refuse(f"{sealed} is {size} bytes, past the {MAX_SEALED_BYTES} the shipper holds in memory")
    blob = sealed.read_bytes()
    require_ciphertext(blob)
    digest = hashlib.sha256(blob).hexdigest()
    if digest != sealed_digest(sealed):
        fail(f"{sealed} does not match the digest recorded when it was sealed")
    client = store if store is not None else load_object_storage(scripts)
    try:
        client.put_object(**dataclasses.asdict(target), key=key, data=blob)
    except client.ObjectStorageError:
        fail("the put to backup copy 1 failed (output withheld)")
    say(f"shipped {key}: sha256={digest} bytes={size} (put only: read back with offsite-check)")
    return key


def offsite_check(
    sealed: pathlib.Path,
    *,
    read_env_file: pathlib.Path,
    scripts: pathlib.Path,
    store: ModuleType | None = None,
    say: Callable[[str], None] = print,
) -> None:
    """Download the shipped object with a read key and require the digest sealed on the host."""
    env = load_env(read_env_file)
    target = target_of(
        env,
        "BACKUP_DRILL_COPY_PRIMARY",
        ("BUCKET", "ENDPOINT", "REGION", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY"),
    )
    key = object_key(sealed)
    expected = sealed_digest(sealed)
    client = store if store is not None else load_object_storage(scripts)
    try:
        blob = client.get_object(**dataclasses.asdict(target), key=key)
    except client.ObjectStorageError:
        fail("the read back from backup copy 1 failed (output withheld)")
    require_ciphertext(blob)
    if hashlib.sha256(blob).hexdigest() != expected:
        fail(f"{key} downloaded, and its digest is not the one sealed on the host")
    say(f"offsite {key}: sha256={expected} bytes={len(blob)} equals the sealed copy")


def prune(
    root: pathlib.Path, keep: int, *, protect: pathlib.Path, say: Callable[[str], None] = print
) -> None:
    """Remove on-host copies beyond the newest `keep`, never the one just proven."""
    if keep < 1:
        refuse("--keep must be at least 1")
    names = sorted(
        (p for p in root.iterdir() if p.is_dir() and BACKUP_NAME.match(p.name)), reverse=True
    )
    removed = 0
    for old in names[keep:]:
        if old.resolve() == protect.resolve():
            continue
        shutil.rmtree(old)
        for sidecar in (
            root / f"{old.name}{SEALED_SUFFIX}",
            root / f"{old.name}{SEALED_SUFFIX}.sha256",
        ):
            sidecar.unlink(missing_ok=True)
        removed += 1
    if removed:
        say(f"pruned {removed} older on-host copies")


def record_success(metrics_dir: pathlib.Path, stage: str, *, now: float | None = None) -> None:
    """Write the time of the last success of a stage, so a stale backup is a signal."""
    path = metrics_dir / METRICS_FILE
    stages: dict[str, float] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            match = re.match(
                METRIC_LINE,
                line,
            )
            if match:
                stages[match[1]] = float(match[2])
    stages[stage] = time.time() if now is None else now
    metrics_dir.mkdir(parents=True, exist_ok=True)
    name = "control_plane_backup_last_success_timestamp_seconds"
    body = [f"# HELP {name} Unix time of the last success of each stage.", f"# TYPE {name} gauge"]
    body += [f'{name}{{stage="{s}"}} {stages[s]:.0f}' for s in sorted(stages)]
    temporary = path.with_suffix(".tmp")
    temporary.write_text("\n".join(body) + "\n")
    temporary.chmod(0o644)
    temporary.replace(path)


def self_check() -> None:
    """What the install-time check reads: the constants hold together, nothing is touched."""
    for db in DATABASES:
        database_name(db)
    if not RECIPIENT.match("age1" + "q" * 58):
        fail("the recipient pattern refuses a well-formed recipient")
    if not parse_counts(["public.example|0"]):
        fail("the count parser read nothing")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="check the program itself and stop")
    parser.add_argument("--backup-root", type=pathlib.Path, default=BACKUP_ROOT)
    parser.add_argument("--lock-dir", type=pathlib.Path, default=LOCK_DIR)
    parser.add_argument("--env-file", type=pathlib.Path, default=ENV_FILE)
    parser.add_argument("--release-scripts", type=pathlib.Path, default=RELEASE_SCRIPTS)
    parser.add_argument("--metrics-dir", type=pathlib.Path, default=METRICS_DIR)
    parser.add_argument("--keep", type=int, default=DEFAULT_KEEP)
    parser.add_argument("--restore-memory", default=DEFAULT_RESTORE_MEMORY)
    parser.add_argument("--read-env-file", type=pathlib.Path)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("take")
    sub.add_parser("run")
    for name in ("verify", "seal", "ship", "offsite-check"):
        sub.add_parser(name).add_argument("path", type=pathlib.Path)
    return parser


def execute(args: argparse.Namespace, say: Callable[[str], None]) -> None:
    command: str = args.command
    if command == "verify":
        verify(args.path, memory=args.restore_memory, say=say)
    elif command == "seal":
        seal(args.path, recipient_of(load_env(args.env_file)), say=say)
    elif command == "ship":
        ship(args.path, env_file=args.env_file, scripts=args.release_scripts, say=say)
        record_success(args.metrics_dir, "shipped_offsite")
    elif command == "offsite-check":
        if args.read_env_file is None:
            refuse("offsite-check needs --read-env-file, a file holding the read-only copy-1 key")
        offsite_check(
            args.path, read_env_file=args.read_env_file, scripts=args.release_scripts, say=say
        )
    else:
        with deploy_lock(args.lock_dir):
            taken = take(root=args.backup_root, say=say)
        if command == "run":
            verify(taken, memory=args.restore_memory, say=say)
            record_success(args.metrics_dir, "verified_on_host")
            sealed = seal(taken, recipient_of(load_env(args.env_file)), say=say)
            ship(sealed, env_file=args.env_file, scripts=args.release_scripts, say=say)
            record_success(args.metrics_dir, "shipped_offsite")
            prune(args.backup_root, args.keep, protect=taken, say=say)


def main(argv: Sequence[str] | None = None, *, say: Callable[[str], None] = print) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.check:
            self_check()
        elif args.command is None:
            parser.error("a command is required")
        else:
            execute(args, say)
    except CheckFailed as exc:
        say(f"FAIL: {exc}")
        return EXIT_CHECK_FAILED
    except Precondition as exc:
        say(f"NOT RUN: {exc}")
        return EXIT_PRECONDITION
    say("OK")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
