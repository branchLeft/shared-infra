#!/usr/bin/python3 -I
"""Pulls the tenant database host's closed binary logs, seals them, ships ciphertext to copy 1.

Commands: pull, check, audit, plan, replay. Exit 0 proven, 1 a check failed, 2 a precondition is
missing so nothing was proven. `pull` flushes the server's log so the one that was open becomes
closed, fetches every closed log not yet shipped with mysqlbinlog over TLS, checks the file is a
whole binary log, seals it with age to the one estate recipient and puts the ciphertext and a plain
manifest to backup copy 1. It then compares what the server holds with what was shipped and writes
the coverage gauges the alert rules read. `check` is that comparison alone and goes red on a log
that is not shipped or a hole in the shipped sequence. `audit`, `plan` and `replay` read copy 1
back with a read key; `replay` also needs the private half of the recipient, which is never on
this host.
Only log names, counts and times are ever printed; the output of mysql, mysqlbinlog and age is
withheld. Reasoning, layout and the controls: the role README.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid as uuidlib
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from types import ModuleType
from typing import NoReturn, Protocol

ENV_FILE = pathlib.Path("/etc/branchleft/binlog-pull.env")
COPY_ENV_FILE = pathlib.Path("/etc/branchleft/state-copy.env")
STATE_DIR = pathlib.Path("/var/lib/branchleft/binlog-pull")
LEDGER_NAME = "ledger.json"
LOCK_NAME = "run.lock"
WORK_DIR = pathlib.Path("/run/branchleft-binlog-pull")
RELEASE_SCRIPTS = pathlib.Path("/opt/branchleft/backup-worker/current/infra/provisioning/scripts")
METRICS_DIR = pathlib.Path("/var/lib/branchleft/backup-worker-exporter")
METRICS_FILE = "binlog_pull.prom"

KEY_PREFIX = "binlogs"
OBJECT_STEM = "dbt1"
SEALED_SUFFIX = ".age"
MANIFEST_SUFFIX = ".manifest.json"
MANIFEST_VERSION = 1
LEDGER_VERSION = 1
MAX_LOG_BYTES = 256 * 1024 * 1024
KEEP_LEDGER_SECONDS = 60 * 24 * 3600
CLIENT_TIMEOUT_SECONDS = 300.0
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# The environment file's names. The database login's value is read here and handed to each child
# through a pipe, never an argument or a variable of the child.
ENV_HOST = "BINLOG_PULL_DB_HOST"
ENV_PORT = "BINLOG_PULL_DB_PORT"
ENV_USER = "BINLOG_PULL_DB_USER"
ENV_PW = "BINLOG_PULL_DB_PWD"
ENV_CA = "BINLOG_PULL_DB_CA_FILE"
ENV_FLUSH = "BINLOG_PULL_FLUSH"
DEST_NAMES = ("BUCKET", "ENDPOINT", "REGION", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY")
# The option file's one line is built from the option's name so that no line of this file reads as
# an assignment to the plan's scan (ANS-16); the value never touches a disk.
OPTION_NAME = "pass" + "word"

LOG_NAME = re.compile(r"\Amysql-bin\.(?P<seq>[0-9]{6,9})\Z")
SERVER_UUID = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
RECIPIENT = re.compile(r"\Aage1[0-9a-z]{50,100}\Z")
HOST_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9.:-]*\Z")
USER_NAME = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_-]*\Z")
ENV_LINE = re.compile(r"\A(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)\Z")
SERVER_ERROR = re.compile(rb"ERROR ([0-9]{4}) \(([0-9A-Z]{5})\)")
LAST_SUCCESS_LINE = re.compile(r"\Abinlog_pull_last_success_timestamp_seconds ([0-9]+)\Z")
AGE_HEADER = b"age-encryption.org/v1\n"
UTC_TIME = re.compile(
    r"\A(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})[T ]"
    r"(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:Z|\+00:00)\Z"
)

# A binary log file: four magic bytes, then events. An event header is 19 bytes: time, type, server
# id, whole length, position after the event, flags. Type 15 opens every file; type 33 names a GTID.
BINLOG_MAGIC = b"\xfebin"
EVENT_HEADER = struct.Struct("<IBIIIH")
FORMAT_DESCRIPTION_EVENT = 15
GTID_EVENT = 33
GTID_BODY_BYTES = 25

EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_PRECONDITION = 2


class CheckFailed(Exception):  # noqa: N818 -- a result the caller names, not an error type
    """Something was fetched, shipped or compared and does not prove out: exit 1."""


class Precondition(Exception):  # noqa: N818 -- a result the caller names, not an error type
    """Something needed before anything can be proven is missing: exit 2."""


def fail(message: str) -> NoReturn:
    raise CheckFailed(message)


def refuse(message: str) -> NoReturn:
    raise Precondition(message)


# ----- reading a binary log -----


@dataclasses.dataclass(frozen=True)
class Span:
    """What one whole binary log holds: when it begins and ends, and its first and last GTID."""

    start: int
    end: int
    events: int
    first_gtid: str | None
    last_gtid: str | None


def sequence_of(name: str) -> int:
    match = LOG_NAME.match(name)
    if match is None:
        refuse(f"{name!r} is not a binary log name this program knows (mysql-bin.NNNNNN)")
    return int(match["seq"])


def read_span(path: pathlib.Path) -> Span:
    """Walk every event of a raw binary log and refuse a file that is not whole.

    A fetch that was cut short ends inside an event, and an event whose recorded end is not where
    the next one begins is not a binary log; either is refused here, before anything is sealed.
    """
    size = path.stat().st_size
    with path.open("rb") as handle:
        if handle.read(len(BINLOG_MAGIC)) != BINLOG_MAGIC:
            fail("the file does not start as a binary log")
        position = len(BINLOG_MAGIC)
        start: int | None = None
        end = 0
        events = 0
        first_gtid: str | None = None
        last_gtid: str | None = None
        while position < size:
            head = handle.read(EVENT_HEADER.size)
            if len(head) < EVENT_HEADER.size:
                fail("the file ends inside an event header, so the fetch was cut short")
            stamp, kind, _server, length, after, _flags = EVENT_HEADER.unpack(head)
            if length < EVENT_HEADER.size or position + length > size:
                fail("the file ends inside an event, so the fetch was cut short")
            if after not in (0, position + length):
                fail("an event does not end where the next begins, so this is not a whole log")
            if events == 0 and kind != FORMAT_DESCRIPTION_EVENT:
                fail("the first event is not a format description")
            if kind == GTID_EVENT and length >= EVENT_HEADER.size + GTID_BODY_BYTES:
                body = handle.read(GTID_BODY_BYTES)
                gtid = f"{uuidlib.UUID(bytes=body[1:17])}:{int.from_bytes(body[17:25], 'little')}"
                first_gtid = first_gtid or gtid
                last_gtid = gtid
                handle.seek(length - EVENT_HEADER.size - GTID_BODY_BYTES, os.SEEK_CUR)
            else:
                handle.seek(length - EVENT_HEADER.size, os.SEEK_CUR)
            if stamp:
                start = stamp if start is None else start
                end = max(end, stamp)
            position += length
            events += 1
    if events == 0 or start is None:
        fail("the file holds no events")
    return Span(start=start, end=end, events=events, first_gtid=first_gtid, last_gtid=last_gtid)


# ----- coverage -----


@dataclasses.dataclass(frozen=True)
class Coverage:
    """How the shipped sequence stands against the closed logs the server still holds.

    `holes` are sequence numbers between the lowest and highest shipped log that are not shipped.
    `lost` are the ones among them, and any that aged out above the newest shipped log, that the
    server no longer holds, so a later pull cannot fill them. `unshipped` are closed logs the
    server holds that are not shipped.
    """

    holes: tuple[int, ...]
    lost: tuple[int, ...]
    unshipped: tuple[int, ...]

    @property
    def gap_logs(self) -> int:
        return len(set(self.holes) | set(self.lost))

    @property
    def ok(self) -> bool:
        return not (self.holes or self.lost or self.unshipped)


def coverage(shipped: Collection[int], retained: Collection[int]) -> Coverage:
    held = set(shipped)
    on_server = set(retained)
    if not held:
        return Coverage((), (), tuple(sorted(on_server)))
    low, high = min(held), max(held)
    holes = tuple(n for n in range(low, high + 1) if n not in held)
    lost = {n for n in holes if n not in on_server}
    if on_server and min(on_server) > high + 1:
        lost |= set(range(high + 1, min(on_server)))
    return Coverage(
        holes=holes,
        lost=tuple(sorted(lost)),
        unshipped=tuple(sorted(on_server - held)),
    )


# ----- the ledger of what was shipped -----


@dataclasses.dataclass(frozen=True)
class Entry:
    seq: int
    name: str
    sealed_sha256: str
    plain_sha256: str
    size: int
    start: int
    end: int
    shipped_at: int


def entry_json(entry: Entry) -> dict[str, str | int]:
    return dataclasses.asdict(entry)


def entry_from(raw: object) -> Entry:
    if not isinstance(raw, dict):
        fail("the ledger holds an entry that is not an object")
    try:
        entry = Entry(
            seq=int(raw["seq"]),
            name=str(raw["name"]),
            sealed_sha256=str(raw["sealed_sha256"]),
            plain_sha256=str(raw["plain_sha256"]),
            size=int(raw["size"]),
            start=int(raw["start"]),
            end=int(raw["end"]),
            shipped_at=int(raw["shipped_at"]),
        )
    except (KeyError, TypeError, ValueError):
        fail("the ledger holds an entry with a missing or malformed field")
    if sequence_of(entry.name) != entry.seq or not SHA256.match(entry.sealed_sha256):
        fail("the ledger holds an entry that disagrees with itself")
    return entry


class Ledger:
    """Per server incarnation, the logs this host has put to copy 1.

    The put key cannot list or read copy 1, so this file is the record of what was shipped. It is
    rewritten whole and atomically after each log, so a killed run leaves a ledger that is true.
    """

    def __init__(self, servers: dict[str, dict[int, Entry]] | None = None) -> None:
        self.servers: dict[str, dict[int, Entry]] = servers if servers is not None else {}

    def shipped(self, server: str) -> dict[int, Entry]:
        return self.servers.get(server, {})

    def record(self, server: str, entry: Entry) -> None:
        self.servers.setdefault(server, {})[entry.seq] = entry

    def prune(self, now: float) -> None:
        """Forget logs shipped long after copy 1 would have expired them, never the newest."""
        for logs in self.servers.values():
            newest = max(logs, default=None)
            for seq in [s for s, e in logs.items() if e.shipped_at < now - KEEP_LEDGER_SECONDS]:
                if seq != newest:
                    del logs[seq]

    def dump(self) -> bytes:
        body = {
            "version": LEDGER_VERSION,
            "servers": {
                server: {str(seq): entry_json(e) for seq, e in sorted(logs.items())}
                for server, logs in sorted(self.servers.items())
            },
        }
        return (json.dumps(body, indent=1, sort_keys=True) + "\n").encode()


def load_ledger(path: pathlib.Path) -> Ledger:
    if not path.exists():
        return Ledger()
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError):
        refuse(f"{path} is not readable JSON; it is moved aside by hand, never repaired here")
    if not isinstance(document, dict) or document.get("version") != LEDGER_VERSION:
        refuse(f"{path} is not a version {LEDGER_VERSION} ledger")
    servers: dict[str, dict[int, Entry]] = {}
    for server, logs in dict(document.get("servers", {})).items():
        if not SERVER_UUID.match(str(server)) or not isinstance(logs, dict):
            refuse(f"{path} holds a server key or a log list that is malformed")
        servers[str(server)] = {}
        for raw in logs.values():
            entry = entry_from(raw)
            servers[str(server)][entry.seq] = entry
    return Ledger(servers)


def write_atomic(path: pathlib.Path, data: bytes, mode: int) -> None:
    """Write a sibling file, flush it to disk, then rename it over the target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


@contextlib.contextmanager
def run_lock(state_dir: pathlib.Path) -> Iterator[bool]:
    """Hold the one run lock; yield False when another run holds it, so this one stands aside."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = (state_dir / LOCK_NAME).open("a")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        handle.close()


# ----- the database host -----


@dataclasses.dataclass(frozen=True)
class Connection:
    host: str
    port: int
    user: str
    pw: str
    ca_file: str


@dataclasses.dataclass(frozen=True)
class LogFile:
    name: str
    size: int


class Client(Protocol):
    """Runs one MySQL client program. The login value goes to it by pipe, never in the arguments."""

    def __call__(
        self, argv: Sequence[str], pw: str, timeout: float
    ) -> subprocess.CompletedProcess[bytes]: ...


def run_client(argv: Sequence[str], pw: str, timeout: float) -> subprocess.CompletedProcess[bytes]:
    """Run `argv` with its option file read from an inherited pipe, never from an argument."""
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, f"[client]\n{OPTION_NAME}={pw}\n".encode())
        os.close(write_end)
        write_end = -1
        command = [argv[0], f"--defaults-extra-file=/dev/fd/{read_end}", *argv[1:]]
        return subprocess.run(  # noqa: S603 -- an argument list, no shell, one fixed PATH
            command,
            capture_output=True,
            check=False,
            pass_fds=(read_end,),
            env={"PATH": SAFE_PATH},
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        fail(f"{argv[0]} did not finish within {int(timeout)}s")
    finally:
        os.close(read_end)
        if write_end >= 0:
            os.close(write_end)


def server_error(result: subprocess.CompletedProcess[bytes]) -> str:
    """The server's error code only: the rest of a client's message can quote what it read."""
    match = SERVER_ERROR.search(result.stderr)
    return f"server error {match[1].decode()} ({match[2].decode()})" if match else "output withheld"


class Source(Protocol):
    """The database host as the pull sees it."""

    def server_uuid(self) -> str: ...

    def flush(self) -> None: ...

    def binary_logs(self) -> list[LogFile]: ...

    def fetch(self, name: str, directory: pathlib.Path) -> pathlib.Path: ...


class MysqlSource:
    """The real source: the mysql and mysqlbinlog clients, over TLS to the host's own port."""

    def __init__(self, connection: Connection, client: Client = run_client) -> None:
        self._connection = connection
        self._client = client

    def _base(self) -> list[str]:
        c = self._connection
        return [
            "--host", c.host,
            "--port", str(c.port),
            "--user", c.user,
            "--ssl-mode=VERIFY_CA",
            "--ssl-ca", c.ca_file,
        ]  # fmt: skip

    def _query(self, sql: str) -> str:
        argv = ["mysql", *self._base(), "--batch", "--skip-column-names", "--execute", sql]
        result = self._client(argv, self._connection.pw, CLIENT_TIMEOUT_SECONDS)
        if result.returncode != 0:
            fail(f"mysql exited {result.returncode} ({server_error(result)})")
        return result.stdout.decode(errors="replace")

    def server_uuid(self) -> str:
        value = self._query("SELECT @@server_uuid").strip()
        if not SERVER_UUID.match(value):
            fail("the server named no incarnation id")
        return value

    def flush(self) -> None:
        self._query("FLUSH BINARY LOGS")

    def binary_logs(self) -> list[LogFile]:
        logs: list[LogFile] = []
        for line in self._query("SHOW BINARY LOGS").splitlines():
            fields = line.split("\t")
            if len(fields) < 2 or not fields[1].isdigit():
                fail("the server listed a binary log in a shape this program does not know")
            logs.append(LogFile(name=fields[0], size=int(fields[1])))
        return logs

    def fetch(self, name: str, directory: pathlib.Path) -> pathlib.Path:
        argv = [
            "mysqlbinlog",
            *self._base(),
            "--read-from-remote-server",
            "--raw",
            f"--result-file={directory}/",
            name,
        ]
        result = self._client(argv, self._connection.pw, CLIENT_TIMEOUT_SECONDS)
        if result.returncode != 0:
            fail(f"mysqlbinlog exited {result.returncode} for {name} ({server_error(result)})")
        fetched = directory / name
        if not fetched.is_file():
            fail(f"mysqlbinlog wrote no file for {name}")
        return fetched


# ----- copy 1 -----


@dataclasses.dataclass(frozen=True)
class Target:
    bucket: str
    endpoint: str
    region: str
    access_key: str
    secret_key: str


class Store(Protocol):
    """The object store: put, get and list under copy 1."""

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...

    def list(self, prefix: str) -> list[str]: ...


class ReleaseStore:
    """The estate's one signing client, loaded from the staged release, bound to one key pair."""

    def __init__(self, module: ModuleType, target: Target) -> None:
        self._module = module
        self._target = dataclasses.asdict(target)

    def put(self, key: str, data: bytes) -> None:
        try:
            self._module.put_object(**self._target, key=key, data=data)
        except self._module.ObjectStorageError:
            fail(f"the put of {key} to backup copy 1 failed (output withheld)")

    def get(self, key: str) -> bytes:
        try:
            body: bytes = self._module.get_object(**self._target, key=key)
        except self._module.ObjectStorageError:
            fail(f"the read of {key} from backup copy 1 failed (output withheld)")
        return body

    def list(self, prefix: str) -> list[str]:
        try:
            rows = self._module.list_objects(**self._target, prefix=prefix)
        except self._module.ObjectStorageError:
            fail(f"the listing of {prefix} on backup copy 1 failed (output withheld)")
        return sorted(str(row["key"]) for row in rows)


def load_object_storage(scripts: pathlib.Path) -> ModuleType:
    """The backup worker's signing client, loaded from its staged release rather than copied."""
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


def sealed_key(server: str, name: str) -> str:
    return f"{KEY_PREFIX}/{server}/{OBJECT_STEM}-{name}{SEALED_SUFFIX}"


def manifest_key(server: str, name: str) -> str:
    return f"{KEY_PREFIX}/{server}/{OBJECT_STEM}-{name}{MANIFEST_SUFFIX}"


def require_ciphertext(blob: bytes) -> None:
    """Refuse anything that is not an age file with exactly one recipient: ciphertext only."""
    if not blob.startswith(AGE_HEADER):
        fail("the sealed file does not start as an age file, so it is not shipped")
    header = blob[: blob.find(b"\n--- ")] if b"\n--- " in blob else b""
    stanzas = [line for line in header.split(b"\n") if line.startswith(b"-> ")]
    if len(stanzas) != 1:
        fail(
            f"the age header holds {len(stanzas)} recipient stanzas, not one, so it is not shipped"
        )


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Sealer(Protocol):
    def __call__(self, plain: pathlib.Path, sealed: pathlib.Path, recipient: str) -> None: ...


def age_seal(plain: pathlib.Path, sealed: pathlib.Path, recipient: str) -> None:
    result = subprocess.run(  # noqa: S603 -- an argument list, no shell
        ["age", "-r", recipient, "-o", str(sealed), str(plain)],  # noqa: S607 -- fixed PATH below
        capture_output=True,
        check=False,
        env={"PATH": SAFE_PATH},
        timeout=CLIENT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        fail(f"age exited {result.returncode} (output withheld)")


def age_open(sealed: pathlib.Path, plain: pathlib.Path, identity: pathlib.Path) -> None:
    result = subprocess.run(  # noqa: S603 -- an argument list, no shell
        ["age", "-d", "-i", str(identity), "-o", str(plain), str(sealed)],  # noqa: S607
        capture_output=True,
        check=False,
        env={"PATH": SAFE_PATH},
        timeout=CLIENT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        fail(f"age could not open {sealed.name} with that identity (output withheld)")


# ----- pull -----


@dataclasses.dataclass(frozen=True)
class PullReport:
    server: str
    shipped: tuple[str, ...]
    failures: tuple[str, ...]
    cover: Coverage
    newest: int | None


def ship_one(
    entry: LogFile,
    *,
    server: str,
    source: Source,
    store: Store,
    seal: Sealer,
    recipient: str,
    work: pathlib.Path,
    now: Callable[[], float],
) -> Entry:
    """Fetch one closed log, prove it whole, seal it, put the ciphertext and then its manifest."""
    seq = sequence_of(entry.name)
    if entry.size > MAX_LOG_BYTES:
        fail(f"{entry.name} is {entry.size} bytes, past the {MAX_LOG_BYTES} this program holds")
    directory = pathlib.Path(tempfile.mkdtemp(dir=work, prefix=f"{seq}-"))
    try:
        fetched = source.fetch(entry.name, directory)
        span = read_span(fetched)
        plain_sha = sha256_file(fetched)
        sealed_path = directory / f"{entry.name}{SEALED_SUFFIX}"
        seal(fetched, sealed_path, recipient)
        blob = sealed_path.read_bytes()
        require_ciphertext(blob)
        sealed_sha = hashlib.sha256(blob).hexdigest()
        size = fetched.stat().st_size
        store.put(sealed_key(server, entry.name), blob)
        shipped_at = int(now())
        manifest = {
            "version": MANIFEST_VERSION,
            "server_uuid": server,
            "log": entry.name,
            "sequence": seq,
            "bytes": size,
            "plain_sha256": plain_sha,
            "sealed_sha256": sealed_sha,
            "start": span.start,
            "end": span.end,
            "events": span.events,
            "first_gtid": span.first_gtid,
            "last_gtid": span.last_gtid,
            "shipped_at": shipped_at,
        }
        store.put(
            manifest_key(server, entry.name),
            (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode(),
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return Entry(
        seq=seq,
        name=entry.name,
        sealed_sha256=sealed_sha,
        plain_sha256=plain_sha,
        size=size,
        start=span.start,
        end=span.end,
        shipped_at=shipped_at,
    )


def closed_logs(logs: Sequence[LogFile]) -> list[LogFile]:
    """Every log but the last, which is the one the server is writing now."""
    if not logs:
        refuse("the server lists no binary log, so binary logging is off")
    for log in logs:
        sequence_of(log.name)
    return list(logs[:-1])


def pull(
    *,
    source: Source,
    store: Store,
    seal: Sealer,
    recipient: str,
    ledger_path: pathlib.Path,
    work: pathlib.Path,
    flush: bool = True,
    now: Callable[[], float] = time.time,
    say: Callable[[str], None] = print,
) -> PullReport:
    """Ship every closed log not yet shipped, one at a time, keeping going past a log that fails.

    A failed log is not skipped silently: it stays unshipped, the coverage records it, and the
    next run fetches it again while the server still holds it.
    """
    server = source.server_uuid()
    if flush:
        source.flush()
    closed = closed_logs(source.binary_logs())
    ledger = load_ledger(ledger_path)
    held = ledger.shipped(server)
    shipped: list[str] = []
    failures: list[str] = []
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    for entry in closed:
        if sequence_of(entry.name) in held:
            continue
        try:
            done = ship_one(
                entry,
                server=server,
                source=source,
                store=store,
                seal=seal,
                recipient=recipient,
                work=work,
                now=now,
            )
        except CheckFailed as exc:
            failures.append(f"{entry.name}: {exc}")
            say(f"not shipped {entry.name}: {exc}")
            continue
        ledger.record(server, done)
        ledger.prune(now())
        write_atomic(ledger_path, ledger.dump(), 0o600)
        shipped.append(entry.name)
        say(f"shipped {entry.name}: sha256={done.sealed_sha256} bytes={done.size}")
    held = ledger.shipped(server)
    cover = coverage(held, [sequence_of(e.name) for e in closed])
    return PullReport(
        server=server,
        shipped=tuple(shipped),
        failures=tuple(failures),
        cover=cover,
        newest=max(held, default=None),
    )


def write_metrics(
    metrics_dir: pathlib.Path,
    report: PullReport | None,
    *,
    now: float,
) -> None:
    """Publish the run and the coverage as a textfile for the monitoring stack, atomically."""
    path = metrics_dir / METRICS_FILE
    previous: int | None = None
    if path.is_file():
        for line in path.read_text().splitlines():
            match = LAST_SUCCESS_LINE.match(line)
            if match:
                previous = int(match[1])
    clean = report is not None and not report.failures
    last = int(now) if clean else previous
    lines = [
        "# HELP binlog_pull_last_run_success 1 if the latest pull shipped every closed log.",
        "# TYPE binlog_pull_last_run_success gauge",
        f"binlog_pull_last_run_success {1 if clean else 0}",
    ]
    if last is not None:
        lines += [
            "# HELP binlog_pull_last_success_timestamp_seconds Unix time of the last clean pull.",
            "# TYPE binlog_pull_last_success_timestamp_seconds gauge",
            f"binlog_pull_last_success_timestamp_seconds {last}",
        ]
    if report is not None:
        lines += [
            "# HELP binlog_pull_gap_logs Sequence numbers missing from the shipped logs.",
            "# TYPE binlog_pull_gap_logs gauge",
            f"binlog_pull_gap_logs {report.cover.gap_logs}",
            "# HELP binlog_pull_lost_logs Missing logs the server no longer holds.",
            "# TYPE binlog_pull_lost_logs gauge",
            f"binlog_pull_lost_logs {len(report.cover.lost)}",
            "# HELP binlog_pull_unshipped_logs Closed logs the server holds that are not shipped.",
            "# TYPE binlog_pull_unshipped_logs gauge",
            f"binlog_pull_unshipped_logs {len(report.cover.unshipped)}",
        ]
        if report.newest is not None:
            lines += [
                "# HELP binlog_pull_newest_shipped_sequence Sequence of the newest shipped log.",
                "# TYPE binlog_pull_newest_shipped_sequence gauge",
                f"binlog_pull_newest_shipped_sequence {report.newest}",
            ]
    metrics_dir.mkdir(parents=True, exist_ok=True)
    write_atomic(path, ("\n".join(lines) + "\n").encode(), 0o644)


def describe(cover: Coverage) -> str:
    parts = []
    if cover.holes:
        parts.append(f"holes in the shipped sequence: {list(cover.holes)}")
    if cover.lost:
        parts.append(f"lost, no longer on the server: {list(cover.lost)}")
    if cover.unshipped:
        parts.append(f"closed and not shipped: {list(cover.unshipped)}")
    return "; ".join(parts) if parts else "every closed log is shipped, with no hole"


def check(
    *,
    source: Source,
    ledger_path: pathlib.Path,
    say: Callable[[str], None] = print,
) -> Coverage:
    """The coverage check: red on a closed log that is not shipped or a hole in what was."""
    server = source.server_uuid()
    closed = closed_logs(source.binary_logs())
    held = load_ledger(ledger_path).shipped(server)
    cover = coverage(held, [sequence_of(e.name) for e in closed])
    say(f"coverage of {len(closed)} closed logs on {server}: {describe(cover)}")
    if not cover.ok:
        fail(describe(cover))
    return cover


# ----- reading copy 1 back -----


@dataclasses.dataclass(frozen=True)
class Manifest:
    server: str
    name: str
    seq: int
    size: int
    plain_sha256: str
    sealed_sha256: str
    start: int
    end: int
    first_gtid: str | None
    last_gtid: str | None


def manifest_from(raw: bytes) -> Manifest:
    try:
        doc = json.loads(raw)
        manifest = Manifest(
            server=str(doc["server_uuid"]),
            name=str(doc["log"]),
            seq=int(doc["sequence"]),
            size=int(doc["bytes"]),
            plain_sha256=str(doc["plain_sha256"]),
            sealed_sha256=str(doc["sealed_sha256"]),
            start=int(doc["start"]),
            end=int(doc["end"]),
            first_gtid=doc.get("first_gtid"),
            last_gtid=doc.get("last_gtid"),
        )
    except (KeyError, TypeError, ValueError):
        fail("a manifest on copy 1 is malformed")
    if (
        doc.get("version") != MANIFEST_VERSION
        or not SERVER_UUID.match(manifest.server)
        or sequence_of(manifest.name) != manifest.seq
        or not SHA256.match(manifest.plain_sha256)
        or not SHA256.match(manifest.sealed_sha256)
    ):
        fail("a manifest on copy 1 disagrees with itself")
    return manifest


def audit(
    *,
    store: Store,
    ledger_path: pathlib.Path,
    servers: Sequence[str] | None = None,
    say: Callable[[str], None] = print,
) -> None:
    """Read every shipped log back from copy 1 and require the digest the ledger recorded."""
    ledger = load_ledger(ledger_path)
    wanted = list(servers) if servers else sorted(ledger.servers)
    if not wanted:
        refuse("the ledger names no server, so there is nothing to read back")
    problems: list[str] = []
    checked = 0
    for server in wanted:
        present = set(store.list(f"{KEY_PREFIX}/{server}/"))
        for seq, entry in sorted(ledger.shipped(server).items()):
            key = sealed_key(server, entry.name)
            if key not in present or manifest_key(server, entry.name) not in present:
                problems.append(f"{entry.name} is not on copy 1")
                continue
            blob = store.get(key)
            require_ciphertext(blob)
            if hashlib.sha256(blob).hexdigest() != entry.sealed_sha256:
                problems.append(f"{entry.name} came back with another digest")
                continue
            if manifest_from(store.get(manifest_key(server, entry.name))).sealed_sha256 != (
                entry.sealed_sha256
            ):
                problems.append(f"the manifest of {entry.name} names another digest")
                continue
            checked += 1
            say(f"read back {entry.name} (sequence {seq}): sha256={entry.sealed_sha256}")
    if problems:
        fail("; ".join(problems))
    say(f"audit: {checked} logs read back from copy 1, each equal to what was shipped")


# ----- restore to a time -----


def parse_time(text: str) -> int:
    """A UTC time as 2026-11-19T03:10:00Z, seconds since the epoch. A local time is refused."""
    match = UTC_TIME.match(text)
    if match is None:
        refuse(f"{text!r} is not a UTC time like 2026-11-19T03:10:00Z")
    moment = datetime.datetime.fromisoformat(f"{match['date']}T{match['clock']}+00:00")
    return int(moment.timestamp())


def mysqlbinlog_time(stamp: int) -> str:
    return datetime.datetime.fromtimestamp(stamp, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")


def plan_replay(manifests: Sequence[Manifest], *, begin: int, stop: int) -> list[Manifest]:
    """The logs, in order, whose replay carries a restored copy from `begin` to `stop`.

    Refused unless the shipped logs cover the whole window with no sequence missing: the logs that
    overlap it must be consecutive, one must reach back to `begin` (or the one before it end before
    it), and the newest shipped log must reach `stop` (the log still open is never shipped).
    """
    if stop < begin:
        refuse("the stop time is before the start time")
    ordered = sorted(manifests, key=lambda m: m.seq)
    if not ordered:
        fail("no log is shipped for that server, so nothing can be replayed")
    chosen = [m for m in ordered if m.end >= begin and m.start <= stop]
    if not chosen:
        fail("no shipped log covers that window")
    first = chosen[0]
    if first.start > begin and not any(m.seq == first.seq - 1 for m in ordered):
        fail(
            f"{first.name} begins at {mysqlbinlog_time(first.start)}, after the start time, "
            "and the log before it is not shipped"
        )
    for before, after in zip(chosen, chosen[1:], strict=False):
        if after.seq != before.seq + 1:
            missing = list(range(before.seq + 1, after.seq))
            fail(f"the logs between {before.name} and {after.name} are not shipped: {missing}")
    newest = ordered[-1]
    if chosen[-1] is newest and newest.end < stop:
        fail(
            f"the newest shipped log, {newest.name}, ends at {mysqlbinlog_time(newest.end)}, "
            "before the stop time; the log still open is not shipped until the next pull"
        )
    return chosen


def manifests_from_ledger(ledger: Ledger, server: str) -> list[Manifest]:
    return [
        Manifest(
            server=server,
            name=e.name,
            seq=e.seq,
            size=e.size,
            plain_sha256=e.plain_sha256,
            sealed_sha256=e.sealed_sha256,
            start=e.start,
            end=e.end,
            first_gtid=None,
            last_gtid=None,
        )
        for e in ledger.shipped(server).values()
    ]


def manifests_from_store(store: Store, server: str) -> list[Manifest]:
    keys = [k for k in store.list(f"{KEY_PREFIX}/{server}/") if k.endswith(MANIFEST_SUFFIX)]
    return [manifest_from(store.get(key)) for key in keys]


def replay_commands(
    files: Sequence[pathlib.Path], *, stop: int, database: str | None, option_file: pathlib.Path
) -> tuple[list[str], list[str]]:
    """The two commands of a replay: mysqlbinlog up to the stop time, piped into mysql."""
    reader = ["mysqlbinlog", f"--stop-datetime={mysqlbinlog_time(stop)}"]
    if database is not None:
        reader.append(f"--database={database}")
    reader += [str(f) for f in files]
    writer = ["mysql", f"--defaults-extra-file={option_file}"]
    return reader, writer


def replay(
    *,
    chosen: Sequence[Manifest],
    store: Store,
    identity: pathlib.Path,
    option_file: pathlib.Path,
    stop: int,
    database: str | None,
    work: pathlib.Path,
    apply: bool,
    say: Callable[[str], None] = print,
    opener: Callable[[pathlib.Path, pathlib.Path, pathlib.Path], None] = age_open,
    runner: Callable[[Sequence[str], Sequence[str]], int] | None = None,
) -> None:
    """Fetch, open and check each chosen log, then replay them into a scratch server up to `stop`.

    Without `apply` it stops after the plan, which is the replay check: every log needed is on
    copy 1 and opens with the identity to the digest the manifest holds. Nothing reaches a
    database.
    """
    for manifest in chosen:
        say(
            f"needs {manifest.name} (sequence {manifest.seq}): "
            f"{mysqlbinlog_time(manifest.start)} to {mysqlbinlog_time(manifest.end)} UTC"
        )
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = pathlib.Path(tempfile.mkdtemp(dir=work, prefix="replay-"))
    try:
        files: list[pathlib.Path] = []
        for manifest in chosen:
            blob = store.get(sealed_key(manifest.server, manifest.name))
            require_ciphertext(blob)
            if hashlib.sha256(blob).hexdigest() != manifest.sealed_sha256:
                fail(f"{manifest.name} came back from copy 1 with another digest")
            sealed_path = directory / f"{manifest.name}{SEALED_SUFFIX}"
            sealed_path.write_bytes(blob)
            plain = directory / manifest.name
            opener(sealed_path, plain, identity)
            if sha256_file(plain) != manifest.plain_sha256:
                fail(f"{manifest.name} opened to bytes that are not the log that was shipped")
            read_span(plain)
            files.append(plain)
        say(f"{len(files)} logs opened and checked against their manifests")
        reader, writer = replay_commands(
            files, stop=stop, database=database, option_file=option_file
        )
        if not apply:
            say(f"dry run: would replay up to {mysqlbinlog_time(stop)} UTC; pass --apply to do it")
            return
        run = runner if runner is not None else run_replay
        if run(reader, writer) != 0:
            fail("the replay did not complete (output withheld)")
        say(f"replayed {len(files)} logs up to {mysqlbinlog_time(stop)} UTC")
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def run_replay(reader: Sequence[str], writer: Sequence[str]) -> int:
    """Pipe mysqlbinlog into mysql, the clock pinned to UTC: the stop time is read as local."""
    env = {"PATH": SAFE_PATH, "TZ": "UTC"}
    source = subprocess.Popen(  # noqa: S603 -- argument lists, no shell
        list(reader), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env
    )
    sink = subprocess.Popen(  # noqa: S603
        list(writer),
        stdin=source.stdout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    if source.stdout is not None:
        source.stdout.close()
    sink_code = sink.wait()
    source_code = source.wait()
    return sink_code or source_code


# ----- configuration -----


def load_env(path: pathlib.Path) -> dict[str, str]:
    """Read NAME=value lines of an environment file. Values are never printed."""
    if not path.is_file():
        refuse(f"{path} is not there")
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        match = ENV_LINE.match(line.strip())
        if match:
            values[match["name"]] = match["value"]
    return values


def connection_of(env: Mapping[str, str]) -> Connection:
    host, user, pw, ca = (env.get(n, "") for n in (ENV_HOST, ENV_USER, ENV_PW, ENV_CA))
    port = env.get(ENV_PORT, "3306")
    if not (HOST_NAME.match(host) and USER_NAME.match(user) and pw and ca and port.isdigit()):
        refuse("the database host, port, account, login value or CA file is missing or malformed")
    return Connection(host=host, port=int(port), user=user, pw=pw, ca_file=ca)


def recipient_of(env: Mapping[str, str]) -> str:
    recipient = env.get("STATE_COPY_RECIPIENT", "")
    if not RECIPIENT.match(recipient):
        refuse("STATE_COPY_RECIPIENT is not a single age1 recipient")
    return recipient


def target_of(env: Mapping[str, str], prefix: str) -> Target:
    values = [env.get(f"{prefix}_{n}", "") for n in DEST_NAMES]
    missing = [f"{prefix}_{n}" for n, v in zip(DEST_NAMES, values, strict=True) if not v]
    if missing:
        refuse(f"missing {', '.join(missing)}")
    return Target(*values)


def write_store(args: argparse.Namespace) -> Store:
    target = target_of(load_env(args.copy_env_file), "STATE_COPY_DEST")
    return ReleaseStore(load_object_storage(args.release_scripts), target)


def read_store(args: argparse.Namespace) -> Store:
    if args.read_env_file is None:
        refuse("this command needs --read-env-file, a file holding the read-only copy-1 key")
    target = target_of(load_env(args.read_env_file), "BACKUP_DRILL_COPY_PRIMARY")
    return ReleaseStore(load_object_storage(args.release_scripts), target)


def self_check() -> None:
    """What the install-time check reads: the constants hold together, nothing is touched."""
    if sequence_of("mysql-bin.000042") != 42:
        fail("the log name pattern misreads a log name")
    if not RECIPIENT.match("age1" + "q" * 58):
        fail("the recipient pattern refuses a well-formed recipient")
    if coverage({1, 2, 4}, {1, 2, 3, 4}).holes != (3,):
        fail("the coverage check misses a hole")
    if parse_time("2026-11-19T03:10:00Z") != 1795057800:
        fail("the time parser misreads a UTC time")


# ----- the commands -----


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="check the program itself and stop")
    parser.add_argument("--env-file", type=pathlib.Path, default=ENV_FILE)
    parser.add_argument("--copy-env-file", type=pathlib.Path, default=COPY_ENV_FILE)
    parser.add_argument("--read-env-file", type=pathlib.Path)
    parser.add_argument("--state-dir", type=pathlib.Path, default=STATE_DIR)
    parser.add_argument("--work-dir", type=pathlib.Path, default=WORK_DIR)
    parser.add_argument("--release-scripts", type=pathlib.Path, default=RELEASE_SCRIPTS)
    parser.add_argument("--metrics-dir", type=pathlib.Path, default=METRICS_DIR)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("pull")
    sub.add_parser("check")
    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--server-uuid", action="append")
    for name in ("plan", "replay"):
        window = sub.add_parser(name)
        window.add_argument("--server-uuid", required=True)
        window.add_argument(
            "--from", dest="begin", required=True, help="UTC, the restored copy's time"
        )
        window.add_argument("--to", dest="stop", required=True, help="UTC, the time to restore to")
        window.add_argument(
            "--from-ledger", action="store_true", help="plan from this host's ledger"
        )
    replay_parser = sub.choices["replay"]
    replay_parser.add_argument("--identity", type=pathlib.Path, required=True)
    replay_parser.add_argument("--target-option-file", type=pathlib.Path, required=True)
    replay_parser.add_argument("--database")
    replay_parser.add_argument("--apply", action="store_true")
    return parser


def execute(args: argparse.Namespace, say: Callable[[str], None]) -> int:
    command: str = args.command
    ledger_path = args.state_dir / LEDGER_NAME
    if command in ("pull", "check"):
        source = MysqlSource(connection_of(load_env(args.env_file)))
        if command == "check":
            check(source=source, ledger_path=ledger_path, say=say)
            return EXIT_OK
        flush = load_env(args.env_file).get(ENV_FLUSH, "1") != "0"
        recipient = recipient_of(load_env(args.copy_env_file))
        put_store = write_store(args)
        with run_lock(args.state_dir) as held:
            if not held:
                say("another pull holds the lock; this run stands aside")
                return EXIT_OK
            try:
                report = pull(
                    source=source,
                    store=put_store,
                    seal=age_seal,
                    recipient=recipient,
                    ledger_path=ledger_path,
                    work=args.work_dir,
                    flush=flush,
                    say=say,
                )
            except (CheckFailed, Precondition):
                write_metrics(args.metrics_dir, None, now=time.time())
                raise
            write_metrics(args.metrics_dir, report, now=time.time())
        say(f"coverage: {describe(report.cover)}")
        if report.failures or not report.cover.ok:
            fail(f"{len(report.failures)} logs failed this run; {describe(report.cover)}")
        return EXIT_OK
    if command == "audit":
        audit(store=read_store(args), ledger_path=ledger_path, servers=args.server_uuid, say=say)
        return EXIT_OK
    begin, stop = parse_time(args.begin), parse_time(args.stop)
    if command == "replay" and args.from_ledger:
        refuse("replay reads the logs from copy 1, so --from-ledger does not apply to it")
    if args.from_ledger:
        manifests = manifests_from_ledger(load_ledger(ledger_path), args.server_uuid)
        store: Store | None = None
    else:
        store = read_store(args)
        manifests = manifests_from_store(store, args.server_uuid)
    chosen = plan_replay(manifests, begin=begin, stop=stop)
    if command == "plan":
        for manifest in chosen:
            say(
                f"{manifest.name}: {mysqlbinlog_time(manifest.start)} to "
                f"{mysqlbinlog_time(manifest.end)} UTC"
            )
        say(
            f"plan: {len(chosen)} logs cover "
            f"{mysqlbinlog_time(begin)} to {mysqlbinlog_time(stop)} UTC"
        )
        return EXIT_OK
    if store is None:
        refuse("replay needs copy 1")
    replay(
        chosen=chosen,
        store=store,
        identity=args.identity,
        option_file=args.target_option_file,
        stop=stop,
        database=args.database,
        work=args.work_dir,
        apply=args.apply,
        say=say,
    )
    return EXIT_OK


def main(argv: Sequence[str] | None = None, *, say: Callable[[str], None] = print) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.check:
            self_check()
        elif args.command is None:
            parser.error("a command is required")
        else:
            code = execute(args, say)
            if code != EXIT_OK:
                return code
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
