#!/usr/bin/python3 -I
"""Tells the monitoring stack which active CrowdSec bans hit an address the owner uses.

Run by a systemd timer on the edge host. Two reads, both through `docker exec`: the edge's own
Caddy access log and its rolled siblings from the last window, and `cscli decisions list`. An
address is the owner's when a request from it reached Ghost's staff session check and was
answered 2xx (Caddy marks that line `edge_trusted` 1) inside the window. Those addresses are
kept in a root-only state file. A ban on one of them, or on a range holding one, is owned.

Writes a node_exporter textfile with one sample per owned ban, labelled by CrowdSec's numeric
decision id so a repeat ban is a new series, a count per scenario for the bans that are not
owned, and the time of the run. No address is ever written to it, to stderr or to the journal;
only the state file holds addresses. When the log is missing, unreadable or shows no owner
address, every ban is written as owned, so it pages: failing closed costs extra pages, failing
open would silence the phone. When cscli fails nothing is written, so the textfile ages and the
staleness alert fires.

Exit 0 written, 2 usage, 3 cscli failed (nothing written), 4 a path was unsafe or a write failed.
Reasoning, layout and the controls: the role README.
"""

import argparse
import contextlib
import dataclasses
import enum
import errno
import gzip
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import zlib
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol, cast

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CROWDSEC = 3
EXIT_OUTPUT = 4

OWNED_METRIC = "edge_ban_owned"
LAST_RUN_METRIC = "edge_ban_owner_last_run_timestamp_seconds"

DEFAULT_DOCKER_BINARY = Path("/usr/bin/docker")
DEFAULT_COMPOSE_PROJECT = "edge"
DEFAULT_CADDY_SERVICE = "caddy"
DEFAULT_CROWDSEC_SERVICE = "crowdsec"
DEFAULT_LOG_DIR = "/var/log/caddy"
DEFAULT_LOG_STEM = "access"
DEFAULT_WINDOW_DAYS = 30
DEFAULT_STATE_FILE = Path("/var/lib/branchleft/edge-ban-owner/trusted.json")
DEFAULT_TEXTFILE = Path("/var/lib/branchleft/snds-exporter/edge_ban_owner.prom")

SECONDS_PER_DAY = 86400
# The systemd unit stops a run at 240 seconds; reading stops first so the textfile is still written.
READ_DEADLINE_SECONDS = 200.0
READ_ATTEMPTS = 2
# A rolled file is named for the moment it was rolled, and the line a request left in it can be
# older by up to a rolling interval; two days is wider than any interval the edge configures.
ROLLED_NAME_MARGIN_SECONDS = 2 * SECONDS_PER_DAY
# A line stamped later than this past the clock is not a real request.
CLOCK_SKEW_SECONDS = 300
MAX_LINE_BYTES = 1024 * 1024
DEADLINE_CHECK_INTERVAL = 4096
MAX_STATE_BYTES = 32 * 1024 * 1024
DRAIN_BYTES = 65536
DOCKER_TIMEOUT_SECONDS = 30
CSCLI_TIMEOUT_SECONDS = 60
STATE_SCHEMA_VERSION = 1
STATE_MODE = 0o600
TEXTFILE_MODE = 0o644
UNKNOWN_REASON = "unknown"

LABEL_VALUE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
LOG_STEM = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
# A scenario name is used as a label and must never carry an address: only these characters, and
# nothing shaped like a dotted quad.
SAFE_REASON = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_./-]{0,127}\Z")
DOTTED_QUAD = re.compile(r"\d+\.\d+\.\d+\.\d+")
# CrowdSec's decision id is a database row number; written only as digits, it holds no address.
DECISION_ID = re.compile(r"\A[0-9]{1,18}\Z")

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
# A sample of the textfile: scenario, owned flag, and the decision id when the sample is one ban.
SampleKey = tuple[str, str, str | None]
Clock = Callable[[], float]


class Problem(enum.StrEnum):
    """The text of every failure, kept here so a message never carries more than a name or count."""

    NOT_ONE_CONTAINER = "expected exactly one matching container, found"
    DOCKER_NOT_STARTED = "docker could not be started"
    DOCKER_NOT_FINISHED = "docker did not finish"
    DOCKER_STATUS = "docker exited with a failure status"
    DOCKER_NOT_COMPLETED = "docker could not be completed"
    NOT_PLAIN_NAME = "not a plain name"
    NOT_ABSOLUTE_PATH = "not an absolute path"
    NOT_POSITIVE_NUMBER = "not a whole number above zero"
    STATE_NOT_JSON = "the state file is not valid JSON"
    STATE_SCHEMA = "the state file has no known schema version"
    STATE_FIELDS = "the state file lacks generated_at or addresses"
    STATE_ENTRY = "the state file holds an entry that is not an address and a time"
    STATE_UNOPENABLE = "the state file cannot be opened"
    STATE_TOO_LARGE = "the state file is too large"
    SYMBOLIC_LINK = "a symbolic link was found where a file belongs"
    NOT_OWN_REGULAR_FILE = "not a regular file of the running user"
    NOT_REGULAR_FILE = "not a regular file"
    PATH_UNINSPECTABLE = "the path cannot be inspected"
    NO_TEMPORARY_FILE = "no temporary file can be made beside"
    WRITE_FAILED = "the file could not be written"
    LOG_FILE_UNREADABLE = "a log file could not be read from the container"
    LOG_FILE_CORRUPT = "a log file is not readable as the format its name claims"
    LISTING_FAILED = "the log directory could not be listed"
    NO_LOG_FILES = "the log directory holds no access log file"
    DEADLINE_PASSED = "the read deadline passed"
    DECISION_NOT_OBJECT = "cscli listed a decision that is not an object"
    CSCLI_NOT_JSON = "cscli printed text that is not JSON"
    CSCLI_NOT_LIST = "cscli printed JSON that is not a list"
    ENTRY_NOT_OBJECT = "cscli listed an entry that is not an object"
    DECISIONS_NOT_LIST = "cscli listed decisions that are not a list"
    CSCLI_NO_ANSWER = "cscli did not answer"


class EdgeBanOwnerError(Exception):
    """Base of every error this program raises on purpose.

    The message is the problem and, at most, a file name or a count: never an address and never
    what a subprocess printed.
    """

    def __init__(self, problem: Problem, subject: str = "") -> None:
        super().__init__(f"{problem}: {subject}" if subject else str(problem))
        self.problem = problem


class ContainerRuntimeError(EdgeBanOwnerError):
    """The docker client could not do what was asked of a container."""


class LogReadError(EdgeBanOwnerError):
    """The access log could not be read completely, so the owner's addresses are not known."""


class StateFormatError(EdgeBanOwnerError):
    """The state file is not a document this program wrote."""


class CrowdSecQueryError(EdgeBanOwnerError):
    """CrowdSec's decisions could not be listed or understood."""


class UnsafePathError(EdgeBanOwnerError):
    """A file this program reads or replaces is not an ordinary file of the running user."""


class OutputWriteError(EdgeBanOwnerError):
    """An output file could not be written."""


class ContainerRuntime(Protocol):
    """What the program needs from the container engine; tests and molecule substitute a fake."""

    def find_container(self, project: str, service: str) -> str: ...

    def list_directory(self, container: str, directory: str) -> list[str]: ...

    def open_file(
        self, container: str, path: str
    ) -> contextlib.AbstractContextManager[BinaryIO]: ...

    def run_cscli(self, container: str) -> str: ...


def single_container_id(output: str) -> str:
    """The one container id on a line of `docker ps -q` output.

    Raises:
        ContainerRuntimeError: no container matched, or more than one did.
    """
    identifiers = output.split()
    if len(identifiers) != 1:
        raise ContainerRuntimeError(Problem.NOT_ONE_CONTAINER, str(len(identifiers)))
    return identifiers[0]


class DockerCommandRuntime:
    """ContainerRuntime over the docker command line; no shell, argument lists only."""

    def __init__(self, docker_binary: Path) -> None:
        self.docker_binary = docker_binary

    def find_container(self, project: str, service: str) -> str:
        """The id of the one running container of a compose service.

        Raises:
            ContainerRuntimeError: docker failed, or the service is not exactly one container.
        """
        output = self.capture(
            [
                "ps",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--filter",
                f"label=com.docker.compose.service={service}",
            ],
            DOCKER_TIMEOUT_SECONDS,
        )
        return single_container_id(output)

    def list_directory(self, container: str, directory: str) -> list[str]:
        """The names in a directory of the container.

        Raises:
            ContainerRuntimeError: docker or `ls` failed.
        """
        output = self.capture(
            ["exec", container, "ls", "-1", "--", directory], DOCKER_TIMEOUT_SECONDS
        )
        return output.splitlines()

    @contextlib.contextmanager
    def open_file(self, container: str, path: str) -> Iterator[BinaryIO]:
        """A file of the container as a byte stream, checked to have been read in full.

        Raises:
            ContainerRuntimeError: `cat` could not start, did not finish, or exited non-zero.
        """
        try:
            process = subprocess.Popen(  # noqa: S603 -- an argument list, no shell
                [str(self.docker_binary), "exec", container, "cat", "--", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise ContainerRuntimeError(Problem.DOCKER_NOT_STARTED) from error
        stream = cast(BinaryIO, process.stdout)
        try:
            yield stream
            while stream.read(DRAIN_BYTES):
                pass
            status = process.wait(timeout=DOCKER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ContainerRuntimeError(Problem.DOCKER_NOT_FINISHED, "cat") from error
        finally:
            if process.poll() is None:
                process.kill()
            stream.close()
            process.wait()
        if status != 0:
            raise ContainerRuntimeError(Problem.DOCKER_STATUS, f"cat status {status}")

    def run_cscli(self, container: str) -> str:
        """The JSON `cscli decisions list` prints; CAPI decisions are left out, as the gauge does.

        Raises:
            ContainerRuntimeError: docker or cscli failed.
        """
        return self.capture(
            [
                "exec",
                container,
                "cscli",
                "decisions",
                "list",
                "-o",
                "json",
                "--limit",
                "0",
            ],
            CSCLI_TIMEOUT_SECONDS,
        )

    def capture(self, arguments: Sequence[str], timeout: int) -> str:
        """Standard output of one docker call; its standard error is never kept.

        Raises:
            ContainerRuntimeError: it could not start, timed out, exited non-zero or printed
                something that is not text.
        """
        verb = arguments[0]
        try:
            done = subprocess.run(  # noqa: S603 -- an argument list, no shell
                [str(self.docker_binary), *arguments],
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            if done.returncode != 0:
                raise ContainerRuntimeError(
                    Problem.DOCKER_STATUS, f"{verb} status {done.returncode}"
                )
            return done.stdout.decode("utf-8")
        except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError) as error:
            raise ContainerRuntimeError(Problem.DOCKER_NOT_COMPLETED, verb) from error


@dataclasses.dataclass(frozen=True)
class Config:
    """The run's settings; every value arrives on the command line from the role's defaults."""

    docker_binary: Path
    compose_project: str
    caddy_service: str
    crowdsec_service: str
    log_dir: str
    log_stem: str
    window_days: int
    state_file: Path
    textfile: Path
    check_only: bool


def label_value(text: str) -> str:
    """A compose project or service name.

    Raises:
        argparse.ArgumentTypeError: the text is not a plain name.
    """
    if LABEL_VALUE.fullmatch(text) is None:
        raise argparse.ArgumentTypeError(Problem.NOT_PLAIN_NAME)
    return text


def log_stem(text: str) -> str:
    """The first part of the access log's file name.

    Raises:
        argparse.ArgumentTypeError: the text is not a plain name.
    """
    if LOG_STEM.fullmatch(text) is None:
        raise argparse.ArgumentTypeError(Problem.NOT_PLAIN_NAME)
    return text


def absolute_directory(text: str) -> str:
    """A directory inside the container, as a normalised absolute path.

    Raises:
        argparse.ArgumentTypeError: the path is not absolute or climbs with "..".
    """
    path = PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts:
        raise argparse.ArgumentTypeError(Problem.NOT_ABSOLUTE_PATH)
    return path.as_posix()


def absolute_path(text: str) -> Path:
    """A path on this host.

    Raises:
        argparse.ArgumentTypeError: the path is not absolute or climbs with "..".
    """
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts:
        raise argparse.ArgumentTypeError(Problem.NOT_ABSOLUTE_PATH)
    return path


def positive_days(text: str) -> int:
    """A whole number of days above zero.

    Raises:
        argparse.ArgumentTypeError: the text is not a whole number above zero.
    """
    if not text.isdecimal() or int(text) < 1:
        raise argparse.ArgumentTypeError(Problem.NOT_POSITIVE_NUMBER)
    return int(text)


def parse_config(argv: Sequence[str]) -> Config:
    """Reads the command line; a bad option ends the process with the usage status."""
    parser = argparse.ArgumentParser(
        prog="branchleft_edge_ban_owner", allow_abbrev=False, description=__doc__
    )
    parser.add_argument("--check", action="store_true", help="parse the options and exit")
    parser.add_argument("--docker-binary", type=absolute_path, default=DEFAULT_DOCKER_BINARY)
    parser.add_argument("--compose-project", type=label_value, default=DEFAULT_COMPOSE_PROJECT)
    parser.add_argument("--caddy-service", type=label_value, default=DEFAULT_CADDY_SERVICE)
    parser.add_argument("--crowdsec-service", type=label_value, default=DEFAULT_CROWDSEC_SERVICE)
    parser.add_argument("--log-dir", type=absolute_directory, default=DEFAULT_LOG_DIR)
    parser.add_argument("--log-stem", type=log_stem, default=DEFAULT_LOG_STEM)
    parser.add_argument("--window-days", type=positive_days, default=DEFAULT_WINDOW_DAYS)
    parser.add_argument("--state-file", type=absolute_path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--textfile", type=absolute_path, default=DEFAULT_TEXTFILE)
    arguments = parser.parse_args(list(argv))
    return Config(
        docker_binary=arguments.docker_binary,
        compose_project=arguments.compose_project,
        caddy_service=arguments.caddy_service,
        crowdsec_service=arguments.crowdsec_service,
        log_dir=arguments.log_dir,
        log_stem=arguments.log_stem,
        window_days=arguments.window_days,
        state_file=arguments.state_file,
        textfile=arguments.textfile,
        check_only=arguments.check,
    )


def parse_address(value: object) -> Address | None:
    """The address a text names, with IPv4-mapped IPv6 turned into IPv4; None when it is not one."""
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.scope_id is not None:
            return ipaddress.IPv6Address(int(address))
    return address


@dataclasses.dataclass(frozen=True)
class TrustedState:
    """The owner's addresses and when each was last seen, as kept between runs."""

    generated_at: int
    addresses: dict[Address, int]


def whole_number(value: object) -> int | None:
    """The value when it is a JSON integer (a boolean is not one)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def parse_state(content: bytes) -> TrustedState:
    """Reads a state document.

    Raises:
        StateFormatError: the bytes are not JSON of the documented shape and schema version.
    """
    try:
        document = json.loads(content)
    except (ValueError, RecursionError) as error:
        raise StateFormatError(Problem.STATE_NOT_JSON) from error
    if not isinstance(document, dict) or whole_number(document.get("schema_version")) != (
        STATE_SCHEMA_VERSION
    ):
        raise StateFormatError(Problem.STATE_SCHEMA)
    generated_at = whole_number(document.get("generated_at"))
    stored = document.get("addresses")
    if generated_at is None or not isinstance(stored, dict):
        raise StateFormatError(Problem.STATE_FIELDS)
    addresses: dict[Address, int] = {}
    for key, last_seen in stored.items():
        address = parse_address(key)
        seen = whole_number(last_seen)
        if address is None or seen is None:
            raise StateFormatError(Problem.STATE_ENTRY)
        addresses[address] = max(seen, addresses.get(address, seen))
    return TrustedState(generated_at, addresses)


def read_state(path: Path) -> TrustedState | None:
    """The previous state, or None when there is none yet.

    Raises:
        UnsafePathError: the path is a symbolic link, is not a regular file, or belongs to
            another user.
        StateFormatError: the file cannot be read or is not a document this program wrote.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafePathError(Problem.SYMBOLIC_LINK, path.name) from error
        raise StateFormatError(Problem.STATE_UNOPENABLE, path.name) from error
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise UnsafePathError(Problem.NOT_OWN_REGULAR_FILE, path.name)
        content = handle.read(MAX_STATE_BYTES + 1)
    if len(content) > MAX_STATE_BYTES:
        raise StateFormatError(Problem.STATE_TOO_LARGE, path.name)
    return parse_state(content)


def render_state(generated_at: int, addresses: Mapping[Address, int]) -> bytes:
    """The state document for these addresses."""
    document = {
        "schema_version": STATE_SCHEMA_VERSION,
        "generated_at": generated_at,
        "addresses": {str(address): seen for address, seen in sorted(addresses.items(), key=str)},
    }
    return (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")


def write_atomically(path: Path, content: bytes, mode: int) -> None:
    """Replaces a file with new content in one rename, so a reader sees old or new, never half.

    Raises:
        UnsafePathError: the path exists and is a symbolic link or not a regular file.
        OutputWriteError: the temporary file, the rename or a sync failed; the old file is kept.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise OutputWriteError(Problem.PATH_UNINSPECTABLE, path.name) from error
    else:
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError(Problem.NOT_REGULAR_FILE, path.name)
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
    except OSError as error:
        raise OutputWriteError(Problem.NO_TEMPORARY_FILE, path.name) from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    except OSError as error:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise OutputWriteError(Problem.WRITE_FAILED, path.name) from error


def sync_directory(directory: Path) -> None:
    """Makes a rename in the directory durable."""
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclasses.dataclass(frozen=True)
class LogFile:
    """One file of the access log in the container; rolled_at is None for the live file."""

    name: str
    rolled_at: float | None
    compressed: bool


def match_log_files(names: Sequence[str], stem: str) -> list[LogFile]:
    """The files that are the access log or its rolls, by the stem and nothing broader.

    The live file is `STEM.log`. A roll is `STEM-<UTC time>-<reason>.log`, gzip-compressed once
    its compression has finished, so `.log.gz`. Another log in the directory, such as the probe
    log, shares no stem and is never matched.
    """
    rolled = re.compile(
        rf"\A{re.escape(stem)}-(\d{{4}})-(\d\d)-(\d\d)T(\d\d)-(\d\d)-(\d\d)\.(\d{{3}})"
        r"-[a-z0-9_-]+\.log(\.gz)?\Z"
    )
    found: list[LogFile] = []
    for name in names:
        if name == f"{stem}.log":
            found.append(LogFile(name, None, compressed=False))
            continue
        match = rolled.fullmatch(name)
        if match is None:
            continue
        year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
        try:
            moment = datetime(year, month, day, hour, minute, second, tzinfo=UTC)
        except ValueError:
            continue
        found.append(LogFile(name, moment.timestamp(), compressed=match.group(8) is not None))
    return found


def files_to_read(
    matches: Sequence[LogFile], cutoff: float, previous_generated_at: int | None
) -> list[LogFile]:
    """The files that can hold a line newer than the window, or newer than the last run."""
    floor = cutoff - ROLLED_NAME_MARGIN_SECONDS
    if previous_generated_at is not None:
        floor = max(floor, previous_generated_at - ROLLED_NAME_MARGIN_SECONDS)
    return [entry for entry in matches if entry.rolled_at is None or entry.rolled_at >= floor]


def is_trusted_flag(value: object) -> bool:
    """True for the string "1" or the number 1, the two forms Caddy may write; nothing else."""
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return value == "1"
    return isinstance(value, int | float) and value == 1


def trusted_request(
    entry: Mapping[str, object], cutoff: float, latest: float
) -> tuple[Address, int] | None:
    """The address and time of a request a verified staff session made inside the window."""
    seen = entry.get("ts")
    request = entry.get("request")
    if (
        not is_trusted_flag(entry.get("edge_trusted"))
        or isinstance(seen, bool)
        or not isinstance(seen, int | float)
        or not cutoff <= seen <= latest
        or not isinstance(request, dict)
    ):
        return None
    address = parse_address(request.get("remote_ip"))
    return None if address is None else (address, int(seen))


def decode_line(raw: bytes) -> Mapping[str, object] | None:
    """The JSON object on a log line; None when the line is not one."""
    try:
        entry = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return entry if isinstance(entry, dict) else None


def read_lines(stream: BinaryIO) -> Iterator[bytes | None]:
    """Lines of a stream; None stands for a line longer than MAX_LINE_BYTES, which is skipped."""
    while True:
        chunk = stream.readline(MAX_LINE_BYTES + 1)
        if not chunk:
            return
        if len(chunk) > MAX_LINE_BYTES:
            while chunk and not chunk.endswith(b"\n"):
                chunk = stream.readline(MAX_LINE_BYTES)
            yield None
        else:
            yield chunk


@dataclasses.dataclass
class ScanTally:
    """What one pass over the log has found so far."""

    addresses: dict[Address, int]
    files_read: int = 0
    bad_lines: int = 0

    def add_stream(
        self, stream: BinaryIO, cutoff: float, latest: float, check_deadline: Callable[[], None]
    ) -> None:
        """Folds one log file into the tally; a line that is not usable is counted, not fatal."""
        for count, raw in enumerate(read_lines(stream)):
            if count % DEADLINE_CHECK_INTERVAL == 0:
                check_deadline()
            if raw is not None and not raw.strip():
                continue
            entry = None if raw is None else decode_line(raw)
            if entry is None:
                self.bad_lines += 1
                continue
            found = trusted_request(entry, cutoff, latest)
            if found is not None:
                address, seen = found
                self.addresses[address] = max(seen, self.addresses.get(address, seen))
        self.files_read += 1


def read_log_file(
    runtime: ContainerRuntime,
    container: str,
    directory: str,
    entry: LogFile,
    tally: ScanTally,
    cutoff: float,
    latest: float,
    check_deadline: Callable[[], None],
) -> None:
    """Reads one file of the log into the tally, gunzipping on this host when it is compressed.

    Raises:
        LogReadError: the file could not be read to its end, or is not the gzip it claims to be.
    """
    try:
        with runtime.open_file(container, f"{directory}/{entry.name}") as raw:
            stream = cast(BinaryIO, gzip.GzipFile(fileobj=raw)) if entry.compressed else raw
            tally.add_stream(stream, cutoff, latest, check_deadline)
    except ContainerRuntimeError as error:
        raise LogReadError(Problem.LOG_FILE_UNREADABLE, entry.name) from error
    except (OSError, EOFError, zlib.error) as error:
        raise LogReadError(Problem.LOG_FILE_CORRUPT, entry.name) from error


@dataclasses.dataclass(frozen=True)
class TrustedScan:
    """The owner's addresses after reading the log, and what the reading met."""

    addresses: dict[Address, int]
    files_read: int
    bad_lines: int


def read_window(
    config: Config,
    runtime: ContainerRuntime,
    now: float,
    previous: TrustedState | None,
    check_deadline: Callable[[], None],
) -> TrustedScan:
    """One full attempt at reading the log files that matter.

    Raises:
        LogReadError: the container, the listing or any file could not be read, or no log exists.
    """
    check_deadline()
    cutoff = now - config.window_days * SECONDS_PER_DAY
    try:
        container = runtime.find_container(config.compose_project, config.caddy_service)
        names = runtime.list_directory(container, config.log_dir)
    except ContainerRuntimeError as error:
        raise LogReadError(Problem.LISTING_FAILED) from error
    matches = match_log_files(names, config.log_stem)
    if not matches:
        raise LogReadError(Problem.NO_LOG_FILES)
    known = {} if previous is None else previous.addresses
    tally = ScanTally({address: seen for address, seen in known.items() if seen >= cutoff})
    generated_at = None if previous is None else previous.generated_at
    for entry in files_to_read(matches, cutoff, generated_at):
        check_deadline()
        read_log_file(
            runtime,
            container,
            config.log_dir,
            entry,
            tally,
            cutoff,
            now + CLOCK_SKEW_SECONDS,
            check_deadline,
        )
    return TrustedScan(tally.addresses, tally.files_read, tally.bad_lines)


def collect_trusted(
    config: Config,
    runtime: ContainerRuntime,
    now: float,
    monotonic: Clock,
    previous: TrustedState | None,
) -> TrustedScan:
    """The owner's addresses from the log, trying twice because a log can roll mid-read.

    Raises:
        LogReadError: both attempts failed, or the read deadline passed.
    """
    expires = monotonic() + READ_DEADLINE_SECONDS

    def check_deadline() -> None:
        if monotonic() > expires:
            raise LogReadError(Problem.DEADLINE_PASSED)

    try:
        return read_window(config, runtime, now, previous, check_deadline)
    except LogReadError as error:
        print(f"edge_ban_owner: log read failed, trying once more: {error}", file=sys.stderr)
    return read_window(config, runtime, now, previous, check_deadline)


@dataclasses.dataclass(frozen=True)
class Ban:
    """One active ban: the scenario that raised it, what it covers and CrowdSec's id for it."""

    reason: str
    scope: str
    value: str
    decision_id: str | None


def sanitise_reason(candidate: object) -> str | None:
    """The scenario name when it is safe to use as a label; None when it is absent or unsafe."""
    if not isinstance(candidate, str) or not candidate:
        return None
    if SAFE_REASON.fullmatch(candidate) is None or DOTTED_QUAD.search(candidate) is not None:
        return UNKNOWN_REASON
    return candidate


def usable_decision_id(candidate: object) -> str | None:
    """The decision id as digits when it is a JSON integer or a digit string; None otherwise."""
    if isinstance(candidate, bool):
        return None
    text = str(candidate) if isinstance(candidate, int) else candidate
    if not isinstance(text, str) or DECISION_ID.fullmatch(text) is None:
        return None
    return text


def is_simulated(flag: object) -> bool:
    """Whether a decision's `simulated` field marks it as simulated.

    CrowdSec writes a JSON boolean; only true counts. Any other value is a ban, so an odd
    encoding pages instead of being dropped.
    """
    return flag is True


def ban_from_decision(decision: object, alert_scenario: object) -> Ban | None:
    """The ban a decision stands for; None when it is simulated or not a ban.

    Raises:
        CrowdSecQueryError: the decision is not a JSON object.
    """
    if not isinstance(decision, dict):
        raise CrowdSecQueryError(Problem.DECISION_NOT_OBJECT)
    kind = decision.get("type")
    if is_simulated(decision.get("simulated")) or not isinstance(kind, str):
        return None
    if kind.casefold() != "ban":
        return None
    reason = sanitise_reason(decision.get("scenario")) or sanitise_reason(alert_scenario)
    scope = decision.get("scope")
    value = decision.get("value")
    return Ban(
        reason or UNKNOWN_REASON,
        scope if isinstance(scope, str) else "",
        value if isinstance(value, str) else "",
        usable_decision_id(decision.get("id")),
    )


def parse_decisions(text: str) -> list[Ban]:
    """The bans in `cscli decisions list -o json`, which is alerts that each hold decisions.

    A flat list of decisions is read too. Empty output and `null` mean no decisions.

    Raises:
        CrowdSecQueryError: the text is not JSON of that shape.
    """
    if not text.strip():
        return []
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise CrowdSecQueryError(Problem.CSCLI_NOT_JSON) from error
    if document is None:
        return []
    if not isinstance(document, list):
        raise CrowdSecQueryError(Problem.CSCLI_NOT_LIST)
    bans: list[Ban] = []
    for item in document:
        if not isinstance(item, dict):
            raise CrowdSecQueryError(Problem.ENTRY_NOT_OBJECT)
        if "decisions" not in item:
            nested: object = [item]
        else:
            nested = item["decisions"]
        if nested is None:
            continue
        if not isinstance(nested, list):
            raise CrowdSecQueryError(Problem.DECISIONS_NOT_LIST)
        for decision in nested:
            ban = ban_from_decision(decision, item.get("scenario"))
            if ban is not None:
                bans.append(ban)
    return bans


def is_owned(ban: Ban, trusted: Mapping[Address, int]) -> bool:
    """Whether a ban covers an owner address; what is not a readable address or range is owned."""
    scope = ban.scope.casefold()
    if scope == "ip":
        address = parse_address(ban.value)
        return address is None or address in trusted
    if scope == "range":
        try:
            network = ipaddress.ip_network(ban.value, strict=False)
        except ValueError:
            return True
        return any(address in network for address in trusted)
    return True


def classify(bans: Sequence[Ban], trusted: Mapping[Address, int] | None) -> Counter[SampleKey]:
    """Counts per sample: an owned ban with a usable id is its own sample, the rest aggregate.

    Owned bans without a usable id are counted per scenario, and so are all unowned bans. With no
    usable signal every ban is owned.
    """
    counts: Counter[SampleKey] = Counter()
    for ban in bans:
        if trusted is None or is_owned(ban, trusted):
            counts[(ban.reason, "true", ban.decision_id)] += 1
        else:
            counts[(ban.reason, "false", None)] += 1
    return counts


def render_textfile(counts: Mapping[SampleKey, int], now: int) -> bytes:
    """The node_exporter textfile: the ban samples in sorted order, then the run time."""
    lines = [
        f"# HELP {OWNED_METRIC} Active CrowdSec bans by scenario, and whether the banned address"
        " is one of the owner's. One sample per owned ban, labelled with its CrowdSec decision id,"
        " and a count per scenario for the rest.",
        f"# TYPE {OWNED_METRIC} gauge",
    ]
    samples = []
    for (reason, owned, decision_id), count in counts.items():
        labels = f'reason="{reason}",owned="{owned}"'
        if decision_id is not None:
            labels += f',decision_id="{decision_id}"'
        samples.append(f"{OWNED_METRIC}{{{labels}}} {count}")
    lines += sorted(samples)
    lines += [
        f"# HELP {LAST_RUN_METRIC} Unix time of the last completed classification.",
        f"# TYPE {LAST_RUN_METRIC} gauge",
        f"{LAST_RUN_METRIC} {now}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


@dataclasses.dataclass(frozen=True)
class RunSummary:
    """What a run did, in counts only."""

    signal_problem: str | None
    files_read: int
    bad_lines: int
    trusted_addresses: int
    bans: int

    def describe(self) -> str:
        """One line for the journal; it holds no address."""
        line = (
            f"edge_ban_owner: signal_usable={str(self.signal_problem is None).lower()}"
            f" files_read={self.files_read} bad_lines={self.bad_lines}"
            f" trusted_addresses={self.trusted_addresses} bans={self.bans}"
        )
        return line if self.signal_problem is None else f"{line} problem={self.signal_problem!r}"


def load_previous_state(path: Path) -> TrustedState | None:
    """The previous state, or None when it is absent or unreadable as a state document.

    Raises:
        UnsafePathError: the state path is a symbolic link or not an ordinary file.
    """
    try:
        return read_state(path)
    except StateFormatError as error:
        print(
            f"edge_ban_owner: ignoring the state file, reading the whole window: {error}",
            file=sys.stderr,
        )
        return None


def list_bans(config: Config, runtime: ContainerRuntime) -> list[Ban]:
    """The active bans from CrowdSec.

    Raises:
        CrowdSecQueryError: the container or cscli failed, or cscli's output is not understood.
    """
    try:
        container = runtime.find_container(config.compose_project, config.crowdsec_service)
        text = runtime.run_cscli(container)
    except ContainerRuntimeError as error:
        raise CrowdSecQueryError(Problem.CSCLI_NO_ANSWER) from error
    return parse_decisions(text)


def run(config: Config, runtime: ContainerRuntime, clock: Clock, monotonic: Clock) -> RunSummary:
    """One classification: read the log, list the bans, write the state and then the textfile.

    Raises:
        CrowdSecQueryError: the bans could not be listed; nothing has been written.
        UnsafePathError: the state or textfile path is not an ordinary file.
        OutputWriteError: an output file could not be written.
    """
    now = clock()
    previous = load_previous_state(config.state_file)
    problem: str | None = None
    scan = TrustedScan({}, 0, 0)
    try:
        scan = collect_trusted(config, runtime, now, monotonic, previous)
    except LogReadError as error:
        problem = str(error)
    if problem is None and not scan.addresses:
        problem = "the log shows no verified staff request in the window"
    bans = list_bans(config, runtime)
    trusted = scan.addresses if problem is None else None
    counts = classify(bans, trusted)
    if trusted is not None:
        write_atomically(config.state_file, render_state(int(now), trusted), STATE_MODE)
    write_atomically(config.textfile, render_textfile(counts, int(now)), TEXTFILE_MODE)
    return RunSummary(problem, scan.files_read, scan.bad_lines, len(scan.addresses), len(bans))


def main(
    argv: Sequence[str],
    runtime: ContainerRuntime | None = None,
    clock: Clock = time.time,
    monotonic: Clock = time.monotonic,
) -> int:
    """Entry point; returns the exit status, and the runtime and clocks are replaceable."""
    config = parse_config(argv)
    if config.check_only:
        return EXIT_OK
    engine = runtime if runtime is not None else DockerCommandRuntime(config.docker_binary)
    try:
        summary = run(config, engine, clock, monotonic)
    except CrowdSecQueryError as error:
        print(f"edge_ban_owner: nothing written: {error}", file=sys.stderr)
        return EXIT_CROWDSEC
    except (UnsafePathError, OutputWriteError) as error:
        print(f"edge_ban_owner: refused: {error}", file=sys.stderr)
        return EXIT_OUTPUT
    print(summary.describe(), file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
