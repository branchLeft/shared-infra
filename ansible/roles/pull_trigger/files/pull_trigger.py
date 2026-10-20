#!/usr/bin/python3 -I
"""Apply one exact, verified commit of main to this host.

The role installs this file as one root-owned program, the only thing the CI key
can run. The caller supplies one commit id of 40 lowercase hex digits; every
other value comes from a root-owned configuration file.

The steps, their order and the exit codes are in the role README. ``Exit`` names
the exit statuses.
"""

import contextlib
import dataclasses
import enum
import fcntl
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, ClassVar, Final, Literal, TextIO

DEFAULT_CONFIG: Final = Path("/etc/pull-trigger/config.json")
SEARCH_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
COMMIT_PATTERN: Final = re.compile(r"[0-9a-f]{40}")
# The caller's only input. Everything about the repository layout is fixed here.
PLAYBOOK_PREFIX: Final = ("ansible", "playbooks")
ANSIBLE_DIRECTORY: Final = "ansible"
PATH_PART_PATTERN: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
MAIN_REF: Final = "refs/pull-trigger/main"
MAX_CONFIG_BYTES: Final = 1_000_000
# gpg connects to an agent through a socket under the keyring directory, and a socket path
# longer than about 104 characters fails. The keyring is made under the state directory.
MAX_STATE_DIR_LENGTH: Final = 60
GIT_TIMEOUT_SECONDS: Final = 600
TERMINATE_GRACE_SECONDS: Final = 30
POLL_SECONDS: Final = 0.2
RECAP_TAIL_BYTES: Final = 262_144
FLOOR_NAME: Final = "last-applied"
CURRENT_NAME: Final = "current"

HTTPS_URL: Final = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)+")
FILE_URL: Final = re.compile(r"file:///[A-Za-z0-9._~/-]+")
SSH_KEY: Final = re.compile(
    r"(?P<type>ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r" (?P<body>[A-Za-z0-9+/]+={0,2})(?: [ -~]*)?",
)
PGP_KEY: Final = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----\n[\n -~]+\n-----END PGP PUBLIC KEY BLOCK-----\n?",
)
RECAP_LINE: Final = re.compile(
    r"^\S+\s*:\s+ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)"
    r"\s+failed=(?P<failed>\d+)",
    re.MULTILINE,
)
CONFIG_KEYS: Final = frozenset(
    {
        "remote_url",
        "signers",
        "playbooks",
        "playbook",
        "ansible_playbook",
        "state_dir",
        "log_dir",
        "timeout_seconds",
        "keep_runs",
    },
)

Clock = Callable[[], datetime]


class Exit(enum.IntEnum):
    """The exit status, which says what happened.

    0 and 10 and 11 mean the run completed; 20 and 21 mean the request was
    refused before any change; 40 means the program could not get as far as the
    playbook; 30 and 31 mean the playbook started and did not complete.
    """

    UNCHANGED = 0
    APPLIED = 10
    WOULD_CHANGE = 11
    REFUSED = 20
    BUSY = 21
    FAILED = 30
    TIMED_OUT = 31
    ERROR = 40


VERDICT_NAMES: Final[Mapping[Exit, str]] = {
    Exit.UNCHANGED: "unchanged",
    Exit.APPLIED: "applied",
    Exit.WOULD_CHANGE: "would-change",
    Exit.REFUSED: "refused",
    Exit.BUSY: "busy",
    Exit.FAILED: "failed",
    Exit.TIMED_OUT: "timed-out",
    Exit.ERROR: "error",
}


class Mode(enum.Enum):
    """What the request asks for."""

    APPLY = "apply"
    CHECK = "check"


class Why(enum.Enum):
    """Every sentence the program gives for a refusal or a fault, kept in one place.

    The wording is fixed so that a log line can be searched for and so that no
    text from the caller can reach a log or a message.
    """

    OPTION_UNKNOWN = "unknown option"
    MODE_MISSING = "--mode is required"
    OPTION_REPEATED = "an option was given twice"
    MODE_UNKNOWN = "--mode must be apply or check"
    CONFIG_OPTION_RELATIVE = "--config must be an absolute path"
    COMMIT_REPEATED = "the commit was given twice"
    COMMIT_COUNT = "exactly one commit is required"
    COMMIT_SHAPE = "the commit must be exactly 40 lowercase hex digits"
    COMMIT_UNKNOWN = "the commit is not in the history of main"
    COMMIT_NOT_ANCESTOR = "the commit is not an ancestor of the tip of main"
    COMMIT_OLDER = "the commit is older than the last one applied here"
    SIGNATURE_ABSENT = "the commit carries no signature"
    SIGNATURE_BAD = "the signature does not verify, or its key is expired or revoked"
    SIGNER_NOT_LISTED = "the commit is not signed by an allowlisted key"
    PLAYBOOK_NOT_LISTED = "the host's playbook is not on the allowlist"
    PLAYBOOK_NOT_REGULAR = "the playbook is not a regular file in the commit"
    PLAYBOOK_ESCAPES = "the playbook resolves outside ansible/playbooks"
    PLAYBOOK_LINKED = "a part of the playbook path is a link in the checkout"
    LOCK_HELD = "another trigger is running"
    CONFIG_UNREADABLE = "the configuration file cannot be opened"
    CONFIG_NOT_REGULAR = "the configuration is not a regular file"
    CONFIG_TOO_LARGE = "the configuration file is too large"
    CONFIG_UNSAFE = "must belong to this user and not be writable by others"
    CONFIG_JSON = "the configuration is not valid JSON"
    CONFIG_KEY_SET = "the configuration has missing or unknown keys"
    CONFIG_URL = "remote_url must be an https or file URL"
    CONFIG_NO_SIGNERS = "signers must be a non-empty list"
    CONFIG_NO_PLAYBOOKS = "playbooks must be a non-empty list"
    CONFIG_PLAYBOOK_PATH = "every allowlisted playbook must be a plain path under ansible/playbooks"
    CONFIG_NOT_TEXT = "must be text"
    CONFIG_NOT_NUMBER = "must be a whole number in its range"
    CONFIG_NOT_PATH = "must be an absolute normalised path"
    CONFIG_PATH_LONG = "is too long for the GnuPG agent socket that lives beneath it"
    SIGNER_FIELDS = "a signer needs exactly a format and a key"
    SIGNER_KEY_TYPE = "a signer key must be text"
    SIGNER_FORMAT = "a signer format must be ssh or openpgp"
    SIGNER_SSH_SHAPE = "an ssh signer key is not a public key line"
    SIGNER_PGP_SHAPE = "an openpgp signer key is not an armoured public key block"
    SSH_KEY_REJECTED = "ssh-keygen did not accept a configured ssh signer key"
    PGP_KEY_REJECTED = "gpg did not accept a configured openpgp signer key"
    PGP_NO_FINGERPRINT = "gpg reported no fingerprint for a configured openpgp signer key"
    FLOOR_DAMAGED = "the record of the last applied commit is damaged"
    DIRECTORY_NOT_MADE = "a state directory cannot be created"
    DIRECTORY_NOT_PRIVATE = "a state directory is not private and owned by this user"
    TOOL_MISSING = "a program this one runs is not installed"
    COMMAND_INCOMPLETE = "a command could not run to completion"
    COMMAND_STATUS = "a git command failed"
    GIT_INIT = "git init failed"
    GIT_MERGE_BASE = "git merge-base failed"


class TriggerError(Exception):
    """Base of every error the program reports on purpose; it carries its verdict."""

    exit_code: ClassVar[Exit] = Exit.ERROR
    reason: ClassVar[str] = "error"

    def __init__(self, why: "Why | None" = None, subject: str = "") -> None:
        """Keep the detail, which is for the maintainer and never contains caller text.

        Args:
            why: The fixed sentence saying what went wrong.
            subject: A name this program chose (a configuration key, a file name).
        """
        detail = why.value if why is not None else self.reason
        self.detail = f"{detail}: {subject}" if subject else detail
        super().__init__(self.detail)


class RefusedError(TriggerError):
    """The request was understood and refused before any change."""

    exit_code = Exit.REFUSED
    reason = "refused"


class BadRequestError(RefusedError):
    """The caller's input is not exactly a mode and one 40-digit lowercase hex commit."""

    reason = "bad-request"


class BusyError(RefusedError):
    """Another trigger holds the lock, so this one is refused rather than queued."""

    exit_code = Exit.BUSY
    reason = "busy"


class NotOnMainError(RefusedError):
    """The commit is not an ancestor of the fetched tip of main."""

    reason = "not-on-main"


class RollbackError(RefusedError):
    """The commit is older than the last one applied on this host."""

    reason = "rollback"


class UnsignedError(RefusedError):
    """The commit carries no signature."""

    reason = "unsigned"


class BadSignatureError(RefusedError):
    """The commit's signature does not verify, or its key is expired or revoked."""

    reason = "bad-signature"


class SignerNotAllowedError(RefusedError):
    """The commit is signed, but not by a key on the allowlist."""

    reason = "signer-not-allowed"


class PlaybookNotAllowedError(RefusedError):
    """The playbook is not on the allowlist, or is not a regular file in the commit."""

    reason = "playbook-not-allowed"


class ConfigError(TriggerError):
    """The configuration file is unsafe, unreadable or invalid."""

    reason = "config-invalid"


class StateError(TriggerError):
    """The program's own directories or files are not what they must be."""

    reason = "state-unsafe"


class ToolMissingError(TriggerError):
    """A program this one runs is not installed."""

    reason = "tool-missing"


class GitError(TriggerError):
    """A git, gpg or ssh-keygen command failed."""

    reason = "git-failed"


@dataclasses.dataclass(frozen=True)
class Verdict:
    """How a run ended."""

    exit_code: Exit
    reason: str
    changed: int | None = None

    @property
    def name(self) -> str:
        """The verdict word printed and logged."""
        return VERDICT_NAMES[self.exit_code]


@dataclasses.dataclass(frozen=True)
class Tools:
    """Absolute paths of the programs this one runs."""

    git: Path = Path("/usr/bin/git")
    gpg: Path = Path("/usr/bin/gpg")
    gpgconf: Path = Path("/usr/bin/gpgconf")
    ssh_keygen: Path = Path("/usr/bin/ssh-keygen")


@dataclasses.dataclass(frozen=True)
class Signer:
    """One allowed signer: an SSH public key or an armoured OpenPGP public key."""

    key_format: Literal["ssh", "openpgp"]
    key: str


@dataclasses.dataclass(frozen=True)
class Config:
    """The root-owned configuration. The caller can change none of it."""

    remote_url: str
    signers: tuple[Signer, ...]
    playbooks: tuple[str, ...]
    playbook: str
    ansible_playbook: Path
    state_dir: Path
    log_dir: Path
    timeout_seconds: int
    keep_runs: int


@dataclasses.dataclass(frozen=True)
class Arguments:
    """What the program's own command line (set by root, not the caller) says."""

    mode: Mode
    config_path: Path
    positional: tuple[str, ...]


def utc_now() -> datetime:
    """Return the current time in UTC."""
    return datetime.now(UTC)


def stamp(moment: datetime) -> str:
    """Format a time the way the log writes it."""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_arguments(argv: Sequence[str]) -> Arguments:
    """Read the options that root put on the command line.

    Only ``--mode apply|check`` (required, once) and ``--config PATH`` (once) are
    options. The caller cannot add to this line. Any other option is refused.

    Raises:
        BadRequestError: An option is unknown, repeated, or missing its value, or no mode is given.
    """
    values: dict[str, str] = {}
    positional: list[str] = []
    words = iter(argv)
    for word in words:
        if word in ("--mode", "--config"):
            if word in values:
                raise BadRequestError(Why.OPTION_REPEATED)
            values[word] = next(words, "")
        elif word.startswith("-"):
            raise BadRequestError(Why.OPTION_UNKNOWN)
        else:
            positional.append(word)
    return Arguments(
        _mode_from(values.get("--mode")),
        _config_path_from(values.get("--config")),
        tuple(positional),
    )


def _mode_from(value: str | None) -> Mode:
    """Return the mode named on the command line.

    Raises:
        BadRequestError: The mode is missing or is neither ``apply`` nor ``check``.
    """
    if value is None:
        raise BadRequestError(Why.MODE_MISSING)
    try:
        return Mode(value)
    except ValueError:
        raise BadRequestError(Why.MODE_UNKNOWN) from None


def _config_path_from(value: str | None) -> Path:
    """Return the configuration path named on the command line, or the default.

    Raises:
        BadRequestError: The path is not absolute.
    """
    if value is None:
        return DEFAULT_CONFIG
    if not value.startswith("/"):
        raise BadRequestError(Why.CONFIG_OPTION_RELATIVE)
    return Path(value)


def resolve_commit(arguments: Arguments, environ: Mapping[str, str]) -> str:
    """Return the one commit the caller asked for, or refuse.

    The commit comes from ``SSH_ORIGINAL_COMMAND``, or, run by hand, from the one
    positional word; both, or neither, is refused. Anything but 40 lowercase hex
    digits is refused.

    Raises:
        BadRequestError: The input is not exactly one 40-digit lowercase hex commit.
    """
    original = environ.get("SSH_ORIGINAL_COMMAND")
    if original is not None:
        if arguments.positional:
            raise BadRequestError(Why.COMMIT_REPEATED)
        candidate = original
    else:
        if len(arguments.positional) != 1:
            raise BadRequestError(Why.COMMIT_COUNT)
        candidate = arguments.positional[0]
    if COMMIT_PATTERN.fullmatch(candidate) is None:
        raise BadRequestError(Why.COMMIT_SHAPE)
    return candidate


def canonical_playbook(path: str) -> str | None:
    """Return ``path`` if it is a playbook path the allowlist may hold, else None.

    The path is relative, already normalised (no ``.``, no ``..``, no doubled or
    trailing slash), inside ``ansible/playbooks/``, made of plain name parts, and
    ends in ``.yml`` or ``.yaml``.

    Returns:
        The same path when acceptable, otherwise None.
    """
    pure = PurePosixPath(path)
    parts = pure.parts
    acceptable = (
        not pure.is_absolute()
        and str(pure) == path
        and len(parts) > len(PLAYBOOK_PREFIX)
        and parts[: len(PLAYBOOK_PREFIX)] == PLAYBOOK_PREFIX
        and all(PATH_PART_PATTERN.fullmatch(part) is not None for part in parts)
        and parts[-1].endswith((".yml", ".yaml"))
    )
    return path if acceptable else None


def _signer_from(value: object) -> Signer:
    """Validate one allowlist entry.

    Raises:
        ConfigError: The entry is not an SSH or OpenPGP public key in a recognised shape.
    """
    if not isinstance(value, dict) or set(value) != {"format", "key"}:
        raise ConfigError(Why.SIGNER_FIELDS)
    key_format, key = value["format"], value["key"]
    if not isinstance(key, str):
        raise ConfigError(Why.SIGNER_KEY_TYPE)
    if key_format == "ssh":
        match = SSH_KEY.fullmatch(key)
        if match is None:
            raise ConfigError(Why.SIGNER_SSH_SHAPE)
        return Signer("ssh", f"{match['type']} {match['body']}")
    if key_format == "openpgp":
        if PGP_KEY.fullmatch(key) is None:
            raise ConfigError(Why.SIGNER_PGP_SHAPE)
        return Signer("openpgp", key)
    raise ConfigError(Why.SIGNER_FORMAT)


def _text(data: Mapping[str, object], key: str) -> str:
    """Return a text value of the configuration.

    Raises:
        ConfigError: The value is not text.
    """
    value = data[key]
    if not isinstance(value, str):
        raise ConfigError(Why.CONFIG_NOT_TEXT, key)
    return value


def _whole(data: Mapping[str, object], key: str, low: int, high: int) -> int:
    """Return a whole-number value of the configuration within a range.

    Raises:
        ConfigError: The value is not a whole number in the range.
    """
    value = data[key]
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ConfigError(Why.CONFIG_NOT_NUMBER, f"{key} ({low} to {high})")
    return value


def _absolute(data: Mapping[str, object], key: str, longest: int = 4096) -> Path:
    """Return an absolute, normalised path value of the configuration.

    Raises:
        ConfigError: The value is not an absolute normalised path, or is longer than allowed.
    """
    text = _text(data, key)
    if not text.startswith("/") or str(PurePosixPath(text)) != text or ".." in text.split("/"):
        raise ConfigError(Why.CONFIG_NOT_PATH, key)
    if len(text) > longest:
        raise ConfigError(Why.CONFIG_PATH_LONG, key)
    return Path(text)


def parse_config(text: str) -> Config:
    """Turn the configuration text into a validated ``Config``.

    The allowlist entries must be well-formed playbook paths. The playbook the
    host runs is not checked here: whether it is on the allowlist is a refusal
    of the request, not a fault in the file.

    Raises:
        ConfigError: The text is not valid JSON, has unknown or missing keys, or a bad value.
    """
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise ConfigError(Why.CONFIG_JSON) from None
    if not isinstance(data, dict) or set(data) != CONFIG_KEYS:
        raise ConfigError(Why.CONFIG_KEY_SET)
    url = _text(data, "remote_url")
    if HTTPS_URL.fullmatch(url) is None and (
        FILE_URL.fullmatch(url) is None or ".." in url.split("/")
    ):
        raise ConfigError(Why.CONFIG_URL)
    signers_value, playbooks_value = data["signers"], data["playbooks"]
    if not isinstance(signers_value, list) or not signers_value:
        raise ConfigError(Why.CONFIG_NO_SIGNERS)
    if not isinstance(playbooks_value, list) or not playbooks_value:
        raise ConfigError(Why.CONFIG_NO_PLAYBOOKS)
    playbooks: list[str] = []
    for entry in playbooks_value:
        if not isinstance(entry, str) or canonical_playbook(entry) is None:
            raise ConfigError(Why.CONFIG_PLAYBOOK_PATH)
        playbooks.append(entry)
    return Config(
        remote_url=url,
        signers=tuple(_signer_from(entry) for entry in signers_value),
        playbooks=tuple(playbooks),
        playbook=_text(data, "playbook"),
        ansible_playbook=_absolute(data, "ansible_playbook"),
        state_dir=_absolute(data, "state_dir", MAX_STATE_DIR_LENGTH),
        log_dir=_absolute(data, "log_dir"),
        timeout_seconds=_whole(data, "timeout_seconds", 1, 86_400),
        keep_runs=_whole(data, "keep_runs", 1, 1_000),
    )


def _check_not_writable_by_others(info: os.stat_result, name: str) -> None:
    """Refuse a file or directory another user could replace or edit.

    Raises:
        ConfigError: The owner is not this user, or group or others can write.
    """
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ConfigError(Why.CONFIG_UNSAFE, name)


def _vet_config_file(info: os.stat_result, parent: os.stat_result) -> None:
    """Check that the opened file is a regular file that only this user can change.

    Raises:
        ConfigError: It is not a regular file, or it or its directory is unsafe.
    """
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(Why.CONFIG_NOT_REGULAR)
    _check_not_writable_by_others(info, "the configuration file")
    _check_not_writable_by_others(parent, "the configuration directory")


def load_config(path: Path) -> Config:
    """Read and validate the configuration file, which must be safe to trust.

    The file is opened without following a symlink, must be a regular file owned
    by the user running the program, and neither it nor its directory may be
    writable by group or others.

    Raises:
        ConfigError: The file is missing, unsafe or invalid.
    """
    try:
        parent = path.parent.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ConfigError(Why.CONFIG_UNREADABLE) from None
    try:
        _vet_config_file(os.fstat(descriptor), parent)
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read(MAX_CONFIG_BYTES + 1)
    if len(text) > MAX_CONFIG_BYTES:
        raise ConfigError(Why.CONFIG_TOO_LARGE)
    return parse_config(text)


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` with mode 0700, or check that an existing one is private and ours.

    Args:
        path: The directory. Its parent must exist.

    Raises:
        StateError: The directory cannot be made, or is a symlink, or is not private to this user.
    """
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError:
        raise StateError(Why.DIRECTORY_NOT_MADE, path.name) from None
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StateError(Why.DIRECTORY_NOT_PRIVATE, path.name)


def write_private_file(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` atomically, at mode 0600.

    Args:
        path: The file, in a private directory.
        text: What to write.
    """
    pending = path.with_name(path.name + ".new")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    pending.replace(path)


@contextlib.contextmanager
def single_flight(lock_path: Path) -> Iterator[None]:
    """Hold the host-wide lock for the duration of a run, or refuse at once.

    The lock is ``flock`` on a file. The kernel drops it when the holder exits
    for any reason, including being killed, so a dead holder cannot wedge the
    host and no stale-lock cleanup is needed. The descriptor is not inherited
    by the playbook.

    Raises:
        BusyError: Another trigger holds the lock.
    """
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BusyError(Why.LOCK_HELD) from None
        yield
    finally:
        os.close(descriptor)


def run_command(
    argv: Sequence[str],
    environment: Mapping[str, str],
    timeout: float = GIT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    """Run one program, as an argument list with no shell, and capture its output.

    Returns:
        The completed process; the caller reads its return code.

    Raises:
        GitError: The program cannot be started or runs too long.
    """
    try:
        # The arguments are built from constants and from values validated
        # earlier (a 40-digit hex commit, paths this program made). No shell is used.
        return subprocess.run(  # noqa: S603
            list(argv),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise GitError(Why.COMMAND_INCOMPLETE, Path(argv[0]).name) from None


def last_line(text: str) -> str:
    """Return the last line of a tool's complaint, cut short and with only printable ASCII.

    It is added to a fault message for the maintainer. The tools it comes from
    (gpg, ssh-keygen) are given only public keys, so the line holds no secret.
    """
    for line in reversed(text.split("\n")):
        if line.strip():
            return "".join(ch if " " <= ch <= "~" else "?" for ch in line.strip())[:120]
    return ""


class Git:
    """Runs git against the cache with a fixed, clean environment."""

    def __init__(self, tools: Tools, git_dir: Path, home: Path) -> None:
        """Remember the cache directory and build the environment git runs in."""
        self._tools = tools
        self._git_dir = git_dir
        self.environment: dict[str, str] = {
            "PATH": SEARCH_PATH,
            "HOME": str(home),
            "LC_ALL": "C",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https:file",
        }

    def attempt(
        self,
        *args: str,
        settings: Sequence[str] = (),
        extra_environment: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run ``git`` on the cache and return the process whatever its status."""
        argv = [str(self._tools.git), f"--git-dir={self._git_dir}"]
        for setting in (
            "core.hooksPath=/dev/null",
            "gc.auto=0",
            "transfer.fsckObjects=true",
            *settings,
        ):
            argv += ["-c", setting]
        environment = {**self.environment, **(extra_environment or {})}
        return run_command([*argv, *args], environment)

    def output(
        self,
        *args: str,
        settings: Sequence[str] = (),
        extra_environment: Mapping[str, str] | None = None,
    ) -> str:
        """Run ``git`` on the cache and return its output.

        Raises:
            GitError: git exits with a non-zero status.
        """
        done = self.attempt(*args, settings=settings, extra_environment=extra_environment)
        if done.returncode != 0:
            raise GitError(Why.COMMAND_STATUS, f"git {args[0]} exited {done.returncode}")
        return done.stdout

    def initialise(self) -> None:
        """Create the bare cache if it does not exist yet.

        Raises:
            GitError: git cannot create the repository.
        """
        if (self._git_dir / "HEAD").exists():
            return
        argv = [str(self._tools.git), "init", "--bare", "--quiet", str(self._git_dir)]
        if run_command(argv, self.environment).returncode != 0:
            raise GitError(Why.GIT_INIT)


class Cache:
    """A root-owned bare repository holding only what was fetched from main."""

    def __init__(self, git: Git, remote_url: str) -> None:
        """Remember the git runner and the read-only remote."""
        self._git = git
        self._remote_url = remote_url

    def fetch_main(self) -> None:
        """Fetch ``main`` and nothing else, so a commit not on main is not even present.

        Raises:
            GitError: the fetch fails.
        """
        self._git.initialise()
        self._git.output(
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--force",
            "--quiet",
            "--",
            self._remote_url,
            f"+refs/heads/main:{MAIN_REF}",
        )

    def require_ancestor_of_main(self, commit: str) -> None:
        """Refuse a commit that is not an ancestor of the fetched tip of main.

        The cache may still hold an object from an earlier fetch (for example a
        commit that main has since moved away from), so presence is not enough.

        Raises:
            NotOnMainError: The commit is unknown here or is not an ancestor of the tip.
            GitError: git fails for another reason.
        """
        known = self._git.attempt("cat-file", "-e", f"{commit}^{{commit}}")
        if known.returncode != 0:
            raise NotOnMainError(Why.COMMIT_UNKNOWN)
        if not self.is_ancestor(commit, MAIN_REF):
            raise NotOnMainError(Why.COMMIT_NOT_ANCESTOR)

    def is_ancestor(self, older: str, newer: str) -> bool:
        """Say whether ``older`` is ``newer`` or an ancestor of it.

        Raises:
            GitError: git cannot answer (for example ``older`` is not in the cache).
        """
        answer = self._git.attempt("merge-base", "--is-ancestor", older, newer)
        if answer.returncode not in (0, 1):
            raise GitError(Why.GIT_MERGE_BASE)
        return answer.returncode == 0

    def commit_is_signed(self, commit: str) -> bool:
        """Say whether the commit object carries a signature header."""
        header = self._git.output("cat-file", "commit", commit).split("\n\n", 1)[0]
        return any(line.startswith(("gpgsig ", "gpgsig-sha256 ")) for line in header.split("\n"))

    def regular_file_in_commit(self, commit: str, path: str) -> bool:
        """Say whether ``path`` is a regular (not symlink, not directory) file in the commit."""
        listing = self._git.output("ls-tree", "-z", commit, "--", path)
        return listing.startswith(("100644 blob ", "100755 blob "))


def judge_signature(
    signed: bool,
    status: str,
    fingerprints: Sequence[str],
    allowed: frozenset[str],
) -> None:
    """Decide from what git reported whether the signature is acceptable.

    git reports ``U`` (good, unknown validity) for a valid SSH signature by a key
    that is not on the list, so the key's fingerprint must be on the allowlist too.

    Raises:
        UnsignedError: The commit has no signature.
        BadSignatureError: The signature is bad, or made by an expired or revoked key.
        SignerNotAllowedError: The signature is not by an allowlisted key, or cannot be checked.
    """
    if not signed:
        raise UnsignedError(Why.SIGNATURE_ABSENT)
    if status in ("B", "X", "Y", "R"):
        raise BadSignatureError(Why.SIGNATURE_BAD)
    if status not in ("G", "U") or not any(item in allowed for item in fingerprints if item):
        raise SignerNotAllowedError(Why.SIGNER_NOT_LISTED)


class Verifier:
    """Checks a commit's signature against the allowlist, with a keyring made for the run."""

    def __init__(self, git: Git, cache: Cache, tools: Tools, signers: Sequence[Signer]) -> None:
        """Remember what verification needs."""
        self._git = git
        self._cache = cache
        self._tools = tools
        self._signers = signers

    def verify(self, commit: str, scratch_root: Path) -> None:
        """Verify the commit, using a throwaway keyring and allowed-signers file.

        Only the allowlisted keys are in the keyring, so no key the host happens
        to hold can make a signature acceptable.

        Raises:
            GitError: the keyring cannot be built or git cannot run.
        """
        signed = self._cache.commit_is_signed(commit)
        with tempfile.TemporaryDirectory(dir=scratch_root, prefix="v-") as scratch:
            home = Path(scratch)
            try:
                allowed, settings = self._prepare(home)
                shown = self._git.output(
                    "show",
                    "-s",
                    "--format=%G?%x00%GF%x00%GP",
                    commit,
                    settings=settings,
                    extra_environment={"GNUPGHOME": str(home / "gnupg")},
                )
            finally:
                self._stop_agent(home / "gnupg")
        status, signing_key, primary_key = (shown.rstrip("\n").split("\x00") + ["", "", ""])[:3]
        judge_signature(signed, status, (signing_key, primary_key), allowed)

    def _stop_agent(self, gnupg: Path) -> None:
        """Stop the gpg-agent that gpg started for the throwaway keyring, so none outlives the run.

        A failure to stop it is not allowed to change the verdict on the signature, so
        the status is deliberately not read; the keyring directory is removed either way.
        """
        if gnupg.is_dir() and any(signer.key_format == "openpgp" for signer in self._signers):
            with contextlib.suppress(GitError):
                run_command(
                    [str(self._tools.gpgconf), "--homedir", str(gnupg), "--kill", "all"],
                    {**self._git.environment, "GNUPGHOME": str(gnupg)},
                )

    def _prepare(self, home: Path) -> tuple[frozenset[str], list[str]]:
        """Build the keyring and the allowed-signers file; return fingerprints and git settings.

        Raises:
            GitError: a configured key cannot be read by gpg or ssh-keygen.
        """
        fingerprints: set[str] = set()
        gnupg = home / "gnupg"
        gnupg.mkdir(mode=0o700)
        (gnupg / "gpg.conf").write_text(
            "no-auto-key-retrieve\nno-auto-key-locate\n", encoding="utf-8"
        )
        lines: list[str] = []
        for number, signer in enumerate(self._signers):
            if signer.key_format == "ssh":
                lines.append(f'signer-{number} namespaces="git" {signer.key}')
                fingerprints.add(self._ssh_fingerprint(home, signer.key))
            else:
                fingerprints.update(self._import_pgp(gnupg, home, signer.key))
        allowed_file = home / "allowed_signers"
        allowed_file.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        settings = [
            f"gpg.program={self._tools.gpg}",
            f"gpg.ssh.program={self._tools.ssh_keygen}",
            f"gpg.ssh.allowedSignersFile={allowed_file}",
        ]
        return frozenset(fingerprints), settings

    def _ssh_fingerprint(self, home: Path, key: str) -> str:
        """Return the SHA256 fingerprint ssh-keygen prints for a public key.

        Raises:
            GitError: ssh-keygen does not accept the key.
        """
        key_file = home / "key.pub"
        key_file.write_text(f"{key}\n", encoding="utf-8")
        done = run_command(
            [str(self._tools.ssh_keygen), "-l", "-f", str(key_file)], self._git.environment
        )
        fields = done.stdout.split()
        if done.returncode != 0 or len(fields) < 2 or not fields[1].startswith("SHA256:"):
            raise GitError(Why.SSH_KEY_REJECTED, last_line(done.stderr))
        return fields[1]

    def _import_pgp(self, gnupg: Path, home: Path, armoured: str) -> set[str]:
        """Import one armoured key into the throwaway keyring; return its primary fingerprints.

        Raises:
            GitError: gpg does not accept the key or reports no fingerprint.
        """
        key_file = home / "key.asc"
        key_file.write_text(armoured, encoding="utf-8")
        environment = {**self._git.environment, "GNUPGHOME": str(gnupg)}
        base = [str(self._tools.gpg), "--batch", "--no-tty", "--homedir", str(gnupg)]
        imported = run_command([*base, "--import", str(key_file)], environment)
        if imported.returncode != 0:
            raise GitError(Why.PGP_KEY_REJECTED, last_line(imported.stderr))
        listing = run_command(
            [*base, "--list-keys", "--with-colons", "--fixed-list-mode"], environment
        )
        found: set[str] = set()
        previous = ""
        for line in listing.stdout.split("\n"):
            fields = line.split(":")
            if fields[0] == "fpr" and previous == "pub" and len(fields) > 9:
                found.add(fields[9])
            if fields[0] in ("pub", "sub"):
                previous = fields[0]
        if not found:
            raise GitError(Why.PGP_NO_FINGERPRINT)
        return found


class Workspace:
    """The program's private state: cache, work directories, floor, lock and the current link."""

    def __init__(self, state_dir: Path) -> None:
        """Name the paths under the state directory."""
        self.root = state_dir
        self.repo = state_dir / "repo.git"
        self.work = state_dir / "work"
        self.scratch = state_dir / "tmp"
        self.home = state_dir / "home"
        self.lock = state_dir / "lock"
        self.floor = state_dir / FLOOR_NAME
        self.current = state_dir / CURRENT_NAME

    def prepare(self) -> None:
        """Create the private directories, or check the existing ones."""
        for directory in (self.root, self.repo, self.work, self.scratch, self.home):
            ensure_private_dir(directory)

    def sweep(self) -> None:
        """Remove work directories and scratch left by a run that died (called under the lock)."""
        keep = self.current.resolve() if self.current.is_symlink() else None
        for stale in self.work.iterdir():
            if stale != keep:
                shutil.rmtree(stale, ignore_errors=True)
        for stale in self.scratch.iterdir():
            shutil.rmtree(stale, ignore_errors=True)

    def last_applied(self) -> str | None:
        """Return the commit last applied here, or None on a host that has none.

        Raises:
            StateError: the record does not hold exactly one commit id.
        """
        try:
            text = self.floor.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        recorded = text.strip()
        if COMMIT_PATTERN.fullmatch(recorded) is None:
            raise StateError(Why.FLOOR_DAMAGED)
        return recorded

    def record_applied(self, commit: str) -> None:
        """Record that an apply of this commit has started."""
        write_private_file(self.floor, f"{commit}\n")

    def new_checkout(self, git: Git, commit: str) -> Path:
        """Check out exactly this commit into a fresh directory and return it.

        The files are written with ``checkout-index`` from a private index, so the
        directory holds the commit's files and no ``.git`` of its own. On any
        failure the half-made directory is removed.

        Raises:
            GitError: git cannot check the commit out.
        """
        directory = Path(tempfile.mkdtemp(prefix=f"{commit}.", dir=self.work))
        try:
            with tempfile.TemporaryDirectory(dir=self.scratch, prefix="index-") as index_dir:
                index = {"GIT_INDEX_FILE": str(Path(index_dir) / "index")}
                git.output("read-tree", commit, extra_environment=index)
                git.output(
                    "checkout-index",
                    "--all",
                    extra_environment={**index, "GIT_WORK_TREE": str(directory)},
                )
        except GitError:
            shutil.rmtree(directory, ignore_errors=True)
            raise
        return directory

    def is_current(self, directory: Path) -> bool:
        """Say whether ``directory`` is what the ``current`` link points at."""
        return self.current.is_symlink() and self.current.resolve() == directory.resolve()

    def promote(self, directory: Path) -> None:
        """Make ``directory`` the current checkout and remove the one it replaces."""
        previous = self.current.resolve() if self.current.is_symlink() else None
        link = self.root / (CURRENT_NAME + ".new")
        link.unlink(missing_ok=True)
        link.symlink_to(directory)
        link.replace(self.current)
        if previous is not None and previous != directory and previous.parent == self.work:
            shutil.rmtree(previous, ignore_errors=True)


def describe(verdict: Verdict, mode: str, commit: str, playbook: str) -> str:
    """Return the fields the log line and the summary share.

    Every value is a word this program made or a validated commit and path;
    nothing the caller typed is copied, so a line cannot be forged.
    """
    changed = "-" if verdict.changed is None else str(verdict.changed)
    return (
        f"verdict={verdict.name} exit={int(verdict.exit_code)} reason={verdict.reason} "
        f"mode={mode} commit={commit} playbook={playbook} changed={changed}"
    )


@dataclasses.dataclass(frozen=True)
class Entry:
    """What one run writes to the log."""

    verdict: Verdict
    mode: str
    commit: str
    playbook: str
    started: datetime
    finished: datetime


class Journal:
    """The root-owned log: one line per run, and the playbook output of each run."""

    def __init__(self, log_dir: Path, keep_runs: int) -> None:
        """Remember where the log is and how many run outputs to keep."""
        self._dir = log_dir
        self._runs = log_dir / "runs"
        self._keep = keep_runs

    def prepare(self) -> None:
        """Create the log directories, or check the existing ones."""
        ensure_private_dir(self._dir)
        ensure_private_dir(self._runs)

    def run_log_path(self, moment: datetime, mode: Mode, commit: str) -> Path:
        """Return the path for one run's playbook output."""
        return self._runs / f"{moment.strftime('%Y%m%dT%H%M%S%fZ')}-{mode.value}-{commit[:12]}.log"

    def prune(self) -> None:
        """Keep the newest ``keep_runs`` run outputs and remove the rest."""
        names = sorted(path for path in self._runs.iterdir() if path.suffix == ".log")
        for old in names[: max(0, len(names) - self._keep)]:
            old.unlink(missing_ok=True)

    def record(self, entry: Entry) -> str:
        """Append one line to the log and return it.

        Every value is a word this program made or a validated commit and path;
        nothing the caller typed is copied, so a line cannot be forged.
        """
        fields = describe(entry.verdict, entry.mode, entry.commit, entry.playbook)
        line = f"{fields} started={stamp(entry.started)} finished={stamp(entry.finished)}"
        descriptor = os.open(
            self._dir / "pull-trigger.log",
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return line


@dataclasses.dataclass(frozen=True)
class PlaybookResult:
    """How a playbook run ended."""

    returncode: int
    timed_out: bool
    interrupted: bool


class PlaybookRunner:
    """Runs ansible-playbook against this host only and relays its output to the caller."""

    def __init__(
        self, ansible_playbook: Path, home: Path, caller: BinaryIO, stop: threading.Event
    ) -> None:
        """Remember the program, a private HOME, where the output goes and the stop signal."""
        self._program = ansible_playbook
        self._home = home
        self._caller = caller
        self._stop = stop
        self._caller_gone = False

    def run(
        self, checkout: Path, playbook: str, mode: Mode, log_path: Path, timeout: int
    ) -> PlaybookResult:
        """Run the playbook in the checkout and wait for it, killing it at the limit.

        The playbook's output is written to ``log_path`` (mode 0600) and relayed to
        the caller as it appears. A caller that disconnects does not stop the run.

        Returns:
            How the run ended.
        """
        argv = [str(self._program), "-i", "localhost,", "--connection", "local"]
        if mode is Mode.CHECK:
            argv += ["--check", "--diff"]
        argv.append(str(checkout / playbook))
        environment = {
            "PATH": SEARCH_PATH,
            "HOME": str(self._home),
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_FORCE_COLOR": "0",
            "ANSIBLE_RETRY_FILES_ENABLED": "0",
            "PYTHONUNBUFFERED": "1",
        }
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            # The program and the playbook path come from the root-owned
            # configuration and this program's own checkout. No shell is used.
            process = subprocess.Popen(  # noqa: S603
                argv,
                cwd=checkout / ANSIBLE_DIRECTORY,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=descriptor,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            os.close(descriptor)
        with log_path.open("rb") as reader:
            return self._wait(process, reader, timeout)

    def _wait(
        self, process: subprocess.Popen[bytes], reader: BinaryIO, timeout: int
    ) -> PlaybookResult:
        """Relay output until the process ends, the time runs out or a stop is requested."""
        deadline = time.monotonic() + timeout
        timed_out = interrupted = False
        while True:
            try:
                returncode = process.wait(timeout=POLL_SECONDS)
            except subprocess.TimeoutExpired:
                self._relay(reader)
                timed_out = timed_out or time.monotonic() > deadline
                interrupted = interrupted or self._stop.is_set()
                if timed_out or interrupted:
                    returncode = self._terminate(process)
                else:
                    continue
            self._relay(reader)
            return PlaybookResult(returncode, timed_out, interrupted)

    def _relay(self, reader: BinaryIO) -> None:
        """Copy any new output to the caller; a caller that has gone is ignored."""
        chunk = reader.read()
        if chunk and not self._caller_gone:
            try:
                self._caller.write(chunk)
                self._caller.flush()
            except OSError:
                self._caller_gone = True

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> int:
        """Stop the playbook's process group: TERM, then KILL after a grace period."""
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            return process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            return process.wait()


def changed_count(log_path: Path) -> int | None:
    """Return the changed total from the play recap at the end of a run's output.

    Args:
        log_path: The run's output file.

    Returns:
        The total across hosts, or None if no recap line is present.
    """
    with log_path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(max(0, handle.tell() - RECAP_TAIL_BYTES))
        tail = handle.read().decode("utf-8", errors="replace")
    lines = list(RECAP_LINE.finditer(tail))
    if not lines:
        return None
    return sum(int(line["changed"]) for line in lines)


def require_playbook_in_checkout(checkout: Path, playbook: str) -> None:
    """Refuse a playbook that is reached through a link, or that is not a file inside the checkout.

    Independent of the ``ls-tree`` test on the commit: it looks at the disk. The
    root is the checkout this program made, resolved once, so a link in the
    commit cannot move it. No part of the path may be a link, and the resolved
    playbook must lie under ``ansible/playbooks`` of that root.

    Raises:
        PlaybookNotAllowedError: a part of the path is a link, or the file is outside.
    """
    root = checkout.resolve()
    walked = root
    for part in PurePosixPath(playbook).parts:
        walked = walked / part
        if walked.is_symlink():
            raise PlaybookNotAllowedError(Why.PLAYBOOK_LINKED, part)
    resolved = (root / playbook).resolve()
    if not resolved.is_file() or not resolved.is_relative_to(root.joinpath(*PLAYBOOK_PREFIX)):
        raise PlaybookNotAllowedError(Why.PLAYBOOK_ESCAPES)


class Trigger:
    """One run from request to verdict."""

    def __init__(
        self,
        config: Config,
        tools: Tools,
        caller: BinaryIO,
        stop: threading.Event,
        clock: Clock = utc_now,
    ) -> None:
        """Wire the pieces a run needs."""
        self._config = config
        self._tools = tools
        self._stop = stop
        self._caller = caller
        self._clock = clock
        self._workspace = Workspace(config.state_dir)
        self._journal = Journal(config.log_dir, config.keep_runs)

    @property
    def playbook_label(self) -> str:
        """The playbook as the log and the summary name it: only a well-formed path."""
        return self._config.playbook if canonical_playbook(self._config.playbook) else "-"

    def execute(self, mode: Mode, request: str | TriggerError) -> Verdict:
        """Run the request and record the outcome.

        Every failure ends as a verdict with a named reason: an expected one
        (a refusal, a git failure) and an unexpected one (a bug, a full disk)
        alike. Nothing the caller typed is copied into the log or the summary.

        Returns:
            The verdict.
        """
        started = self._clock()
        commit = request if isinstance(request, str) else "-"
        try:
            self._workspace.prepare()
            self._journal.prepare()
            if isinstance(request, TriggerError):
                raise request
            verdict = self._guarded(mode, request)
        except TriggerError as error:
            verdict = Verdict(error.exit_code, error.reason)
            sys.stderr.write(f"pull-trigger: {error.reason}: {error.detail}\n")
        except OSError as error:
            verdict = Verdict(Exit.ERROR, "io-error")
            sys.stderr.write(f"pull-trigger: io-error: {error.strerror}\n")
        try:
            self._journal.record(
                Entry(verdict, mode.value, commit, self.playbook_label, started, self._clock()),
            )
        except OSError as error:
            sys.stderr.write(f"pull-trigger: the log could not be written: {error.strerror}\n")
        return verdict

    def _guarded(self, mode: Mode, commit: str) -> Verdict:
        """Check the playbook allowlist, take the lock and run.

        Raises:
            PlaybookNotAllowedError: the host's playbook is not on the allowlist.
        """
        if self._config.playbook not in self._config.playbooks:
            raise PlaybookNotAllowedError(Why.PLAYBOOK_NOT_LISTED)
        with single_flight(self._workspace.lock):
            self._workspace.sweep()
            return self._admitted(mode, commit)

    def _admitted(self, mode: Mode, commit: str) -> Verdict:
        """Fetch, verify, check out and run, under the lock.

        Raises:
            RollbackError: the commit is older than the last one applied here.
            PlaybookNotAllowedError: the playbook is not a regular file in the commit.
        """
        self._require_tools()
        git = Git(self._tools, self._workspace.repo, self._workspace.home)
        cache = Cache(git, self._config.remote_url)
        cache.fetch_main()
        cache.require_ancestor_of_main(commit)
        floor = self._workspace.last_applied()
        if floor is not None and floor != commit and not cache.is_ancestor(floor, commit):
            raise RollbackError(Why.COMMIT_OLDER)
        Verifier(git, cache, self._tools, self._config.signers).verify(
            commit, self._workspace.scratch
        )
        if not cache.regular_file_in_commit(commit, self._config.playbook):
            raise PlaybookNotAllowedError(Why.PLAYBOOK_NOT_REGULAR)
        checkout = self._workspace.new_checkout(git, commit)
        try:
            return self._run(mode, commit, checkout)
        finally:
            # Only an apply that got as far as running keeps its checkout (as
            # ``current``); a check, a refusal and a failure before that leave nothing behind.
            if not self._workspace.is_current(checkout):
                shutil.rmtree(checkout, ignore_errors=True)

    def _require_tools(self) -> None:
        """Check that every program this run will start is installed.

        Raises:
            ToolMissingError: git, ansible-playbook or a signer's verifier is missing.
        """
        needed = {self._tools.git, self._config.ansible_playbook}
        formats = {signer.key_format for signer in self._config.signers}
        if "openpgp" in formats:
            needed.update({self._tools.gpg, self._tools.gpgconf})
        if "ssh" in formats:
            needed.add(self._tools.ssh_keygen)
        for program in sorted(needed):
            if not (program.is_file() and os.access(program, os.X_OK)):
                raise ToolMissingError(Why.TOOL_MISSING, program.name)

    def _run(self, mode: Mode, commit: str, checkout: Path) -> Verdict:
        """Run the playbook in the checkout and turn its end into a verdict.

        Raises:
            PlaybookNotAllowedError: the playbook resolves outside ansible/playbooks.
        """
        require_playbook_in_checkout(checkout, self._config.playbook)
        if self._stop.is_set():
            return Verdict(Exit.FAILED, "interrupted")
        if mode is Mode.APPLY:
            self._workspace.record_applied(commit)
            self._workspace.promote(checkout)
        started = self._clock()
        log_path = self._journal.run_log_path(started, mode, commit)
        runner = PlaybookRunner(
            self._config.ansible_playbook, self._workspace.home, self._caller, self._stop
        )
        result = runner.run(
            checkout, self._config.playbook, mode, log_path, self._config.timeout_seconds
        )
        self._journal.prune()
        if result.timed_out:
            return Verdict(Exit.TIMED_OUT, "timed-out")
        if result.interrupted:
            return Verdict(Exit.FAILED, "interrupted")
        if result.returncode != 0:
            return Verdict(Exit.FAILED, "playbook-failed")
        changed = changed_count(log_path)
        if changed is None:
            return Verdict(Exit.FAILED, "no-recap")
        if changed == 0:
            return Verdict(Exit.UNCHANGED, "ok", 0)
        return Verdict(Exit.APPLIED if mode is Mode.APPLY else Exit.WOULD_CHANGE, "ok", changed)


def summary(verdict: Verdict, mode: str, commit: str, playbook: str) -> str:
    """Return the one line printed on stdout for the caller."""
    return f"pull-trigger {describe(verdict, mode, commit, playbook)}"


def main(
    argv: Sequence[str],
    environ: Mapping[str, str],
    stop: threading.Event,
    tools: Tools | None = None,
    stdout: TextIO | None = None,
    caller: BinaryIO | None = None,
) -> int:
    """Run one request and return the exit status.

    Returns:
        An ``Exit`` value.
    """
    out = sys.stdout if stdout is None else stdout
    relay = sys.stderr.buffer if caller is None else caller
    try:
        arguments = parse_arguments(argv)
        config = load_config(arguments.config_path)
    except TriggerError as error:
        sys.stderr.write(f"pull-trigger: {error.reason}: {error.detail}\n")
        out.write(summary(Verdict(error.exit_code, error.reason), "-", "-", "-") + "\n")
        return int(error.exit_code)
    request: str | TriggerError
    try:
        request = resolve_commit(arguments, environ)
    except TriggerError as error:
        request = error
    trigger = Trigger(config, tools or Tools(), relay, stop)
    try:
        verdict = trigger.execute(arguments.mode, request)
    except Exception as error:  # noqa: BLE001 - nothing may leave as an unnamed status
        # Only the class name is printed: a message could carry text from a failed command.
        sys.stderr.write(f"pull-trigger: internal-error: {type(error).__name__}\n")
        verdict = Verdict(Exit.ERROR, "internal-error")
    commit = request if isinstance(request, str) else "-"
    out.write(summary(verdict, arguments.mode.value, commit, trigger.playbook_label) + "\n")
    out.flush()
    return int(verdict.exit_code)


def run_as_program() -> int:
    """Run as the installed program: set the umask and the signal handlers, then ``main``.

    A dropped connection must not stop an apply half-way, so SIGHUP is ignored.
    A person's TERM or INT asks the playbook to stop and the stop is recorded.
    """
    os.umask(0o022)
    stop = threading.Event()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda _signal, _frame: stop.set())
    return main(sys.argv[1:], os.environ, stop)


if __name__ == "__main__":
    sys.exit(run_as_program())
