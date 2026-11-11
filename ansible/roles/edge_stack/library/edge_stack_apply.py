#!/usr/bin/python
"""Validate, place and apply the edge stack's files under one hold of the deploy lock.

One call takes the lock branchleft-deploy takes (flock(2) on the stack's deploy lock file),
reads the image pin, validates the candidate Caddyfile and Compose file, places the files
the role hands it, then acts on each due class, and lets go of the lock only when it
returns. No other process that takes the lock runs between the validation and the last
action. The role's README, "The locked module", says what each step does and what each exit
code means; the module's own documentation says what it takes and returns.
"""

import base64
import binascii
import contextlib
import dataclasses
import enum
import errno
import fcntl
import grp
import hashlib
import os
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import NoReturn, cast

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: edge_stack_apply
short_description: Validate, place and apply the edge stack under the deploy lock
description:
  - Takes an exclusive flock(2) on I(lock_file), the file branchleft-deploy locks for the
    same stack, and keeps it until the module returns. The pin read, the validation, the
    placement of files and every action are inside that one hold.
  - Waits for the lock for I(lock_timeout) seconds. A lock that is not free in time is outcome
    C(lock-busy), code 75, and nothing has been validated, placed or done.
  - Reads I(image_env) inside the lock and refuses anything but exactly one line that matches
    I(image_pin_pattern). The reference it read is the one the candidates are validated in,
    and the actions run only if the file still holds exactly that reference.
  - Validates the candidate Caddyfile in the pinned image and the candidate Compose file with
    C(docker compose config -q). A refusal stops the module before anything is placed.
  - Marks each stamp in I(pending_stamps), makes I(dirs), places I(files), removes I(remove),
    sets the owner and mode of I(fix_modes) that exist, and reloads systemd when a file flagged
    I(reload) changed or I(daemon_reload_needed) is true.
  - Acts on each class that is due, in this order. Writes the Caddyfile in place (I(caddy_write)),
    restarts the unit (I(compose_restart)), restarts CrowdSec (I(crowdsec_restart)) and
    reloads Caddy (I(caddy_reload)). Each is read back before the next.
  - Takes the lock only when there is something to validate or act on. With none of the
    candidates and none of the action flags it places files without the lock, as a role with
    nothing due does.
  - Returns a closed set of outcomes. Any exit code outside the set is a failure.
version_added: "1.0.0"
author:
  - branchLeft
options:
  project_dir:
    description: The stack's project directory on the host.
    type: path
    required: true
  image_env:
    description: The file that holds the one-line image pin. Read, never written.
    type: path
    required: true
  env_file:
    description: The secrets file Compose reads with C(--env-file). Never read by the module.
    type: path
    required: true
  image_pin_pattern:
    description: Regular expression the whole pin line must match.
    type: str
    required: true
  unit:
    description: The systemd unit that runs C(docker compose up) for the stack.
    type: str
    required: true
  lock_file:
    description: The deploy lock file, opened with O_CREAT and mode 0600 as branchleft-deploy does.
    type: path
    required: true
  lock_timeout:
    description: Seconds to wait for the lock. Zero tries once.
    type: int
    default: 600
  caddy_candidate:
    description: The candidate Caddyfile to validate, and to write when I(caddy_write) is set.
    type: path
  compose_candidate:
    description: Path of the candidate Compose file to validate.
    type: path
  caddy_write:
    description: Write I(caddy_candidate) over the Caddyfile in place.
    type: bool
    default: false
  caddy_reload:
    description: Reload Caddy and read the Caddyfile back inside the container.
    type: bool
    default: false
  compose_restart:
    description: Restart I(unit) and check the unit and both services are up.
    type: bool
    default: false
  crowdsec_restart:
    description: Restart the CrowdSec container and read its files back.
    type: bool
    default: false
  wait_tries:
    description: Times CrowdSec's Local API is asked before the read-back fails.
    type: int
    default: 24
  wait_interval:
    description: Seconds between those asks.
    type: float
    default: 5
  owner:
    description: Owner of everything the module creates or places.
    type: str
    default: root
  group:
    description: Group of everything the module creates or places.
    type: str
    default: root
  pending_stamps:
    description: Stamp files set to I(pending_text) (mode 0600) once the candidates are accepted.
    type: list
    elements: path
    default: []
  pending_text:
    description: What a stamp holds while an action is under way.
    type: str
    default: pending
  dirs:
    description: Directories to make (mode 0755) after the candidates are accepted.
    type: list
    elements: path
    default: []
  files:
    description: Files to place after the candidates are accepted, by rename, in this order.
    type: list
    elements: dict
    default: []
    suboptions:
      dest:
        description: Where the file goes.
        type: path
        required: true
      src:
        description: A file on the host to copy. Exclusive with I(content_b64).
        type: path
      content_b64:
        description: The bytes to place, base64 encoded. Exclusive with I(src).
        type: str
      sha256:
        description: The sha256 the bytes must have. The module refuses the call if they differ.
        type: str
      mode:
        description: Octal mode, such as C(0644).
        type: str
        required: true
      reload:
        description: Reload systemd after this file changed.
        type: bool
        default: false
  remove:
    description: Paths to remove after the candidates are accepted. One that is not there is fine.
    type: list
    elements: path
    default: []
  fix_modes:
    description: Files whose mode is set, in place, when they exist.
    type: list
    elements: dict
    default: []
    suboptions:
      path:
        description: The file.
        type: path
        required: true
      mode:
        description: Octal mode, such as C(0644).
        type: str
        required: true
  daemon_reload_needed:
    description: Reload systemd even if no flagged file changed, because it says it is behind.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: >-
      Reads the host and reports what would change. Takes no lock, creates no file, runs no
      command and contacts nothing.
  diff_mode:
    support: none
    description: The files placed may be configuration, so no diff is shown.
"""

EXAMPLES = r"""
- name: Validate, place and apply the due classes under the deploy lock
  edge_stack_apply:
    project_dir: /opt/EXAMPLE/edge
    image_env: /etc/EXAMPLE/edge.image.env
    env_file: /etc/EXAMPLE/edge.env
    image_pin_pattern: '^IMAGE=[a-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$'
    unit: EXAMPLE@edge.service
    lock_file: /etc/EXAMPLE/edge.deploy.lock
    caddy_candidate: /var/lib/EXAMPLE/edge.candidate/Caddyfile
    caddy_write: true
    caddy_reload: true
  register: example_apply
  failed_when: false
"""

RETURN = r"""
changed:
  description: True if a file, stamp or directory was placed or removed, or an action ran.
  returned: always
  type: bool
code:
  description: >-
    The exit code of the outcome, one of 0, 64 to 77. 64 the pin is wrong, 65 the Caddyfile is
    refused, 66 the Caddyfile could not be written, 67 the Compose file is refused, 68 the unit
    restart failed, 69 the unit or a service is not up, 70 the CrowdSec restart failed, 71
    CrowdSec's read-back failed, 72 the Caddy reload failed, 73 the Caddyfile inside the
    container differs, 74 the pin moved since the validation, 75 the lock was not free in time,
    76 the lock file cannot be used, 77 a host error outside those.
  returned: always
  type: int
outcome:
  description: The outcome's name, such as C(ok) or C(lock-busy), or C(unmapped) outside the set.
  returned: always
  type: str
phase:
  description: The last phase reached, one of C(lock), C(validate), C(place), C(apply).
  returned: always
  type: str
message:
  description: One line saying what failed, empty on success. Names a path, never a value.
  returned: always
  type: str
detail:
  description: The tail of the output of the command that failed, as it wrote it. Empty if none.
  returned: always
  type: str
pin:
  description: The image reference the candidates were validated in, a name and a digest.
  returned: when the lock was taken and the pin was read
  type: str
validated:
  description: Which candidates were accepted, C(caddy-validated) and C(compose-validated).
  returned: always
  type: list
  elements: str
markers:
  description: >-
    What was done and read back, in order: C(caddy-written), C(compose-restarted),
    C(crowdsec-restarted), C(crowdsec-not-running), C(caddy-reloaded), C(caddy-not-running).
    Present on failure too, for the steps that finished before it.
  returned: always
  type: list
  elements: str
placed:
  description: The paths of files and directories changed, and of paths removed. Never a content.
  returned: always
  type: list
  elements: str
marked:
  description: The stamp files that were set to pending.
  returned: always
  type: list
  elements: str
reloaded:
  description: Whether systemd was reloaded.
  returned: always
  type: bool
"""

PHASE_LOCK = "lock"
PHASE_VALIDATE = "validate"
PHASE_PLACE = "place"
PHASE_APPLY = "apply"

LOCK_POLL_INTERVAL = 0.2
DETAIL_LIMIT = 2000
CADDYFILE_INSIDE = "/etc/caddy/Caddyfile"
CROWDSEC_CONFIG_INSIDE = "/etc/crowdsec/config.yaml.local"
CROWDSEC_ACQUIS_INSIDE = "/etc/crowdsec-acquis.d"
MODE_PATTERN = re.compile(r"0?[0-7]{3,4}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class Code(enum.IntEnum):
    """The closed set of exit codes. A code that is not here is a failure, never a success."""

    OK = 0
    PIN_REFUSED = 64
    CADDY_REFUSED = 65
    CADDYFILE_WRITE = 66
    COMPOSE_REFUSED = 67
    UNIT_RESTART = 68
    UNIT_NOT_UP = 69
    CROWDSEC_RESTART = 70
    CROWDSEC_READBACK = 71
    CADDY_RELOAD = 72
    CADDY_READBACK = 73
    PIN_MOVED = 74
    LOCK_BUSY = 75
    LOCK_UNUSABLE = 76
    HOST_ERROR = 77


def outcome_of(code: int) -> Code | None:
    """Return the named outcome of an exit code, or None for a code the contract does not hold."""
    try:
        return Code(code)
    except ValueError:
        return None


def outcome_name(outcome: Code) -> str:
    """Return the outcome as it is reported: lower case, words joined by dashes."""
    return outcome.name.lower().replace("_", "-")


class SettingsError(Exception):
    """The arguments are not usable. Nothing has been done."""


class StepError(Exception):
    """A step stopped the run with an exit code, a one-line message and the tail of its output."""

    def __init__(self, code: int, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def refuse(code: int, message: str, detail: str = "") -> NoReturn:
    """Stop the run with ``code``.

    Raises:
        StepError: Always.
    """
    raise StepError(code, message, detail)


@dataclasses.dataclass(frozen=True)
class Placement:
    """One file to place: where, with which mode, and either a source on the host or bytes."""

    dest: str
    mode: int
    src: str | None
    content: bytes | None
    reload: bool


@dataclasses.dataclass(frozen=True)
class Settings:
    """The module's arguments, checked and typed."""

    project_dir: str
    image_env: str
    env_file: str
    image_pin_pattern: re.Pattern[str]
    unit: str
    lock_file: str
    lock_timeout: int
    caddy_candidate: str | None
    compose_candidate: str | None
    caddy_write: bool
    caddy_reload: bool
    compose_restart: bool
    crowdsec_restart: bool
    wait_tries: int
    wait_interval: float
    uid: int
    gid: int
    pending_stamps: tuple[str, ...]
    pending_text: str
    dirs: tuple[str, ...]
    files: tuple[Placement, ...]
    remove: tuple[str, ...]
    fix_modes: tuple[tuple[str, int], ...]
    daemon_reload_needed: bool

    @property
    def has_actions(self) -> bool:
        """Whether any class is to be acted on."""
        return (
            self.caddy_write or self.caddy_reload or self.compose_restart or self.crowdsec_restart
        )

    @property
    def needs_lock(self) -> bool:
        """Whether anything is to be validated or acted on, which is what the lock is for."""
        return bool(self.caddy_candidate or self.compose_candidate or self.has_actions)


@dataclasses.dataclass
class Report:
    """What a run did. It is filled as the run goes, so a failure still reports its progress."""

    phase: str = PHASE_LOCK
    pin: str = ""
    validated: list[str] = dataclasses.field(default_factory=list)
    markers: list[str] = dataclasses.field(default_factory=list)
    placed: list[str] = dataclasses.field(default_factory=list)
    marked: list[str] = dataclasses.field(default_factory=list)
    reloaded: bool = False
    would_act: bool = False

    @property
    def changed(self) -> bool:
        """Whether the host was changed, or in check mode would be. A reload alone is not."""
        return bool(self.markers or self.placed or self.marked or self.would_act)


@dataclasses.dataclass(frozen=True)
class Context:
    """The clock and the sleep, so a test can wait without waiting."""

    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


@dataclasses.dataclass(frozen=True)
class Ran:
    """A finished command."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        """The output of the command as one text, standard output first."""
        return self.stdout + self.stderr


def tail(text: str) -> str:
    """Return the end of ``text``, the part that says why a command failed."""
    return text.strip()[-DETAIL_LIMIT:]


def run(argv: Sequence[str]) -> Ran:
    """Run ``argv`` with no shell and no input, and return what it wrote."""
    try:
        done = subprocess.run(  # noqa: S603
            list(argv),
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{argv[0]} could not be run ({error.strerror or 'error'})")
    return Ran(done.returncode, done.stdout, done.stderr)


@contextlib.contextmanager
def deploy_lock(path: str, timeout: float, context: Context) -> Iterator[None]:
    """Hold an exclusive flock on ``path`` for the length of the block.

    This is the lock branchleft-deploy takes: the same file, opened O_CREAT | O_RDWR with
    mode 0600, taken with LOCK_EX | LOCK_NB and retried every 0.2 seconds until the deadline.
    It is released by LOCK_UN and by the close, and by the process ending however it ends.

    Raises:
        StepError: The file cannot be opened or locked (76), or is not free in time (75).
    """
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as error:
        refuse(Code.LOCK_UNUSABLE, f"{path} cannot be opened ({error.strerror or 'error'})")
    try:
        deadline = context.clock() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    message = f"{path} cannot be locked ({error.strerror or 'error'})"
                    raise StepError(Code.LOCK_UNUSABLE, message) from None
                if context.clock() >= deadline:
                    message = f"the deploy lock {path} was not free within {timeout:g} seconds"
                    raise StepError(Code.LOCK_BUSY, message) from None
                context.sleep(LOCK_POLL_INTERVAL)
            else:
                break
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def sha256_of(path: str) -> str:
    """Return the sha256 of a file, as lower-case hexadecimal."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_pin(settings: Settings) -> str:
    """Return the image reference the pin file holds, or stop with 64.

    The file must be exactly one line, as ``grep -c ''`` counts lines, and the line must match
    the pattern as a whole. A file that cannot be read has no lines.
    """
    try:
        data = Path(settings.image_env).read_bytes()
    except OSError:
        data = b""
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    if len(lines) != 1:
        refuse(Code.PIN_REFUSED, f"{settings.image_env} is not exactly one line")
    line = lines[0].decode("utf-8", errors="replace")
    if settings.image_pin_pattern.fullmatch(line) is None:
        refuse(
            Code.PIN_REFUSED,
            f"{settings.image_env} is not IMAGE=<reference>@sha256:<64 hex digits>",
        )
    return line.removeprefix("IMAGE=")


def compose_argv(settings: Settings, compose_file: str, *args: str) -> list[str]:
    """Return the Compose command as the unit runs it: the project directory and both env files."""
    return [
        "docker",
        "compose",
        "--project-directory",
        settings.project_dir,
        "--env-file",
        settings.image_env,
        "--env-file",
        settings.env_file,
        "-f",
        compose_file,
        *args,
    ]


def compose(settings: Settings, *args: str) -> Ran:
    """Run Compose on the stack's own Compose file."""
    return run(compose_argv(settings, f"{settings.project_dir}/compose.yml", *args))


def validate(settings: Settings, pin: str, report: Report) -> None:
    """Accept or refuse the candidates. Nothing is placed and nothing is contacted.

    The Caddy check parses and adapts the file in the pinned image with placeholder values; it
    issues no certificate. The Compose check passes the secrets file to Compose, which reads it.
    """
    if settings.caddy_candidate:
        ran = run(
            [
                "docker",
                "run",
                "--rm",
                "--env",
                "CROWDSEC_BOUNCER_KEY=validation-only",
                "--env",
                "ACME_EMAIL=validation@example.invalid",
                "--volume",
                f"{settings.caddy_candidate}:{CADDYFILE_INSIDE}:ro",
                pin,
                "caddy",
                "validate",
                "--adapter",
                "caddyfile",
                "--config",
                CADDYFILE_INSIDE,
            ]
        )
        if ran.returncode != 0:
            refuse(Code.CADDY_REFUSED, "Caddy refused the candidate Caddyfile", tail(ran.output))
        if "Valid configuration" not in ran.output:
            refuse(
                Code.CADDY_REFUSED,
                "Caddy did not report a valid configuration",
                tail(ran.output),
            )
        report.validated.append("caddy-validated")
    if settings.compose_candidate:
        ran = run(compose_argv(settings, settings.compose_candidate, "config", "-q"))
        if ran.returncode != 0:
            refuse(
                Code.COMPOSE_REFUSED,
                "docker compose refused the candidate Compose file",
                tail(ran.output),
            )
        report.validated.append("compose-validated")


@dataclasses.dataclass(frozen=True)
class Host:
    """Who owns what the module makes, and whether this call may change anything."""

    uid: int
    gid: int
    dry_run: bool


def _owned(status: os.stat_result, host: Host) -> bool:
    return status.st_uid == host.uid and status.st_gid == host.gid


def ensure_dir(path: str, host: Host) -> bool:
    """Make ``path`` a directory with mode 0755 and the owner; return whether that changed it."""
    try:
        status: os.stat_result | None = os.lstat(path)
    except FileNotFoundError:
        status = None
    if status is not None and not stat.S_ISDIR(status.st_mode):
        refuse(Code.HOST_ERROR, f"{path} exists and is not a directory")
    if status is not None and stat.S_IMODE(status.st_mode) == 0o755 and _owned(status, host):
        return False
    if host.dry_run:
        return True
    try:
        if status is None:
            os.makedirs(path, mode=0o755, exist_ok=True)
        os.chmod(path, 0o755)  # noqa: S103 (the stack's directories are world-readable by contract)
        os.chown(path, host.uid, host.gid)
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{path} could not be made ({error.strerror or 'error'})")
    return True


def install_bytes(path: str, data: bytes, mode: int, host: Host) -> bool:
    """Make ``path`` hold ``data`` with ``mode`` and the owner, by rename; say whether it changed.

    A file that already holds the bytes keeps its inode and only has its mode and owner set.
    """
    try:
        status: os.stat_result | None = os.lstat(path)
    except FileNotFoundError:
        status = None
    if status is not None and not stat.S_ISREG(status.st_mode):
        refuse(Code.HOST_ERROR, f"{path} exists and is not a regular file")
    try:
        same = status is not None and Path(path).read_bytes() == data
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{path} could not be read ({error.strerror or 'error'})")
    metadata_ok = (
        status is not None and stat.S_IMODE(status.st_mode) == mode and _owned(status, host)
    )
    if same and metadata_ok:
        return False
    if host.dry_run:
        return True
    try:
        if same:
            os.chmod(path, mode)
            os.chown(path, host.uid, host.gid)
        else:
            _replace(path, data, mode, host)
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{path} could not be placed ({error.strerror or 'error'})")
    return True


def _replace(path: str, data: bytes, mode: int, host: Host) -> None:
    """Write ``data`` beside ``path`` with its final mode and owner, then rename it into place."""
    handle, temporary = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".edge-stack-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, mode)
        os.chown(temporary, host.uid, host.gid)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def remove_path(path: str, host: Host) -> bool:
    """Remove a file, link or directory; return whether there was one."""
    if not os.path.lexists(path):
        return False
    if host.dry_run:
        return True
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{path} could not be removed ({error.strerror or 'error'})")
    return True


def fix_mode(path: str, mode: int, host: Host) -> bool:
    """Set the mode and owner of a plain file that is there, in place; return whether it changed."""
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(status.st_mode):
        refuse(Code.HOST_ERROR, f"{path} exists and is not a regular file")
    if stat.S_IMODE(status.st_mode) == mode and _owned(status, host):
        return False
    if host.dry_run:
        return True
    try:
        os.chmod(path, mode)
        os.chown(path, host.uid, host.gid)
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{path} could not be changed ({error.strerror or 'error'})")
    return True


def placement_bytes(placement: Placement, host: Host) -> bytes | None:
    """Return the bytes of a placement, or None when its source is not there in a dry run."""
    if placement.content is not None:
        return placement.content
    try:
        return Path(cast("str", placement.src)).read_bytes()
    except FileNotFoundError:
        if host.dry_run:
            return None
        refuse(Code.HOST_ERROR, f"{placement.src} is not there to be placed")
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{placement.src} could not be read ({error.strerror or 'error'})")


def place(settings: Settings, report: Report, host: Host) -> None:
    """Mark the stamps, make the directories, place the files, prune, and reload systemd.

    Called only after every candidate was accepted, so a refused candidate leaves the host as
    it was. With ``host.dry_run`` it changes nothing and reports what it would change.
    """
    stamp = f"{settings.pending_text}\n".encode()
    for path in settings.pending_stamps:
        if install_bytes(path, stamp, 0o600, host):
            report.marked.append(path)
    for path in settings.dirs:
        if ensure_dir(path, host):
            report.placed.append(path)
    reload_wanted = settings.daemon_reload_needed
    for placement in settings.files:
        data = placement_bytes(placement, host)
        if data is None or install_bytes(placement.dest, data, placement.mode, host):
            report.placed.append(placement.dest)
            reload_wanted = reload_wanted or placement.reload
    for path in settings.remove:
        if remove_path(path, host):
            report.placed.append(path)
    for path, mode in settings.fix_modes:
        if fix_mode(path, mode, host):
            report.placed.append(path)
    if reload_wanted and not host.dry_run:
        ran = run(["systemctl", "daemon-reload"])
        if ran.returncode != 0:
            refuse(Code.HOST_ERROR, "systemctl daemon-reload failed", tail(ran.output))
        report.reloaded = True


def is_running(settings: Settings, service: str) -> bool:
    """Whether Compose lists the service as running."""
    ran = compose(settings, "ps", "--status", "running", "--services")
    return ran.returncode == 0 and service in ran.stdout.splitlines()


def same_inside(settings: Settings, service: str, inside: str, host_path: str, code: Code) -> None:
    """Stop with ``code`` unless the file inside the container is the file on the host."""
    try:
        wanted = sha256_of(host_path)
    except OSError as error:
        refuse(Code.HOST_ERROR, f"{host_path} could not be read ({error.strerror or 'error'})")
    ran = compose(settings, "exec", "-T", service, "sha256sum", inside)
    if ran.returncode != 0:
        refuse(code, f"could not read {inside} inside {service}", tail(ran.output))
    words = ran.stdout.split()
    if not words or words[0] != wanted:
        refuse(code, f"{inside} inside {service} is not the file on the host")


def visible_names(directory: str) -> list[str]:
    """Return the entries ``ls -1`` lists: all but those that start with a dot."""
    return sorted(name for name in os.listdir(directory) if not name.startswith("."))


def write_caddyfile(settings: Settings, report: Report) -> None:
    """Write the candidate over the Caddyfile in place, so the mounted inode is kept."""
    candidate = cast("str", settings.caddy_candidate)
    destination = f"{settings.project_dir}/caddy/Caddyfile"
    try:
        if os.path.lexists(destination):
            status = os.lstat(destination)
            if not stat.S_ISREG(status.st_mode):
                refuse(Code.CADDYFILE_WRITE, f"{destination} is not a regular file")
        else:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            os.close(descriptor)
            os.chmod(destination, 0o644)
            os.chown(destination, settings.uid, settings.gid)
        data = Path(candidate).read_bytes()
        with open(destination, "wb") as stream:
            stream.write(data)
        written = sha256_of(destination) == hashlib.sha256(data).hexdigest()
    except OSError as error:
        refuse(Code.CADDYFILE_WRITE, f"could not write {destination} ({error.strerror or 'error'})")
    if not written:
        refuse(Code.CADDYFILE_WRITE, f"{destination} is not the candidate after the write")
    report.markers.append("caddy-written")


def restart_unit(settings: Settings, report: Report) -> None:
    """Restart the unit, the only path that runs ``docker compose up``, and check it came back."""
    ran = run(["systemctl", "restart", settings.unit])
    if ran.returncode != 0:
        refuse(Code.UNIT_RESTART, f"restarting {settings.unit} failed", tail(ran.output))
    if run(["systemctl", "is-active", "--quiet", settings.unit]).returncode != 0:
        refuse(Code.UNIT_NOT_UP, f"{settings.unit} is not active after the restart")
    for service in ("caddy", "crowdsec"):
        if not is_running(settings, service):
            refuse(Code.UNIT_NOT_UP, f"{service} is not running after the restart")
    report.markers.append("compose-restarted")


def restart_crowdsec(settings: Settings, report: Report, context: Context) -> None:
    """Restart the CrowdSec container, wait for its API, and read each file it reads back."""
    if not is_running(settings, "crowdsec"):
        report.markers.append("crowdsec-not-running")
        return
    ran = compose(settings, "restart", "crowdsec")
    if ran.returncode != 0:
        refuse(Code.CROWDSEC_RESTART, "restarting the crowdsec container failed", tail(ran.output))
    tries = 0
    while compose(settings, "exec", "-T", "crowdsec", "cscli", "lapi", "status").returncode != 0:
        tries += 1
        if tries >= settings.wait_tries:
            refuse(
                Code.CROWDSEC_READBACK,
                f"CrowdSec's Local API did not answer after {tries} tries",
            )
        context.sleep(settings.wait_interval)
    crowdsec_dir = f"{settings.project_dir}/crowdsec"
    same_inside(
        settings,
        "crowdsec",
        CROWDSEC_CONFIG_INSIDE,
        f"{crowdsec_dir}/config.yaml.local",
        Code.CROWDSEC_READBACK,
    )
    host_names = visible_names(f"{crowdsec_dir}/acquis.d")
    for name in host_names:
        host_path = f"{crowdsec_dir}/acquis.d/{name}"
        if os.path.exists(host_path):
            same_inside(
                settings,
                "crowdsec",
                f"{CROWDSEC_ACQUIS_INSIDE}/{name}",
                host_path,
                Code.CROWDSEC_READBACK,
            )
    listing = compose(settings, "exec", "-T", "crowdsec", "ls", "-1", CROWDSEC_ACQUIS_INSIDE)
    if listing.returncode != 0:
        refuse(
            Code.CROWDSEC_READBACK,
            "could not list the acquisition directory inside crowdsec",
            tail(listing.output),
        )
    if sorted(listing.stdout.splitlines()) != host_names:
        refuse(
            Code.CROWDSEC_READBACK,
            "the acquisition directory inside crowdsec lists different files from the host",
        )
    report.markers.append("crowdsec-restarted")


def reload_caddy(settings: Settings, report: Report) -> None:
    """Reload Caddy and read the Caddyfile back inside the container."""
    if not is_running(settings, "caddy"):
        report.markers.append("caddy-not-running")
        return
    ran = compose(
        settings,
        "exec",
        "-T",
        "caddy",
        "caddy",
        "reload",
        "--config",
        CADDYFILE_INSIDE,
        "--adapter",
        "caddyfile",
    )
    if ran.returncode != 0:
        refuse(Code.CADDY_RELOAD, "caddy reload failed", tail(ran.output))
    same_inside(
        settings,
        "caddy",
        CADDYFILE_INSIDE,
        f"{settings.project_dir}/caddy/Caddyfile",
        Code.CADDY_READBACK,
    )
    report.markers.append("caddy-reloaded")


def act(settings: Settings, pin: str, report: Report, context: Context) -> None:
    """Act on each due class, in order, if the pin is still the one the candidates passed in."""
    if read_pin(settings) != pin:
        refuse(Code.PIN_MOVED, f"{settings.image_env} changed since the candidates were validated")
    if settings.caddy_write:
        write_caddyfile(settings, report)
    if settings.compose_restart:
        restart_unit(settings, report)
    if settings.crowdsec_restart:
        restart_crowdsec(settings, report, context)
    if settings.caddy_reload:
        reload_caddy(settings, report)


def locked_run(settings: Settings, report: Report, host: Host, context: Context) -> None:
    """The work that is done inside the lock, in one block: validate, place, act."""
    report.phase = PHASE_VALIDATE
    pin = read_pin(settings)
    report.pin = pin
    validate(settings, pin, report)
    report.phase = PHASE_PLACE
    place(settings, report, host)
    if settings.has_actions:
        report.phase = PHASE_APPLY
        act(settings, pin, report, context)


def execute(
    settings: Settings, report: Report, *, check_mode: bool, context: Context | None = None
) -> None:
    """Do what the settings say, or in check mode report what would change.

    Raises:
        StepError: A step stopped the run; its code is one of the contract's.
    """
    context = context or Context()
    host = Host(settings.uid, settings.gid, dry_run=check_mode)
    try:
        if check_mode:
            report.phase = PHASE_PLACE
            place(settings, report, host)
            report.would_act = settings.has_actions
        elif settings.needs_lock:
            with deploy_lock(settings.lock_file, settings.lock_timeout, context):
                locked_run(settings, report, host, context)
        else:
            report.phase = PHASE_PLACE
            place(settings, report, host)
    except StepError:
        raise
    except Exception as error:  # noqa: BLE001
        raise StepError(Code.HOST_ERROR, f"unexpected {type(error).__name__}") from None


def _mode_of(text: str, name: str) -> int:
    """Return an octal mode written as text.

    Raises:
        SettingsError: The text is not an octal mode.
    """
    if MODE_PATTERN.match(text) is None:
        message = f"{name}: {text!r} is not an octal mode such as 0644"
        raise SettingsError(message)
    return int(text, 8)


def _placement(entry: Mapping[str, object]) -> Placement:
    dest = str(entry["dest"])
    content: bytes | None = None
    encoded = entry.get("content_b64")
    if encoded is not None:
        try:
            content = base64.b64decode(str(encoded), validate=True)
        except (binascii.Error, ValueError):
            message = f"files: the content for {dest} is not base64"
            raise SettingsError(message) from None
        wanted = entry.get("sha256")
        if wanted is not None and hashlib.sha256(content).hexdigest() != wanted:
            message = f"files: the content for {dest} is not the sha256 given for it"
            raise SettingsError(message)
    wanted = entry.get("sha256")
    if wanted is not None and SHA256_PATTERN.match(str(wanted)) is None:
        message = f"files: the sha256 for {dest} is not 64 lower-case hexadecimal digits"
        raise SettingsError(message)
    source = entry.get("src")
    return Placement(
        dest=dest,
        mode=_mode_of(str(entry["mode"]), f"files: {dest}"),
        src=None if source is None else str(source),
        content=content,
        reload=bool(entry.get("reload")),
    )


def _optional_path(params: Mapping[str, object], name: str) -> str | None:
    value = params.get(name)
    return str(value) if value else None


def _id_of(owner: str, group: str) -> tuple[int, int]:
    try:
        return pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        message = f"owner {owner!r} or group {group!r} is not known on this host"
        raise SettingsError(message) from None


def settings_from(params: Mapping[str, object]) -> Settings:
    """Check the module's arguments and return them typed.

    Raises:
        SettingsError: An argument is not usable. Nothing has been done.
    """
    try:
        pattern = re.compile(str(params["image_pin_pattern"]))
    except re.error:
        message = "image_pin_pattern is not a regular expression"
        raise SettingsError(message) from None
    uid, gid = _id_of(str(params["owner"]), str(params["group"]))
    entries = cast("list[Mapping[str, object]]", params.get("files") or [])
    fixes = cast("list[Mapping[str, object]]", params.get("fix_modes") or [])
    stamps = cast("list[str]", params.get("pending_stamps") or [])
    return Settings(
        project_dir=str(params["project_dir"]),
        image_env=str(params["image_env"]),
        env_file=str(params["env_file"]),
        image_pin_pattern=pattern,
        unit=str(params["unit"]),
        lock_file=str(params["lock_file"]),
        lock_timeout=cast("int", params["lock_timeout"]),
        caddy_candidate=_optional_path(params, "caddy_candidate"),
        compose_candidate=_optional_path(params, "compose_candidate"),
        caddy_write=bool(params["caddy_write"]),
        caddy_reload=bool(params["caddy_reload"]),
        compose_restart=bool(params["compose_restart"]),
        crowdsec_restart=bool(params["crowdsec_restart"]),
        wait_tries=cast("int", params["wait_tries"]),
        wait_interval=float(cast("float", params["wait_interval"])),
        uid=uid,
        gid=gid,
        pending_stamps=tuple(str(item) for item in stamps),
        pending_text=str(params["pending_text"]),
        dirs=tuple(str(item) for item in cast("list[str]", params.get("dirs") or [])),
        files=tuple(_placement(entry) for entry in entries),
        remove=tuple(str(item) for item in cast("list[str]", params.get("remove") or [])),
        fix_modes=tuple(
            (str(entry["path"]), _mode_of(str(entry["mode"]), f"fix_modes: {entry['path']}"))
            for entry in fixes
        ),
        daemon_reload_needed=bool(params["daemon_reload_needed"]),
    )


ARGUMENT_SPEC: dict[str, dict[str, object]] = {
    "project_dir": {"type": "path", "required": True},
    "image_env": {"type": "path", "required": True},
    "env_file": {"type": "path", "required": True},
    "image_pin_pattern": {"type": "str", "required": True},
    "unit": {"type": "str", "required": True},
    "lock_file": {"type": "path", "required": True},
    "lock_timeout": {"type": "int", "default": 600},
    "caddy_candidate": {"type": "path"},
    "compose_candidate": {"type": "path"},
    "caddy_write": {"type": "bool", "default": False},
    "caddy_reload": {"type": "bool", "default": False},
    "compose_restart": {"type": "bool", "default": False},
    "crowdsec_restart": {"type": "bool", "default": False},
    "wait_tries": {"type": "int", "default": 24},
    "wait_interval": {"type": "float", "default": 5},
    "owner": {"type": "str", "default": "root"},
    "group": {"type": "str", "default": "root"},
    "pending_stamps": {"type": "list", "elements": "path", "default": []},
    "pending_text": {"type": "str", "default": "pending"},
    "dirs": {"type": "list", "elements": "path", "default": []},
    "files": {
        "type": "list",
        "elements": "dict",
        "default": [],
        "options": {
            "dest": {"type": "path", "required": True},
            "src": {"type": "path"},
            "content_b64": {"type": "str", "no_log": True},
            "sha256": {"type": "str"},
            "mode": {"type": "str", "required": True},
            "reload": {"type": "bool", "default": False},
        },
        "mutually_exclusive": [["src", "content_b64"]],
        "required_one_of": [["src", "content_b64"]],
    },
    "remove": {"type": "list", "elements": "path", "default": []},
    "fix_modes": {
        "type": "list",
        "elements": "dict",
        "default": [],
        "options": {
            "path": {"type": "path", "required": True},
            "mode": {"type": "str", "required": True},
        },
    },
    "daemon_reload_needed": {"type": "bool", "default": False},
}


def result_fields(
    report: Report, code: int, outcome: str, message: str, detail: str
) -> dict[str, object]:
    """Return what the module reports, which names paths and outcomes and never a content."""
    return {
        "changed": report.changed,
        "code": code,
        "outcome": outcome,
        "phase": report.phase,
        "message": message,
        "detail": detail,
        "pin": report.pin,
        "validated": report.validated,
        "markers": report.markers,
        "placed": report.placed,
        "marked": report.marked,
        "reloaded": report.reloaded,
    }


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        required_if=[("caddy_write", True, ("caddy_candidate",))],
    )
    try:
        settings = settings_from(module.params)
    except SettingsError as error:
        module.fail_json(msg=f"edge_stack_apply: {error}", code=-1, outcome="unusable-arguments")
        return
    report = Report()
    code: int = Code.OK
    message = ""
    detail = ""
    stopped = False
    try:
        execute(settings, report, check_mode=module.check_mode)
    except StepError as error:
        code, message, detail, stopped = error.code, error.message, error.detail, True
    outcome = outcome_of(code)
    if outcome is None or (stopped and outcome is Code.OK):
        fields = result_fields(report, code, "unmapped", message, detail)
        text = f"edge_stack_apply: exit code {code} is not in the contract ({message})"
        module.fail_json(msg=text, **fields)
        return
    fields = result_fields(report, code, outcome_name(outcome), message, detail)
    if outcome is Code.OK:
        module.exit_json(**fields)
    text = f"edge_stack_apply: exit code {code} ({outcome_name(outcome)}): {message}"
    module.fail_json(msg=text, **fields)


if __name__ == "__main__":
    main()
