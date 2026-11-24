#!/usr/bin/python3 -I
"""Set up one tenant's slot, deploy key and host files on the app host, one step per request.

Run through sudo as the one forced command of the controller's key. The request is two words
in SSH_ORIGINAL_COMMAND, a verb and a slug, and a verb that needs more reads one JSON object
on stdin. Every step calls a program that already has its own rules; this file decides only
which step may run, for which slug, and in what order. The README ("What the program accepts")
holds the verbs, the order and the exit codes.
"""

import contextlib
import fcntl
import importlib.util
import json
import os
import re
import signal
import stat
import subprocess
import sys
import syslog
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import FrameType
from typing import IO, Final, NoReturn, Protocol, cast

SERVE_FLAG: Final = "--from-ssh"
MAX_PAYLOAD: Final = 64 * 1024
MAX_TEMPLATE: Final = 16 * 1024
MAX_SECRETS_FILE: Final = 64 * 1024
STEP_TIMEOUT_SECONDS: Final = 120

# The tenant uid range is the volume program's own (TENANT_UID_MIN, TENANT_UID_MAX).
UID_MIN: Final = 30000
UID_MAX: Final = 30999
# Four ports to a tenant: colour a, colour b, the health router, and one left spare.
PORT_BASE: Final = 40000
PORT_BLOCKS: Final = 250
PORT_BLOCK_SIZE: Final = 4

REQUEST_PATTERN: Final = re.compile(r"\A([a-z]{1,16}) ([a-z0-9-]{1,26})\Z")
# The volume program's slug rule, at its length. The program stays the authority.
SLUG_PATTERN: Final = re.compile(r"\A[a-z]([a-z0-9-]{0,24}[a-z0-9])?\Z")
KEY_NAME_PATTERN: Final = re.compile(r"\A[A-Z][A-Z0-9_]{0,63}\Z")
CLAIM_LINE_PATTERN: Final = re.compile(r"\A([a-z][a-z0-9-]*)=([0-9]{1,6})\Z")
PUBLIC_KEY_PATTERN: Final = re.compile(r"\Assh-ed25519 [A-Za-z0-9+/]{68}( [ -~]{0,100})?\Z")
CONTAINER_ID_PATTERN: Final = re.compile(r"\A[0-9a-f]{64}\Z")
PRINTABLE_PATTERN: Final = re.compile(r"\A[ -~]+\Z")
# Owner name and title go to the platform's script as argv: a value that starts with a dash would
# be read there as an option, so it is refused here.
OWNER_TEXT_PATTERN: Final = re.compile(r"\A(?!-)[ -~]+\Z")
SITE_URL_PATTERN: Final = re.compile(r"\Ahttps://[a-z0-9]([a-z0-9.-]{0,250}[a-z0-9])?\Z")

# What `stack` writes: one compose file, built here from the claim and a few checked parameters.
# The modes are tenant_compose's own, held equal by tests/unit/test_branchleft_tenant_entry.py.
COMPOSE_MODE: Final = 0o644
STACK_DIR_MODE: Final = 0o755
DETAIL_LIMIT: Final = 1000

# The parameters a `stack` request may carry, and what each may hold. Nothing else is read.
STACK_KEYS: Final = frozenset({"size", "mail", "environment"})
# A request that carries a pin or a compose text of its own is refused by name: the first pin
# comes only from branchleft-deploy (which verifies the attestation), and the host writes the stack.
PIN_KEYS: Final = frozenset({"image_env_text", "image_env", "image", "pin"})
COMPOSE_KEYS: Final = frozenset({"compose_text", "compose"})
MAX_ENVIRONMENT: Final = 64
ENV_KEY_PATTERN: Final = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,99}\Z")
# Printable ASCII but for `$`, which compose would read as a reference.
ENV_LITERAL_PATTERN: Final = re.compile(r"\A[ -#%-~]{0,500}\Z")
SECRET_NAME_PATTERN: Final = re.compile(r"\AGHOST_[A-Z0-9_]{1,56}\Z")
# The app host's own private address, written by the role: where a tenant's ports are published.
BIND_ADDRESS_FILE: Final = "bind-address"
BIND_ADDRESS_PATTERN: Final = re.compile(
    r"\A(10(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){2}"
    r"|192\.168(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){2})\n?\Z"
)
# The stack's fixed posture. Mirrors the platform renderer's runtime posture for a paying tenant.
GHOST_CONTAINER_PORT: Final = 2368
GHOST_STOP_GRACE_PERIOD: Final = "60s"
TMPFS_SIZE: Final = "128m"
MEMORY_LIMIT: Final = "640m"
CONTENT_MOUNT: Final = "/var/lib/ghost/content"
ADAPTERS_MOUNT: Final = "/var/lib/ghost/content/adapters"
METRICS_MOUNT: Final = "/var/lib/ghost/metrics"
# The judge insists on a pin line. This one is never written: it only lets the judge read the rest.
JUDGE_PLACEHOLDER_PIN: Final = "IMAGE=ghcr.io/branchleft/ghost-tenant@sha256:" + "0" * 64 + "\n"

CHILD_ENVIRONMENT: Final = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}

EXIT_DONE: Final = 0
EXIT_REFUSED: Final = 1
EXIT_USAGE: Final = 2
EXIT_BUSY: Final = 3
EXIT_FAILED: Final = 4


class RefusedError(Exception):
    """The request is not allowed. The reason is a fixed word and never echoes the request."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class FailedError(Exception):
    """A step the request was allowed to run did not finish."""

    def __init__(self, step: str, detail: str = "") -> None:
        super().__init__(step)
        self.step = step
        self.detail = detail


class Terminated(BaseException):
    """A termination signal reached the program. It is a BaseException, so the claim's cleanup runs
    on it and no handler written for an ordinary error catches it by accident."""


# A dropped connection sends SIGHUP to the session, which sudo relays. Both clean up the same way.
TERMINATION_SIGNALS: Final = (signal.SIGTERM, signal.SIGHUP)


def on_termination(signum: int, frame: FrameType | None) -> NoReturn:
    raise Terminated(signum)


def refuse(reason: str, detail: str = "") -> NoReturn:
    """Stop the request with a refusal. A detail is allowed only where it can hold no value.

    Raises:
        RefusedError: always.
    """
    raise RefusedError(reason, detail)


def fail(step: str, detail: str = "") -> NoReturn:
    """Stop the request with a failed step.

    Raises:
        FailedError: always.
    """
    raise FailedError(step, detail)


@dataclass(frozen=True)
class Paths:
    """Every path the program touches. The defaults are the host's; tests give their own."""

    etc_dir: str = "/etc/branchleft"
    opt_dir: str = "/opt/branchleft"
    entry_dir: str = "/etc/branchleft/tenant-entry"
    volume_program: str = "/root/platform-provision/provision_tenant_volume.py"
    secrets_program: str = "/root/platform-provision/render_tenant_secrets.py"
    owner_program: str = "/root/platform-provision/provision-owner.mjs"
    slot_program: str = "/usr/local/sbin/branchleft-provision-deploy-slot"
    judge_module: str = "/usr/local/lib/branchleft-tenant-entry/tenant_compose_check.py"
    systemctl: str = "/usr/bin/systemctl"
    docker: str = "/usr/bin/docker"
    node: str = "/usr/local/lib/branchleft-tenant-entry/node/bin/node"
    root_uid: int = 0


@dataclass(frozen=True)
class Outcome:
    """What a step's program returned."""

    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], bytes | None], Outcome]
Logger = Callable[[str], None]


def run_command(argv: Sequence[str], stdin: bytes | None) -> Outcome:
    """Run one fixed argument list with a clean environment, a timeout and no shell."""
    try:
        done = subprocess.run(  # noqa: S603  # argv holds fixed program paths and checked words.
            list(argv),
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            env=CHILD_ENVIRONMENT,
            timeout=STEP_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        fail("timeout")
    except OSError:
        fail("program-missing")
    return Outcome(
        done.returncode,
        done.stdout.decode("utf-8", "replace"),
        done.stderr.decode("utf-8", "replace"),
    )


@dataclass
class Host:
    """What a step works with: the paths, the runner and the request's own stdin."""

    paths: Paths
    runner: Runner
    stdin: IO[bytes]


def parse_request(text: str | None) -> tuple[str, str]:
    """Return the verb and the slug, or refuse. The text is never repeated in a refusal."""
    if text is None or len(text) > 64:
        refuse("request-shape")
    match = REQUEST_PATTERN.match(text)
    if match is None:
        refuse("request-shape")
    verb, slug = match.group(1), match.group(2)
    if verb not in VERBS:
        refuse("unknown-verb")
    if SLUG_PATTERN.match(slug) is None:
        refuse("slug-shape")
    return verb, slug


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            refuse("payload-not-json")
        result[key] = value
    return result


def read_object(host: Host) -> dict[str, object]:
    """Read one JSON object from stdin, of at most MAX_PAYLOAD bytes, with no repeated key."""
    raw = host.stdin.read(MAX_PAYLOAD + 1)
    if len(raw) > MAX_PAYLOAD:
        refuse("payload-too-large")
    try:
        parsed: object = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        refuse("payload-not-json")
    if not isinstance(parsed, dict):
        refuse("payload-not-object")
    payload: dict[str, object] = parsed
    return payload


def read_payload(host: Host, keys: frozenset[str]) -> dict[str, object]:
    """Read one JSON object from stdin whose keys are exactly `keys`."""
    payload = read_object(host)
    if set(payload) != set(keys):
        refuse("payload-keys")
    return payload


def text_field(payload: Mapping[str, object], name: str, pattern: re.Pattern[str]) -> str:
    """Return a payload field that is a string and matches `pattern`, or refuse by its name."""
    value = payload[name]
    if not isinstance(value, str) or pattern.match(value) is None:
        refuse(f"field-{name}")
    return value


def check_register_dir(host: Host) -> None:
    """The register directory is a real directory, root's, mode 0700. Anything else stops."""
    try:
        info = os.lstat(host.paths.entry_dir)
    except OSError:
        refuse("register-unsafe")
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != host.paths.root_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        refuse("register-unsafe")


def marker_path(host: Host, slug: str) -> str:
    return os.path.join(host.paths.entry_dir, f"{slug}.json")


def env_path(host: Host, slug: str) -> str:
    return os.path.join(host.paths.etc_dir, f"{slug}.env")


def slot_path(host: Host, slug: str) -> str:
    return os.path.join(host.paths.etc_dir, "deploy-slots", f"{slug}.pub")


def stack_dir(host: Host, slug: str) -> str:
    return os.path.join(host.paths.opt_dir, slug)


def compose_path(host: Host, slug: str) -> str:
    return os.path.join(stack_dir(host, slug), "compose.yml")


def image_env_path(host: Host, slug: str) -> str:
    return os.path.join(host.paths.etc_dir, f"{slug}.image.env")


def read_marker(host: Host, path: str) -> dict[str, int]:
    """Read one marker: a regular file, root's, mode 0600, holding the uid and the port."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        refuse("register-unsafe")
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != host.paths.root_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            refuse("register-unsafe")
        try:
            parsed: object = json.loads(handle.read(4096).decode("utf-8"))
        except ValueError:
            refuse("register-unsafe")
    if not isinstance(parsed, dict):
        refuse("register-unsafe")
    uid, port = parsed.get("uid"), parsed.get("port")
    if not isinstance(uid, int) or not isinstance(port, int):
        refuse("register-unsafe")
    return {"uid": uid, "port": port}


def all_markers(host: Host) -> dict[str, dict[str, int]]:
    """Every marker, read one by one. An unreadable one stops the request."""
    markers: dict[str, dict[str, int]] = {}
    for name in sorted(os.listdir(host.paths.entry_dir)):
        if name.startswith(".") or not name.endswith(".json"):
            continue
        markers[name.removesuffix(".json")] = read_marker(
            host, os.path.join(host.paths.entry_dir, name)
        )
    return markers


def list_claims(host: Host) -> dict[str, int]:
    """Ask the volume program which slugs hold a uid. A line it cannot read stops the request."""
    outcome = host.runner([host.paths.volume_program, "--list-claims"], None)
    if outcome.returncode != 0:
        fail("claims")
    claims: dict[str, int] = {}
    for line in outcome.stdout.splitlines():
        match = CLAIM_LINE_PATTERN.match(line)
        if match is None:
            fail("claims-unreadable")
        claims[match.group(1)] = int(match.group(2))
    return claims


def file_is_closed(host: Host, path: str) -> bool:
    """True for a regular file, not a link, root's, mode 0600."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == host.paths.root_uid
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def unit_name(slug: str) -> str:
    return f"branchleft-compose@{slug}.service"


def unit_enabled(host: Host, slug: str) -> bool:
    outcome = host.runner([host.paths.systemctl, "is-enabled", unit_name(slug)], None)
    return outcome.returncode == 0 and outcome.stdout.strip() == "enabled"


def require_claimed(host: Host, slug: str) -> dict[str, int]:
    """The slug was claimed through this entry point and still holds its uid."""
    check_register_dir(host)
    if not os.path.lexists(marker_path(host, slug)):
        refuse("not-claimed-here")
    marker = read_marker(host, marker_path(host, slug))
    if slug not in list_claims(host):
        refuse("claim-missing")
    return marker


def require_secrets(host: Host, slug: str) -> dict[str, int]:
    """The secrets file is in place. Nothing that names the service runs before this."""
    marker = require_claimed(host, slug)
    if not file_is_closed(host, env_path(host, slug)):
        refuse("secrets-first")
    return marker


def require_enabled(host: Host, slug: str) -> dict[str, int]:
    marker = require_secrets(host, slug)
    if not unit_enabled(host, slug):
        refuse("enable-first")
    return marker


def secret_forms(value: str) -> tuple[str, ...]:
    """The ways a value can show in a message: as it is, and escaped as JSON or as a Python repr."""
    return (value, json.dumps(value)[1:-1], repr(value)[1:-1])


def detail_of(outcome: Outcome, hidden: Iterable[str] = ()) -> str:
    """A step's own message, withheld whole if it holds a hidden value in any form, then cut short.

    The check runs on the whole message before the cut, so a value that the cut would split still
    counts, and a value escaped by a program's JSON or repr output still counts.
    """
    text = (outcome.stderr or outcome.stdout).strip()
    forms = [form for value in hidden if value for form in secret_forms(value)]
    if any(form in text for form in forms):
        return "withheld: the message held a secret value"
    return text[:1000]


def slug_in_use(host: Host, slug: str) -> bool:
    """True when any file or register of the slug already exists on the host."""
    candidates = (
        marker_path(host, slug),
        env_path(host, slug),
        os.path.join(host.paths.opt_dir, slug),
        image_env_path(host, slug),
        slot_path(host, slug),
    )
    return any(os.path.lexists(path) for path in candidates)


def first_free_uid(taken: set[int]) -> int:
    for uid in range(UID_MIN, UID_MAX + 1):
        if uid not in taken:
            return uid
    refuse("no-free-uid")


def first_free_port(taken: set[int]) -> int:
    for block in range(PORT_BLOCKS):
        base = PORT_BASE + block * PORT_BLOCK_SIZE
        if base not in taken:
            return base
    refuse("no-free-port")


def write_marker(host: Host, slug: str, uid: int, port: int) -> None:
    """Make the marker whole or not at all.

    The bytes go to a temporary file in the register first, are flushed and synced, and only then
    are linked to the marker's name. The link is exclusive, so a marker is never replaced, and a
    write that fails (a full disk, say) leaves no half marker behind: the temporary file is removed
    and the slug is free for a retry. The temporary name starts with a dot, which the marker scan
    skips.
    """
    fd, temporary = tempfile.mkstemp(prefix=".marker-", suffix=".tmp", dir=host.paths.entry_dir)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps({"uid": uid, "port": port}).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, marker_path(host, slug), follow_symlinks=False)
        except FileExistsError:
            refuse("slug-in-use")
    finally:
        os.unlink(temporary)


def step_claim(host: Host, slug: str) -> list[str]:
    """Take a uid and four ports for a slug that exists nowhere, then make its volumes."""
    check_register_dir(host)
    release_orphan_marker(host, slug)
    if slug_in_use(host, slug):
        refuse("slug-in-use")
    claims = list_claims(host)
    if slug in claims:
        refuse("slug-in-use")
    markers = all_markers(host)
    uid = first_free_uid(set(claims.values()) | {m["uid"] for m in markers.values()})
    port = first_free_port({m["port"] for m in markers.values()})
    try:
        write_marker(host, slug, uid, port)
    except OSError:
        fail("marker")
    # Every way out of the volume step, a timeout, a missing program or a termination signal
    # included, releases the marker when no claim sits behind it, so a retry needs no hand step.
    try:
        outcome = host.runner([host.paths.volume_program, "--uid", str(uid), slug], None)
    except BaseException:
        release_unclaimed_marker(host, slug)
        raise
    if outcome.returncode != 0:
        release_unclaimed_marker(host, slug)
        fail("volumes", detail_of(outcome))
    return [f"claimed uid={uid} port_a={port} port_b={port + 1} port_health={port + 2}"]


def release_orphan_marker(host: Host, slug: str) -> None:
    """Remove a marker a failed claim left behind, so the slug can be claimed again.

    Only this program writes markers, so a valid marker with no claim behind it is a failed claim's.
    An unreadable marker, or one whose claim stands, keeps the slug in use. When the listing fails,
    nothing is removed, and the request stops with the listing's own failure.
    """
    path = marker_path(host, slug)
    if not os.path.lexists(path):
        return
    try:
        read_marker(host, path)
    except RefusedError:
        refuse("slug-in-use")
    if slug in list_claims(host):
        refuse("slug-in-use")
    os.unlink(path)


def release_unclaimed_marker(host: Host, slug: str) -> None:
    """Remove the slug's marker unless the volume program lists a claim for it.

    A marker with no claim holds the slug for nothing, and a listed claim keeps its marker. When the
    listing itself fails, neither can be shown, so the marker stays: the failure that stopped the
    claim is what the caller reports, and the next claim settles the marker with a working listing
    (release_orphan_marker). Removing it here would drop the marker of a claim that may stand.
    """
    try:
        claimed = slug in list_claims(host)
    except FailedError:
        return
    if not claimed:
        os.unlink(marker_path(host, slug))


def step_secrets(host: Host, slug: str) -> list[str]:
    """Fill the tenant's secrets file from the template and values on stdin, through the program."""
    require_claimed(host, slug)
    payload = read_payload(host, frozenset({"template", "values"}))
    template = payload["template"]
    values = payload["values"]
    if not isinstance(template, str) or len(template) > MAX_TEMPLATE or "\x00" in template:
        refuse("field-template")
    if not isinstance(values, dict) or not 0 < len(values) <= 32:
        refuse("field-values")
    given: dict[str, str] = {}
    for name, value in values.items():
        if (
            not isinstance(name, str)
            or KEY_NAME_PATTERN.match(name) is None
            or not isinstance(value, str)
            or not 0 < len(value) <= 4096
        ):
            refuse("field-values")
        given[name] = value
    fd, template_file = tempfile.mkstemp(prefix=".template-", dir=host.paths.entry_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(template)
        argv = [
            host.paths.secrets_program,
            f"--slug={slug}",
            f"--template-file={template_file}",
            f"--etc-dir={host.paths.etc_dir}",
        ]
        outcome = host.runner(argv, json.dumps(given).encode("utf-8"))
    finally:
        os.unlink(template_file)
    hidden = list(given.values())
    if outcome.returncode != 0:
        fail("secrets", detail_of(outcome, hidden))
    if not file_is_closed(host, env_path(host, slug)):
        fail("secrets-file")
    return [detail_of(Outcome(0, outcome.stdout, ""), hidden) or "written"]


def step_enable(host: Host, slug: str) -> list[str]:
    """Enable the tenant's unit, never start it: it has no image pin until its first deploy."""
    require_secrets(host, slug)
    outcome = host.runner([host.paths.systemctl, "enable", unit_name(slug)], None)
    if outcome.returncode != 0 or not unit_enabled(host, slug):
        fail("enable", detail_of(outcome))
    return ["enabled"]


class VerdictLike(Protocol):
    """What the judge returns: the rules broken, whether the claim agrees, the normalised pin."""

    @property
    def refusals(self) -> tuple[str, ...]: ...

    @property
    def claim_state(self) -> str: ...

    @property
    def image_env(self) -> str: ...


@dataclass(frozen=True)
class Judge:
    """The tenant compose judge, loaded from the one file the role installs for it."""

    params_from_mapping: Callable[[Mapping[str, object]], object]
    judge: Callable[[object], VerdictLike]


def load_judge(host: Host) -> Judge:
    """Load the judge from its installed file, which must be root's and closed to everyone else.

    The judge is the file tenant_compose runs on a stack before it delivers one, copied byte for
    byte by the role and held equal to it by a test. A file that is missing, a link, not root's or
    writable by another user stops the request.
    """
    path = host.paths.judge_module
    try:
        info = os.lstat(path)
    except OSError:
        fail("judge-missing")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != host.paths.root_uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        refuse("judge-unsafe")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tenant_compose_check", path)
    if spec is None or spec.loader is None:
        fail("judge-missing")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return Judge(
            cast(
                "Callable[[Mapping[str, object]], object]",
                module.params_from_mapping,
            ),
            cast("Callable[[object], VerdictLike]", module.judge),
        )
    except Exception:  # noqa: BLE001  # whatever is wrong with the file, the answer is one word.
        fail("judge-missing")


def read_secrets_text(host: Host, slug: str) -> str:
    """Read the tenant's closed secrets file for the judge, which checks it against the stack."""
    try:
        fd = os.open(env_path(host, slug), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        fail("secrets-file")
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(MAX_SECRETS_FILE + 1)
    if len(raw) > MAX_SECRETS_FILE:
        fail("secrets-file")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("secrets-file")


def secret_values(secrets_text: str) -> list[str]:
    """The value of every KEY=value line, so that a message that repeats one can be withheld."""
    values = [line.partition("=")[2] for line in secrets_text.split("\n") if "=" in line]
    return [value for value in values if value]


def check_slot_targets(host: Host, slug: str) -> str:
    """Return the one file `stack` may write, after checking it is inside the slug's own slot.

    The slot is the slug's stack directory under the stack root. A stack root that is not a
    directory, not root's or open to a write by group or other, a stack directory that is a link,
    not a directory or not root's, and a path that resolves anywhere else are refused, so no
    request can place a file outside it.
    """
    root = host.paths.root_uid
    try:
        base_info = os.stat(host.paths.opt_dir)
    except OSError:
        refuse("path-outside-slot")
    if (
        not stat.S_ISDIR(base_info.st_mode)
        or base_info.st_uid != root
        or stat.S_IMODE(base_info.st_mode) & 0o022
    ):
        refuse("path-outside-slot")
    directory = stack_dir(host, slug)
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        pass
    except OSError:
        refuse("path-outside-slot")
    else:
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != root:
            refuse("path-outside-slot")
    compose = compose_path(host, slug)
    inside = os.path.realpath(os.path.dirname(compose)) == os.path.join(
        os.path.realpath(host.paths.opt_dir), slug
    )
    if not inside:
        refuse("path-outside-slot")
    return compose


@dataclass(frozen=True)
class StackParameters:
    """The checked parameters of one `stack` request. Nothing else reaches the stack."""

    size: str
    mail: bool
    environment: dict[str, str]


@dataclass(frozen=True)
class SizeCaps:
    """The resource caps of one size, as the platform's renderer states them."""

    cpus: str
    cpu_shares: int
    pids_limit: int
    nofile: int


# The three caps a stack may have. The host holds the numbers; a request only names one.
SIZES: Final = {
    "small": SizeCaps("0.5", 256, 128, 2048),
    "standard": SizeCaps("1.0", 512, 256, 4096),
    "large": SizeCaps("2.0", 1024, 512, 8192),
}


def read_stack_parameters(host: Host) -> StackParameters:
    """Read the request's parameters and check each against its schema, or refuse by name.

    A request that carries a pin or a compose text is refused for that: the first pin is
    branchleft-deploy's, which verifies the attestation, and the stack is built here. Any other
    key is `payload-keys`. A refusal names the field and never repeats a value.
    """
    payload = read_object(host)
    if PIN_KEYS & set(payload):
        refuse("pin-not-accepted")
    if COMPOSE_KEYS & set(payload):
        refuse("compose-not-accepted")
    if set(payload) != STACK_KEYS:
        refuse("payload-keys")
    size, mail, environment = payload["size"], payload["mail"], payload["environment"]
    if not isinstance(size, str) or size not in SIZES:
        refuse("field-size")
    if not isinstance(mail, bool):
        refuse("field-mail")
    if not isinstance(environment, dict) or not 0 < len(environment) <= MAX_ENVIRONMENT:
        refuse("field-environment")
    checked: dict[str, str] = {}
    for name, value in environment.items():
        if not isinstance(name, str) or ENV_KEY_PATTERN.match(name) is None:
            refuse("field-environment")
        checked[name] = environment_value(value)
    return StackParameters(size, mail, checked)


def environment_value(value: object) -> str:
    """One environment value as compose text: a literal with no `$`, or a reference to a secret."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if not 0 <= value <= 2**31:
            refuse("field-environment")
        return str(value)
    if isinstance(value, str):
        if ENV_LITERAL_PATTERN.match(value) is None:
            refuse("field-environment")
        return value
    if isinstance(value, dict) and set(value) == {"secret"}:
        name = value["secret"]
        if not isinstance(name, str) or SECRET_NAME_PATTERN.match(name) is None:
            refuse("field-environment")
        return f"${{{name}:?set {name} in the env file}}"
    refuse("field-environment")


def read_bind_address(host: Host) -> str:
    """The app host's private address, from the file the role writes (root's, closed, one line)."""
    path = os.path.join(host.paths.entry_dir, BIND_ADDRESS_FILE)
    if not file_is_closed(host, path):
        fail("bind-address")
    try:
        with open(path, encoding="ascii") as handle:
            text = handle.read(64)
    except (OSError, UnicodeDecodeError):
        fail("bind-address")
    if BIND_ADDRESS_PATTERN.match(text) is None:
        fail("bind-address")
    return text.strip()


def ghost_service(
    slug: str, uid: int, port: int, bind: str, caps: SizeCaps, parameters: StackParameters
) -> dict[str, object]:
    """One colour's Ghost service, fixed but for its port, its caps and its environment."""
    mail_network = f"branchleft-mail-{uid}"
    service: dict[str, object] = {
        "image": "${IMAGE}",
        "restart": "unless-stopped",
        "stop_grace_period": GHOST_STOP_GRACE_PERIOD,
        "user": f"{uid}:{uid}",
        "init": True,
        "read_only": True,
        "tmpfs": [f"/tmp:rw,noexec,nosuid,nodev,size={TMPFS_SIZE}"],  # noqa: S108  # in the container.
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": caps.pids_limit,
        "mem_limit": MEMORY_LIMIT,
        "memswap_limit": MEMORY_LIMIT,
        "cpus": caps.cpus,
        "cpu_shares": caps.cpu_shares,
        "ulimits": {"nofile": {"soft": caps.nofile, "hard": caps.nofile}},
        "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
        "ports": [f"{bind}:{port}:{GHOST_CONTAINER_PORT}"],
        "environment": dict(sorted(parameters.environment.items())),
    }
    if parameters.mail:
        service["networks"] = ["default", mail_network]
    service["volumes"] = [
        f"ghost-{slug}-content:{CONTENT_MOUNT}",
        f"ghost-{slug}-adapters:{ADAPTERS_MOUNT}:ro",
        f"ghost-{slug}-metrics:{METRICS_MOUNT}",
    ]
    service["healthcheck"] = {
        "test": [
            "CMD",
            "wget",
            "-q",
            "-O",
            "/dev/null",
            "--header",
            "X-Forwarded-Proto: https",
            f"http://127.0.0.1:{GHOST_CONTAINER_PORT}/",
        ],
        "interval": "30s",
        "timeout": "5s",
        "retries": 3,
        "start_period": "60s",
    }
    return service


def build_stack(
    slug: str, marker: Mapping[str, int], bind: str, parameters: StackParameters
) -> str:
    """The tenant's compose text, from the host's own template, its claim and the parameters.

    The text is JSON, which is YAML, so every value is quoted by the encoder and none can add a
    key. The uid and the ports are the claim's: colour a on the claimed port, colour b on the next.
    """
    uid, port = marker["uid"], marker["port"]
    caps = SIZES[parameters.size]
    document: dict[str, object] = {
        "name": slug,
        "services": {
            "ghost-a": ghost_service(slug, uid, port, bind, caps, parameters),
            "ghost-b": ghost_service(slug, uid, port + 1, bind, caps, parameters),
        },
    }
    if parameters.mail:
        network = f"branchleft-mail-{uid}"
        document["networks"] = {network: {"name": network, "external": True}}
    document["volumes"] = {
        f"ghost-{slug}-content": {"external": True},
        f"ghost-{slug}-adapters": {"external": True},
        f"ghost-{slug}-metrics": {"external": True},
    }
    return json.dumps(document, indent=2) + "\n"


def compose_matches(host: Host, path: str, text: str) -> bool:
    """True when the file at `path` is a plain root-owned file holding exactly `text`."""
    try:
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != host.paths.root_uid
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            return False
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    with os.fdopen(fd, "rb") as handle:
        return handle.read(len(text.encode("utf-8")) + 1) == text.encode("utf-8")


def stage_file(final: str, data: str, mode: int, root_uid: int) -> str:
    """Write `data` to a new temporary file beside `final`, closed to everyone but root."""
    temp = os.path.join(os.path.dirname(final), f".stack-{os.urandom(8).hex()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), root_uid, -1)
            handle.write(data.encode("utf-8"))
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
    except BaseException:
        os.unlink(temp)
        raise
    return temp


def place_file(temp: str, final: str) -> None:
    """Put the staged file in its place with no way to replace one that is there.

    A hard link fails when the name exists, whoever made it and whatever it is, so a file that
    appeared since the check is refused and not overwritten. The temporary name always goes.
    """
    try:
        os.link(temp, final)
    except FileExistsError:
        refuse("stack-exists")
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp)


def step_stack(host: Host, slug: str) -> list[str]:
    """Write the tenant's compose file, built here from its claim and a few checked parameters.

    Only for a slug this entry point claimed whose secrets file is in place. The request carries
    parameters and never a compose text or an image pin: the stack comes from the host's own
    template, so its shape is not the caller's, and the first pin is written only by
    branchleft-deploy after it has verified the image's attestation. The tenant compose judge,
    the one tenant_compose runs, then reads the built text against the tenant's uid, the volume
    program's claims and the secrets file. A request repeated with the same parameters finds its
    file in place and succeeds; different parameters over an existing file are `stack-exists`.
    Nothing is replaced and nothing is written outside the slug's own slot.
    """
    marker = require_secrets(host, slug)
    parameters = read_stack_parameters(host)
    compose = check_slot_targets(host, slug)
    secrets_text = read_secrets_text(host, slug)
    text = build_stack(slug, marker, read_bind_address(host), parameters)
    if os.path.lexists(compose):
        if compose_matches(host, compose, text):
            return ["compose.yml already in place"]
        refuse("stack-exists")
    claims = list_claims(host)
    judge = load_judge(host)
    try:
        verdict = judge.judge(
            judge.params_from_mapping(
                {
                    "slug": slug,
                    "profile": "tenant",
                    "uid": marker["uid"],
                    "compose_text": text,
                    "secrets_env_text": secrets_text,
                    "image_env_text": JUDGE_PLACEHOLDER_PIN,
                    "claims_text": "".join(f"{name}={uid}\n" for name, uid in claims.items()),
                }
            )
        )
    except Exception as error:  # noqa: BLE001  # a traceback could carry the secrets: one word.
        fail("judge-yaml-missing" if type(error).__name__ == "YamlMissingError" else "judge")
    if verdict.refusals:
        # The judge's sentences name rules, services and key names and never a value; a message
        # that repeats a secret anyway is withheld whole.
        sentences = "; ".join(verdict.refusals)[:DETAIL_LIMIT]
        if any(value in sentences for value in secret_values(secrets_text)):
            sentences = "withheld: the message held a secret value"
        refuse("judge-refused", sentences)
    if verdict.claim_state != "same":
        refuse("claim-mismatch")
    directory = os.path.dirname(compose)
    try:
        if not os.path.lexists(directory):
            os.mkdir(directory, STACK_DIR_MODE)
            os.chmod(directory, STACK_DIR_MODE)
        staged = stage_file(compose, text, COMPOSE_MODE, host.paths.root_uid)
    except FileExistsError:
        refuse("stack-exists")
    except OSError:
        fail("write")
    place_file(staged, compose)
    return ["compose.yml written"]


def step_key(host: Host, slug: str) -> list[str]:
    """Grant the slug's deploy slot to the public key on stdin, once."""
    require_enabled(host, slug)
    payload = read_payload(host, frozenset({"public_key"}))
    key = text_field(payload, "public_key", PUBLIC_KEY_PATTERN)
    if os.path.lexists(slot_path(host, slug)):
        refuse("slot-exists")
    argv = [host.paths.slot_program, "--public-key-file", "/dev/stdin"]
    # The stack directory is made by the compose delivery. It is this slug's own, because the
    # slug passed every check above, so the program's guard against a stranger's stack is met.
    if os.path.lexists(os.path.join(host.paths.opt_dir, slug)):
        argv.append("--adopt-existing-stack")
    outcome = host.runner([*argv, slug], (key + "\n").encode("utf-8"))
    if outcome.returncode != 0:
        fail("slot", detail_of(outcome, [key]))
    if not os.path.lexists(slot_path(host, slug)):
        fail("slot-register")
    return ["slot granted"]


def step_owner(host: Host, slug: str) -> list[str]:
    """Make the Ghost owner before the site is reachable, through the platform's own script."""
    require_enabled(host, slug)
    payload = read_payload(host, frozenset({"colour", "name", "site_url", "site_title"}))
    colour = payload["colour"]
    if colour not in ("a", "b"):
        refuse("field-colour")
    name = text_field(payload, "name", OWNER_TEXT_PATTERN)
    title = text_field(payload, "site_title", OWNER_TEXT_PATTERN)
    site_url = text_field(payload, "site_url", SITE_URL_PATTERN)
    if len(name) > 64 or len(title) > 120:
        refuse("field-length")
    found = host.runner(
        [
            host.paths.docker,
            "ps",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={slug}",
            "--filter",
            f"label=com.docker.compose.service=ghost-{colour}",
            "--filter",
            "status=running",
        ],
        None,
    )
    containers = found.stdout.split()
    if (
        found.returncode != 0
        or len(containers) != 1
        or not CONTAINER_ID_PATTERN.match(containers[0])
    ):
        refuse("container-not-running")
    outcome = host.runner(
        [
            host.paths.node,
            host.paths.owner_program,
            "--container",
            containers[0],
            "--secrets-file",
            env_path(host, slug),
            "--name",
            name,
            "--site-url",
            site_url,
            "--site-title",
            title,
        ],
        None,
    )
    if outcome.returncode != 0:
        fail("owner", detail_of(outcome))
    return [outcome.stdout.strip()[:300] or "owner done"]


def stack_is_in_place(host: Host, slug: str) -> bool:
    """True when the compose file is a regular file, root's and closed to writes by others."""
    try:
        info = os.lstat(compose_path(host, slug))
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == host.paths.root_uid
        and not stat.S_IMODE(info.st_mode) & 0o022
    )


def step_status(host: Host, slug: str) -> list[str]:
    """Report how far one slug has got. A slug this entry point never claimed reports only that."""
    check_register_dir(host)
    if not os.path.lexists(marker_path(host, slug)):
        return ["claimed-here=no"]
    marker = read_marker(host, marker_path(host, slug))
    port = marker["port"]
    return [
        "claimed-here=yes",
        f"uid={marker['uid']}",
        f"port_a={port}",
        f"port_b={port + 1}",
        f"port_health={port + 2}",
        f"volumes={'yes' if slug in list_claims(host) else 'no'}",
        f"secrets={'yes' if file_is_closed(host, env_path(host, slug)) else 'no'}",
        f"stack={'yes' if stack_is_in_place(host, slug) else 'no'}",
        f"enabled={'yes' if unit_enabled(host, slug) else 'no'}",
        f"slot={'yes' if os.path.lexists(slot_path(host, slug)) else 'no'}",
    ]


Step = Callable[[Host, str], list[str]]
STEPS: Final[dict[str, Step]] = {
    "status": step_status,
    "claim": step_claim,
    "secrets": step_secrets,
    "stack": step_stack,
    "enable": step_enable,
    "key": step_key,
    "owner": step_owner,
}
VERBS: Final = frozenset(STEPS)


def serve(
    environ: Mapping[str, str],
    stdin: IO[bytes],
    out: IO[str],
    err: IO[str],
    *,
    paths: Paths,
    runner: Runner,
    log: Logger,
) -> int:
    """Run one request under the register's lock and return the exit code."""
    verb = slug = "-"
    try:
        verb, slug = parse_request(environ.get("SSH_ORIGINAL_COMMAND"))
        host = Host(paths, runner, stdin)
        check_register_dir(host)
        lock_fd = os.open(
            os.path.join(paths.entry_dir, ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                log(f"verb={verb} slug={slug} result=busy")
                err.write("busy\n")
                return EXIT_BUSY
            lines = STEPS[verb](host, slug)
        finally:
            os.close(lock_fd)
    except RefusedError as refusal:
        log(f"verb={verb} slug={slug} result=refused reason={refusal.reason}")
        err.write(f"refused: {refusal.reason}\n")
        if refusal.detail:
            err.write(refusal.detail + "\n")
        return EXIT_REFUSED
    except FailedError as failure:
        log(f"verb={verb} slug={slug} result=failed step={failure.step}")
        err.write(f"failed: {failure.step}\n")
        if failure.detail:
            err.write(failure.detail + "\n")
        return EXIT_FAILED
    except Terminated:
        log(f"verb={verb} slug={slug} result=terminated")
        err.write("failed: terminated\n")
        return EXIT_FAILED
    log(f"verb={verb} slug={slug} result=done")
    out.write("\n".join(lines) + "\n")
    return EXIT_DONE


def syslog_line(line: str) -> None:
    syslog.syslog(syslog.LOG_AUTH | syslog.LOG_INFO, line)


def main(
    argv: Sequence[str],
    environ: Mapping[str, str],
    stdin: IO[bytes],
    out: IO[str],
    err: IO[str],
    *,
    paths: Paths | None = None,
    runner: Runner = run_command,
    log: Logger = syslog_line,
    geteuid: Callable[[], int] = os.geteuid,
) -> int:
    """The program's one entry. Only `--from-ssh` is accepted, and only as root."""
    chosen = paths if paths is not None else Paths()
    if list(argv) != [SERVE_FLAG]:
        err.write(f"usage: branchleft-tenant-entry {SERVE_FLAG}\n")
        return EXIT_USAGE
    if geteuid() != chosen.root_uid:
        err.write("refused: not-root\n")
        return EXIT_REFUSED
    os.umask(0o077)
    previous = {number: signal.signal(number, on_termination) for number in TERMINATION_SIGNALS}
    try:
        return serve(environ, stdin, out, err, paths=chosen, runner=runner, log=log)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    syslog.openlog("branchleft-tenant-entry")
    sys.exit(main(sys.argv[1:], os.environ, sys.stdin.buffer, sys.stdout, sys.stderr))
