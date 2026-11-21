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
import stat
import subprocess
import sys
import syslog
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
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

# The one image a tenant's stack may run, as its pin line, and the two modes of what `stack` writes.
# Held equal to tenant_compose's own pattern by tests/unit/test_branchleft_tenant_entry.py.
TENANT_IMAGE_PATTERN: Final = re.compile(
    r"\AIMAGE=ghcr\.io/branchleft/ghost-tenant@sha256:[0-9a-f]{64}\n\Z"
)
COMPOSE_MODE: Final = 0o644
STACK_DIR_MODE: Final = 0o755
IMAGE_ENV_MODE: Final = 0o600
DETAIL_LIMIT: Final = 1000

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
    node: str = "/usr/bin/node"
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


def read_payload(host: Host, keys: frozenset[str]) -> dict[str, object]:
    """Read one JSON object from stdin whose keys are exactly `keys`."""
    raw = host.stdin.read(MAX_PAYLOAD + 1)
    if len(raw) > MAX_PAYLOAD:
        refuse("payload-too-large")
    try:
        parsed: object = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError:
        refuse("payload-not-json")
    if not isinstance(parsed, dict):
        refuse("payload-not-object")
    payload: dict[str, object] = parsed
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


def detail_of(outcome: Outcome, hidden: Iterable[str] = ()) -> str:
    """A step's own message, cut short, and withheld whole if it holds any hidden value."""
    text = (outcome.stderr or outcome.stdout).strip()[:1000]
    if any(value and value in text for value in hidden):
        return "withheld: the message held a secret value"
    return text


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
    """Create the marker with no way to replace one: exclusive, no link followed, mode 0600."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(marker_path(host, slug), flags, 0o600)
    except FileExistsError:
        refuse("slug-in-use")
    with os.fdopen(fd, "wb") as handle:
        os.fchown(handle.fileno(), host.paths.root_uid, -1)
        os.fchmod(handle.fileno(), 0o600)
        handle.write(json.dumps({"uid": uid, "port": port}).encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())


def step_claim(host: Host, slug: str) -> list[str]:
    """Take a uid and four ports for a slug that exists nowhere, then make its volumes."""
    check_register_dir(host)
    if slug_in_use(host, slug):
        refuse("slug-in-use")
    claims = list_claims(host)
    if slug in claims:
        refuse("slug-in-use")
    markers = all_markers(host)
    uid = first_free_uid(set(claims.values()) | {m["uid"] for m in markers.values()})
    port = first_free_port({m["port"] for m in markers.values()})
    write_marker(host, slug, uid, port)
    # Every way out of the volume step, a timeout or a missing program included, releases the
    # marker when no claim sits behind it, so a retry needs no hand step.
    try:
        outcome = host.runner([host.paths.volume_program, "--uid", str(uid), slug], None)
    except BaseException:
        release_unclaimed_marker(host, slug)
        raise
    if outcome.returncode != 0:
        release_unclaimed_marker(host, slug)
        fail("volumes", detail_of(outcome))
    return [f"claimed uid={uid} port_a={port} port_b={port + 1} port_health={port + 2}"]


def release_unclaimed_marker(host: Host, slug: str) -> None:
    """Remove the slug's marker unless the volume program lists a claim for it.

    A marker with no claim holds the slug for nothing. A claim that is listed keeps its marker.
    When the listing itself fails, no claim is confirmed, so the marker goes: later verbs then
    refuse it by name (not-claimed-here), and the listing still refuses a repeat claim if the
    volume program had in fact made one.
    """
    try:
        claimed = slug in list_claims(host)
    except FailedError:
        claimed = False
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


def check_slot_targets(host: Host, slug: str) -> tuple[str, str]:
    """Return the two files `stack` may write, after checking they are inside the slug's own slot.

    The slot is the slug's stack directory under the stack root, and the slug's own image pin
    name in the configuration directory. A stack directory that is a link, not a directory or not
    root's, a configuration directory that is not root's, and a path that resolves anywhere else
    are refused, so no request can place a file outside it.
    """
    root = host.paths.root_uid
    for base in (host.paths.opt_dir, host.paths.etc_dir):
        try:
            base_info = os.stat(base)
        except OSError:
            refuse("path-outside-slot")
        if not stat.S_ISDIR(base_info.st_mode) or base_info.st_uid != root:
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
    pin = image_env_path(host, slug)
    inside = (
        os.path.realpath(os.path.dirname(compose))
        == os.path.join(os.path.realpath(host.paths.opt_dir), slug)
        and os.path.realpath(os.path.dirname(pin)) == os.path.realpath(host.paths.etc_dir)
        and os.path.basename(pin) == f"{slug}.image.env"
    )
    if not inside:
        refuse("path-outside-slot")
    return compose, pin


@dataclass(frozen=True)
class Staged:
    """One file written whole under a temporary name in its final directory, not yet in place."""

    temp: str
    final: str


def stage_file(final: str, data: str, mode: int, root_uid: int) -> Staged:
    """Write `data` to a new temporary file beside `final`, closed to everyone but root."""
    directory = os.path.dirname(final)
    temp = os.path.join(directory, f".stack-{os.urandom(8).hex()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        os.fchown(handle.fileno(), root_uid, -1)
        handle.write(data.encode("utf-8"))
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())
    return Staged(temp, final)


def place_files(staged: Sequence[Staged]) -> None:
    """Put each staged file in its final place with no way to replace one that is there.

    A hard link fails when the name exists, whoever made it and whatever it is, so a file that
    appeared since the check is refused and not overwritten. Either both files are placed or
    neither: the first is taken back if the second cannot be placed.
    """
    placed: list[str] = []
    try:
        for item in staged:
            try:
                os.link(item.temp, item.final)
            except FileExistsError:
                refuse("stack-exists")
            placed.append(item.final)
    except BaseException:
        for final in placed:
            os.unlink(final)
        raise
    finally:
        for item in staged:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(item.temp)


def step_stack(host: Host, slug: str) -> list[str]:
    """Write the tenant's compose file and first image pin, once, after the judge has passed them.

    Only for a slug this entry point claimed whose secrets file is in place. The judge is the one
    tenant_compose runs, given the tenant's own uid, the volume program's claims and the secrets
    file, so a stack it refuses is never written. Nothing is replaced and nothing is written
    outside the slug's own slot.
    """
    marker = require_secrets(host, slug)
    payload = read_payload(host, frozenset({"compose_text", "image_env_text"}))
    compose_text = payload["compose_text"]
    image_env_text = payload["image_env_text"]
    if not isinstance(compose_text, str) or not compose_text or "\x00" in compose_text:
        refuse("field-compose_text")
    if not isinstance(image_env_text, str) or not image_env_text or "\x00" in image_env_text:
        refuse("field-image_env_text")
    compose, pin = check_slot_targets(host, slug)
    if os.path.lexists(compose) or os.path.lexists(pin):
        refuse("stack-exists")
    secrets_text = read_secrets_text(host, slug)
    claims = list_claims(host)
    judge = load_judge(host)
    try:
        verdict = judge.judge(
            judge.params_from_mapping(
                {
                    "slug": slug,
                    "profile": "tenant",
                    "uid": marker["uid"],
                    "compose_text": compose_text,
                    "secrets_env_text": secrets_text,
                    "image_env_text": image_env_text,
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
    if TENANT_IMAGE_PATTERN.match(verdict.image_env) is None:
        refuse("image-not-tenant")
    directory = os.path.dirname(compose)
    if not os.path.lexists(directory):
        os.mkdir(directory, STACK_DIR_MODE)
        os.chmod(directory, STACK_DIR_MODE)
    place_files(
        [
            stage_file(compose, compose_text, COMPOSE_MODE, host.paths.root_uid),
            stage_file(pin, verdict.image_env, IMAGE_ENV_MODE, host.paths.root_uid),
        ]
    )
    return ["compose.yml and image.env written"]


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
    """True when the compose file is a regular file, not a link, and the image pin is closed."""
    try:
        info = os.lstat(compose_path(host, slug))
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and file_is_closed(host, image_env_path(host, slug))


def step_status(host: Host, slug: str) -> list[str]:
    """Report how far one slug has got. A slug this entry point never claimed reports only that."""
    check_register_dir(host)
    if not os.path.lexists(marker_path(host, slug)):
        return ["claimed-here=no"]
    read_marker(host, marker_path(host, slug))
    return [
        "claimed-here=yes",
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
    return serve(environ, stdin, out, err, paths=chosen, runner=runner, log=log)


if __name__ == "__main__":
    syslog.openlog("branchleft-tenant-entry")
    sys.exit(main(sys.argv[1:], os.environ, sys.stdin.buffer, sys.stdout, sys.stderr))
