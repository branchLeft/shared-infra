#!/usr/bin/python3 -I
"""Move tenant stacks to the images a signed promotion ledger names.

See branchleft_promote.md, "Module overview".
"""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from types import ModuleType
from typing import Any

CONFIG_DIR = "/etc/branchleft/promote"
STATE_DIR = "/var/lib/branchleft/promote"
WRAPPER = "/usr/local/sbin/branchleft-deploy"
ALLOWED_SIGNERS = f"{CONFIG_DIR}/allowed_signers"
SLOT_MAP = f"{CONFIG_DIR}/slots.json"

# See branchleft_promote.md, "The ledger".
NAMESPACE = "branchleft-promotion-ledger"
SIGNER_IDENTITY = "ring-controller"
SCHEMA_VERSION = 1
SLOT_UIDS = range(30000, 31000)
MAX_LEDGER_BYTES = 1 << 20
MAX_VALIDITY = timedelta(hours=36)
MAX_ISSUED_SKEW = timedelta(minutes=5)
FETCH_TIMEOUT = 30.0
SIGNATURE_TIMEOUT = 20.0
BLOCKED_KEEP = 8

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_VERSION = re.compile(r"\A(\d{1,6})\.(\d{1,6})\.(\d{1,6})\Z")
_STATE_FILE = "state.json"
_LOCK_FILE = "promote.lock"


class PromoteError(Exception):
    """Raised for anything that stops a run before a wrapper call."""


class LedgerRefused(PromoteError):
    """The ledger as a whole is not acted on."""


Version = tuple[int, int, int]


@dataclasses.dataclass(frozen=True)
class Entry:
    uid: int
    image: str
    version: str


@dataclasses.dataclass(frozen=True)
class Ledger:
    seq: int
    issued: datetime
    expires: datetime
    entries: tuple[Entry, ...]
    digest: str


@dataclasses.dataclass(frozen=True)
class SlotState:
    """What the host remembers about one slot. See branchleft_promote.md, "State"."""

    applied_image: str | None = None
    applied_version: str | None = None
    previous_image: str | None = None
    previous_version: str | None = None
    desired_image: str | None = None
    pending_image: str | None = None
    blocked: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class State:
    last_seq: int = 0
    last_digest: str | None = None
    last_success: int = 0
    slots: Mapping[int, SlotState] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class Action:
    uid: int
    stack: str
    image: str
    version: str


@dataclasses.dataclass(frozen=True)
class Refused:
    uid: int
    reason: str


@dataclasses.dataclass(frozen=True)
class Judgement:
    """The whole decision for one ledger. `ledger_refusal` set means do nothing."""

    ledger_refusal: str | None = None
    up_to_date: bool = False
    actions: tuple[Action, ...] = ()
    unchanged: tuple[int, ...] = ()
    refusals: tuple[Refused, ...] = ()


def version_key(version: str) -> Version:
    match = _VERSION.match(version)
    if match is None:
        raise LedgerRefused(f"version {version!r} is not MAJOR.MINOR.PATCH")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise LedgerRefused("a key appears twice in the ledger")
    return dict(pairs)


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    # bool is an int subclass: a signed `true` must not read as seq 1.
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise LedgerRefused(f"{name} must be an integer of at least {minimum}")
    return value


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.match(value):
        raise LedgerRefused(f"{name} must be a UTC time like 2026-01-02T03:04:05Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise LedgerRefused(f"{name} is not a real time") from None


def _exact_keys(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LedgerRefused(f"{name} must be an object with exactly: {', '.join(sorted(keys))}")
    return value


def parse_ledger(body: bytes) -> Ledger:
    """Read a ledger body strictly. Call it only on bytes whose signature verified."""
    try:
        document = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise LedgerRefused("the ledger is not valid UTF-8 JSON") from None
    document = _exact_keys(
        document, frozenset({"v", "seq", "issued", "expires", "entries"}), "the ledger"
    )
    if _integer(document["v"], "v") != SCHEMA_VERSION:
        raise LedgerRefused(f"ledger schema v must be {SCHEMA_VERSION}")
    seq = _integer(document["seq"], "seq", minimum=1)
    issued = _timestamp(document["issued"], "issued")
    expires = _timestamp(document["expires"], "expires")
    if not issued < expires <= issued + MAX_VALIDITY:
        raise LedgerRefused(f"expires must be after issued and within {MAX_VALIDITY} of it")
    raw_entries = document["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) > len(SLOT_UIDS):
        raise LedgerRefused("entries must be a list with at most one row per slot")
    entries = []
    for raw in raw_entries:
        row = _exact_keys(raw, frozenset({"uid", "image", "version"}), "an entry")
        uid = _integer(row["uid"], "uid")
        if uid not in SLOT_UIDS:
            raise LedgerRefused(f"uid {uid} is outside {SLOT_UIDS.start}-{SLOT_UIDS.stop - 1}")
        image, version = row["image"], row["version"]
        if not isinstance(image, str) or not isinstance(version, str):
            raise LedgerRefused(f"entry {uid}: image and version must be strings")
        version_key(version)
        entries.append(Entry(uid, image, version))
    if len({entry.uid for entry in entries}) != len(entries):
        raise LedgerRefused("a uid appears in two entries")
    return Ledger(seq, issued, expires, tuple(entries), hashlib.sha256(body).hexdigest())


def verify_signature(
    body: bytes, signature: bytes, allowed_signers: str, *, run=subprocess.run
) -> None:
    """Raise LedgerRefused unless `signature` is a good signature over `body`.

    Fails closed: a missing ssh-keygen, a timeout or any non-zero exit refuses.
    """
    with tempfile.TemporaryDirectory(prefix="branchleft-promote-") as scratch:
        signature_path = os.path.join(scratch, "ledger.sig")
        with open(signature_path, "wb") as handle:
            handle.write(signature)
        command = ["ssh-keygen", "-Y", "verify", "-f", allowed_signers]
        command += ["-I", SIGNER_IDENTITY, "-n", NAMESPACE, "-s", signature_path]
        try:
            result = run(
                command,
                input=body,
                capture_output=True,
                check=False,
                timeout=SIGNATURE_TIMEOUT,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            raise LedgerRefused("the signature could not be checked; refusing") from None
    if result.returncode != 0:
        raise LedgerRefused("the ledger signature is not valid for the trusted signer")


def judge(
    ledger: Ledger,
    state: State,
    slot_map: Mapping[int, str],
    now: datetime,
    wrapper: ModuleType,
) -> Judgement:
    """Decide what to do with a verified ledger. No effects, no clock, no files.

    `wrapper` supplies the image grammar and the register of attested images, so
    neither is restated here. See branchleft_promote.md, "What is refused".
    """
    if now >= ledger.expires:
        return Judgement(ledger_refusal="the ledger has expired")
    if ledger.issued > now + MAX_ISSUED_SKEW:
        return Judgement(ledger_refusal="the ledger is issued in the future")
    if ledger.seq < state.last_seq:
        return Judgement(ledger_refusal="replay: seq is older than the last one seen")
    if ledger.seq == state.last_seq:
        if ledger.digest == state.last_digest:
            return Judgement(up_to_date=True)
        return Judgement(ledger_refusal="seq reused with different content")

    actions, unchanged, refusals = [], [], []
    for entry in ledger.entries:
        slot = state.slots.get(entry.uid, SlotState())
        stack = slot_map.get(entry.uid)
        if stack is None:
            refusals.append(Refused(entry.uid, "no slot map row for this uid"))
            continue
        problem = _image_problem(entry.image, wrapper)
        if problem is not None:
            refusals.append(Refused(entry.uid, problem))
            continue
        if entry.image == slot.applied_image:
            unchanged.append(entry.uid)
            continue
        if entry.image in slot.blocked or entry.image == slot.pending_image:
            refusals.append(
                Refused(entry.uid, "this digest failed or was interrupted on this slot")
            )
            continue
        is_revert = entry.image == slot.previous_image
        if (
            slot.applied_version is not None
            and version_key(entry.version) < version_key(slot.applied_version)
            and not is_revert
        ):
            refusals.append(Refused(entry.uid, "downgrade to a digest that is not the previous one"))
            continue
        actions.append(Action(entry.uid, stack, entry.image, entry.version))
    return Judgement(
        actions=tuple(actions), unchanged=tuple(unchanged), refusals=tuple(refusals)
    )


def _image_problem(image: str, wrapper: ModuleType) -> str | None:
    """Why an image cannot be acted on, or None. Spellings the wrapper accepts but
    this route does not (a tag, a registry port) are refused: the ledger names
    `name@sha256:...` exactly."""
    try:
        wrapper.validate_image_ref(image)
    except wrapper.DeployError:
        return "image is not a digest-pinned reference"
    name = wrapper.attested_name(image)
    if image != f"{name}@{image.partition('@')[2]}":
        return "image carries a tag or registry port; the ledger names name@digest only"
    if name not in wrapper.ATTESTED_IMAGES:
        return "image is not on the attested register"
    return None


def _state_to_json(state: State) -> str:
    document = {
        "last_seq": state.last_seq,
        "last_digest": state.last_digest,
        "last_success": state.last_success,
        "slots": {str(uid): dataclasses.asdict(slot) for uid, slot in sorted(state.slots.items())},
    }
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def _state_from_json(text: str) -> State:
    try:
        document = json.loads(text)
        slots = {
            int(uid): SlotState(**{**row, "blocked": tuple(row.get("blocked", ()))})
            for uid, row in document["slots"].items()
        }
        state = State(
            last_seq=document["last_seq"],
            last_digest=document["last_digest"],
            last_success=document["last_success"],
            slots=slots,
        )
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise PromoteError(f"the state file cannot be read ({type(error).__name__})") from None
    if not isinstance(state.last_seq, int) or not isinstance(state.last_success, int):
        raise PromoteError("the state file cannot be read (counters are not integers)")
    return state


def require_trusted(path: str, *, uid: int, directory: bool = False) -> None:
    """The file or directory is what the role installed: not a link, owned by
    `uid`, not writable by group or others."""
    try:
        info = os.lstat(path)
    except OSError as error:
        raise PromoteError(f"{path} cannot be read ({error.strerror})") from None
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind_ok:
        raise PromoteError(f"{path} is not a plain {'directory' if directory else 'file'}")
    if info.st_uid != uid:
        raise PromoteError(f"{path} is not owned by uid {uid}")
    if info.st_mode & 0o022:
        raise PromoteError(f"{path} is writable by group or others")


def load_state(state_dir: str) -> State:
    path = os.path.join(state_dir, _STATE_FILE)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return State()
    return _state_from_json(text)


def save_state(state_dir: str, state: State) -> None:
    """Replace the state file atomically, as the wrapper replaces a pin file."""
    path = os.path.join(state_dir, _STATE_FILE)
    handle_fd, temporary = tempfile.mkstemp(dir=state_dir, prefix=".state-")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(_state_to_json(state))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def load_wrapper(path: str, *, trusted_uid: int = 0) -> ModuleType:
    """Read the wrapper's register and grammar from the installed wrapper itself.

    Executed from source rather than imported, so nothing writes bytecode into
    the wrapper's directory.
    """
    require_trusted(path, uid=trusted_uid)
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    module = ModuleType("branchleft_deploy_wrapper")
    exec(compile(source, path, "exec"), module.__dict__)  # noqa: S102
    for name in ("ATTESTED_IMAGES", "DeployError", "attested_name", "validate_image_ref"):
        if not hasattr(module, name):
            raise PromoteError(f"{path} does not look like branchleft-deploy (no {name})")
    if not hasattr(module, "validate_stack_name"):
        raise PromoteError(f"{path} does not look like branchleft-deploy (no validate_stack_name)")
    return module


def load_slot_map(path: str, wrapper: ModuleType, *, trusted_uid: int = 0) -> dict[int, str]:
    """`[{"slot": <uid>, "stack": "<name>"}, ...]`, one stack per uid and the reverse."""
    require_trusted(path, uid=trusted_uid)
    try:
        with open(path, encoding="utf-8") as handle:
            rows = json.load(handle)
    except ValueError:
        raise PromoteError(f"{path} is not valid JSON") from None
    if not isinstance(rows, list):
        raise PromoteError(f"{path} must be a list of slot rows")
    slot_map: dict[int, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"slot", "stack"}:
            raise PromoteError(f"{path}: each row must be exactly slot and stack")
        uid, stack = row["slot"], row["stack"]
        if isinstance(uid, bool) or not isinstance(uid, int) or uid not in SLOT_UIDS:
            raise PromoteError(f"{path}: a slot is outside {SLOT_UIDS.start}-{SLOT_UIDS.stop - 1}")
        try:
            wrapper.validate_stack_name(stack)
        except (wrapper.DeployError, TypeError):
            raise PromoteError(f"{path}: slot {uid} names an invalid stack") from None
        slot_map[uid] = stack
    if len(slot_map) != len(rows) or len(set(slot_map.values())) != len(slot_map):
        raise PromoteError(f"{path}: a slot or a stack appears twice")
    return slot_map


class FetchError(PromoteError):
    """The ledger could not be fetched."""


def fetch_url(url: str, *, timeout: float = FETCH_TIMEOUT, limit: int = MAX_LEDGER_BYTES) -> bytes:
    if not url.startswith("https://"):
        raise FetchError("the ledger URL must be https")
    request = urllib.request.Request(url, headers={"User-Agent": "branchleft-promote"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if not response.geturl().startswith("https://"):
                raise FetchError("the ledger fetch was redirected off https")
            data = response.read(limit + 1)
    except OSError as error:
        raise FetchError(f"the ledger could not be fetched ({type(error).__name__})") from None
    if len(data) > limit:
        raise FetchError("the ledger is larger than the limit")
    return data


def apply_action(action: Action, *, wrapper_path: str = WRAPPER, run=subprocess.run) -> bool:
    """Hand one move to the wrapper. Its exit status is the whole answer; the wrapper
    verifies the attestation itself, before it pins or restarts anything."""
    argv = [wrapper_path, action.stack, action.image]
    try:
        result = run(argv, check=False, stdin=subprocess.DEVNULL)
    except OSError:
        return False
    return result.returncode == 0


def write_metrics(path: str, state: State, now: datetime) -> None:
    """Prometheus textfile: when the run happened, when it last succeeded, drift per uid."""
    lines = [
        "branchleft_promote_last_run_timestamp_seconds " + str(int(now.timestamp())),
        "branchleft_promote_last_success_timestamp_seconds " + str(state.last_success),
        "branchleft_promote_ledger_seq " + str(state.last_seq),
    ]
    for uid, slot in sorted(state.slots.items()):
        drift = int(slot.desired_image is not None and slot.desired_image != slot.applied_image)
        lines.append(f'branchleft_promote_slot_drift{{uid="{uid}"}} {drift}')
    directory = os.path.dirname(path) or "."
    handle_fd, temporary = tempfile.mkstemp(dir=directory, prefix=".promote-metrics-")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


@dataclasses.dataclass(frozen=True)
class Config:
    ledger_url: str
    allowed_signers: str = ALLOWED_SIGNERS
    slot_map: str = SLOT_MAP
    state_dir: str = STATE_DIR
    wrapper: str = WRAPPER
    metrics_file: str | None = None
    # Not a command-line option: root is the only owner the trust anchors may have.
    trusted_uid: int = 0


def _log(message: str) -> None:
    print(f"branchleft-promote: {message}", file=sys.stderr)


def _utcnow() -> datetime:
    return datetime.fromtimestamp(time.time(), tz=timezone.utc)


def _revise(state: State, uid: int, **changes: Any) -> State:
    slot = dataclasses.replace(state.slots.get(uid, SlotState()), **changes)
    return dataclasses.replace(state, slots={**state.slots, uid: slot})


def run_once(
    config: Config,
    *,
    fetch: Callable[[str], bytes] = fetch_url,
    run=subprocess.run,
    now: Callable[[], datetime] = _utcnow,
    log: Callable[[str], None] = _log,
) -> int:
    """One timer tick. 0: nothing wrong. 1: something was refused or failed. Never raises
    for an input problem; every refusal happens before any wrapper call."""
    try:
        require_trusted(config.state_dir, uid=config.trusted_uid, directory=True)
        lock_fd = os.open(os.path.join(config.state_dir, _LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
    except (PromoteError, OSError) as error:
        log(f"refusing: {error}")
        return 1
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("another run holds the lock; nothing done")
            return 1
        return _locked_run(config, fetch=fetch, run=run, now=now, log=log)
    finally:
        os.close(lock_fd)


def _locked_run(config: Config, *, fetch, run, now, log) -> int:
    moment = now()
    try:
        state = load_state(config.state_dir)
        wrapper = load_wrapper(config.wrapper, trusted_uid=config.trusted_uid)
        require_trusted(config.allowed_signers, uid=config.trusted_uid)
        slot_map = load_slot_map(config.slot_map, wrapper, trusted_uid=config.trusted_uid)
    except PromoteError as error:
        log(f"refusing: {error}")
        return 1

    def finish(status: int, current: State) -> int:
        if config.metrics_file:
            write_metrics(config.metrics_file, current, moment)
        return status

    try:
        body = fetch(config.ledger_url)
        signature = fetch(config.ledger_url + ".sig")
        verify_signature(body, signature, config.allowed_signers, run=run)
        ledger = parse_ledger(body)
    except PromoteError as error:
        log(f"refusing, nothing changed: {error}")
        return finish(1, state)

    judgement = judge(ledger, state, slot_map, moment, wrapper)
    if judgement.ledger_refusal:
        log(f"refusing seq {ledger.seq}, nothing changed: {judgement.ledger_refusal}")
        return finish(1, state)
    if judgement.up_to_date:
        state = dataclasses.replace(state, last_success=int(moment.timestamp()))
        save_state(config.state_dir, state)
        return finish(0, state)

    failed = bool(judgement.refusals)
    for entry in ledger.entries:
        state = _revise(state, entry.uid, desired_image=entry.image)
    for refusal in judgement.refusals:
        log(f"slot {refusal.uid} refused: {refusal.reason}")
    for action in judgement.actions:
        slot = state.slots.get(action.uid, SlotState())
        # Written before the call: a crash mid-move leaves this digest blocked, so a
        # digest that kills the run is not retried every tick.
        state = _revise(state, action.uid, pending_image=action.image)
        save_state(config.state_dir, state)
        if apply_action(action, wrapper_path=config.wrapper, run=run):
            blocked = slot.blocked
            if action.image == slot.previous_image and slot.applied_image:
                blocked = (*blocked, slot.applied_image)[-BLOCKED_KEEP:]
            state = _revise(
                state,
                action.uid,
                applied_image=action.image,
                applied_version=action.version,
                previous_image=slot.applied_image,
                previous_version=slot.applied_version,
                pending_image=None,
                blocked=blocked,
            )
            log(f"slot {action.uid} moved to version {action.version}")
        else:
            failed = True
            state = _revise(
                state,
                action.uid,
                pending_image=None,
                blocked=(*slot.blocked, action.image)[-BLOCKED_KEEP:],
            )
            log(f"slot {action.uid} move to version {action.version} failed; not retried")
        save_state(config.state_dir, state)
    state = dataclasses.replace(
        state,
        last_seq=ledger.seq,
        last_digest=ledger.digest,
        last_success=state.last_success if failed else int(moment.timestamp()),
    )
    save_state(config.state_dir, state)
    return finish(1 if failed else 0, state)


def main(argv: Sequence[str], **kwargs) -> int:
    parser = argparse.ArgumentParser(prog="branchleft-promote", description=__doc__)
    parser.add_argument("--ledger-url", required=True, help="https URL of the signed ledger")
    parser.add_argument("--allowed-signers", default=ALLOWED_SIGNERS)
    parser.add_argument("--slots", default=SLOT_MAP)
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--wrapper", default=WRAPPER)
    parser.add_argument("--metrics-file", default=None)
    try:
        args = parser.parse_args(list(argv[1:]))
    except SystemExit as error:
        return 2 if error.code else 0
    config = Config(
        ledger_url=args.ledger_url,
        allowed_signers=args.allowed_signers,
        slot_map=args.slots,
        state_dir=args.state_dir,
        wrapper=args.wrapper,
        metrics_file=args.metrics_file,
    )
    return run_once(config, **kwargs)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
