#!/usr/bin/python
"""Make the deploy account's slot keys exactly the declared set, through the slot program.

The rules (one key holds one slot, the forced command, the discarded key comment, the
root-owned home, the refusal to take a stack already on the host) live in the slot
program, installed on the host. This module loads that program, plans from the program's
own functions, applies through its grant and revoke, and then reads the result back
against a shape it pins for itself, so a program that has drifted fails closed.
"""

import dataclasses
import errno
import os
import stat
import types
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, cast

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: deploy_slot_keys_reconcile
short_description: Make the deploy account's slot keys exactly the declared set
description:
  - Loads the slot provisioning program installed on the host and makes the host's slots
    exactly the declared list, granting new ones, rotating changed keys and revoking
    those not declared.
  - An empty list is not declared, so it changes nothing and never revokes every slot.
  - Reports a change only when the register, the rendered authorized_keys, the owner and
    mode of the files or the root ownership of the deploy home would differ.
  - After an apply it reads authorized_keys back and compares each managed line with a
    shape pinned in this module, independent of the program.
  - Returns counts only. It never returns or logs a stack name, a key or a fingerprint.
version_added: "1.0.0"
author:
  - branchLeft
options:
  slots:
    description: The exact set of slots this host holds. A stack not listed is revoked.
    type: list
    elements: dict
    required: true
    suboptions:
      stack:
        description: The stack name, validated by the program before anything is written.
        type: str
        required: true
      public_key:
        description: One OpenSSH public key. Its comment is discarded. One key holds one slot.
        type: str
        required: true
      adopt_existing:
        description: Allow the first slot on a stack the host already runs.
        type: bool
        default: false
  program_path:
    description: Absolute path of the installed slot program. It runs as root, so it and every
      directory above it must be root's, not links and not writable by a group or others.
    type: path
    required: true
attributes:
  check_mode:
    support: full
    description: Plans from the host as it is and changes nothing.
  diff_mode:
    support: none
    description: No diff is produced, because the entries are private.
"""

EXAMPLES = r"""
- name: Make the slots exactly this list
  deploy_slot_keys_reconcile:
    program_path: /usr/local/sbin/EXAMPLE_PROGRAM
    slots:
      - stack: example-stack-a
        public_key: "{{ example_public_key_a }}"
  no_log: true
"""

RETURN = r"""
changed:
  description: Whether the host changed, or in check mode would change.
  returned: always
  type: bool
granted:
  description: Slots that did not exist and are granted.
  returned: success
  type: int
rotated:
  description: Slots whose key changed.
  returned: success
  type: int
revoked:
  description: Slots that were held and are not declared.
  returned: success
  type: int
unchanged:
  description: Declared slots that already held the declared key.
  returned: success
  type: int
"""

# The oracle. Everything below is pinned here, apart from the program, and the program's
# constants must equal it before anything is planned. ansible/checks/
# test_deploy_slot_keys_single_home.py holds these to the program's and the wrapper's.
PINNED_SUDO = "/usr/bin/sudo"
PINNED_WRAPPER = "/usr/local/sbin/branchleft-deploy"
PINNED_SLOT_FLAG = "--slot"
PINNED_MARKER = "branchleft-slot:"
PINNED_ACCOUNT = "deploy"
PINNED_HOME = "/home/deploy"
PINNED_SSH_DIR = "/home/deploy/.ssh"
PINNED_AUTHORIZED_KEYS = "/home/deploy/.ssh/authorized_keys"
PINNED_SLOT_DIR = "/etc/branchleft/deploy-slots"
PINNED_STACK_DIR = "/opt/branchleft"
PINNED_SLOT_DIR_MODE = 0o700
PINNED_SLOT_FILE_MODE = 0o600
PINNED_AUTHORIZED_KEYS_MODE = 0o640
PINNED_DEPLOY_DIR_MODE = 0o750

PINNED_PROGRAM_CONSTANTS: Mapping[str, str | int] = {
    "SUDO": PINNED_SUDO,
    "WRAPPER": PINNED_WRAPPER,
    "MANAGED_MARKER": PINNED_MARKER,
    "DEPLOY_ACCOUNT": PINNED_ACCOUNT,
    "DEPLOY_HOME": PINNED_HOME,
    "DEPLOY_SSH_DIR": PINNED_SSH_DIR,
    "AUTHORIZED_KEYS": PINNED_AUTHORIZED_KEYS,
    "SLOT_DIR": PINNED_SLOT_DIR,
    "STACK_DIR": PINNED_STACK_DIR,
    "SLOT_DIR_MODE": PINNED_SLOT_DIR_MODE,
    "SLOT_FILE_MODE": PINNED_SLOT_FILE_MODE,
    "AUTHORIZED_KEYS_MODE": PINNED_AUTHORIZED_KEYS_MODE,
    "DEPLOY_DIR_MODE": PINNED_DEPLOY_DIR_MODE,
}

PROGRAM_MODULE_NAME = "branchleft_provision_deploy_slot"
WRITABLE_BEYOND_OWNER = 0o022
OWNER_EXECUTE = 0o100

# The rule names. A refusal says which rule and, for an entry, its place in the list. It
# never says a stack, a key or a fingerprint: the log of a plan is public.
RULE_STACK_NAME = "stack-name-invalid"
RULE_PUBLIC_KEY = "public-key-invalid"
RULE_STACK_TWICE = "stack-declared-twice"
RULE_KEY_TWICE = "key-declared-twice"
RULE_KEY_IN_USE = "key-already-installed"
RULE_STACK_ON_HOST = "stack-already-on-host-not-adopted"
RULE_GRANT = "grant-refused"
RULE_REVOKE = "revoke-refused"
RULE_PROGRAM_UNTRUSTED = "program-missing-or-not-root-owned"
RULE_PROGRAM_NOT_LOADABLE = "program-not-loadable"
RULE_PROGRAM_CONSTANTS = "program-constants-differ-from-pinned"
RULE_WRAPPER = "wrapper-missing-or-not-root-owned"
RULE_ACCOUNT = "deploy-account-or-home-missing"
RULE_REGISTER = "register-unreadable"
RULE_DISAGREE = "register-and-authorized-keys-disagree"
RULE_RENDER = "render-refused"
RULE_PLAN_SHAPE = "rendered-line-differs-from-pinned-shape"
RULE_READBACK_SHAPE = "readback-line-differs-from-pinned-shape"
RULE_READBACK_REGISTER = "readback-register-differs-from-declared"
RULE_READBACK_DRIFT = "readback-drift-remains"

DRIFT_CONTENT = "authorized-keys-content"
DRIFT_FILE = "authorized-keys-owner-or-mode"
DRIFT_HOME = "deploy-home-owner-or-mode"
DRIFT_WRITABLE = "deploy-home-writable-by-the-account"
DRIFT_REGISTER_DIR = "register-directory"
DRIFT_REGISTER_FILE = "register-file-owner-or-mode"


class SlotRefusalError(Exception):
    """A refusal the module reports by rule name only."""


class EntryRefusalError(SlotRefusalError):
    """A declared entry broke a rule: its place in the list and the rule, nothing else."""

    def __init__(self, number: int, rule: str) -> None:
        super().__init__(f"slot entry number {number}: {rule}")


class HostRefusalError(SlotRefusalError):
    """The host, or the program on it, broke a rule."""

    def __init__(self, rule: str) -> None:
        super().__init__(f"host: {rule}")


class WrongTypeError(TypeError):
    """A value AnsibleModule validated is not the type the module reads."""

    def __init__(self, key: str, expected: str) -> None:
        super().__init__(f"{key} is not {expected}")


class Fs(Protocol):
    """The filesystem operations the slot program performs, which this module also reads."""

    def exists(self, path: str) -> bool:
        """Say whether a path exists."""
        ...

    def listdir(self, path: str) -> list[str]:
        """List a directory, empty when it is absent."""
        ...

    def walk(self, path: str) -> list[str]:
        """List every path beneath a directory."""
        ...

    def is_symlink(self, path: str) -> bool:
        """Say whether a path is a link."""
        ...

    def owner_mode(self, path: str) -> tuple[int, int, int]:
        """Return the owner, the group and the permission bits of a path."""
        ...

    def account_gid(self, name: str) -> int:
        """Return the group of an account."""
        ...

    def read_text(self, path: str) -> str:
        """Return a file's text, empty when it is absent."""
        ...

    def replace_text(self, path: str, text: str, mode: int, uid: int, gid: int) -> None:
        """Replace a file atomically with its owner and mode set."""
        ...


class Program(Protocol):
    """The slot program's surface this module uses. The module is cast to it once."""

    ProvisionError: type[Exception]
    _RealFs: Callable[[], Fs]

    def validate_stack_name(self, stack: str) -> str:
        """Return the stack name or raise."""
        ...

    def fingerprint(self, public_key: str) -> str:
        """Return the SHA256 form `ssh-keygen -lf` prints."""
        ...

    def normalise_public_key(self, text: str) -> str:
        """Return the key's type and blob with the comment discarded, or raise."""
        ...

    def read_slots(self, *, fs: Fs) -> dict[str, str]:
        """Return the register."""
        ...

    def reconcile(self, slots: dict[str, str], authorized_text: str) -> None:
        """Raise unless every managed line is explained by the register."""
        ...

    def assert_key_is_unused(
        self, stack: str, public_key: str, slots: dict[str, str], authorized_text: str
    ) -> None:
        """Raise when the key already authenticates as something else."""
        ...

    def existing_stacks(self, *, fs: Fs) -> set[str]:
        """Return the stack names the host runs."""
        ...

    def render_authorized_keys(self, existing: str, slots: dict[str, str]) -> str:
        """Return authorized_keys as the register renders it."""
        ...

    def unhardened_paths(self, *, fs: Fs) -> list[str]:
        """Return the paths under the deploy home the account could write."""
        ...

    def slot_path(self, stack: str) -> str:
        """Return a stack's register file."""
        ...

    def grant(
        self, stack: str, public_key_text: str, *, fs: Fs, adopt_existing_stack: bool
    ) -> list[str]:
        """Grant or rotate one slot."""
        ...

    def revoke(self, stack: str, *, fs: Fs) -> list[str]:
        """Revoke one slot."""
        ...


@dataclasses.dataclass(frozen=True)
class Entry:
    """One declared slot, as given."""

    stack: str
    public_key: str = dataclasses.field(repr=False)
    adopt_existing: bool


@dataclasses.dataclass(frozen=True)
class Valid:
    """One declared slot after the program has validated it."""

    stack: str
    key: str = dataclasses.field(repr=False)
    adopt_existing: bool


@dataclasses.dataclass(frozen=True)
class Plan:
    """What an apply would do. The names stay inside the module; only counts leave it."""

    granted: tuple[str, ...]
    rotated: tuple[str, ...]
    revoked: tuple[str, ...]
    unchanged: tuple[str, ...]
    drift: tuple[str, ...]
    original_text: str
    gid: int

    @property
    def changed(self) -> bool:
        """Whether the host differs from the declared set in any way the module repairs."""
        return bool(self.granted or self.rotated or self.revoked or self.drift)


@dataclasses.dataclass(frozen=True)
class Result:
    """Counts, and whether the host changed. Nothing here names a stack."""

    granted: int
    rotated: int
    revoked: int
    unchanged: int
    changed: bool


def pinned_line(stack: str, key: str) -> str:
    """Return the authorized_keys line a slot must have, built here and not by the program."""
    return (
        f'restrict,command="{PINNED_SUDO} -n {PINNED_WRAPPER} {PINNED_SLOT_FLAG} {stack}" '
        f"{key} {PINNED_MARKER}{stack}"
    )


def is_trusted(info: os.stat_result, *, directory: bool, owner_uid: int) -> bool:
    """Say whether metadata is the owner's, the right kind, not a link and closed to others."""
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    return kind and info.st_uid == owner_uid and not info.st_mode & WRITABLE_BEYOND_OWNER


def read_trusted_program(
    path: str, *, lstat: Callable[[str], os.stat_result] = os.lstat, owner_uid: int = 0
) -> str:
    """Return the source of the program at ``path``, after checking it may run as root.

    The file and every directory above it, up to the root of the filesystem, are the
    owner's, are not links and are not writable by a group or others. The file is then
    opened without following a link and checked again by its descriptor, so the bytes
    read are the bytes checked.

    Raises:
        HostRefusalError: when the path, a directory above it or the file is not trustworthy.
    """
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise HostRefusalError(RULE_PROGRAM_UNTRUSTED)
    parts = path.split("/")[1:-1]
    directories = ["/"] + ["/" + "/".join(parts[:count]) for count in range(1, len(parts) + 1)]
    try:
        trusted = all(
            is_trusted(lstat(directory), directory=True, owner_uid=owner_uid)
            for directory in directories
        )
        before = lstat(path)
        trusted = trusted and is_trusted(before, directory=False, owner_uid=owner_uid)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW) if trusted else -1
    except OSError:
        raise HostRefusalError(RULE_PROGRAM_UNTRUSTED) from None
    if descriptor < 0:
        raise HostRefusalError(RULE_PROGRAM_UNTRUSTED)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise HostRefusalError(RULE_PROGRAM_UNTRUSTED)
        return handle.read()


def load_program(source: str, path: str) -> Program:
    """Run the program's source as a module of its own and return it, constants checked.

    Raises:
        HostRefusalError: when the source does not load, or a constant differs from the pinned one.
    """
    module = types.ModuleType(PROGRAM_MODULE_NAME)
    module.__file__ = path
    try:
        code = compile(source, path, "exec")
        # The source was read by read_trusted_program from a root-owned file.
        exec(code, module.__dict__)  # noqa: S102
    except (SyntaxError, ValueError, ImportError, NameError, TypeError, AttributeError):
        raise HostRefusalError(RULE_PROGRAM_NOT_LOADABLE) from None
    for name, pinned in PINNED_PROGRAM_CONSTANTS.items():
        if getattr(module, name, None) != pinned:
            raise HostRefusalError(RULE_PROGRAM_CONSTANTS)
    return cast("Program", module)


def validate_entries(program: Program, entries: Sequence[Entry]) -> list[Valid]:
    """Validate every declared entry before anything is read from or written to the host.

    Raises:
        EntryRefusalError: for the first entry that breaks a rule, naming its place in the list.
    """
    valid: list[Valid] = []
    stacks: set[str] = set()
    keys: set[str] = set()
    for number, entry in enumerate(entries, start=1):
        try:
            program.validate_stack_name(entry.stack)
        except program.ProvisionError:
            raise EntryRefusalError(number, RULE_STACK_NAME) from None
        try:
            key = program.normalise_public_key(entry.public_key)
        except program.ProvisionError:
            raise EntryRefusalError(number, RULE_PUBLIC_KEY) from None
        if entry.stack in stacks:
            raise EntryRefusalError(number, RULE_STACK_TWICE)
        if key in keys:
            raise EntryRefusalError(number, RULE_KEY_TWICE)
        stacks.add(entry.stack)
        keys.add(key)
        valid.append(Valid(entry.stack, key, entry.adopt_existing))
    return valid


def require_host(program: Program, fs: Fs) -> int:
    """Refuse a host with no trusted wrapper or no deploy account, and return its group.

    Raises:
        HostRefusalError: when the wrapper, the account or its home is missing or not as expected.
    """
    wrapper = PINNED_WRAPPER
    if not fs.exists(wrapper) or fs.is_symlink(wrapper):
        raise HostRefusalError(RULE_WRAPPER)
    uid, _group, mode = fs.owner_mode(wrapper)
    if uid != 0 or mode & WRITABLE_BEYOND_OWNER or not mode & OWNER_EXECUTE:
        raise HostRefusalError(RULE_WRAPPER)
    try:
        gid = fs.account_gid(PINNED_ACCOUNT)
    except program.ProvisionError:
        raise HostRefusalError(RULE_ACCOUNT) from None
    if not (fs.exists(PINNED_HOME) and fs.exists(PINNED_SSH_DIR)):
        raise HostRefusalError(RULE_ACCOUNT)
    return gid


def read_host(program: Program, fs: Fs) -> tuple[dict[str, str], str]:
    """Return the register and authorized_keys, after the program says they agree.

    Raises:
        HostRefusalError: when the register cannot be read or does not explain authorized_keys.
    """
    try:
        slots = program.read_slots(fs=fs)
    except program.ProvisionError:
        raise HostRefusalError(RULE_REGISTER) from None
    text = fs.read_text(PINNED_AUTHORIZED_KEYS)
    try:
        program.reconcile(slots, text)
    except program.ProvisionError:
        raise HostRefusalError(RULE_DISAGREE) from None
    return slots, text


def assert_pinned_shape(text: str, desired: Mapping[str, str], rule: str) -> None:
    """Fail unless the managed lines of ``text`` are exactly the pinned line of each slot.

    A key must also appear on one line only: sshd takes the first line a key matches, so a
    second line carrying a declared key would keep whatever reach that line has.

    Raises:
        HostRefusalError: with ``rule`` when a managed line differs, is missing or is extra.
    """
    lines = text.splitlines()
    managed = [
        line.strip()
        for line in lines
        if line.split() and line.split()[-1].startswith(PINNED_MARKER)
    ]
    if sorted(managed) != sorted(pinned_line(stack, key) for stack, key in desired.items()):
        raise HostRefusalError(rule)
    for key in desired.values():
        blob = key.split(" ", 1)[1]
        if sum(1 for line in lines if blob in line.split()) != 1:
            raise HostRefusalError(rule)


def drift_of(
    program: Program, fs: Fs, desired: Mapping[str, str], text: str, rendered: str, gid: int
) -> tuple[str, ...]:
    """Name each way the host differs from the declared set apart from the slots themselves."""
    found: list[str] = []
    if rendered != text:
        found.append(DRIFT_CONTENT)
    if fs.exists(PINNED_AUTHORIZED_KEYS) and fs.owner_mode(PINNED_AUTHORIZED_KEYS) != (
        0,
        gid,
        PINNED_AUTHORIZED_KEYS_MODE,
    ):
        found.append(DRIFT_FILE)
    if any(
        fs.owner_mode(path) != (0, gid, PINNED_DEPLOY_DIR_MODE)
        for path in (PINNED_HOME, PINNED_SSH_DIR)
    ):
        found.append(DRIFT_HOME)
    if program.unhardened_paths(fs=fs):
        found.append(DRIFT_WRITABLE)
    if not fs.exists(PINNED_SLOT_DIR) or fs.owner_mode(PINNED_SLOT_DIR) != (
        0,
        0,
        PINNED_SLOT_DIR_MODE,
    ):
        found.append(DRIFT_REGISTER_DIR)
    for stack in desired:
        path = program.slot_path(stack)
        if fs.exists(path) and fs.owner_mode(path) != (0, 0, PINNED_SLOT_FILE_MODE):
            found.append(DRIFT_REGISTER_FILE)
            break
    return tuple(found)


def make_plan(program: Program, fs: Fs, valid: Sequence[Valid]) -> Plan:
    """Plan from the host as it is. Reads only, and fails before any write on a broken rule.

    Raises:
        EntryRefusalError: when an entry cannot be granted on this host, in the order it will be.
        HostRefusalError: when the host, the program or the program's own rendering breaks a rule.
    """
    gid = require_host(program, fs)
    slots, text = read_host(program, fs)
    desired = {item.stack: item.key for item in valid}
    revoked = tuple(sorted(set(slots) - set(desired)))
    working = {stack: key for stack, key in slots.items() if stack in desired}
    on_host = program.existing_stacks(fs=fs)
    granted: list[str] = []
    rotated: list[str] = []
    unchanged: list[str] = []
    for number, item in enumerate(valid, start=1):
        try:
            program.assert_key_is_unused(item.stack, item.key, working, text)
        except program.ProvisionError:
            raise EntryRefusalError(number, RULE_KEY_IN_USE) from None
        previous = working.get(item.stack)
        if previous is None:
            if item.stack in on_host and not item.adopt_existing:
                raise EntryRefusalError(number, RULE_STACK_ON_HOST)
            granted.append(item.stack)
        elif previous != item.key:
            rotated.append(item.stack)
        else:
            unchanged.append(item.stack)
        working[item.stack] = item.key
    try:
        rendered = program.render_authorized_keys(text, desired)
    except program.ProvisionError:
        raise HostRefusalError(RULE_RENDER) from None
    assert_pinned_shape(rendered, desired, RULE_PLAN_SHAPE)
    return Plan(
        tuple(granted),
        tuple(rotated),
        revoked,
        tuple(unchanged),
        drift_of(program, fs, desired, text, rendered, gid),
        text,
        gid,
    )


def read_back(program: Program, fs: Fs, valid: Sequence[Valid], plan: Plan) -> None:
    """Read the host again and fail unless it is the declared set, in the pinned shape.

    Raises:
        HostRefusalError: when the register, a managed line or the ownership differs from declared.
    """
    desired = {item.stack: item.key for item in valid}
    try:
        slots = program.read_slots(fs=fs)
    except program.ProvisionError:
        raise HostRefusalError(RULE_READBACK_REGISTER) from None
    if slots != desired:
        raise HostRefusalError(RULE_READBACK_REGISTER)
    text = fs.read_text(PINNED_AUTHORIZED_KEYS)
    assert_pinned_shape(text, desired, RULE_READBACK_SHAPE)
    try:
        rendered = program.render_authorized_keys(text, desired)
    except program.ProvisionError:
        raise HostRefusalError(RULE_READBACK_DRIFT) from None
    if drift_of(program, fs, desired, text, rendered, plan.gid):
        raise HostRefusalError(RULE_READBACK_DRIFT)


def restore_authorized_keys(fs: Fs, plan: Plan) -> None:
    """Put the authorized_keys text from before the apply back, so a bad line is not left."""
    fs.replace_text(
        PINNED_AUTHORIZED_KEYS, plan.original_text, PINNED_AUTHORIZED_KEYS_MODE, 0, plan.gid
    )


def apply_plan(program: Program, fs: Fs, valid: Sequence[Valid], plan: Plan) -> None:
    """Carry the plan out through the program's revoke and grant, then read the host back.

    A grant also repairs the deploy home, the register's modes and authorized_keys, so when
    anything but a slot drifted every declared slot is granted again with its own key.

    Raises:
        HostRefusalError: when the program refuses a step, or the read-back differs from declared.
        EntryRefusalError: when the program refuses to grant an entry.
    """
    for stack in plan.revoked:
        try:
            program.revoke(stack, fs=fs)
        except program.ProvisionError:
            raise HostRefusalError(RULE_REVOKE) from None
    touched = set(plan.granted) | set(plan.rotated)
    slots_changed = bool(touched or plan.revoked)
    repair_all = DRIFT_REGISTER_FILE in plan.drift or (bool(plan.drift) and not slots_changed)
    for number, item in enumerate(valid, start=1):
        if item.stack not in touched and not repair_all:
            continue
        try:
            program.grant(item.stack, item.key, fs=fs, adopt_existing_stack=item.adopt_existing)
        except program.ProvisionError:
            raise EntryRefusalError(number, RULE_GRANT) from None
    try:
        read_back(program, fs, valid, plan)
    except HostRefusalError:
        restore_authorized_keys(fs, plan)
        raise


def converge(program: Program, fs: Fs, entries: Sequence[Entry], *, check_mode: bool) -> Result:
    """Validate, plan and, unless in check mode, apply. An empty list is not declared."""
    if not entries:
        return Result(0, 0, 0, 0, changed=False)
    valid = validate_entries(program, entries)
    plan = make_plan(program, fs, valid)
    if plan.changed and not check_mode:
        apply_plan(program, fs, valid, plan)
    return Result(
        len(plan.granted), len(plan.rotated), len(plan.revoked), len(plan.unchanged), plan.changed
    )


def converge_reporting(
    program: Program, fs: Fs, entries: Sequence[Entry], *, check_mode: bool
) -> Result:
    """Converge, and turn a filesystem error into a rule name.

    An OSError names the path it failed on, and a register file's path holds a stack name.

    Raises:
        HostRefusalError: for a filesystem error, named by its code only.
    """
    try:
        return converge(program, fs, entries, check_mode=check_mode)
    except OSError as error:
        code = errno.errorcode.get(error.errno or 0, "unknown")
        raise HostRefusalError(f"filesystem-error-{code}") from None
    except UnicodeDecodeError:
        raise HostRefusalError("filesystem-error-undecodable") from None


def run(entries: Sequence[Entry], *, program_path: str, check_mode: bool) -> Result:
    """Load the installed program and converge the host it is on."""
    program = load_program(read_trusted_program(program_path), program_path)
    return converge_reporting(program, program._RealFs(), entries, check_mode=check_mode)


def _text(values: Mapping[str, object], key: str) -> str:
    """Return ``values[key]`` as a string.

    Raises:
        WrongTypeError: when the value is not a string.
    """
    value = values[key]
    if not isinstance(value, str):
        raise WrongTypeError(key, "a string")
    return value


def entries_from_params(values: object) -> list[Entry]:
    """Build the typed entries from the list AnsibleModule validated.

    Raises:
        WrongTypeError: when the list or an entry is not the type the argument_spec states.
    """
    if not isinstance(values, list):
        raise WrongTypeError("slots", "a list")
    found: list[Entry] = []
    for item in values:
        if not isinstance(item, dict):
            raise WrongTypeError("slots", "a list of mappings")
        mapping = {str(name): value for name, value in item.items()}
        adopt = mapping.get("adopt_existing", False)
        if not isinstance(adopt, bool):
            raise WrongTypeError("adopt_existing", "a boolean")
        found.append(Entry(_text(mapping, "stack"), _text(mapping, "public_key"), adopt))
    return found


ARGUMENT_SPEC: dict[str, dict[str, object]] = {
    "slots": {
        "type": "list",
        "elements": "dict",
        "required": True,
        "options": {
            "stack": {"type": "str", "required": True},
            "public_key": {"type": "str", "required": True, "no_log": True},
            "adopt_existing": {"type": "bool", "default": False},
        },
    },
    "program_path": {"type": "path", "required": True},
}


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    try:
        entries = entries_from_params(module.params["slots"])
        result = run(
            entries, program_path=str(module.params["program_path"]), check_mode=module.check_mode
        )
    except SlotRefusalError as error:
        module.fail_json(msg=str(error))
    else:
        module.exit_json(
            changed=result.changed,
            granted=result.granted,
            rotated=result.rotated,
            revoked=result.revoked,
            unchanged=result.unchanged,
        )


if __name__ == "__main__":
    main()
