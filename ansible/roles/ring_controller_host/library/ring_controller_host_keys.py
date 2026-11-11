#!/usr/bin/python
"""Make the ring controller's two OpenSSH keys on the host, once, and never again.

The controller signs its ledger with one Ed25519 key and pushes the signed ledger with a second,
separate Ed25519 key. This module makes both pairs with `ssh-keygen` (the tool that will sign and
verify) the first time, and never replaces or rewrites an existing private key. Beside each
private key it writes the matching public file, derived from the private key by `ssh-keygen -y`,
and returns each public line and its SHA256 fingerprint so the apply can print them. A public
half is not a secret; the private half is.

The private key is never read by this process. Only `ssh-keygen` opens it, with a cleared
environment, no terminal and its standard error discarded, so no byte of it can reach a return
value, a message, an argument or an exception. A refusal is a fixed code and a path, nothing
else, so the module can be shown although the task that calls it is hidden.
"""

import base64
import dataclasses
import errno
import grp
import hashlib
import os
import pwd
import re
import secrets
import stat
import subprocess  # noqa: S404 - the one call is ssh-keygen, by argv, never a shell
from collections.abc import Callable

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: ring_controller_host_keys
short_description: Generate the ring controller's ledger-signing key and push key if absent
description:
  - Makes the key directory, and in it two Ed25519 OpenSSH key pairs, `ledger-signing` and
    `push`, each with a `.pub` file.
  - Generates a pair only when its private key is absent. An existing private key is never
    replaced and its bytes are never rewritten. A valid key with another owner or a narrower
    mode is adopted, which changes the owner and mode only.
  - A public file with no private key beside it is refused, because replacing a key that others
    trust is the owner's act.
  - Never reads a private key itself. `ssh-keygen` does, and its output is not shown.
version_added: "1.0.0"
author:
  - branchLeft
options:
  directory:
    description: >-
      Absolute path of the directory that holds both pairs. Its parent must exist, be a real
      directory owned by root and not writable by group or others. The module makes this
      directory only.
    type: str
    required: true
  owner:
    description: The account that owns the directory and every file in it.
    type: str
    required: true
  group:
    description: The group that owns the directory and every file in it.
    type: str
    required: true
  ssh_keygen:
    description: >-
      Absolute path of the `ssh-keygen` binary. It must be a regular file owned by root and not
      writable by group or others.
    type: str
    required: true
attributes:
  check_mode:
    support: full
    description: Computes the same plan and writes nothing.
  diff_mode:
    support: none
    description: No diff is produced, so nothing about a key can appear in one.
"""

EXAMPLES = r"""
- name: Make the ring controller's keys if they are absent
  ring_controller_host_keys:
    directory: /etc/branchleft/ring-controller/keys
    owner: ring-controller
    group: ring-controller
    ssh_keygen: /usr/bin/ssh-keygen
  register: ring_controller_host_keys_result
  no_log: true
  diff: false
"""

RETURN = r"""
changed:
  description: True when anything was created, adopted, rewritten or cleaned (or would be).
  returned: always
  type: bool
created:
  description: The names of the pairs generated (or that would be).
  returned: success
  type: list
  elements: str
adopted:
  description: The names whose key or the directory had its owner or mode set.
  returned: success
  type: list
  elements: str
public_changed:
  description: The names whose public file was written because it was missing or different.
  returned: success
  type: list
  elements: str
temp_cleaned:
  description: How many leftover temporary files of an earlier interrupted run were removed.
  returned: success
  type: int
ledger_signing_public:
  description: The public line of the ledger-signing key. Not a secret. Null before it exists.
  returned: success
  type: str
ledger_signing_fingerprint:
  description: The SHA256 fingerprint of the ledger-signing public half.
  returned: success
  type: str
push_public:
  description: The public line of the push key. Not a secret. Null before it exists.
  returned: success
  type: str
push_fingerprint:
  description: The SHA256 fingerprint of the push public half.
  returned: success
  type: str
"""

# The names, comments and modes the role and the controller agree on. The role's vars/main.yml
# holds the same values; the unit test holds the two copies equal.
LEDGER_NAME = "ledger-signing"
PUSH_NAME = "push"
LEDGER_COMMENT = "ring-controller-ledger-signing"
PUSH_COMMENT = "ring-controller-ledger-push"
DIR_MODE = 0o700
KEY_MODE = 0o600
PUB_MODE = 0o644
KEY_TYPE = "ssh-ed25519"
# An OpenSSH Ed25519 private key is a few hundred bytes. Anything much bigger is not opened.
MAX_KEY_FILE_BYTES = 4096
MAX_PUB_FILE_BYTES = 512
KEYGEN_TIMEOUT_SECONDS = 30
TEMP_NAME = re.compile(r"\.(ledger-signing|push)\.tmp-[0-9a-f]{16}(\.pub)?\Z")
ACCOUNT_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
ROOT_UID = 0
# The environment ssh-keygen runs with: nothing that a caller or the host could steer it by.
KEYGEN_ENV = {"LC_ALL": "C"}

# The refusal codes. A refusal is one of these and a path, so no code can carry a value.
E_ARGS = "E-ARGS"
E_OWNER = "E-OWNER-UNKNOWN"
E_PARENT = "E-PARENT"
E_DIR = "E-DIR"
E_FOREIGN = "E-DIR-FOREIGN"
E_TEMP = "E-TEMP-NOT-A-FILE"
E_KEYGEN_BIN = "E-KEYGEN-BINARY"
E_KEYGEN = "E-KEYGEN"
E_KEY_OPEN = "E-KEY-OPEN"
E_KEY_TYPE = "E-KEY-NOT-REGULAR"
E_KEY_LINKS = "E-KEY-LINKED"
E_KEY_SIZE = "E-KEY-SIZE"
E_KEY_MODE = "E-KEY-MODE-WIDE"
E_KEY_FORM = "E-KEY-FORM"
E_KEY_LOST = "E-KEY-LOST"
E_PUB = "E-PUB"
E_IO = "E-IO"
E_INTERNAL = "E-INTERNAL"


class RefusalError(Exception):
    """A stop with a fixed code and the path it concerns. It never holds a value."""

    def __init__(self, code: str, path: str) -> None:
        """Hold the code and the path, and no other text."""
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


@dataclasses.dataclass(frozen=True)
class KeySpec:
    """One key pair the module makes: the file name and the comment its public line carries."""

    name: str
    comment: str

    @property
    def pub_name(self) -> str:
        """The name of the public file."""
        return self.name + ".pub"


SPECS = (KeySpec(LEDGER_NAME, LEDGER_COMMENT), KeySpec(PUSH_NAME, PUSH_COMMENT))


def _nothing() -> None:
    """Do nothing; the default for the test hooks."""


@dataclasses.dataclass
class Seams:
    """The few things a test replaces: the trusted owners, chown, random source and two hooks."""

    trusted_uids: frozenset[int] = frozenset((ROOT_UID,))
    chown: Callable[[int, int, int], None] = os.fchown
    random_hex: Callable[[int], str] = secrets.token_hex
    after_temp_write: Callable[[], None] = _nothing
    before_link: Callable[[], None] = _nothing


@dataclasses.dataclass(frozen=True)
class Settings:
    """The directory, the account that owns it and every file, and the ssh-keygen binary."""

    directory: str
    uid: int
    gid: int
    ssh_keygen: str


@dataclasses.dataclass
class Outcome:
    """What a run did to one pair, or would do in check mode. It holds no private bytes."""

    created: bool = False
    adopted: bool = False
    public_changed: bool = False
    public: str | None = None
    fingerprint: str | None = None


@dataclasses.dataclass
class Result:
    """What a run did, or would do in check mode."""

    directory_created: bool = False
    directory_adopted: bool = False
    temp_cleaned: int = 0
    outcomes: dict[str, Outcome] = dataclasses.field(default_factory=dict)

    @property
    def changed(self) -> bool:
        """Whether anything was or would be written."""
        return (
            self.directory_created
            or self.directory_adopted
            or self.temp_cleaned > 0
            or any(o.created or o.adopted or o.public_changed for o in self.outcomes.values())
        )


@dataclasses.dataclass(frozen=True)
class KeyFacts:
    """What was learned from a valid private key: its public blob, owner and mode. Not the key."""

    blob: str
    uid: int
    gid: int
    mode: int


def _join(settings: Settings, name: str) -> str:
    """Return the path of a file in the directory, for a refusal."""
    return os.path.join(settings.directory, name)


def public_text(spec: KeySpec, blob: str) -> str:
    """Return the text of a public file: the type, the base64 blob, the fixed comment, a newline."""
    return f"{KEY_TYPE} {blob} {spec.comment}\n"


def fingerprint(blob: str) -> str:
    """Return the OpenSSH SHA256 fingerprint of a public blob."""
    digest = hashlib.sha256(base64.b64decode(blob)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def parse_public(line: str) -> str | None:
    """Return the base64 blob of an ssh-ed25519 public line, or None when it is not one."""
    fields = line.split()
    if len(fields) < 2 or fields[0] != KEY_TYPE:
        return None
    try:
        raw = base64.b64decode(fields[1], validate=True)
    except ValueError:
        return None
    if len(raw) > 128 or raw[4 : 4 + len(KEY_TYPE)] != KEY_TYPE.encode("ascii"):
        return None
    return fields[1]


def check_binary(settings: Settings, seams: Seams) -> None:
    """Refuse unless ssh-keygen is a regular file that only root can change.

    Raises:
        RefusalError: when it is missing, a link, not root's or writable by group or others.
    """
    try:
        info = os.lstat(settings.ssh_keygen)
    except OSError as error:
        raise RefusalError(E_KEYGEN_BIN, settings.ssh_keygen) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in seams.trusted_uids
        or info.st_mode & 0o022
    ):
        raise RefusalError(E_KEYGEN_BIN, settings.ssh_keygen)


def check_parent(settings: Settings, seams: Seams) -> None:
    """Refuse unless the directory's parent is a real directory that only root can change.

    Raises:
        RefusalError: when the parent is missing, is a link, is not root's or is writable.
    """
    parent = os.path.dirname(settings.directory)
    try:
        info = os.lstat(parent)
    except OSError as error:
        raise RefusalError(E_PARENT, parent) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in seams.trusted_uids
        or info.st_mode & 0o022
    ):
        raise RefusalError(E_PARENT, parent)


def _run_keygen(settings: Settings, argv: list[str]) -> bytes | None:
    """Run ssh-keygen by argv and return its standard output, or None when it fails.

    No shell, an empty environment, no terminal, no standard input and no standard error: what
    ssh-keygen says about a key is never kept, so it cannot be shown.
    """
    try:
        done = subprocess.run(  # noqa: S603 - argv list, absolute path checked by check_binary
            [settings.ssh_keygen, *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=KEYGEN_ENV,
            timeout=KEYGEN_TIMEOUT_SECONDS,
            check=False,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _derive_blob(settings: Settings, path: str) -> str | None:
    """Return the public blob ssh-keygen derives from the private key at path, or None."""
    out = _run_keygen(settings, ["-y", "-f", path])
    if out is None or len(out) > MAX_PUB_FILE_BYTES:
        return None
    try:
        return parse_public(out.decode("ascii"))
    except UnicodeDecodeError:
        return None


def _open_directory(path: str) -> int:
    """Open the directory itself, refusing a link in its place.

    Raises:
        RefusalError: when the path is not a directory that can be opened.
    """
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise RefusalError(E_DIR, path) from error


def _make_directory(
    settings: Settings, seams: Seams, check_mode: bool, result: Result
) -> int | None:
    """Return a descriptor for the directory, making it when absent (None: absent, check mode).

    Raises:
        RefusalError: when the directory cannot be made or opened.
    """
    try:
        os.lstat(settings.directory)
    except FileNotFoundError:
        result.directory_created = True
        if check_mode:
            return None
        try:
            os.mkdir(settings.directory, DIR_MODE)
        except OSError as error:
            raise RefusalError(E_DIR, settings.directory) from error
        fd = _open_directory(settings.directory)
        # Made by this run, so setting its owner is making it, not adopting it.
        seams.chown(fd, settings.uid, settings.gid)
        os.fchmod(fd, DIR_MODE)
        return fd
    except OSError as error:
        raise RefusalError(E_DIR, settings.directory) from error
    return _open_directory(settings.directory)


def _list_directory(settings: Settings, dfd: int) -> list[str]:
    """Return the leftover temporary files, refusing a name that is not ours.

    Raises:
        RefusalError: for a foreign name, or a temporary name that is not a regular file.
    """
    ours = {name for spec in SPECS for name in (spec.name, spec.pub_name)}
    temps: list[str] = []
    for name in sorted(os.listdir(dfd)):
        if name in ours:
            continue
        if not TEMP_NAME.fullmatch(name):
            raise RefusalError(E_FOREIGN, _join(settings, name))
        info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise RefusalError(E_TEMP, _join(settings, name))
        temps.append(name)
    return temps


def _judge_key(settings: Settings, fd: int, spec: KeySpec) -> KeyFacts:
    """Judge an open private key by its descriptor and return what is learned from it.

    Raises:
        RefusalError: when it is not a lone regular file of a narrow mode that is an ed25519 key.
    """
    path = _join(settings, spec.name)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise RefusalError(E_KEY_TYPE, path)
    if info.st_nlink != 1:
        raise RefusalError(E_KEY_LINKS, path)
    if info.st_size > MAX_KEY_FILE_BYTES:
        raise RefusalError(E_KEY_SIZE, path)
    # A key readable by anyone else may already be known to them. It is refused before
    # ssh-keygen opens it, so a wide key is never even looked at.
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RefusalError(E_KEY_MODE, path)
    blob = _derive_blob(settings, path)
    if blob is None:
        raise RefusalError(E_KEY_FORM, path)
    return KeyFacts(blob, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def _inspect_key(settings: Settings, dfd: int, spec: KeySpec) -> tuple[int, KeyFacts] | None:
    """Open and judge the private key. Return its descriptor and facts, or None when absent.

    Raises:
        RefusalError: when the key cannot be opened, is not valid, or has lost its private half.
    """
    path = _join(settings, spec.name)
    try:
        # O_NONBLOCK so that a pipe put in the key's place cannot hang the open.
        fd = os.open(
            spec.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=dfd,
        )
    except FileNotFoundError:
        try:
            os.stat(spec.pub_name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        # A public half with no private half: the key was lost or removed. Making a new one
        # would change what others trust, which is the owner's act, not this role's.
        raise RefusalError(E_KEY_LOST, path) from None
    except OSError as error:
        raise RefusalError(E_KEY_OPEN, path) from error
    try:
        facts = _judge_key(settings, fd, spec)
    except BaseException:
        os.close(fd)
        raise
    return fd, facts


def _write_public_file(
    settings: Settings, seams: Seams, dfd: int, spec: KeySpec, blob: str
) -> None:
    """Write the public file through a temporary name and rename it into place.

    Raises:
        RefusalError: when the name is held by something a rename cannot replace.
    """
    temp = f".{spec.name}.tmp-{seams.random_hex(8)}.pub"
    fd = os.open(
        temp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        PUB_MODE,
        dir_fd=dfd,
    )
    try:
        seams.chown(fd, settings.uid, settings.gid)
        os.fchmod(fd, PUB_MODE)
        view = memoryview(public_text(spec, blob).encode("ascii"))
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.rename(temp, spec.pub_name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except OSError as error:
        os.unlink(temp, dir_fd=dfd)
        raise RefusalError(E_PUB, _join(settings, spec.pub_name)) from error


def _public_is_current(settings: Settings, dfd: int, spec: KeySpec, blob: str) -> bool:
    """Whether the public file holds the wanted text with the wanted owner and mode.

    Raises:
        RefusalError: when the public name is held by something that is not a regular file.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(spec.pub_name, flags, dir_fd=dfd)
    except FileNotFoundError:
        return False
    except OSError:
        # A link in its place: the rename that follows replaces the link itself.
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RefusalError(E_PUB, _join(settings, spec.pub_name))
        if info.st_size > MAX_PUB_FILE_BYTES:
            return False
        same_owner = info.st_uid == settings.uid and info.st_gid == settings.gid
        same_mode = stat.S_IMODE(info.st_mode) == PUB_MODE
        text = os.read(fd, MAX_PUB_FILE_BYTES + 1)
    finally:
        os.close(fd)
    return same_owner and same_mode and text == public_text(spec, blob).encode("ascii")


def _create_key(settings: Settings, seams: Seams, dfd: int, spec: KeySpec) -> str | None:
    """Generate the pair and publish the private key only if its name is still free.

    Returns the public blob, or None when another writer published first (the caller then
    judges that key as an existing one). ssh-keygen writes to a temporary name in the same
    directory; the private file is synced and hard-linked to its final name. A link fails if
    the name exists, so no existing key is replaced, and a crash leaves at worst temporary
    files, never part of a key at the final name.

    Raises:
        RefusalError: when ssh-keygen fails, or leaves something that is not a lone regular file.
    """
    temp = f".{spec.name}.tmp-{seams.random_hex(8)}"
    temp_path = _join(settings, temp)
    made = _run_keygen(
        settings,
        ["-q", "-t", "ed25519", "-N", "", "-C", spec.comment, "-f", temp_path],
    )
    try:
        if made is None:
            raise RefusalError(E_KEYGEN, temp_path)
        fd = os.open(temp, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RefusalError(E_KEYGEN, temp_path)
            seams.chown(fd, settings.uid, settings.gid)
            os.fchmod(fd, KEY_MODE)
            os.fsync(fd)
        finally:
            os.close(fd)
        seams.after_temp_write()
        seams.before_link()
        try:
            os.link(temp, spec.name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        except FileExistsError:
            return None
        blob = _derive_blob(settings, _join(settings, spec.name))
        if blob is None:
            raise RefusalError(E_KEY_FORM, _join(settings, spec.name))
        return blob
    finally:
        for leftover in (temp, temp + ".pub"):
            try:
                os.unlink(leftover, dir_fd=dfd)
            except FileNotFoundError:
                pass


def converge(settings: Settings, *, check_mode: bool, seams: Seams | None = None) -> Result:
    """Make the directory and the two pairs as described, or plan them.

    Every refusal about a key is raised before the first change except the creation of the
    directory itself, which is empty when made and so cannot have anything to refuse.
    """
    seams = seams or Seams()
    result = Result()
    check_binary(settings, seams)
    check_parent(settings, seams)
    dfd = _make_directory(settings, seams, check_mode, result)
    if dfd is None:
        # Check mode, directory absent: both pairs would be made as well.
        for spec in SPECS:
            result.outcomes[spec.name] = Outcome(created=True, public_changed=True)
        return result
    try:
        _converge_in_directory(settings, seams, dfd, check_mode=check_mode, result=result)
    finally:
        os.close(dfd)
    return result


def _converge_in_directory(
    settings: Settings, seams: Seams, dfd: int, *, check_mode: bool, result: Result
) -> None:
    """Do the work inside the open directory.

    Raises:
        RefusalError: for anything at a key's or the directory's place that is not ours.
    """
    temps = _list_directory(settings, dfd)
    found: dict[str, tuple[int, KeyFacts] | None] = {}
    try:
        # Judge every key before changing anything, so one refusal leaves both pairs untouched.
        for spec in SPECS:
            found[spec.name] = _inspect_key(settings, dfd, spec)
        info = os.fstat(dfd)
        if (
            info.st_uid != settings.uid
            or info.st_gid != settings.gid
            or stat.S_IMODE(info.st_mode) != DIR_MODE
        ):
            result.directory_adopted = True
            if not check_mode:
                seams.chown(dfd, settings.uid, settings.gid)
                os.fchmod(dfd, DIR_MODE)
        result.temp_cleaned = len(temps)
        if not check_mode:
            for name in temps:
                os.unlink(name, dir_fd=dfd)
        for spec in SPECS:
            result.outcomes[spec.name] = _converge_key(
                settings, seams, dfd, spec, found[spec.name], check_mode=check_mode
            )
        if not check_mode and result.changed:
            os.fsync(dfd)
    finally:
        for entry in found.values():
            if entry is not None:
                os.close(entry[0])


def _converge_key(
    settings: Settings,
    seams: Seams,
    dfd: int,
    spec: KeySpec,
    entry: tuple[int, KeyFacts] | None,
    *,
    check_mode: bool,
) -> Outcome:
    """Bring one pair to the wanted state, or plan it.

    Raises:
        RefusalError: when the pair is in a state the module will not make good.
    """
    outcome = Outcome()
    blob: str | None = None
    facts = entry[1] if entry else None
    if entry is None:
        outcome.created = True
        if not check_mode:
            blob = _create_key(settings, seams, dfd, spec)
            if blob is None:
                # Another writer published between our look and our link. Its key stands.
                again = _inspect_key(settings, dfd, spec)
                if again is None:
                    raise RefusalError(E_KEY_OPEN, _join(settings, spec.name))
                os.close(again[0])
                facts = again[1]
                outcome.created = False
                blob = facts.blob
    if facts is not None:
        blob = facts.blob
        if facts.uid != settings.uid or facts.gid != settings.gid or facts.mode != KEY_MODE:
            outcome.adopted = True
            if not check_mode:
                _adopt_key(settings, seams, dfd, spec)
    if blob is None:
        # Check mode with the key absent: nothing to compare.
        outcome.public_changed = outcome.created
        return outcome
    outcome.public = public_text(spec, blob).rstrip("\n")
    outcome.fingerprint = fingerprint(blob)
    if not _public_is_current(settings, dfd, spec, blob):
        outcome.public_changed = True
        if not check_mode:
            _write_public_file(settings, seams, dfd, spec, blob)
    return outcome


def _adopt_key(settings: Settings, seams: Seams, dfd: int, spec: KeySpec) -> None:
    """Set the owner and mode of an existing valid key through its open descriptor."""
    fd = os.open(
        spec.name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=dfd,
    )
    try:
        seams.chown(fd, settings.uid, settings.gid)
        os.fchmod(fd, KEY_MODE)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------------------------
# The Ansible entry point.
# ---------------------------------------------------------------------------------------------
ARGUMENT_SPEC = {
    "directory": {"type": "str", "required": True},
    "owner": {"type": "str", "required": True},
    "group": {"type": "str", "required": True},
    "ssh_keygen": {"type": "str", "required": True},
}


def _normal_absolute(path: str) -> bool:
    """Whether a path is absolute, normal and not the root."""
    return os.path.isabs(path) and path == os.path.normpath(path) and path != "/"


def settings_from_params(directory: str, owner: str, group: str, ssh_keygen: str) -> Settings:
    """Check the arguments and resolve the account, or refuse.

    Raises:
        RefusalError: for a path that is not absolute and normal, a bad name, or an unknown account.
    """
    if not _normal_absolute(directory):
        raise RefusalError(E_ARGS, directory)
    if not _normal_absolute(ssh_keygen):
        raise RefusalError(E_ARGS, directory)
    if not ACCOUNT_NAME.fullmatch(owner) or not ACCOUNT_NAME.fullmatch(group):
        raise RefusalError(E_ARGS, directory)
    try:
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(group).gr_gid
    except KeyError as error:
        raise RefusalError(E_OWNER, directory) from error
    return Settings(directory, uid, gid, ssh_keygen)


def _facts(result: Result) -> dict[str, str | None]:
    """The public lines and fingerprints a run returns. None for a pair not yet made."""
    ledger = result.outcomes.get(LEDGER_NAME, Outcome())
    push = result.outcomes.get(PUSH_NAME, Outcome())
    return {
        "ledger_signing_public": ledger.public,
        "ledger_signing_fingerprint": ledger.fingerprint,
        "push_public": push.public,
        "push_fingerprint": push.fingerprint,
    }


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    try:
        settings = settings_from_params(
            str(module.params["directory"]),
            str(module.params["owner"]),
            str(module.params["group"]),
            str(module.params["ssh_keygen"]),
        )
        result = converge(settings, check_mode=module.check_mode)
    except RefusalError as refusal:
        module.fail_json(msg=str(refusal))
    except OSError as error:
        # The errno name only: a fixed code is all that is needed to find the cause in the code.
        module.fail_json(msg=f"{E_IO}: {errno.errorcode.get(error.errno or 0, 'UNKNOWN')}")
    except Exception as error:  # noqa: BLE001 - a traceback would show frames of the run
        module.fail_json(msg=f"{E_INTERNAL}: {type(error).__name__}")
    else:
        module.exit_json(
            changed=result.changed,
            created=sorted(n for n, o in result.outcomes.items() if o.created),
            adopted=sorted(
                [n for n, o in result.outcomes.items() if o.adopted]
                + (["directory"] if result.directory_adopted else [])
            ),
            public_changed=sorted(n for n, o in result.outcomes.items() if o.public_changed),
            temp_cleaned=result.temp_cleaned,
            **_facts(result),
        )


if __name__ == "__main__":
    main()
