#!/usr/bin/python
"""Make the safety service's request-signing key on the host, once, and never again.

The key is an Ed25519 seed: 32 random bytes, written as the base64 text of those bytes with no
newline, in a file the service reads. This module creates the file only when it is absent, in
a way that a crash cannot leave half a key at the final name, and never replaces or rewrites
an existing key. Beside it, it writes the matching public half, which is not a secret, and
returns that half so the apply can record it.

The seed is read in this process only to derive the public half. It is never returned, never
printed, never passed on a command line or in the environment, and never part of a refusal
text. A refusal is a fixed code and a path, nothing else, so the module can be shown even
though the task that calls it is hidden. The derivation is written out here (RFC 8032, section
5.1.5) so that the target host needs no library for it; the unit tests check it against the
RFC's own vectors and against the pinned `cryptography` package.
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
from collections.abc import Callable

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: safety_channel_key
short_description: Generate the safety service's request-signing key if it is absent
description:
  - Makes the directory, the key file and the public file the safety service signs its
    requests with. The key is the base64 text of 32 random bytes, with no newline.
  - Generates the key only when the key file is absent. An existing key is never replaced and
    its bytes are never rewritten. A key that is valid and has another owner or a narrower
    mode is adopted, which changes the owner and mode only.
  - Anything else at the key's path is refused, naming the path and nothing else.
  - Reads the key inside this process to derive the public half, and writes the public half
    to a second file. The seed never leaves the process.
version_added: "1.0.0"
author:
  - branchLeft
options:
  directory:
    description: >-
      Absolute path of the directory that holds both files. Its parent must exist, be a real
      directory owned by root and not writable by group or others. The module makes this
      directory only.
    type: str
    required: true
  owner:
    description: The account that owns the directory and both files.
    type: str
    required: true
  group:
    description: The group that owns the directory and both files.
    type: str
    required: true
attributes:
  check_mode:
    support: full
    description: Computes the same plan and writes nothing.
  diff_mode:
    support: none
    description: No diff is produced, so nothing about the key can appear in one.
"""

EXAMPLES = r"""
- name: Make the channel signing key if it is absent
  safety_channel_key:
    directory: /etc/branchleft/content-safety
    owner: root
    group: root
  register: channel_key_result
  no_log: true
  diff: false
"""

RETURN = r"""
changed:
  description: >-
    True when anything was created, adopted, rewritten or cleaned (or would be, in check mode).
  returned: always
  type: bool
created:
  description: True when the key was generated (or would be).
  returned: success
  type: bool
adopted:
  description: True when the directory or the key kept its content and had its owner or mode set.
  returned: success
  type: bool
public_changed:
  description: True when the public file was written because it was missing or different.
  returned: success
  type: bool
temp_cleaned:
  description: How many leftover temporary files of an earlier interrupted run were removed.
  returned: success
  type: int
public_key:
  description: >-
    The public half, base64 of 32 bytes. Not a secret. Null in check mode when the key is absent.
  returned: success
  type: str
"""

# The names and modes the service and the role agree on. The role's vars/main.yml holds the
# same values; the unit test holds the two copies equal.
KEY_NAME = "channel-signing.key"
PUB_NAME = "channel-signing.pub"
DIR_MODE = 0o700
KEY_MODE = 0o400
PUB_MODE = 0o444
SEED_BYTES = 32
# The base64 of 32 bytes is 44 characters. Anything much bigger is not read at all.
KEY_TEXT_BYTES = 44
MAX_KEY_FILE_BYTES = 64
MAX_PUB_FILE_BYTES = 256
# A temporary file is made in the same directory, so that the final link is on one file system.
KEY_TEMP_PREFIX = ".channel-signing.key.tmp-"
PUB_TEMP_PREFIX = ".channel-signing.pub.tmp-"
TEMP_NAME = re.compile(r"\.channel-signing\.(key|pub)\.tmp-[0-9a-f]{16}\Z")
ACCOUNT_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
ROOT_UID = 0

# The refusal codes. A refusal is one of these and a path, so no code can carry a value.
E_ARGS = "E-ARGS"
E_OWNER = "E-OWNER-UNKNOWN"
E_PARENT = "E-PARENT"
E_DIR = "E-DIR"
E_FOREIGN = "E-DIR-FOREIGN"
E_TEMP = "E-TEMP-NOT-A-FILE"
E_KEY_OPEN = "E-KEY-OPEN"
E_KEY_TYPE = "E-KEY-NOT-REGULAR"
E_KEY_LINKS = "E-KEY-LINKED"
E_KEY_SIZE = "E-KEY-SIZE"
E_KEY_FORM = "E-KEY-FORM"
E_KEY_MODE = "E-KEY-MODE-WIDE"
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


# ---------------------------------------------------------------------------------------------
# Ed25519 public half from a seed, RFC 8032 section 5.1.5. Pure Python, no dependency.
# Not constant-time: it runs once, on the host, as root, with no one timing it (README).
# ---------------------------------------------------------------------------------------------
P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]


def _recover_x(y: int, sign: int) -> int | None:
    """Return the x coordinate for y with the given low bit, or None when there is none."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _base_point() -> Point:
    """Return the standard base point in extended coordinates."""
    g_y = 4 * pow(5, P - 2, P) % P
    g_x = _recover_x(g_y, 0)
    assert g_x is not None  # noqa: S101 - the base point's y is a fixed constant with an x
    return (g_x, g_y, 1, g_x * g_y % P)


BASE: Point = _base_point()


def _point_add(a: Point, b: Point) -> Point:
    """Add two points in extended coordinates."""
    t1 = (a[1] - a[0]) * (b[1] - b[0]) % P
    t2 = (a[1] + a[0]) * (b[1] + b[0]) % P
    t3 = 2 * a[3] * b[3] * D % P
    t4 = 2 * a[2] * b[2] % P
    e, f, g, h = t2 - t1, t4 - t3, t4 + t3, t2 + t1
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar: int, point: Point) -> Point:
    """Multiply a point by a scalar, by double and add."""
    result: Point = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _compress(point: Point) -> bytes:
    """Encode a point as 32 bytes."""
    z_inv = pow(point[2], P - 2, P)
    x = point[0] * z_inv % P
    y = point[1] * z_inv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def derive_public(seed: bytes) -> bytes:
    """Return the 32-byte Ed25519 public half of a 32-byte seed."""
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _compress(_point_mul(scalar, BASE))


def decode_seed(data: bytes) -> bytes | None:
    """Return the 32 bytes a key file's text stands for, or None when it is not exactly that.

    The text must be the canonical base64 of exactly 32 bytes, with no whitespace and no
    newline: the service re-encodes what it decodes and refuses a text that differs.
    """
    if len(data) != KEY_TEXT_BYTES:
        return None
    try:
        raw = base64.b64decode(data, validate=True)
    except ValueError:
        return None
    if len(raw) != SEED_BYTES or base64.b64encode(raw) != data:
        return None
    return raw


# ---------------------------------------------------------------------------------------------
# The host. Everything below works through one open directory descriptor, so a path that is
# swapped for a link between a check and a use is not followed.
# ---------------------------------------------------------------------------------------------
def _nothing() -> None:
    """Do nothing; the default for the test hooks."""


@dataclasses.dataclass
class Seams:
    """The few things a test replaces: the root uid, the chown, the random source and two hooks."""

    root_uid: int = ROOT_UID
    chown: Callable[[int, int, int], None] = os.fchown
    random_bytes: Callable[[int], bytes] = secrets.token_bytes
    random_hex: Callable[[int], str] = secrets.token_hex
    after_temp_write: Callable[[], None] = _nothing
    before_link: Callable[[], None] = _nothing


@dataclasses.dataclass(frozen=True)
class Settings:
    """The directory and the account that owns it and both files."""

    directory: str
    uid: int
    gid: int


@dataclasses.dataclass
class Result:
    """What a run did, or would do in check mode. It holds no part of the seed."""

    created: bool = False
    adopted: bool = False
    public_changed: bool = False
    temp_cleaned: int = 0
    directory_created: bool = False
    public_key: str | None = None

    @property
    def changed(self) -> bool:
        """Whether anything was or would be written."""
        return (
            self.created
            or self.adopted
            or self.public_changed
            or self.temp_cleaned > 0
            or self.directory_created
        )


@dataclasses.dataclass(frozen=True)
class KeyFile:
    """What was learned from a valid key file: its public half, owner and mode. Not the seed."""

    public: bytes
    uid: int
    gid: int
    mode: int


def _join(settings: Settings, name: str) -> str:
    """Return the path of a file in the directory, for a refusal."""
    return os.path.join(settings.directory, name)


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
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != seams.root_uid or info.st_mode & 0o022:
        raise RefusalError(E_PARENT, parent)


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
    temps: list[str] = []
    for name in sorted(os.listdir(dfd)):
        if name in (KEY_NAME, PUB_NAME):
            continue
        if not TEMP_NAME.fullmatch(name):
            raise RefusalError(E_FOREIGN, _join(settings, name))
        info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise RefusalError(E_TEMP, _join(settings, name))
        temps.append(name)
    return temps


def _inspect_key(settings: Settings, dfd: int) -> tuple[int, KeyFile] | None:
    """Open and judge the key file. Return its descriptor and facts, or None when it is absent.

    The seed is read here and used for the public half only; it does not leave this function.

    Raises:
        RefusalError: when the key cannot be opened, or is not a valid key as described above.
    """
    path = _join(settings, KEY_NAME)
    try:
        # O_NONBLOCK so that a pipe put in the key's place cannot hang the open.
        fd = os.open(
            KEY_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=dfd,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RefusalError(E_KEY_OPEN, path) from error
    try:
        key = _judge_key(fd, path)
    except BaseException:
        os.close(fd)
        raise
    return fd, key


def _judge_key(fd: int, path: str) -> KeyFile:
    """Judge an open key file by its descriptor and return what is learned from it.

    Raises:
        RefusalError: when it is not a lone regular file of a narrow mode holding a valid key.
    """
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise RefusalError(E_KEY_TYPE, path)
    if info.st_nlink != 1:
        raise RefusalError(E_KEY_LINKS, path)
    if info.st_size > MAX_KEY_FILE_BYTES:
        raise RefusalError(E_KEY_SIZE, path)
    # A key readable by anyone else may already be known to them. It is refused before its
    # content is read, so a wide key is never even looked at.
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RefusalError(E_KEY_MODE, path)
    seed = decode_seed(os.read(fd, MAX_KEY_FILE_BYTES + 1))
    if seed is None:
        raise RefusalError(E_KEY_FORM, path)
    return KeyFile(derive_public(seed), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def _write_new_file(
    settings: Settings,
    seams: Seams,
    dfd: int,
    name: str,
    mode: int,
    data: bytes,
) -> None:
    """Make a new file in the directory, refusing an existing name or a link, and sync it."""
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=dfd,
    )
    try:
        seams.chown(fd, settings.uid, settings.gid)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_key(settings: Settings, seams: Seams, dfd: int) -> bytes | None:
    """Generate the key and publish it only if the name is still free.

    Returns the public half, or None when another writer published first (the caller then
    judges that key as an existing one). The key is written to a temporary file, synced, and
    hard-linked to its final name: link fails if the name exists, so no existing key is ever
    replaced, and a crash leaves at worst a temporary file, never a part of a key.
    """
    seed = seams.random_bytes(SEED_BYTES)
    public = derive_public(seed)
    temp = KEY_TEMP_PREFIX + seams.random_hex(8)
    _write_new_file(settings, seams, dfd, temp, KEY_MODE, base64.b64encode(seed))
    del seed
    seams.after_temp_write()
    try:
        seams.before_link()
        os.link(temp, KEY_NAME, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
    except FileExistsError:
        os.unlink(temp, dir_fd=dfd)
        return None
    os.unlink(temp, dir_fd=dfd)
    return public


def _write_public(settings: Settings, seams: Seams, dfd: int, public: bytes) -> None:
    """Write the public file through a temporary name and rename it into place.

    Raises:
        RefusalError: when the name is held by something a rename cannot replace.
    """
    temp = PUB_TEMP_PREFIX + seams.random_hex(8)
    _write_new_file(settings, seams, dfd, temp, PUB_MODE, public_text(public).encode("ascii"))
    try:
        os.rename(temp, PUB_NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
    except OSError as error:
        os.unlink(temp, dir_fd=dfd)
        raise RefusalError(E_PUB, _join(settings, PUB_NAME)) from error


def public_text(public: bytes) -> str:
    """Return the text of the public file: the base64 of the public half and a newline."""
    return base64.b64encode(public).decode("ascii") + "\n"


def _public_is_current(settings: Settings, dfd: int, public: bytes) -> bool:
    """Whether the public file holds the wanted text with the wanted owner and mode.

    Raises:
        RefusalError: when the public name is held by something that is not a regular file.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(PUB_NAME, flags, dir_fd=dfd)
    except FileNotFoundError:
        return False
    except OSError:
        # A link in its place: the rename that follows replaces the link itself.
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RefusalError(E_PUB, _join(settings, PUB_NAME))
        if info.st_size > MAX_PUB_FILE_BYTES:
            return False
        same_owner = info.st_uid == settings.uid and info.st_gid == settings.gid
        same_mode = stat.S_IMODE(info.st_mode) == PUB_MODE
        text = os.read(fd, MAX_PUB_FILE_BYTES + 1)
    finally:
        os.close(fd)
    return same_owner and same_mode and text == public_text(public).encode("ascii")


def converge(settings: Settings, *, check_mode: bool, seams: Seams | None = None) -> Result:
    """Make the directory, the key and the public file as described, or plan them.

    Every refusal is raised before the first change except the creation of the directory
    itself, which is empty when made and so cannot have anything to refuse.
    """
    seams = seams or Seams()
    result = Result()
    check_parent(settings, seams)
    dfd = _make_directory(settings, seams, check_mode, result)
    if dfd is None:
        # Check mode, directory absent: the key and the public file would be made as well.
        result.created = True
        result.public_changed = True
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
        RefusalError: for anything at the key's or the directory's place that is not ours.
    """
    temps = _list_directory(settings, dfd)
    found = _inspect_key(settings, dfd)
    key_fd = found[0] if found else None
    try:
        info = os.fstat(dfd)
        if (
            info.st_uid != settings.uid
            or info.st_gid != settings.gid
            or stat.S_IMODE(info.st_mode) != DIR_MODE
        ):
            result.adopted = True
            if not check_mode:
                seams.chown(dfd, settings.uid, settings.gid)
                os.fchmod(dfd, DIR_MODE)
        result.temp_cleaned = len(temps)
        if not check_mode:
            for name in temps:
                os.unlink(name, dir_fd=dfd)
        public: bytes | None = None
        if found is None:
            result.created = True
            if not check_mode:
                public = _create_key(settings, seams, dfd)
                if public is None:
                    # Another writer published between our look and our link. Its key stands.
                    found = _inspect_key(settings, dfd)
                    if found is None:
                        raise RefusalError(E_KEY_OPEN, _join(settings, KEY_NAME))
                    result.created = False
                    key_fd = found[0]
        if found is not None:
            public = found[1].public
            if (
                found[1].uid != settings.uid
                or found[1].gid != settings.gid
                or found[1].mode != KEY_MODE
            ):
                result.adopted = True
                if not check_mode and key_fd is not None:
                    seams.chown(key_fd, settings.uid, settings.gid)
                    os.fchmod(key_fd, KEY_MODE)
        if public is None:
            # Check mode with the key absent, or a key that vanished: nothing to compare.
            result.public_changed = result.created
            return
        result.public_key = base64.b64encode(public).decode("ascii")
        if not _public_is_current(settings, dfd, public):
            result.public_changed = True
            if not check_mode:
                _write_public(settings, seams, dfd, public)
        if not check_mode and result.changed:
            os.fsync(dfd)
    finally:
        if key_fd is not None:
            os.close(key_fd)


# ---------------------------------------------------------------------------------------------
# The Ansible entry point.
# ---------------------------------------------------------------------------------------------
ARGUMENT_SPEC = {
    "directory": {"type": "str", "required": True},
    "owner": {"type": "str", "required": True},
    "group": {"type": "str", "required": True},
}


def settings_from_params(directory: str, owner: str, group: str) -> Settings:
    """Check the arguments and resolve the account, or refuse.

    Raises:
        RefusalError: for a path that is not absolute and normal, a bad name, or an unknown account.
    """
    if not os.path.isabs(directory) or directory != os.path.normpath(directory) or directory == "/":
        raise RefusalError(E_ARGS, directory)
    if not ACCOUNT_NAME.fullmatch(owner) or not ACCOUNT_NAME.fullmatch(group):
        raise RefusalError(E_ARGS, directory)
    try:
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(group).gr_gid
    except KeyError as error:
        raise RefusalError(E_OWNER, directory) from error
    return Settings(directory, uid, gid)


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    try:
        settings = settings_from_params(
            str(module.params["directory"]),
            str(module.params["owner"]),
            str(module.params["group"]),
        )
        result = converge(settings, check_mode=module.check_mode)
    except RefusalError as refusal:
        module.fail_json(msg=str(refusal))
    except OSError as error:
        # The errno name only: the message of an OS error can name a path, never the seed,
        # but a fixed code is all that is needed to find the cause in the code.
        module.fail_json(msg=f"{E_IO}: {errno.errorcode.get(error.errno or 0, 'UNKNOWN')}")
    except Exception as error:  # noqa: BLE001 - a traceback would show frames that hold the seed
        module.fail_json(msg=f"{E_INTERNAL}: {type(error).__name__}")
    else:
        module.exit_json(
            changed=result.changed,
            created=result.created,
            adopted=result.adopted,
            public_changed=result.public_changed,
            temp_cleaned=result.temp_cleaned,
            public_key=result.public_key,
        )


if __name__ == "__main__":
    main()
