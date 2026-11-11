#!/usr/bin/python
"""Make the ring controller's record-signing key on the host, once, root-only, and never again.

The key is an Ed25519 private key in PKCS8 PEM form (what `node:crypto` reads), in a file that is
root's with mode 0400, in a directory that is root's with mode 0700. This module creates the file
only when it is absent, in a way that a crash cannot leave half a key at the final name and that
never gives the key a wider mode than 0400 at any moment, and never replaces or rewrites an
existing key. It derives the public half in this process and returns it as an SPKI PEM text, which
is not a secret, so the role can write it to a world-readable file and print it.

The private bytes are read or made in this process only. They are never returned, never printed,
never passed on a command line or in the environment, and never part of a refusal text. A refusal
is a fixed code and a path, nothing else, so the module can be shown although the task that calls
it is hidden. The public half is derived here (RFC 8032, section 5.1.5) so the target host needs no
library for it; the unit tests check the derivation against the RFC's own vectors and against the
pinned `cryptography` package.
"""

import base64
import dataclasses
import errno
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: ring_controller_host_record_key
short_description: Generate the ring controller's record-signing key if it is absent
description:
  - Makes the directory and the key file the ring controller signs its promotion records with.
    The key is an Ed25519 private key in PKCS8 PEM form, owned by root, mode 0400, in a root-only
    directory.
  - Generates the key only when the key file is absent. An existing key is never replaced and
    its bytes are never rewritten. A key with a narrower mode than 0400 is adopted, which sets the
    mode only. A key or directory that another account owns is refused.
  - Refuses to make a new key when the public file already exists and the key does not. A key
    that has gone is not made again, because a new key would change what others trust.
  - Anything else at the key's path is refused, naming the path and nothing else.
  - Reads the key inside this process to derive the public half and returns that half as an SPKI
    PEM text. The private bytes never leave the process.
version_added: "1.0.0"
author:
  - branchLeft
options:
  directory:
    description: >-
      Absolute path of the directory that holds the key. Its parent must exist, be a real
      directory owned by root and not writable by group or others. The module makes this
      directory only.
    type: str
    required: true
  public_file:
    description: >-
      Absolute path of the world-readable file the role writes the public half to. The module
      never writes it. It only refuses to make a new key while this file exists and the key does
      not.
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
- name: Make the record-signing key if it is absent
  ring_controller_host_record_key:
    directory: /etc/branchleft/ring-controller/record-signing
    public_file: /etc/branchleft/ring-controller/record-signing.pub
  register: record_key_result
  no_log: true
  diff: false
"""

RETURN = r"""
changed:
  description: >-
    True when anything was created, adopted or cleaned (or would be, in check mode).
  returned: always
  type: bool
created:
  description: True when the key was generated (or would be).
  returned: success
  type: bool
adopted:
  description: True when the directory or the key kept its content and had its mode set.
  returned: success
  type: bool
temp_cleaned:
  description: How many leftover temporary files of an earlier interrupted run were removed.
  returned: success
  type: int
public_key:
  description: >-
    The public half as an SPKI PEM text. Not a secret. Null in check mode when the key is absent.
  returned: success
  type: str
"""

# The names and modes the role and the module agree on. The role's vars/main.yml holds the same
# values; a unit test holds the two copies equal.
KEY_NAME = "record-signing.key"
DIR_MODE = 0o700
KEY_MODE = 0o400
SEED_BYTES = 32
# PKCS8 PrivateKeyInfo for Ed25519 (RFC 8410): the fixed bytes that precede the 32-byte seed.
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
# SubjectPublicKeyInfo for Ed25519: the fixed bytes that precede the 32-byte public key.
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
PRIVATE_HEADER = b"-----BEGIN PRIVATE KEY-----\n"
PRIVATE_FOOTER = b"\n-----END PRIVATE KEY-----\n"
PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----\n"
PUBLIC_FOOTER = "\n-----END PUBLIC KEY-----\n"
MAX_KEY_FILE_BYTES = 256
# A temporary file is made in the same directory, so that the final link is on one file system.
KEY_TEMP_PREFIX = ".record-signing.key.tmp-"
TEMP_NAME = re.compile(r"\.record-signing\.key\.tmp-[0-9a-f]{16}\Z")
ROOT_UID = 0

# The refusal codes. A refusal is one of these and a path, so no code can carry a value.
E_ARGS = "E-ARGS"
E_NOT_ROOT = "E-NOT-ROOT"
E_PARENT = "E-PARENT"
E_DIR = "E-DIR"
E_DIR_OWNER = "E-DIR-OWNER"
E_FOREIGN = "E-DIR-FOREIGN"
E_TEMP = "E-TEMP-NOT-A-FILE"
E_KEY_OPEN = "E-KEY-OPEN"
E_KEY_TYPE = "E-KEY-NOT-REGULAR"
E_KEY_LINKS = "E-KEY-LINKED"
E_KEY_SIZE = "E-KEY-SIZE"
E_KEY_FORM = "E-KEY-FORM"
E_KEY_MODE = "E-KEY-MODE-WIDE"
E_KEY_OWNER = "E-KEY-OWNER"
E_KEY_LOST = "E-KEY-LOST"
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


def private_pem(seed: bytes) -> bytes:
    """Return the PKCS8 PEM text of the key with this seed: one 64-character line."""
    return PRIVATE_HEADER + base64.b64encode(PKCS8_PREFIX + seed) + PRIVATE_FOOTER


def public_pem(public: bytes) -> str:
    """Return the SPKI PEM text of a public half: one 60-character line."""
    body = base64.b64encode(SPKI_PREFIX + public).decode("ascii")
    return PUBLIC_HEADER + body + PUBLIC_FOOTER


def decode_seed(data: bytes) -> bytes | None:
    """Return the 32-byte seed a key file's text stands for, or None when it is not exactly that.

    The text must be the canonical PKCS8 PEM of an Ed25519 key: the module re-makes the text from
    the seed it found and refuses any difference (another header, a second line, trailing text,
    a non-canonical base64 tail, another algorithm).
    """
    if len(data) != len(private_pem(bytes(SEED_BYTES))):
        return None
    if not data.startswith(PRIVATE_HEADER) or not data.endswith(PRIVATE_FOOTER):
        return None
    body = data[len(PRIVATE_HEADER) : -len(PRIVATE_FOOTER)]
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError:
        return None
    if not der.startswith(PKCS8_PREFIX):
        return None
    seed = der[len(PKCS8_PREFIX) :]
    if len(seed) != SEED_BYTES or private_pem(seed) != data:
        return None
    return seed


# ---------------------------------------------------------------------------------------------
# The host. Everything below works through one open directory descriptor, so a path that is
# swapped for a link between a check and a use is not followed.
# ---------------------------------------------------------------------------------------------
def _nothing() -> None:
    """Do nothing; the default for the test hooks."""


@dataclasses.dataclass
class Seams:
    """The few things a test replaces: the root uid, the running uid, the random source, hooks."""

    root_uid: int = ROOT_UID
    effective_uid: Callable[[], int] = os.geteuid
    random_bytes: Callable[[int], bytes] = secrets.token_bytes
    random_hex: Callable[[int], str] = secrets.token_hex
    after_temp_write: Callable[[], None] = _nothing
    before_link: Callable[[], None] = _nothing


@dataclasses.dataclass(frozen=True)
class Settings:
    """The directory that holds the key, and the path of the public file that goes with it."""

    directory: str
    public_file: str


@dataclasses.dataclass
class Result:
    """What a run did, or would do in check mode. It holds no part of the private key."""

    created: bool = False
    adopted: bool = False
    temp_cleaned: int = 0
    directory_created: bool = False
    public_key: str | None = None

    @property
    def changed(self) -> bool:
        """Whether anything was or would be written."""
        return self.created or self.adopted or self.temp_cleaned > 0 or self.directory_created


@dataclasses.dataclass(frozen=True)
class KeyFile:
    """What was learned from a valid key file: its public half and mode. Not the private bytes."""

    public: bytes
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


def _exists(path: str) -> bool:
    """Whether anything, a link included, is at the path.

    Raises:
        RefusalError: when the path cannot be looked at for a reason other than its absence.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RefusalError(E_IO, path) from error
    return True


def _open_directory(path: str) -> int:
    """Open the directory itself, refusing a link in its place.

    Raises:
        RefusalError: when the path is not a directory that can be opened.
    """
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise RefusalError(E_DIR, path) from error


def _make_directory(settings: Settings, check_mode: bool, result: Result) -> int | None:
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
            # Made with the narrow mode at once, so it is never wider than 0700 at any moment.
            os.mkdir(settings.directory, DIR_MODE)
        except OSError as error:
            raise RefusalError(E_DIR, settings.directory) from error
        fd = _open_directory(settings.directory)
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
        if name == KEY_NAME:
            continue
        if not TEMP_NAME.fullmatch(name):
            raise RefusalError(E_FOREIGN, _join(settings, name))
        info = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise RefusalError(E_TEMP, _join(settings, name))
        temps.append(name)
    return temps


def _inspect_key(settings: Settings, seams: Seams, dfd: int) -> tuple[int, KeyFile] | None:
    """Open and judge the key file. Return its descriptor and facts, or None when it is absent.

    The private bytes are read here and used for the public half only; they do not leave it.

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
        key = judge_key(fd, path, seams)
    except BaseException:
        os.close(fd)
        raise
    return fd, key


def judge_key(fd: int, path: str, seams: Seams) -> KeyFile:
    """Judge an open key file by its descriptor and return what is learned from it.

    Raises:
        RefusalError: when it is not a lone regular root-owned file of a narrow mode holding a
            valid key.
    """
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise RefusalError(E_KEY_TYPE, path)
    if info.st_nlink != 1:
        raise RefusalError(E_KEY_LINKS, path)
    if info.st_size > MAX_KEY_FILE_BYTES:
        raise RefusalError(E_KEY_SIZE, path)
    # A key another account owns, or one it can read, may already be known to it. Both are
    # refused before the content is read, so such a key is never even looked at.
    if info.st_uid != seams.root_uid:
        raise RefusalError(E_KEY_OWNER, path)
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RefusalError(E_KEY_MODE, path)
    seed = decode_seed(os.read(fd, MAX_KEY_FILE_BYTES + 1))
    if seed is None:
        raise RefusalError(E_KEY_FORM, path)
    return KeyFile(derive_public(seed), stat.S_IMODE(info.st_mode))


def _write_new_file(dfd: int, name: str, mode: int, data: bytes) -> None:
    """Make a new file in the directory, refusing an existing name or a link, and sync it.

    The file is created with its final mode, so it is never readable by anyone else for even a
    moment, and its content is written through the descriptor that created it.
    """
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=dfd,
    )
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_key(seams: Seams, dfd: int) -> bytes | None:
    """Generate the key and publish it only if the name is still free.

    Returns the public half, or None when another writer published first (the caller then
    judges that key as an existing one). The key is written to a temporary file, synced, and
    hard-linked to its final name: link fails if the name exists, so no existing key is ever
    replaced, and a crash leaves at worst a temporary file, never a part of a key.
    """
    seed = seams.random_bytes(SEED_BYTES)
    public = derive_public(seed)
    temp = KEY_TEMP_PREFIX + seams.random_hex(8)
    _write_new_file(dfd, temp, KEY_MODE, private_pem(seed))
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


def converge(settings: Settings, *, check_mode: bool, seams: Seams | None = None) -> Result:
    """Make the directory and the key as described, or plan them.

    Every refusal is raised before the first change except the creation of the directory
    itself, which is empty when made and so cannot have anything to refuse.

    Raises:
        RefusalError: when the module is not running as root, or for anything that is not ours.
    """
    seams = seams or Seams()
    result = Result()
    if seams.effective_uid() != seams.root_uid:
        raise RefusalError(E_NOT_ROOT, settings.directory)
    check_parent(settings, seams)
    if _exists(settings.public_file) and not _exists(settings.directory):
        # The key's whole directory has gone while its public half is still there.
        raise RefusalError(E_KEY_LOST, settings.public_file)
    dfd = _make_directory(settings, check_mode, result)
    if dfd is None:
        # Check mode, directory absent: the key would be made as well.
        result.created = True
        return result
    try:
        converge_in_directory(settings, seams, dfd, check_mode=check_mode, result=result)
    finally:
        os.close(dfd)
    return result


def converge_in_directory(
    settings: Settings, seams: Seams, dfd: int, *, check_mode: bool, result: Result
) -> None:
    """Do the work inside the open directory.

    Raises:
        RefusalError: for anything at the key's or the directory's place that is not ours.
    """
    info = os.fstat(dfd)
    if info.st_uid != seams.root_uid:
        raise RefusalError(E_DIR_OWNER, settings.directory)
    temps = _list_directory(settings, dfd)
    found = _inspect_key(settings, seams, dfd)
    key_fd = found[0] if found else None
    try:
        if found is None and _exists(settings.public_file):
            # A key that has gone is never made again: a new one would change what others trust.
            raise RefusalError(E_KEY_LOST, settings.public_file)
        if stat.S_IMODE(info.st_mode) != DIR_MODE:
            result.adopted = True
            if not check_mode:
                os.fchmod(dfd, DIR_MODE)
        result.temp_cleaned = len(temps)
        if not check_mode:
            for name in temps:
                os.unlink(name, dir_fd=dfd)
        public: bytes | None = None
        if found is None:
            result.created = True
            if not check_mode:
                public = _create_key(seams, dfd)
                if public is None:
                    # Another writer published between our look and our link. Its key stands.
                    found = _inspect_key(settings, seams, dfd)
                    if found is None:
                        raise RefusalError(E_KEY_OPEN, _join(settings, KEY_NAME))
                    result.created = False
                    key_fd = found[0]
        if found is not None:
            public = found[1].public
            if found[1].mode != KEY_MODE:
                result.adopted = True
                if not check_mode and key_fd is not None:
                    os.fchmod(key_fd, KEY_MODE)
        if public is not None:
            result.public_key = public_pem(public)
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
    "public_file": {"type": "str", "required": True},
}


def _normal_absolute(path: str) -> bool:
    """Whether a path is absolute, has no dot segments or doubled or trailing slashes."""
    return os.path.isabs(path) and path == os.path.normpath(path) and path != "/"


def settings_from_params(directory: str, public_file: str) -> Settings:
    """Check the arguments, or refuse.

    Raises:
        RefusalError: for a path that is not absolute and normal, or a file inside the directory.
    """
    for path in (directory, public_file):
        if not _normal_absolute(path):
            raise RefusalError(E_ARGS, path)
    if public_file.startswith(directory + "/"):
        # The key's directory holds the key and nothing else, and its listing is closed to all.
        raise RefusalError(E_ARGS, public_file)
    return Settings(directory, public_file)


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    try:
        settings = settings_from_params(
            str(module.params["directory"]), str(module.params["public_file"])
        )
        result = converge(settings, check_mode=module.check_mode)
    except RefusalError as refusal:
        module.fail_json(msg=str(refusal))
    except OSError as error:
        # The errno name only: the message of an OS error can name a path, never the key,
        # but a fixed code is all that is needed to find the cause in the code.
        module.fail_json(msg=f"{E_IO}: {errno.errorcode.get(error.errno or 0, 'UNKNOWN')}")
    except Exception as error:  # noqa: BLE001 - a traceback would show frames that hold the key
        module.fail_json(msg=f"{E_INTERNAL}: {type(error).__name__}")
    else:
        module.exit_json(
            changed=result.changed,
            created=result.created,
            adopted=result.adopted,
            temp_cleaned=result.temp_cleaned,
            public_key=result.public_key,
        )


if __name__ == "__main__":
    main()
