#!/usr/bin/python3
"""Idempotent grant of one deploy slot: a key that can restart one stack only.

Run by hand on the app host itself (as root, once per stack whose repository
deploys to this host, before that repository's first deploy):

    provision_deploy_slot.py --public-key-file blog.pub blog
    provision_deploy_slot.py --revoke blog
    provision_deploy_slot.py --list-slots

The problem it solves is not argument validation. `branchleft-deploy` already
refuses a malformed stack name; what it cannot do in its unscoped form is
refuse a *well-formed* one belonging to somebody else, because the caller is
the one who names it. On a host running one stack that distinction is
invisible. On a host running N tenants it is the whole boundary: one deploy
key shared by N repositories means any one of those repositories can pin an
arbitrary image into any other's Compose slot and restart it, which is
complete takeover of that tenant's site by a credential that was only ever
meant to redeploy its own.

**The binding is the forced command, and the reason is that it removes the
name rather than checking it.** The stack name is written into the `command=`
of the authorized_keys entry, in this file, as root. sshd then executes
exactly that command whatever the client asked for, so a slot key's entire
capability is `branchleft-deploy --slot <its own stack>` with one image
reference on stdin. There is no caller-supplied stack name anywhere on the
path, and therefore nothing for any later code to validate correctly.

The alternative shape -- one shared account, and the wrapper deciding from
which key authenticated -- is not impossible. sshd can be told to expose the
authenticating credential: `ExposeAuthInfo` writes the accepted key to a file
named by `SSH_USER_AUTH`, and `AuthorizedKeysCommand` receives the key's
fingerprint as `%f`. Both are server-side and neither is writable by the
account. It loses on a different property: every such design still has to
compare a caller-supplied stack name against an identity, correctly, on every
future edit of that comparison -- and a mistake there is silent, because a
wrong comparison still deploys something. A forced command has no comparison
to get wrong. (`environment=` in authorized_keys is a third option and a bad
one: it needs `PermitUserEnvironment`, which also lets anything holding this
account set `BASH_ENV` for the non-interactive shell every forced command
runs under.)

Five properties this script exists to hold, none of them recoverable by hand
afterwards:

1. **One key holds at most one slot.** sshd returns on the *first* matching
   authorized_keys line, so a public key installed against two slots always
   resolves to whichever renders first -- giving the second slot's repository
   arbitrary code execution inside the first slot's container, which is the
   exact primitive this file exists to remove. Granting a slot the *host-level*
   key is the sharper form: the unmanaged line renders first, so that slot
   keeps host-wide reach while looking correctly scoped in the register.
   Refused here rather than left to operator discipline, because the
   fingerprints needed to detect it are already computed.

2. **The caller's key comment never reaches the file.** Only the key type and
   its base64 blob are re-emitted; whatever trailed them is discarded. The
   comment field is free text ending at a newline, and this file's lines are
   `restrict,command="..."` -- so a comment carrying a quote closes the forced
   command, and one carrying a newline appends an entry with no forced command
   at all, which is a shell on the deploy account. Discarding the field is
   cheaper than escaping it and leaves nothing to escape.

3. **authorized_keys is rendered from the register, and reconciled against it
   before every write.** The register is `/etc/branchleft/deploy-slots/
   <stack>.pub`, root-owned `0700` directory, `0600` files. `reconcile()` is
   the single arbiter of whether the file and the register agree, and grant,
   revoke and the audit path all call it -- a marked line the register cannot
   explain stops the run rather than being silently dropped by the re-render.
   That mattered: the marker is a plain last field, so an unmanaged key whose
   comment happened to end in one would otherwise have been deleted by the
   next grant, and on this estate that is the host-level key the marketing
   site deploys through.

4. **The deploy account cannot write anything in its own home.** Ownership of
   the home, `.ssh`, `authorized_keys` and **every file beneath them** moves to
   root. Unlink permission comes from the containing directory, so leaving the
   home owned by `deploy` leaves an account that can delete authorized_keys and
   write a replacement -- and every restriction in this design is a line in
   that file. The recursion is not tidiness either: sshd runs a forced command
   through `$SHELL -c`, this account's shell is bash, and Debian builds bash
   with `SSH_SOURCE_BASHRC`, so `~/.bashrc` is sourced for exactly that session
   type. A writable dotfile runs ahead of every slot key's forced command. It
   also closes `~/.ssh/authorized_keys2`, which sshd's default
   `AuthorizedKeysFile` still includes.

5. **A slug that names a stack already on this host is refused** unless the
   operator says otherwise with `--adopt-existing-stack`. A hardcoded reserved
   list was rejected: `RESERVED_STACK_NAMES` lives in `branchLeft/ghost-platform`
   and a copy here is cross-repo drift waiting to happen, where the copy going
   stale fails open. The host's own `/opt/branchleft` is the fact that matters
   and cannot drift from itself. A tenant being onboarded has no stack
   directory yet, so the normal path never sees this; granting a slot on
   `website` does, which is the case worth stopping.

**Residual, stated rather than implied.** The `deploy` account's sudoers grant
still names `/usr/local/sbin/branchleft-deploy` with no argument restriction.
Nothing reaches it through this account today, so the forced command is not
currently the only layer by necessity -- it is the only layer because the
broader grant has not yet been withdrawn. Withdrawing it is tracked as its own
item.

Exit 0 on success, 1 on any refusal or failure, 2 on usage error.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import pwd
import re
import stat
import sys
import tempfile

# Mirrors `branchleft_deploy.py`'s STACK_NAME. The same string becomes a
# systemd instance name there and a `command=` argument here, and a name valid
# in one and not the other produces a slot key that authenticates and then
# cannot deploy.
STACK_NAME = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")

SLOT_DIR = "/etc/branchleft/deploy-slots"
SLOT_DIR_MODE = 0o700
SLOT_FILE_MODE = 0o600

# Mirrors `branchleft_deploy.py`'s STACK_DIR. Read only to answer "does this
# host already run a stack of that name"; nothing here writes to it.
STACK_DIR = "/opt/branchleft"

DEPLOY_ACCOUNT = "deploy"
DEPLOY_HOME = "/home/deploy"
DEPLOY_SSH_DIR = os.path.join(DEPLOY_HOME, ".ssh")
AUTHORIZED_KEYS = os.path.join(DEPLOY_SSH_DIR, "authorized_keys")

# Root-owned, group-readable by the deploy account, writable by neither.
# sshd's StrictModes accepts an authorized_keys file owned by root or by the
# account and rejects one writable by anyone else, and some builds open it as
# the account rather than as root -- `root:deploy` at 0640 satisfies both
# readers without making the home world-readable.
AUTHORIZED_KEYS_MODE = 0o640
DEPLOY_DIR_MODE = 0o750

# Cleared from every path under the deploy home. Ownership alone is not the
# whole property: a file arriving group- or world-writable stays writable by
# the account whoever owns it.
FORBIDDEN_WRITE_BITS = 0o022

SUDO = "/usr/bin/sudo"
WRAPPER = "/usr/local/sbin/branchleft-deploy"

# The last field of every line this script owns. Lines without it belong to
# somebody else -- the host-level key cloud-init installed, an operator's
# break-glass entry -- and are copied through untouched.
MANAGED_MARKER = "branchleft-slot:"

KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)

# Same closed type list as `hetzner-host/cloudInit.ts`, and closed for the same
# reason: what is being validated is less "is this a key" than "can this end
# the line it is on".
PUBLIC_KEY = re.compile(
    r"\A(" + "|".join(re.escape(t) for t in KEY_TYPES) + r")"
    r" ([A-Za-z0-9+/]+={0,3})(?: [^\n\r]*)?\Z"
)

# An ed25519 blob is 68 base64 characters and an RSA-4096 one about 725. The
# bound is generous against both and still refuses a file that is not a key at
# all -- this value becomes one line in a file sshd parses on every connection.
MAX_KEY_BLOB = 4096


class ProvisionError(Exception):
    """Raised for anything a caller could have avoided, or that the host refused."""


class UsageError(ProvisionError):
    """A malformed invocation, as opposed to a refusal about the host's state."""


def validate_stack_name(stack: str) -> str:
    if not STACK_NAME.match(stack):
        raise ProvisionError(
            f"stack name {stack!r} must start with a lowercase letter and contain only "
            "lowercase letters, digits and hyphens, to at most 32 characters"
        )
    return stack


def normalise_public_key(text: str) -> str:
    """Return `<type> <blob>` from one OpenSSH public key, comment discarded.

    Rejects rather than trims a value spanning more than one line: a second
    line here is a second authorized_keys entry, and the one being added would
    be the only one carrying a forced command.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ProvisionError(
            f"expected exactly one OpenSSH public key, found {len(lines)} non-empty lines"
        )
    match = PUBLIC_KEY.match(lines[0].strip())
    if not match:
        raise ProvisionError(
            "not a single-line OpenSSH public key (for example the whole contents of an "
            "`id_ed25519.pub`)"
        )
    if len(match.group(2)) > MAX_KEY_BLOB:
        raise ProvisionError(
            f"public key blob is {len(match.group(2))} characters; the maximum is {MAX_KEY_BLOB}"
        )
    return f"{match.group(1)} {match.group(2)}"


def fingerprint(public_key: str) -> str:
    """The `SHA256:...` form `ssh-keygen -lf` prints, so the two can be compared."""
    blob = public_key.split(" ", 1)[1]
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProvisionError(f"public key blob is not valid base64: {exc}") from exc
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def key_in_line(line: str) -> str | None:
    """The `<type> <blob>` of any authorized_keys line, options and all.

    Used on lines this script does not own, to answer "is this the same key" --
    so it looks for a known key type followed by something base64-shaped rather
    than assuming a field position. Options are a comma-separated field that
    may contain a quoted command with spaces in it, which makes counting fields
    unreliable and a type match the only stable anchor.
    """
    fields = line.split()
    for index, field in enumerate(fields[:-1]):
        if field in KEY_TYPES:
            candidate = f"{field} {fields[index + 1]}"
            if PUBLIC_KEY.match(candidate):
                return candidate
    return None


def slot_path(stack: str, slot_dir: str = SLOT_DIR) -> str:
    return os.path.join(slot_dir, f"{validate_stack_name(stack)}.pub")


def slot_line(stack: str, public_key: str, *, sudo: str = SUDO, wrapper: str = WRAPPER) -> str:
    """The authorized_keys entry for one slot.

    `restrict` is the whole-set deny with nothing added back, exactly as the
    host-level entry carries it; the forced command is what this adds. Both
    interpolated values are already constrained to character sets with no
    quote, space or newline in them, and the assertion below is here because
    that is a property of two regexes in this file rather than of anything at
    this line.
    """
    validate_stack_name(stack)
    if PUBLIC_KEY.fullmatch(public_key) is None:
        raise ProvisionError(f"refusing to emit an unvalidated public key: {public_key!r}")
    return (
        f'restrict,command="{sudo} -n {wrapper} --slot {stack}" '
        f"{public_key} {MANAGED_MARKER}{stack}"
    )


def managed_slot(line: str) -> str | None:
    """The stack a line is the managed entry for, or None if it is not ours."""
    fields = line.split()
    if not fields or not fields[-1].startswith(MANAGED_MARKER):
        return None
    return fields[-1][len(MANAGED_MARKER) :]


def reconcile(slots: dict[str, str], authorized_text: str, *, authorized_keys: str = AUTHORIZED_KEYS,
              slot_dir: str = SLOT_DIR) -> None:
    """The single arbiter of whether authorized_keys and the register agree.

    Every write path calls this **before** mutating anything, and the audit
    path calls it as its whole job. That placement is what makes the guard
    structural rather than a check somebody has to remember: after it passes,
    every marked line in the file is explained by an entry in the register, so
    re-rendering from the register is guaranteed to drop only lines a change to
    the register accounts for. Before it passes, nothing is written at all.

    A marked line the register cannot explain is therefore a refusal and not a
    silent deletion. The marker is a plain last field with no namespace, so an
    unmanaged key whose comment happens to end in one lands here -- and on this
    estate the unmanaged key is the host-level one every platform deploy to the
    host goes through.
    """
    expected = {stack: slot_line(stack, key) for stack, key in slots.items()}
    seen: set[str] = set()
    for line in authorized_text.splitlines():
        stack = managed_slot(line)
        if stack is None:
            continue
        if stack not in expected:
            raise ProvisionError(
                f"{authorized_keys} carries an entry marked {MANAGED_MARKER}{stack} with no "
                f"register file in {slot_dir}. Nothing has been changed. Either it was added by "
                "hand, or it is an unrelated key whose comment ends in a marker-shaped field -- "
                "and rewriting the file would delete it. Resolve it by hand: record it in the "
                "register, or change its comment."
            )
        if line.strip() != expected[stack]:
            raise ProvisionError(
                f"{authorized_keys}'s entry for {stack!r} is not the line the register renders. "
                "Nothing has been changed. It was edited by hand; reconcile it before granting "
                "or revoking anything on this host."
            )
        if stack in seen:
            raise ProvisionError(
                f"{authorized_keys} carries two entries for {stack!r}. Nothing has been changed. "
                "sshd matches the first, so the second is invisible and its removal would look "
                "like a no-op; remove one by hand."
            )
        seen.add(stack)


def assert_key_is_unused(stack: str, public_key: str, slots: dict[str, str],
                         authorized_text: str) -> None:
    """Refuse a key that already authenticates as something else on this host.

    sshd stops at the first authorized_keys line the presented key matches, so
    a key installed twice resolves to exactly one of them, always the same one.
    Both forms of that are a silent privilege transfer rather than a duplicate:
    a key held by two slots gives the loser's repository code execution in the
    winner's container, and a key shared with an unmanaged entry keeps the
    unmanaged entry's reach while the register reports a scoped slot.
    """
    for other_stack, other_key in sorted(slots.items()):
        if other_stack != stack and other_key == public_key:
            raise ProvisionError(
                f"that public key ({fingerprint(public_key)}) already holds slot "
                f"{other_stack!r} on this host. sshd matches the first entry, so granting it "
                f"{stack!r} as well would give {stack!r}'s repository a working deploy into "
                f"{other_stack!r}'s stack. Generate a keypair per slot."
            )
    for line in authorized_text.splitlines():
        if managed_slot(line) is not None:
            continue
        if key_in_line(line) == public_key:
            raise ProvisionError(
                f"that public key ({fingerprint(public_key)}) is already installed on this host "
                "as an entry this script does not manage -- the host-level deploy key, or an "
                "operator's. sshd matches that entry first, so the slot would be cosmetic and "
                f"{stack!r}'s repository would keep whatever reach that entry has. Generate a "
                "keypair for the slot."
            )


def render_authorized_keys(existing: str, slots: dict[str, str]) -> str:
    """Unmanaged lines verbatim and in order, then one line per registered slot.

    Safe to drop marked lines here only because `reconcile()` has already
    established that every one of them is explained by the register; this
    function is never called on an unreconciled file.
    """
    kept = [line for line in existing.splitlines() if managed_slot(line) is None]
    while kept and not kept[-1].strip():
        kept.pop()
    rendered = [slot_line(stack, slots[stack]) for stack in sorted(slots)]
    return "".join(f"{line}\n" for line in kept + rendered)


class _RealFs:
    """The filesystem operations this script performs, in one injectable place."""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def listdir(self, path: str) -> list[str]:
        try:
            return os.listdir(path)
        except FileNotFoundError:
            return []

    def walk(self, path: str) -> list[str]:
        found = []
        for root, directories, files in os.walk(path):
            for name in directories + files:
                found.append(os.path.join(root, name))
        return found

    def is_symlink(self, path: str) -> bool:
        return os.path.islink(path)

    def owner_mode(self, path: str) -> tuple[int, int, int]:
        info = os.stat(path)
        return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)

    def account_gid(self, name: str) -> int:
        try:
            return pwd.getpwnam(name).pw_gid
        except KeyError as exc:
            raise ProvisionError(
                f"no {name!r} account on this host, so it was not created from the platform "
                "cloud-init and a slot cannot be granted on it."
            ) from exc

    def read_text(self, path: str) -> str:
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read()
        except FileNotFoundError:
            return ""

    def remove(self, path: str) -> None:
        os.remove(path)

    def makedirs(self, path: str, mode: int) -> None:
        os.makedirs(path, mode=mode, exist_ok=True)

    def chown(self, path: str, uid: int, gid: int) -> None:
        # follow_symlinks=False so a symlink planted in the account's own home
        # before this ran cannot redirect a root chown onto a file outside it.
        os.chown(path, uid, gid, follow_symlinks=False)

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(path, mode)

    def replace_text(self, path: str, text: str, mode: int, uid: int, gid: int) -> None:
        """Replace a file atomically, ownership and mode set before it is visible.

        authorized_keys is read by sshd on every connection, so the truncate
        window an in-place rewrite opens is a window in which a deploy fails to
        authenticate. The temporary file is created in the destination's own
        directory so the rename stays within one filesystem, where it is
        atomic.
        """
        directory = os.path.dirname(path)
        handle_fd, temporary = tempfile.mkstemp(dir=directory, prefix=".branchleft-slot-")
        try:
            with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chown(temporary, uid, gid)
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        except BaseException:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise


def read_slots(*, slot_dir: str = SLOT_DIR, fs=None) -> dict[str, str]:
    """Every slot granted on this host, keyed by stack name.

    A register file whose name is not a valid stack name, or whose contents are
    not one public key, raises rather than being skipped: this dictionary is
    what authorized_keys is rendered from, and quietly omitting an entry would
    revoke a working deploy key as a side effect of a read.
    """
    fs = fs or _RealFs()
    slots: dict[str, str] = {}
    for name in sorted(fs.listdir(slot_dir)):
        if not name.endswith(".pub"):
            raise ProvisionError(
                f"{os.path.join(slot_dir, name)!r} is not a .pub file. The register holds one "
                "public key per stack and nothing else; move it aside by hand."
            )
        stack = name[: -len(".pub")]
        try:
            validate_stack_name(stack)
            slots[stack] = normalise_public_key(fs.read_text(os.path.join(slot_dir, name)))
        except ProvisionError as exc:
            raise ProvisionError(
                f"register entry {os.path.join(slot_dir, name)!r} is unusable ({exc}). "
                "authorized_keys is rendered from this directory, so it is not read past a "
                "file it cannot parse -- fix or remove it by hand."
            ) from exc
    return slots


def existing_stacks(*, fs=None, stack_dir: str = STACK_DIR) -> set[str]:
    """Stack names this host already runs, read from the host rather than a list."""
    fs = fs or _RealFs()
    return set(fs.listdir(stack_dir))


def harden_deploy_paths(*, fs=None, home: str = DEPLOY_HOME, ssh_dir: str = DEPLOY_SSH_DIR,
                        account: str = DEPLOY_ACCOUNT) -> list[str]:
    """Take the deploy account's whole home to root.

    cloud-init creates it owned by `deploy`, which is the ordinary shape for a
    login account and the wrong one here. Recursive because ownership of the
    directory is not the only reach: bash sources `~/.bashrc` for the
    non-interactive `$SHELL -c` a forced command runs under, so one writable
    dotfile pre-empts every slot key on the host.
    """
    fs = fs or _RealFs()
    for path in (home, ssh_dir):
        if not fs.exists(path):
            raise ProvisionError(
                f"{path} does not exist. This host has no deploy account, so it was not "
                "created from the platform cloud-init and a slot cannot be granted on it."
            )
    gid = fs.account_gid(account)

    actions = []
    for path in (home, ssh_dir):
        fs.chown(path, 0, gid)
        fs.chmod(path, DEPLOY_DIR_MODE)
        actions.append(f"{path} owned by root:{account} at {oct(DEPLOY_DIR_MODE)}")

    hardened = 0
    for path in sorted(fs.walk(home)):
        fs.chown(path, 0, gid)
        if not fs.is_symlink(path):
            _, _, mode = fs.owner_mode(path)
            if mode & FORBIDDEN_WRITE_BITS:
                fs.chmod(path, mode & ~FORBIDDEN_WRITE_BITS)
        hardened += 1
    actions.append(f"{hardened} paths under {home} owned by root and not account-writable")
    return actions


def unhardened_paths(*, fs=None, home: str = DEPLOY_HOME) -> list[str]:
    """Paths under the deploy home the account could still write. Empty is correct."""
    fs = fs or _RealFs()
    problems = []
    for path in sorted([home, *fs.walk(home)]):
        uid, _, mode = fs.owner_mode(path)
        if uid != 0:
            problems.append(f"{path} is owned by uid {uid}, not root")
        elif mode & FORBIDDEN_WRITE_BITS and not fs.is_symlink(path):
            problems.append(f"{path} is mode {oct(mode)}, writable beyond its owner")
    return problems


def write_authorized_keys(slots: dict[str, str], *, fs=None,
                          authorized_keys: str = AUTHORIZED_KEYS,
                          account: str = DEPLOY_ACCOUNT) -> str:
    fs = fs or _RealFs()
    rendered = render_authorized_keys(fs.read_text(authorized_keys), slots)
    fs.replace_text(authorized_keys, rendered, AUTHORIZED_KEYS_MODE, 0, fs.account_gid(account))
    return f"{authorized_keys} rendered with {len(slots)} slot entries"


def grant(stack: str, public_key_text: str, *, fs=None, slot_dir: str = SLOT_DIR,
          authorized_keys: str = AUTHORIZED_KEYS, home: str = DEPLOY_HOME,
          ssh_dir: str = DEPLOY_SSH_DIR, stack_dir: str = STACK_DIR,
          adopt_existing_stack: bool = False) -> list[str]:
    fs = fs or _RealFs()
    validate_stack_name(stack)
    public_key = normalise_public_key(public_key_text)

    slots = read_slots(slot_dir=slot_dir, fs=fs)
    authorized_text = fs.read_text(authorized_keys)
    reconcile(slots, authorized_text, authorized_keys=authorized_keys, slot_dir=slot_dir)
    assert_key_is_unused(stack, public_key, slots, authorized_text)

    if stack not in slots and stack in existing_stacks(fs=fs, stack_dir=stack_dir) \
            and not adopt_existing_stack:
        raise ProvisionError(
            f"{stack_dir}/{stack} already exists, so this host already runs a stack called "
            f"{stack!r} and this would be the first slot for it. If that is a platform stack "
            "(the marketing site, the edge, the database, monitoring) then handing its slot to a "
            "tenant repository hands over that service. Re-run with --adopt-existing-stack if "
            "granting a slot on an existing stack is what you meant."
        )

    actions = harden_deploy_paths(fs=fs, home=home, ssh_dir=ssh_dir)

    fs.makedirs(slot_dir, SLOT_DIR_MODE)
    fs.chown(slot_dir, 0, 0)
    fs.chmod(slot_dir, SLOT_DIR_MODE)

    entry = slot_path(stack, slot_dir)
    previous = slots.get(stack)
    fs.replace_text(entry, f"{public_key}\n", SLOT_FILE_MODE, 0, 0)
    if previous is None:
        actions.append(f"granted slot {stack} to {fingerprint(public_key)}")
    elif previous == public_key:
        actions.append(f"slot {stack} already held {fingerprint(public_key)}, unchanged")
    else:
        actions.append(
            f"rotated slot {stack} from {fingerprint(previous)} to {fingerprint(public_key)}"
        )

    actions.append(
        write_authorized_keys(read_slots(slot_dir=slot_dir, fs=fs), fs=fs,
                              authorized_keys=authorized_keys)
    )
    return actions


def revoke(stack: str, *, fs=None, slot_dir: str = SLOT_DIR,
           authorized_keys: str = AUTHORIZED_KEYS, home: str = DEPLOY_HOME,
           ssh_dir: str = DEPLOY_SSH_DIR) -> list[str]:
    fs = fs or _RealFs()
    validate_stack_name(stack)
    slots = read_slots(slot_dir=slot_dir, fs=fs)
    reconcile(slots, fs.read_text(authorized_keys), authorized_keys=authorized_keys,
              slot_dir=slot_dir)
    if stack not in slots:
        raise ProvisionError(
            f"no deploy slot for {stack!r} on this host. Nothing was changed -- a revoke that "
            "silently succeeded on a stack name with a typo would read as a key removed while "
            "it kept working."
        )

    actions = harden_deploy_paths(fs=fs, home=home, ssh_dir=ssh_dir)
    fs.remove(slot_path(stack, slot_dir))
    actions.append(f"revoked slot {stack}")
    actions.append(
        write_authorized_keys(read_slots(slot_dir=slot_dir, fs=fs), fs=fs,
                              authorized_keys=authorized_keys)
    )
    return actions


def list_slots(*, fs=None, slot_dir: str = SLOT_DIR, authorized_keys: str = AUTHORIZED_KEYS,
               home: str = DEPLOY_HOME) -> list[str]:
    """Report every slot, after checking the host still holds what it should.

    Read-only, and the three checks are the point of it. The register must
    explain every marked line (`reconcile`), no key may hold two slots, and the
    deploy home must still be root-owned -- that last one because the ownership
    is a property nothing else re-asserts and a single `chown -R` undoes it
    while leaving every slot in place and every deploy working.
    """
    fs = fs or _RealFs()
    slots = read_slots(slot_dir=slot_dir, fs=fs)
    authorized_text = fs.read_text(authorized_keys)
    reconcile(slots, authorized_text, authorized_keys=authorized_keys, slot_dir=slot_dir)

    by_fingerprint: dict[str, str] = {}
    for stack, key in sorted(slots.items()):
        printed = fingerprint(key)
        if printed in by_fingerprint:
            raise ProvisionError(
                f"slots {by_fingerprint[printed]!r} and {stack!r} hold the same key "
                f"({printed}). sshd matches the first, so one of these two repositories can "
                "deploy into the other's stack. Rotate one of them onto its own keypair."
            )
        by_fingerprint[printed] = stack

    if slots:
        problems = unhardened_paths(fs=fs, home=home)
        if problems:
            raise ProvisionError(
                "the deploy account can write inside its own home, so it can replace the "
                "authorized_keys entries below or a dotfile that runs ahead of them; the slots "
                "are not the restriction they appear to be. Re-run a grant to repair it. "
                + "; ".join(problems)
            )

    return [f"{stack}={fingerprint(key)}" for stack, key in sorted(slots.items())]


def main(argv: list[str], *, geteuid=os.geteuid, fs=None, out=None, read_key=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stack", nargs="?")
    parser.add_argument(
        "--public-key-file",
        help="path to the OpenSSH public key granted this slot; its comment field is discarded",
    )
    parser.add_argument("--revoke", action="store_true", help="remove this stack's slot")
    parser.add_argument(
        "--adopt-existing-stack",
        action="store_true",
        help="grant a slot on a stack this host already runs, rather than a new one",
    )
    parser.add_argument(
        "--list-slots",
        action="store_true",
        help="print every slot on this host as <stack>=SHA256:<fingerprint> and exit",
    )
    args = parser.parse_args(argv)
    emit = out or (lambda line: print(line))
    read_key = read_key or _read_key_file

    if geteuid() != 0:
        print("provision_deploy_slot: must run as root.", file=sys.stderr)
        return 1

    try:
        if args.list_slots:
            if args.stack is not None or args.public_key_file or args.revoke:
                raise UsageError("--list-slots takes no stack, no key and no --revoke")
            for line in list_slots(fs=fs):
                emit(line)
            return 0

        if args.stack is None:
            raise UsageError("a stack name is required unless --list-slots is given")

        if args.revoke:
            if args.public_key_file:
                raise UsageError("--revoke and --public-key-file are mutually exclusive")
            if args.adopt_existing_stack:
                raise UsageError("--adopt-existing-stack applies to a grant, not a revoke")
            actions = revoke(args.stack, fs=fs)
        else:
            if not args.public_key_file:
                raise UsageError("--public-key-file is required to grant a slot")
            actions = grant(
                args.stack,
                read_key(args.public_key_file),
                fs=fs,
                adopt_existing_stack=args.adopt_existing_stack,
            )

        for action in actions:
            emit(action)
    except UsageError as exc:
        print(f"provision_deploy_slot: {exc}", file=sys.stderr)
        return 2
    except (ProvisionError, OSError) as exc:
        print(f"provision_deploy_slot: {exc}", file=sys.stderr)
        return 1
    return 0


def _read_key_file(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read(MAX_KEY_BLOB * 2)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
