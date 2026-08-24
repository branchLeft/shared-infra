#!/usr/bin/env python3
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

**The binding is the forced command, and it has to be, because nothing else on
this path is out of the caller's reach.** The stack name is written into the
`command=` of the authorized_keys entry, in this file, as root. sshd then
executes exactly that command whatever the client asked for, so a slot key's
entire capability is `branchleft-deploy --slot <its own stack>` with one image
reference on stdin. The alternative shape -- one shared account, and the
wrapper deciding from "which key authenticated" -- has no trustworthy channel
to decide from: sshd does not put the accepted key's fingerprint in the
session environment, and the option that would (`PermitUserEnvironment`) also
lets anything holding that account write `~/.ssh/environment`, which is an
`LD_PRELOAD` into the very sudo call the deploy path depends on. The control
would be defeated by the account it is supposed to bound.

Three properties this script exists to hold, none of them recoverable by
hand afterwards:

1. **The caller's key comment never reaches the file.** Only the key type and
   its base64 blob are re-emitted; whatever trailed them is discarded. The
   comment field is free text ending at a newline, and this file's lines are
   `restrict,command="..."` -- so a comment carrying a quote closes the forced
   command, and one carrying a newline appends an entry with no forced command
   at all, which is a shell on the deploy account. Discarding the field is
   cheaper than escaping it and leaves nothing to escape.

2. **authorized_keys is rendered from the register, never appended to.** The
   register is `/etc/branchleft/deploy-slots/<stack>.pub`, root-owned `0700`
   directory, `0600` files. Every managed line is regenerated from it on every
   run and unmanaged lines are preserved verbatim, so a revoke is a re-render
   rather than an edit, and a rotation cannot leave the replaced key behind
   as a second working entry -- the failure mode of the append-then-remove
   procedure this replaces for slot keys.

3. **The deploy account cannot write its own authorized_keys, its `.ssh`
   directory, or the home containing it.** All three become root-owned here.
   Unlink permission comes from the containing directory, so leaving any one
   of them owned by `deploy` leaves an account that can delete the file and
   write a replacement -- and every restriction in this design is a line in
   that file. This does not bound a slot key, which never gets a shell; it
   bounds the unscoped keys that do.

**Residual, stated rather than implied.** The `deploy` account's sudoers grant
still names `/usr/local/sbin/branchleft-deploy` with no argument restriction,
because the platform's own repositories still call the unscoped form. So the
forced command is the only layer: anything that obtains arbitrary execution as
`deploy` reaches every stack on the host regardless of which key it arrived
on. Adding a second layer means per-slot sudoers entries naming exact
arguments, and those buy nothing while a broader rule still matches -- sudo
takes the last matching rule, and the unscoped one matches everything. The
second layer therefore becomes available only once every caller is slot-scoped
and the unscoped grant is withdrawn, which is tracked as its own item.

Exit 0 on success, 1 on any refusal or failure, 2 on usage error.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import re
import sys
import tempfile

# Mirrors `branchleft_deploy.py`'s STACK_NAME. The same string becomes a
# systemd instance name there and a `command=` argument here, and a name valid
# in one and not the other produces a slot key that authenticates and then
# cannot deploy.
STACK_NAME = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")

# Deliberately no reserved-name list, unlike `provision_tenant_volume.py`. That
# script only ever provisions tenants, so `website` there is always a mistake;
# a deploy slot is the generic mechanism and the marketing site is meant to get
# one. Refusing a tenant slug that collides with a platform stack is the tenant
# component's job, upstream of this, where the slug is first seen.

SLOT_DIR = "/etc/branchleft/deploy-slots"
SLOT_DIR_MODE = 0o700
SLOT_FILE_MODE = 0o600

DEPLOY_HOME = "/home/deploy"
DEPLOY_SSH_DIR = os.path.join(DEPLOY_HOME, ".ssh")
AUTHORIZED_KEYS = os.path.join(DEPLOY_SSH_DIR, "authorized_keys")

# Root-owned and world-readable. sshd's StrictModes accepts an authorized_keys
# file owned by root or by the account, and rejects one writable by anyone
# else; root-owned `0644` satisfies both while leaving the account unable to
# rewrite the restrictions it is subject to. The directories above it are
# `0755` for the same reason -- readable, and unlink-able only by root.
AUTHORIZED_KEYS_MODE = 0o644
DEPLOY_DIR_MODE = 0o755

SUDO = "/usr/bin/sudo"
WRAPPER = "/usr/local/sbin/branchleft-deploy"

# The last field of every line this script owns. Lines without it belong to
# somebody else -- the host-level key cloud-init installed, an operator's
# break-glass entry -- and are copied through untouched.
MANAGED_MARKER = "branchleft-slot:"

# Same closed type list as `hetzner-host/cloudInit.ts`, and closed for the same
# reason: what is being validated is less "is this a key" than "can this end
# the line it is on".
PUBLIC_KEY = re.compile(
    r"\A(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r" ([A-Za-z0-9+/]+={0,3})(?: [^\n\r]*)?\Z"
)


class ProvisionError(Exception):
    """Raised for anything a caller could have avoided, or that the host refused."""


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


def render_authorized_keys(existing: str, slots: dict[str, str]) -> str:
    """Unmanaged lines verbatim and in order, then one line per registered slot.

    Managed lines in `existing` are dropped rather than reconciled: the
    register is the only source of truth for them, so a hand-edited entry is
    replaced by what the register says it should be, and a revoked slot leaves
    nothing behind.
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
        os.chown(path, uid, gid)

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


def harden_deploy_paths(*, fs=None, home: str = DEPLOY_HOME, ssh_dir: str = DEPLOY_SSH_DIR) -> list[str]:
    """Take the deploy account's home and .ssh directory to root.

    cloud-init creates both owned by `deploy`, which is the ordinary shape for
    a login account and the wrong one here: an account that owns the directory
    holding authorized_keys can delete that file and write its own, forced
    commands and all.
    """
    fs = fs or _RealFs()
    actions = []
    for path in (home, ssh_dir):
        if not fs.exists(path):
            raise ProvisionError(
                f"{path} does not exist. This host has no deploy account, so it was not "
                "created from the platform cloud-init and a slot cannot be granted on it."
            )
        fs.chown(path, 0, 0)
        fs.chmod(path, DEPLOY_DIR_MODE)
        actions.append(f"{path} owned by root:root at {oct(DEPLOY_DIR_MODE)}")
    return actions


def write_authorized_keys(
    slots: dict[str, str],
    *,
    fs=None,
    authorized_keys: str = AUTHORIZED_KEYS,
) -> str:
    fs = fs or _RealFs()
    rendered = render_authorized_keys(fs.read_text(authorized_keys), slots)
    fs.replace_text(authorized_keys, rendered, AUTHORIZED_KEYS_MODE, 0, 0)
    return f"{authorized_keys} rendered with {len(slots)} slot entries"


def grant(
    stack: str,
    public_key_text: str,
    *,
    fs=None,
    slot_dir: str = SLOT_DIR,
    authorized_keys: str = AUTHORIZED_KEYS,
    home: str = DEPLOY_HOME,
    ssh_dir: str = DEPLOY_SSH_DIR,
) -> list[str]:
    fs = fs or _RealFs()
    validate_stack_name(stack)
    public_key = normalise_public_key(public_key_text)

    actions = harden_deploy_paths(fs=fs, home=home, ssh_dir=ssh_dir)

    fs.makedirs(slot_dir, SLOT_DIR_MODE)
    fs.chown(slot_dir, 0, 0)
    fs.chmod(slot_dir, SLOT_DIR_MODE)

    entry = slot_path(stack, slot_dir)
    previous = read_slots(slot_dir=slot_dir, fs=fs).get(stack)
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
        write_authorized_keys(
            read_slots(slot_dir=slot_dir, fs=fs), fs=fs, authorized_keys=authorized_keys
        )
    )
    return actions


def revoke(
    stack: str,
    *,
    fs=None,
    slot_dir: str = SLOT_DIR,
    authorized_keys: str = AUTHORIZED_KEYS,
    home: str = DEPLOY_HOME,
    ssh_dir: str = DEPLOY_SSH_DIR,
) -> list[str]:
    fs = fs or _RealFs()
    validate_stack_name(stack)
    if stack not in read_slots(slot_dir=slot_dir, fs=fs):
        raise ProvisionError(
            f"no deploy slot for {stack!r} on this host. Nothing was changed -- a revoke that "
            "silently succeeded on a stack name with a typo would read as a key removed while "
            "it kept working."
        )

    actions = harden_deploy_paths(fs=fs, home=home, ssh_dir=ssh_dir)
    fs.remove(slot_path(stack, slot_dir))
    actions.append(f"revoked slot {stack}")
    actions.append(
        write_authorized_keys(
            read_slots(slot_dir=slot_dir, fs=fs), fs=fs, authorized_keys=authorized_keys
        )
    )
    return actions


def list_slots(
    *, fs=None, slot_dir: str = SLOT_DIR, authorized_keys: str = AUTHORIZED_KEYS
) -> list[str]:
    """Report every slot, after checking the file agrees with the register.

    Read-only, and the disagreement check is the point of it: the register is
    what a rewrite is rendered from, so an entry that reached authorized_keys
    by hand would be silently dropped by the next grant on this host. Better to
    say so while both still exist.
    """
    fs = fs or _RealFs()
    slots = read_slots(slot_dir=slot_dir, fs=fs)
    expected = {stack: slot_line(stack, key) for stack, key in slots.items()}

    for line in fs.read_text(authorized_keys).splitlines():
        stack = managed_slot(line)
        if stack is None:
            continue
        if stack not in expected:
            raise ProvisionError(
                f"{authorized_keys} carries a managed entry for {stack!r} with no register file "
                f"in {slot_dir}. It was added by hand and the next grant on this host would "
                "drop it; record it in the register or remove the line."
            )
        if line.strip() != expected[stack]:
            raise ProvisionError(
                f"{authorized_keys}'s entry for {stack!r} differs from the one the register "
                "renders. It was edited by hand and the next grant would overwrite it."
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
        "--list-slots",
        action="store_true",
        help="print every slot on this host as <stack>=SHA256:<fingerprint> and exit",
    )
    args = parser.parse_args(argv)
    emit = out or (lambda line: print(line))
    read_key = read_key or (lambda path: open(path, encoding="utf-8").read())

    if geteuid() != 0:
        print("provision_deploy_slot: must run as root.", file=sys.stderr)
        return 1

    try:
        if args.list_slots:
            if args.stack is not None or args.public_key_file or args.revoke:
                raise ProvisionError("--list-slots takes no stack, no key and no --revoke")
            for line in list_slots(fs=fs):
                emit(line)
            return 0

        if args.stack is None:
            raise ProvisionError("a stack name is required unless --list-slots is given")

        if args.revoke:
            if args.public_key_file:
                raise ProvisionError("--revoke and --public-key-file are mutually exclusive")
            actions = revoke(args.stack, fs=fs)
        else:
            if not args.public_key_file:
                raise ProvisionError("--public-key-file is required to grant a slot")
            actions = grant(args.stack, read_key(args.public_key_file), fs=fs)

        for action in actions:
            emit(action)
    except (ProvisionError, OSError) as exc:
        print(f"provision_deploy_slot: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
