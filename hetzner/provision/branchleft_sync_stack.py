#!/usr/bin/python3
"""Install one Compose stack's committed files from a tar stream, and restart it
only if they changed. Installed as /usr/local/sbin/branchleft-sync-stack.

    branchleft-sync-stack <stack>                      # archive on stdin
    branchleft-sync-stack --rehearse <dir> <stack>     # same, into <dir>, no host effects

Design, what it replaces and what it does not protect: branchleft_sync_stack.md.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import IO, Callable, Iterator

SYSTEMCTL = "/usr/bin/systemctl"
STACK_ROOT = "/opt/branchleft"
LOCK_DIR = "/run"

# The archive is a few hundred KiB today; these bounds are generous against
# that and exist so a runaway or hostile stream cannot fill the root disk.
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 500
MAX_DEPTH = 8

# The last member of every valid archive. The sender appends it after the
# stack's files, so an archive cut off cleanly between two members (a runner
# dying mid-upload) is missing it and is refused instead of being read as a
# smaller stack.
END_MARKER = "END-OF-STACK"

# Same bound as branchleft-deploy's lock: a restart of a Type=oneshot unit
# with TimeoutStartSec=600 that fails once and is retried.
RESTART_TIMEOUT = 1260

# A path component. No leading dot, so "." and ".." can never match, and no
# character a shell, a path or a unit name would have to be reasoned about for.
COMPONENT = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")


class SyncError(Exception):
    """Raised for anything a caller could have avoided by sending a valid archive."""


@dataclasses.dataclass(frozen=True)
class Stack:
    dest: str
    unit: str
    # Files a complete archive must contain. A stream that lost these lost far
    # more than these.
    required: tuple[str, ...]
    # Written on the host by render_alertmanager_config.py from
    # /etc/branchleft/monitoring.env, with their own owners and modes.
    host_rendered: frozenset[str]


# The registry is the allow-list. A stack is added here, in review, together
# with the key that may sync it.
STACKS = {
    "monitoring": Stack(
        dest=f"{STACK_ROOT}/monitoring",
        unit="branchleft-compose@monitoring.service",
        required=(
            "compose.yml",
            "render_alertmanager_config.py",
            "alertmanager/alertmanager.yml.tmpl",
            "prometheus/prometheus.yml",
            "prometheus/alerts.yml",
        ),
        host_rendered=frozenset(
            {
                "alertmanager/alertmanager.yml",
                "ntfy/server.yml",
                "prometheus/mx1-metrics-password",
            }
        ),
    ),
}


@dataclasses.dataclass(frozen=True)
class Desired:
    dirs: frozenset[str]
    files: dict[str, tuple[bytes, int]]  # relative path -> (content, mode)


class _Limited:
    """Read at most MAX_ARCHIVE_BYTES, then fail rather than keep reading."""

    def __init__(self, raw: IO[bytes]) -> None:
        self.raw = raw
        self.seen = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > 1 << 20:
            size = 1 << 20
        data = self.raw.read(size)
        self.seen += len(data)
        if self.seen > MAX_ARCHIVE_BYTES:
            raise SyncError(f"archive is larger than {MAX_ARCHIVE_BYTES} bytes")
        return data


def _clean_name(raw: str) -> str:
    name = raw[2:] if raw.startswith("./") else raw
    name = name.rstrip("/") if name != "/" else name
    if name in ("", "."):
        return ""
    if name.startswith("/") or "//" in name or "\\" in name:
        raise SyncError(f"refusing archive member {raw!r}: not a plain relative path")
    parts = name.split("/")
    if len(parts) > MAX_DEPTH:
        raise SyncError(f"refusing archive member {raw!r}: deeper than {MAX_DEPTH}")
    for part in parts:
        if not COMPONENT.match(part):
            raise SyncError(f"refusing archive member {raw!r}: component {part!r} is not allowed")
    return name


def read_archive(stack: Stack, stream: IO[bytes]) -> Desired:
    """Parse and validate the whole archive. Touches nothing on disk."""
    dirs: set[str] = set()
    files: dict[str, tuple[bytes, int]] = {}
    ended = False
    count = 0
    try:
        with tarfile.open(fileobj=_Limited(stream), mode="r|") as archive:  # type: ignore[arg-type]
            for member in archive:
                count += 1
                if count > MAX_ENTRIES:
                    raise SyncError(f"archive has more than {MAX_ENTRIES} members")
                if ended:
                    raise SyncError(f"refusing archive: {member.name!r} follows {END_MARKER}")
                name = _clean_name(member.name)
                if member.isdir():
                    if name:
                        dirs.add(name)
                    continue
                if not member.isreg():
                    raise SyncError(
                        f"refusing archive member {member.name!r}: only regular files and "
                        "directories are installed (no links, devices or fifos)"
                    )
                if not name:
                    raise SyncError("refusing archive: a file with no name")
                if name == END_MARKER:
                    if member.size != 0:
                        raise SyncError(f"refusing archive: {END_MARKER} is not empty")
                    ended = True
                    continue
                if name in stack.host_rendered:
                    raise SyncError(
                        f"refusing archive: {name} is rendered on the host from its secrets "
                        "and must not be sent"
                    )
                if name in files:
                    raise SyncError(f"refusing archive: {name} appears twice")
                if member.size > MAX_FILE_BYTES:
                    raise SyncError(f"refusing archive member {name}: larger than {MAX_FILE_BYTES} bytes")
                handle = archive.extractfile(member)
                assert handle is not None
                data = handle.read()
                if len(data) != member.size:
                    raise SyncError(f"refusing archive member {name}: short read")
                files[name] = (data, 0o755 if member.mode & 0o111 else 0o644)
    except tarfile.TarError as exc:
        raise SyncError(f"refusing archive: not a readable tar stream ({exc})") from exc

    if not ended:
        raise SyncError(f"refusing archive: no {END_MARKER} member, so it may be truncated")
    for need in stack.required:
        if need not in files:
            raise SyncError(f"refusing archive: required file {need} is missing")
    for path in list(files) + list(dirs):
        if path in dirs and path in files:
            raise SyncError(f"refusing archive: {path} is both a file and a directory")
        parent = pathlib.PurePosixPath(path).parent
        while str(parent) != ".":
            dirs.add(str(parent))
            parent = parent.parent
    for path in dirs:
        if path in stack.host_rendered:
            raise SyncError(f"refusing archive: {path} is a directory in the archive")
    return Desired(frozenset(dirs), files)


def _protected_ancestors(stack: Stack) -> set[str]:
    out: set[str] = set()
    for path in stack.host_rendered:
        parent = pathlib.PurePosixPath(path).parent
        while str(parent) != ".":
            out.add(str(parent))
            parent = parent.parent
    return out


def _owner_ok(st: os.stat_result, owner: tuple[int, int] | None) -> bool:
    return owner is None or (st.st_uid, st.st_gid) == owner


def _remove(path: pathlib.Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def apply(stack: Stack, desired: Desired, dest: pathlib.Path, owner: tuple[int, int] | None) -> list[str]:
    """Make `dest` match `desired`. Returns what changed, as short lines."""
    changes: list[str] = []
    dest.mkdir(mode=0o755, parents=True, exist_ok=True)
    root_stat = dest.lstat()
    if (root_stat.st_mode & 0o7777) != 0o755 or not _owner_ok(root_stat, owner):
        os.chmod(dest, 0o755)
        if owner is not None:
            os.chown(dest, *owner)
        changes.append("fixed .")

    for rel in sorted(desired.dirs, key=lambda p: (p.count("/"), p)):
        path = dest / rel
        try:
            st = path.lstat()
        except FileNotFoundError:
            st = None
        if st is not None and not (os.path.isdir(path) and not path.is_symlink()):
            _remove(path)
            st = None
        if st is None:
            path.mkdir(mode=0o755)
            changes.append(f"mkdir {rel}")
            st = path.lstat()
        if (st.st_mode & 0o7777) != 0o755 or not _owner_ok(st, owner):
            os.chmod(path, 0o755)
            if owner is not None:
                os.chown(path, *owner)
            changes.append(f"fixed {rel}")

    for rel, (data, mode) in sorted(desired.files.items()):
        path = dest / rel
        current: os.stat_result | None
        try:
            current = path.lstat()
        except FileNotFoundError:
            current = None
        if current is not None and not (path.is_file() and not path.is_symlink()):
            _remove(path)
            current = None
        if current is not None and path.read_bytes() == data:
            if (current.st_mode & 0o7777) != mode or not _owner_ok(current, owner):
                os.chmod(path, mode)
                if owner is not None:
                    os.chown(path, *owner)
                changes.append(f"fixed {rel}")
            continue
        fd, tmp_name = tempfile.mkstemp(prefix=".sync-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.chmod(tmp_name, mode)
            if owner is not None:
                os.chown(tmp_name, *owner)
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise
        changes.append(f"wrote {rel}")

    keep = _protected_ancestors(stack)
    wanted = set(desired.files) | set(desired.dirs)
    for current_dir, subdirs, names in os.walk(dest, topdown=True):
        base = pathlib.Path(current_dir)
        rel_base = base.relative_to(dest).as_posix()
        for name in sorted(names + subdirs):
            rel = name if rel_base == "." else f"{rel_base}/{name}"
            if rel in wanted or rel in stack.host_rendered or rel in keep:
                continue
            _remove(base / name)
            changes.append(f"removed {rel}")
            if name in subdirs:
                subdirs.remove(name)
    return changes


@contextlib.contextmanager
def _locked(stack_name: str) -> Iterator[None]:
    with open(os.path.join(LOCK_DIR, f"branchleft-sync-{stack_name}.lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _systemctl(*args: str) -> int:
    return subprocess.run([SYSTEMCTL, *args], check=False, timeout=RESTART_TIMEOUT).returncode


def sync(
    name: str,
    stream: IO[bytes],
    *,
    dest_root: str | None = None,
    owner: tuple[int, int] | None = (0, 0),
    systemctl: Callable[..., int] = _systemctl,
    out: IO[str] | None = None,
) -> int:
    """Validate, apply, and restart if anything changed. Returns an exit code.

    `dest_root` set means a rehearsal: the stack lands under that directory and
    nothing outside it is touched. The caller owns that choice -- it is a
    keyword, not something the archive or the SSH client can supply.
    """
    out = out or sys.stdout
    if name not in STACKS:
        raise SyncError(f"unknown stack {name!r}; known: {', '.join(sorted(STACKS))}")
    stack = STACKS[name]
    rehearsal = dest_root is not None
    dest = pathlib.Path(dest_root) / name if rehearsal else pathlib.Path(stack.dest)

    desired = read_archive(stack, stream)
    enabled = rehearsal or systemctl("is-enabled", "--quiet", stack.unit) == 0

    changes = apply(stack, desired, dest, owner)
    prefix = "(rehearsal) " if rehearsal else ""
    for line in changes:
        print(f"branchleft-sync-stack: {prefix}{line}", file=out)
    if not changes:
        print(f"branchleft-sync-stack: {prefix}{name} unchanged, no restart", file=out)
        return 0
    if rehearsal:
        print(f"branchleft-sync-stack: (rehearsal) {name} changed ({len(changes)}), would restart", file=out)
        return 0
    if not enabled:
        print(
            f"branchleft-sync-stack: {name} files installed, NOT RESTARTED: {stack.unit} is not "
            "enabled, so first-time bring-up (RUNBOOK-monitoring.md step 7a) is still to do",
            file=out,
        )
        return 0
    if systemctl("restart", stack.unit) != 0:
        print(
            f"branchleft-sync-stack: {name} files are installed but {stack.unit} failed to restart",
            file=sys.stderr,
        )
        return 1
    print(f"branchleft-sync-stack: {name} changed ({len(changes)}), restarted {stack.unit}", file=out)
    return 0


def main(argv: list[str]) -> int:
    rehearse: str | None = None
    args = list(argv)
    if len(args) == 3 and args[0] == "--rehearse":
        rehearse, args = args[1], args[2:]
    if len(args) != 1:
        print("usage: branchleft-sync-stack [--rehearse DIR] <stack>  (tar archive on stdin)", file=sys.stderr)
        return 2
    try:
        if rehearse is not None:
            return sync(args[0], sys.stdin.buffer, dest_root=rehearse, owner=None)
        if os.geteuid() != 0:
            raise SyncError("must run as root")
        with _locked(args[0]):
            return sync(args[0], sys.stdin.buffer)
    except SyncError as exc:
        print(f"branchleft-sync-stack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
