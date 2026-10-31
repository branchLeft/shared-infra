"""Place or rotate a host's private inputs file from the values the host already holds.

Run on the host, as root. It never prints a value and takes none as an argument; what it reads,
writes and refuses is described in ansible/tools/README.md."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn, TextIO

CONFIG_DIR: Final = "/etc/branchleft"
DEST_NAME: Final = "host-inputs.json"
# Every directory above the file, root first: the loader's own list, held to it by a test.
ANCESTORS: Final[tuple[str, ...]] = ("/", "/etc", "/etc/branchleft")
ROOT_UID: Final = 0
ROOT_GID: Final = 0
FILE_MODE: Final = 0o600
MAX_BYTES: Final = 1 << 20

ENV: Final = "env"
WHOLE: Final = "whole"
RECIPIENTS: Final = "recipients"

type Value = str | list[dict[str, str]]


@dataclass(frozen=True)
class Source:
    """Where the hand install left one input: a NAME=value line, a whole file, or tenants."""

    kind: str
    filename: str
    name: str = ""


def _env(filename: str, name: str) -> Source:
    return Source(ENV, filename, name)


# The hosts this tool seeds, each with its row of the loader (host_inputs_required_by_host).
# db1 has its file already and no live file to read; a test names it.
HOSTS: Final[dict[str, tuple[str, ...]]] = {
    "edge1": (
        "monitoring_stack_smtp_username",
        "monitoring_stack_smtp_password",
        "monitoring_stack_healthchecks_ping_url",
        "monitoring_stack_alert_recipient_email",
        "monitoring_stack_mailhost_ping_url",
        "monitoring_stack_grafana_admin_password",
        "monitoring_stack_snds_data_url",
        "ntfy_pager_pager_token",
        "ntfy_pager_watcher_token",
        "ntfy_pager_owner_password_hash",
        "ntfy_pager_machine_password_hash",
    ),
    "ops1": (
        "backup_worker_db_host",
        "backup_worker_db_user",
        "backup_worker_db_password",
        "backup_worker_db_ca_pem",
        "backup_worker_bucket",
        "backup_worker_s3_endpoint",
        "backup_worker_s3_region",
        "backup_worker_s3_access_key_id",
        "backup_worker_s3_secret_access_key",
        "backup_worker_tenants",
        "backup_restore_state_copy_recipient",
        "backup_restore_state_copy_dest_access_key_id",
        "backup_restore_state_copy_estate_bucket",
        "backup_restore_state_copy_estate_endpoint",
        "backup_restore_state_copy_estate_region",
        "backup_restore_state_copy_estate_access_key_id",
        "backup_restore_state_copy_tenant_bucket",
        "backup_restore_state_copy_tenant_endpoint",
        "backup_restore_state_copy_tenant_region",
        "backup_restore_state_copy_tenant_access_key_id",
    ),
    "app1": (
        "website_app1_smtp_host",
        "website_app1_smtp_port",
        "website_app1_smtp_user",
        "website_app1_smtp_password",
    ),
}

# The one table of live homes, by input: the files are in CONFIG_DIR and are tried in order. The
# pager keys look in the pager's own file first (the unit loads it later, so it wins), then in
# monitoring.env, where the hand runbook put them before the role wrote the pager's file.
SOURCES: Final[dict[str, tuple[Source, ...]]] = {
    "monitoring_stack_smtp_username": (_env("monitoring.env", "SMTP_USERNAME"),),
    "monitoring_stack_smtp_password": (_env("monitoring.env", "SMTP_PASSWORD"),),
    "monitoring_stack_healthchecks_ping_url": (_env("monitoring.env", "HEALTHCHECKS_PING_URL"),),
    "monitoring_stack_alert_recipient_email": (_env("monitoring.env", "ALERT_RECIPIENT_EMAIL"),),
    "monitoring_stack_mailhost_ping_url": (_env("monitoring.env", "MAILHOST_PING_URL"),),
    "monitoring_stack_grafana_admin_password": (_env("monitoring.env", "GRAFANA_ADMIN_PASSWORD"),),
    "monitoring_stack_snds_data_url": (_env("monitoring.env", "SNDS_DATA_URL"),),
    "ntfy_pager_pager_token": (
        _env("ntfy-pager.env", "NTFY_PAGER_TOKEN"),
        _env("monitoring.env", "NTFY_PAGER_TOKEN"),
    ),
    "ntfy_pager_watcher_token": (
        _env("ntfy-pager.env", "NTFY_WATCHER_TOKEN"),
        _env("monitoring.env", "NTFY_WATCHER_TOKEN"),
    ),
    "ntfy_pager_owner_password_hash": (
        _env("ntfy-pager.env", "NTFY_OWNER_PASSWORD_HASH"),
        _env("monitoring.env", "NTFY_OWNER_PASSWORD_HASH"),
    ),
    "ntfy_pager_machine_password_hash": (
        _env("ntfy-pager.env", "NTFY_MACHINE_PASSWORD_HASH"),
        _env("monitoring.env", "NTFY_MACHINE_PASSWORD_HASH"),
    ),
    "backup_worker_db_host": (_env("backup-worker.env", "BACKUP_WORKER_DB_HOST"),),
    "backup_worker_db_user": (_env("backup-worker.env", "BACKUP_WORKER_MYSQL_USER"),),
    "backup_worker_db_password": (_env("backup-worker.env", "DB_DUMP_MYSQL_PWD"),),
    "backup_worker_db_ca_pem": (Source(WHOLE, "db1-ca.pem"),),
    "backup_worker_bucket": (_env("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_BUCKET"),),
    "backup_worker_s3_endpoint": (
        _env("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_ENDPOINT"),
    ),
    "backup_worker_s3_region": (_env("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_REGION"),),
    "backup_worker_s3_access_key_id": (
        _env("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_ACCESS_KEY_ID"),
    ),
    "backup_worker_s3_secret_access_key": (
        _env("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_SECRET_ACCESS_KEY"),
    ),
    "backup_worker_tenants": (Source(RECIPIENTS, "backup-worker-recipients"),),
    "backup_restore_state_copy_recipient": (_env("state-copy.env", "STATE_COPY_RECIPIENT"),),
    "backup_restore_state_copy_dest_access_key_id": (
        _env("state-copy.env", "STATE_COPY_DEST_ACCESS_KEY_ID"),
    ),
    "backup_restore_state_copy_estate_bucket": (
        _env("state-copy.env", "STATE_COPY_ESTATE_BUCKET"),
    ),
    "backup_restore_state_copy_estate_endpoint": (
        _env("state-copy.env", "STATE_COPY_ESTATE_ENDPOINT"),
    ),
    "backup_restore_state_copy_estate_region": (
        _env("state-copy.env", "STATE_COPY_ESTATE_REGION"),
    ),
    "backup_restore_state_copy_estate_access_key_id": (
        _env("state-copy.env", "STATE_COPY_ESTATE_ACCESS_KEY_ID"),
    ),
    "backup_restore_state_copy_tenant_bucket": (
        _env("state-copy.env", "STATE_COPY_TENANT_BUCKET"),
    ),
    "backup_restore_state_copy_tenant_endpoint": (
        _env("state-copy.env", "STATE_COPY_TENANT_ENDPOINT"),
    ),
    "backup_restore_state_copy_tenant_region": (
        _env("state-copy.env", "STATE_COPY_TENANT_REGION"),
    ),
    "backup_restore_state_copy_tenant_access_key_id": (
        _env("state-copy.env", "STATE_COPY_TENANT_ACCESS_KEY_ID"),
    ),
    "website_app1_smtp_host": (_env("website.env", "CONTACT_SMTP_HOST"),),
    "website_app1_smtp_port": (_env("website.env", "CONTACT_SMTP_PORT"),),
    "website_app1_smtp_user": (_env("website.env", "CONTACT_SMTP_USER"),),
    "website_app1_smtp_password": (_env("website.env", "CONTACT_SMTP_PASSWORD"),),
}

# Fixed texts. Nothing here ever holds a value: an error is a code, and a code is one of these.
MESSAGES: Final[dict[str, str]] = {
    "unknown-host": "this tool seeds edge1, ops1 or app1 only",
    "not-root": "must run as root",
    "directory": "a directory above the file is not a real directory owned by root and closed",
    "exists": "the inputs file appeared meanwhile and was not overwritten",
    "no-file": "the inputs file does not exist; run without --set first",
    "bad-file": "the inputs file is not a regular root:root 0600 file",
    "bad-content": "the inputs file is not one JSON object with keys inside this host's row",
    "bad-key": "that name is not in this host's row",
    "no-value": "no value was given",
    "read-back": "the file was written but did not read back as written; inspect it",
}
REASONS: Final[dict[str, str]] = {
    "src-type": "not a regular file",
    "src-owner": "not owned by root",
    "src-writable": "writable by others",
}


class SeedError(Exception):
    """A refusal; its code names a fixed message."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class Context:
    """What the tool touches, so a test can stand a temporary directory in for the host."""

    config_dir: Path
    ancestors: tuple[Path, ...]
    euid: int
    root_uid: int
    root_gid: int
    ask_secret: Callable[[str], str]
    ask_path: Callable[[str], str]
    out: TextIO
    err: TextIO


def production_context() -> Context:
    return Context(
        config_dir=Path(CONFIG_DIR),
        ancestors=tuple(Path(path) for path in ANCESTORS),
        euid=os.geteuid(),
        root_uid=ROOT_UID,
        root_gid=ROOT_GID,
        ask_secret=getpass.getpass,
        ask_path=input,
        out=sys.stdout,
        err=sys.stderr,
    )


def parse_env(text: str) -> tuple[dict[str, str], set[str]]:
    """The NAME=value lines of a file, each value raw after the first equals sign.

    Returns the values and the names that appear on more than one line.
    """
    values: dict[str, str] = {}
    duplicates: set[str] = set()
    for line in text.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator:
            continue
        if name in values:
            duplicates.add(name)
        values[name] = value
    return values, duplicates


def parse_tenant_line(line: str) -> dict[str, str] | None:
    slug, separator, recipient = line.partition(" ")
    if not separator or slug.split() != [slug] or recipient.split() != [recipient]:
        return None
    return {"slug": slug, "recipient": recipient}


def parse_recipients(text: str) -> list[dict[str, str]] | None:
    tenants: list[dict[str, str]] = []
    for line in text.split("\n"):
        if not line:
            continue
        tenant = parse_tenant_line(line)
        if tenant is None:
            return None
        tenants.append(tenant)
    return tenants


def is_certificate(text: str) -> bool:
    return (
        "-----BEGIN CERTIFICATE-----" in text
        and "-----END CERTIFICATE-----" in text
        and "PRIVATE KEY" not in text
    )


# Open without following a link, then judge the file that was opened, not the name. A source
# may be closed to its group or not; no source may be writable by group or others. The inputs
# file itself must be exactly root:root 0600.
def read_file(ctx: Context, path: Path, exact: bool) -> str:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SeedError("src-type")
        if info.st_uid != ctx.root_uid or (exact and info.st_gid != ctx.root_gid):
            raise SeedError("src-owner")
        if exact and stat.S_IMODE(info.st_mode) != FILE_MODE:
            raise SeedError("src-writable")
        if info.st_mode & 0o022:
            raise SeedError("src-writable")
        data = os.read(descriptor, MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_BYTES:
        raise SeedError("src-type")
    return data.decode("utf-8")


class Live:
    """The hand install's files, each read once; what cannot be used is noted by file and name."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.problems: list[str] = []
        self._texts: dict[str, str | None] = {}
        self._broken: set[str] = set()
        self._envs: dict[str, tuple[dict[str, str], set[str]]] = {}

    def flag(self, note: str) -> None:
        if note not in self.problems:
            self.problems.append(note)

    def text(self, filename: str) -> str | None:
        if filename in self._texts:
            return self._texts[filename]
        found: str | None = None
        try:
            found = read_file(self.ctx, self.ctx.config_dir / filename, exact=False)
        except FileNotFoundError:
            pass
        except SeedError as err:
            self._broken.add(filename)
            self.flag(f"{filename} ({REASONS[err.code]})")
        except (OSError, ValueError):
            self._broken.add(filename)
            self.flag(f"{filename} (link or unreadable)")
        self._texts[filename] = found
        return found

    # Three states: found, absent (try the next place), unusable (stop; the owner is asked).
    def lookup(self, source: Source) -> tuple[str, Value | None]:
        text = self.text(source.filename)
        if text is None:
            return ("unusable" if source.filename in self._broken else "absent"), None
        if source.kind == ENV:
            return self._env_value(text, source)
        if not text.strip():
            return "absent", None
        if source.kind == WHOLE:
            if is_certificate(text):
                return "found", text
            self.flag(f"{source.filename} (not a certificate)")
            return "unusable", None
        tenants = parse_recipients(text)
        if tenants is None:
            self.flag(f"{source.filename} (malformed)")
            return "unusable", None
        return ("found", tenants) if tenants else ("absent", None)

    def _env_value(self, text: str, source: Source) -> tuple[str, Value | None]:
        if source.filename not in self._envs:
            self._envs[source.filename] = parse_env(text)
        values, duplicates = self._envs[source.filename]
        if source.name in duplicates:
            self.flag(f"{source.filename} {source.name} (duplicate)")
            return "unusable", None
        value = values.get(source.name, "")
        return ("found", value) if value.strip() else ("absent", None)


def ask_certificate(ctx: Context, key: str) -> Value | None:
    try:
        path = ctx.ask_path(f"{key}: path of the PEM file holding the CA certificate: ")
        text = read_file(ctx, Path(path.strip()), exact=False)
    except (EOFError, OSError, ValueError, SeedError):
        return None
    return text if is_certificate(text) else None


def ask_tenants(ctx: Context, key: str) -> Value | None:
    tenants: list[dict[str, str]] = []
    while True:
        prompt = f"{key}: tenant as 'slug recipient' ({len(tenants)} so far), empty line to end: "
        try:
            line = ctx.ask_secret(prompt)
        except (EOFError, OSError):
            return None
        if not line.strip():
            return tenants or None
        tenant = parse_tenant_line(line.strip())
        if tenant is None:
            print("that line is not 'slug recipient'; try again", file=ctx.err)
        else:
            tenants.append(tenant)


def ask_for(ctx: Context, key: str) -> Value | None:
    kind = SOURCES[key][0].kind
    if kind == WHOLE:
        return ask_certificate(ctx, key)
    if kind == RECIPIENTS:
        return ask_tenants(ctx, key)
    try:
        answer = ctx.ask_secret(f"{key}: ")
    except (EOFError, OSError):
        return None
    if not answer.strip() or "\n" in answer or "\r" in answer:
        return None
    return answer


@dataclass
class Collected:
    values: dict[str, Value]
    live: list[str]
    typed: list[str]
    missing: list[str]
    problems: list[str]


def collect(ctx: Context, host: str) -> Collected:
    live = Live(ctx)
    found: dict[str, Value] = {}
    from_live: list[str] = []
    pending: list[str] = []
    for key in HOSTS[host]:
        for source in SOURCES[key]:
            state, value = live.lookup(source)
            if state == "found" and value is not None:
                found[key] = value
                from_live.append(key)
                break
            if state == "unusable":
                break
        if key not in found:
            pending.append(key)
    typed: list[str] = []
    missing: list[str] = []
    for key in pending:
        answer = ask_for(ctx, key)
        if answer is None:
            missing.append(key)
        else:
            found[key] = answer
            typed.append(key)
    ordered = {key: found[key] for key in HOSTS[host] if key in found}
    return Collected(ordered, from_live, typed, missing, live.problems)


def check_ancestors(ctx: Context) -> None:
    for path in ctx.ancestors:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ctx.root_uid or info.st_mode & 0o022:
            raise SeedError("directory")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view) :]


# The file is built beside its destination under a name only this run knows, closed to root
# before a byte is written, then put in place in one step: a hard link when nothing may be
# overwritten (it fails if the destination exists), a rename when --replace says so. The read-back
# compares the whole document, so a wrong key, value, owner or mode is found here.
def install(ctx: Context, document: dict[str, Value], replace: bool) -> None:
    destination = ctx.config_dir / DEST_NAME
    temporary = ctx.config_dir / f".{DEST_NAME}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(temporary, flags, FILE_MODE)
    try:
        try:
            os.fchmod(descriptor, FILE_MODE)
            os.fchown(descriptor, ctx.root_uid, ctx.root_gid)
            write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if replace:
            os.replace(temporary, destination)
        else:
            try:
                os.link(temporary, destination)
            except FileExistsError:
                raise SeedError("exists") from None
        fsync_directory(ctx.config_dir)
        read_back(ctx, destination, document)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def read_back(ctx: Context, destination: Path, document: dict[str, Value]) -> None:
    try:
        text = read_file(ctx, destination, exact=True)
        written = json.loads(text)
    except (OSError, ValueError, SeedError):
        raise SeedError("read-back") from None
    if written != document:
        raise SeedError("read-back")


def load_existing(ctx: Context, host: str) -> dict[str, Value]:
    try:
        text = read_file(ctx, ctx.config_dir / DEST_NAME, exact=True)
    except FileNotFoundError:
        raise SeedError("no-file") from None
    except (OSError, ValueError, SeedError):
        raise SeedError("bad-file") from None
    try:
        loaded = json.loads(text)
    except ValueError:
        raise SeedError("bad-content") from None
    if not isinstance(loaded, dict) or not set(loaded) <= set(HOSTS[host]):
        raise SeedError("bad-content")
    return {str(key): item for key, item in loaded.items()}


def names(listed: Sequence[str]) -> str:
    return ", ".join(listed) if listed else "none"


def run_fill(ctx: Context, host: str, replace: bool) -> int:
    destination = ctx.config_dir / DEST_NAME
    if not replace and os.path.lexists(destination):
        print(
            f"{destination} already exists; nothing read, nothing written. "
            "Run again with --replace to replace it.",
            file=ctx.out,
        )
        return 1
    collected = collect(ctx, host)
    print(f"seed_host_inputs: {host}", file=ctx.out)
    print(f"filled from live ({len(collected.live)}): {names(collected.live)}", file=ctx.out)
    print(f"typed ({len(collected.typed)}): {names(collected.typed)}", file=ctx.out)
    print(f"still missing ({len(collected.missing)}): {names(collected.missing)}", file=ctx.out)
    if collected.problems:
        notes = "; ".join(collected.problems)
        print(f"unusable live sources (treated as not found): {notes}", file=ctx.out)
    if collected.missing:
        print("nothing written; supply the missing keys and run again.", file=ctx.out)
        return 1
    install(ctx, collected.values, replace)
    print(f"written: {destination} (root:root 0600, {len(collected.values)} keys)", file=ctx.out)
    return 0


def size_of(value: Value) -> str:
    if isinstance(value, str):
        return f"{len(value.encode('utf-8'))} bytes"
    return f"{len(value)} entries"


def run_set(ctx: Context, host: str, key: str) -> int:
    if key not in HOSTS[host]:
        raise SeedError("bad-key")
    document = load_existing(ctx, host)
    value = ask_for(ctx, key)
    if value is None:
        raise SeedError("no-value")
    document[key] = value
    install(ctx, document, replace=True)
    destination = ctx.config_dir / DEST_NAME
    print(f"set {key} ({size_of(value)}) in {destination}", file=ctx.out)
    return 0


class QuietParser(argparse.ArgumentParser):
    """A parser whose errors never repeat an argument: one might be a value typed by mistake."""

    def __init__(self, stream: TextIO) -> None:
        super().__init__(
            prog="seed_host_inputs.py",
            description="Place or rotate the host's inputs file. Run on the host, as root.",
        )
        self.stream = stream

    def error(self, message: str) -> NoReturn:
        self.print_usage(self.stream)
        self.exit(2, "seed_host_inputs: unusable arguments (no value is ever an argument)\n")


def parse_args(argv: Sequence[str] | None, stream: TextIO) -> argparse.Namespace:
    parser = QuietParser(stream)
    parser.add_argument("--host", required=True, help="edge1, ops1 or app1")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--replace", action="store_true", help="replace an existing file")
    mode.add_argument("--set", dest="set_key", metavar="KEY", help="change one key, asked hidden")
    return parser.parse_args(argv)


def refuse_unless_ready(context: Context, host: str) -> None:
    if host not in HOSTS:
        raise SeedError("unknown-host")
    if context.euid != context.root_uid:
        raise SeedError("not-root")
    check_ancestors(context)


def main(argv: Sequence[str] | None = None, ctx: Context | None = None) -> int:
    context = ctx or production_context()
    args = parse_args(argv, context.err)
    try:
        refuse_unless_ready(context, args.host)
        if args.set_key is not None:
            return run_set(context, args.host, args.set_key)
        return run_fill(context, args.host, args.replace)
    except SeedError as err:
        print(f"seed_host_inputs: {MESSAGES.get(err.code, err.code)}", file=context.err)
        return 1
    except (OSError, ValueError) as err:
        print(f"seed_host_inputs: failed ({type(err).__name__})", file=context.err)
        return 1
    except KeyboardInterrupt:
        print("seed_host_inputs: interrupted", file=context.err)
        return 130


if __name__ == "__main__":
    sys.exit(main())
