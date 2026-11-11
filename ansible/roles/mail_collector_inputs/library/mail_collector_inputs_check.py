#!/usr/bin/python
"""Check the mail collector's root-only input file and that a host is named, returning no value.

The collector takes its drain credential, its submission credential and its dead-man's-switch
URL from one file the owner places by hand. This module reads that file and reports what is
wrong with it as fixed codes. It never returns, prints or logs a line, a value or a key's
text beyond the names of the keys the collector itself defines, so the task that calls it can
be shown although the file holds secrets.

It is read-only and runs in check mode, so the plan an approver reads says the same as an apply.
A file that is absent is not a fault: the collector is not meant to run until the owner places
it, and the module says so by returning ``present: false``.
"""

import errno
import os
import re
import stat
from dataclasses import dataclass, field

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: mail_collector_inputs_check
short_description: Check the mail collector's input file and that its drain list is not empty
description:
  - Reads the file at I(credentials_path) and returns fixed codes for what is wrong with it. A line,
    a value and a key outside the collector's own names are never returned.
  - Refuses a file that is not a regular file owned by root with mode 0600, in a directory that
    root owns and nobody else can write.
  - Requires the drain token, the dead-man's-switch URL and the submission user and password.
    Requires the URL to be a Healthchecks ping address and the token to be long enough.
  - Requires a host to be named once the file is present, because a collector with an empty drain
    list withholds every heartbeat ping and so pages. A host is named when I(descriptor_dir) holds
    a descriptor file or when I(declared_hosts) is above zero, because the role that writes
    descriptors runs after this check and a host the owner has listed has no file until it does.
  - An absent file is reported as I(present=false) with no problem.
version_added: "1.0.0"
author:
  - branchLeft
options:
  credentials_path:
    description: Absolute path of the owner-placed input file.
    type: path
    required: true
  descriptor_dir:
    description: Absolute path of the directory of descriptor files the collector drains from.
    type: path
    required: true
  declared_hosts:
    description: How many hosts the owner has listed for the collector to drain, a count only.
    type: int
    default: 0
attributes:
  check_mode:
    support: full
    description: The module only reads, in check mode and in an apply alike.
  diff_mode:
    support: none
    description: The file holds secrets, so no diff is shown.
"""

EXAMPLES = r"""
- name: Check the collector's inputs
  mail_collector_inputs_check:
    credentials_path: /etc/branchleft/mail-collector/credentials.env
    descriptor_dir: /etc/branchleft/mail-collector/descriptors
    declared_hosts: 1
  register: mail_collector_inputs_result
  no_log: true
  diff: false
"""

RETURN = r"""
present:
  description: Whether the input file exists.
  returned: success
  type: bool
problems:
  description: Fixed codes, each at most a key name the collector defines or a line number.
  returned: success
  type: list
  elements: str
descriptor_count:
  description: How many descriptor files the directory holds.
  returned: success
  type: int
"""

ROOT = 0
FILE_MODE = 0o600
GROUP_OTHER_WRITE = stat.S_IWGRP | stat.S_IWOTH
DRAIN_KEY = "COLLECTOR_DRAIN_TOKEN"
HEARTBEAT_URL = "COLLECTOR_HEARTBEAT_URL"
REQUIRED_KEYS = (
    DRAIN_KEY,
    HEARTBEAT_URL,
    "COLLECTOR_SMTP_USER",
    "COLLECTOR_SMTP_PASS",
)
MIN_TOKEN_LENGTH = 32
LINE = re.compile(r"(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>.*)\Z")
COLLECTOR_KEY = re.compile(r"COLLECTOR_[A-Z0-9_]+\Z")
# No whitespace, control character, quote, backslash, dollar sign or backtick: the runtime and
# Compose read an environment file differently on exactly those, so the owner avoids them.
VALUE_SHAPE = re.compile(r"[^\s\x00-\x1f\x7f\"'\\$`]+\Z")
TOKEN_SHAPE = re.compile(r"[A-Za-z0-9._~+/=-]+\Z")
# https://hc-ping.com/<uuid>, or https://hc-ping.com/<ping-key>/<slug>, and nothing after. The
# suffixes that report a start, a failure or a log line, or an exit status, are not the plain ping.
PING_URL = re.compile(
    r"https://hc-ping\.com/(?P<first>[A-Za-z0-9_-]{1,64})(?:/(?P<slug>[A-Za-z0-9_-]{1,64}))?\Z"
)
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
SIGNAL_SUFFIXES = frozenset({"start", "fail", "log"})
DESCRIPTOR_SUFFIX = ".json"

E_FILE = "file-mode"
E_DIRECTORY = "directory-mode"
E_READ = "file-unreadable"
E_LINE = "line-shape"
E_UNKNOWN = "unknown-key"
E_DUPLICATE = "duplicate-key"
E_MISSING = "missing-key"
E_VALUE = "value-shape"
E_URL = "heartbeat-url-shape"
E_SHORT = "drain-token-short"
E_NO_HOST = "no-host-named"
E_DESCRIPTORS = "descriptor-dir"


@dataclass
class Result:
    """What the check found. Codes only: nothing in it comes from a value."""

    present: bool = False
    problems: list[str] = field(default_factory=list)
    descriptor_count: int = 0


def directory_problem(path: str, owner_uid: int, owner_gid: int) -> bool:
    """Return True when the directory is not a real directory the owner holds alone."""
    try:
        info = os.lstat(path)
    except OSError:
        return True
    return (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or bool(info.st_mode & GROUP_OTHER_WRITE)
    )


def placed_by_owner(info: os.stat_result, owner_uid: int, owner_gid: int) -> bool:
    """Return True for a plain file with one name, the owner's, with mode 0600."""
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == owner_uid
        and info.st_gid == owner_gid
        and stat.S_IMODE(info.st_mode) == FILE_MODE
        and info.st_nlink == 1
    )


def read_lines(path: str, owner_uid: int, owner_gid: int) -> list[str] | None:
    """Return the file's lines, or None when it is not the file the owner must have placed.

    The file is opened without following a link and without blocking, and the descriptor, not
    the name, is inspected before a byte is read, so a swap between the two steps changes
    nothing and a file with the wrong owner or mode is never read.

    Raises:
        OSError: The file exists and cannot be opened or inspected.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            return None
        raise
    try:
        info = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    if not placed_by_owner(info, owner_uid, owner_gid):
        os.close(descriptor)
        return None
    with os.fdopen(descriptor, "rb") as handle:
        return handle.read().decode("utf-8", errors="replace").splitlines()


def parse(lines: list[str], problems: list[str]) -> dict[str, str]:
    """Return the key and value of each line, recording the lines that are not one.

    A blank line and a line that starts with a hash are skipped. A malformed line is
    reported by its number, never by its text.
    """
    found: dict[str, str] = {}
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if match is None:
            problems.append(f"{E_LINE}:{number}")
            continue
        key = match.group("key")
        if COLLECTOR_KEY.fullmatch(key) is None:
            problems.append(f"{E_UNKNOWN}:{number}")
            continue
        if key in found:
            problems.append(f"{E_DUPLICATE}:{key}")
            continue
        found[key] = match.group("value")
    return found


def is_plain_ping(url: str) -> bool:
    """Return True for a Healthchecks ping address that is not a start, fail or log signal."""
    match = PING_URL.fullmatch(url)
    if match is None:
        return False
    slug = match.group("slug")
    if UUID.fullmatch(match.group("first")) is not None:
        return slug is None
    return slug is not None and slug not in SIGNAL_SUFFIXES and not slug.isdigit()


def check_values(found: dict[str, str], problems: list[str]) -> None:
    """Record what is wrong with the keys the collector cannot run without."""
    for key in REQUIRED_KEYS:
        value = found.get(key, "")
        if not value:
            problems.append(f"{E_MISSING}:{key}")
        elif VALUE_SHAPE.fullmatch(value) is None:
            problems.append(f"{E_VALUE}:{key}")
    token = found.get(DRAIN_KEY, "")
    if token and VALUE_SHAPE.fullmatch(token) is not None:
        if TOKEN_SHAPE.fullmatch(token) is None:
            problems.append(f"{E_VALUE}:{DRAIN_KEY}")
        elif len(token) < MIN_TOKEN_LENGTH:
            problems.append(E_SHORT)
    url = found.get(HEARTBEAT_URL, "")
    if url and not is_plain_ping(url):
        problems.append(E_URL)


def count_descriptors(directory: str) -> int | None:
    """Count the plain ``.json`` files in the directory, or None when it cannot be listed."""
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return None
    return sum(
        1
        for entry in entries
        if entry.name.endswith(DESCRIPTOR_SUFFIX) and entry.is_file(follow_symlinks=False)
    )


def check_inputs(
    credentials_path: str,
    descriptor_dir: str,
    *,
    declared_hosts: int = 0,
    owner_uid: int = ROOT,
    owner_gid: int = ROOT,
) -> Result:
    """Check the input file and the descriptor directory, and return codes only."""
    result = Result()
    if not os.path.lexists(credentials_path):
        return result
    result.present = True
    if directory_problem(os.path.dirname(credentials_path), owner_uid, owner_gid):
        result.problems.append(E_DIRECTORY)
    try:
        lines = read_lines(credentials_path, owner_uid, owner_gid)
    except OSError:
        result.problems.append(E_READ)
        return result
    if lines is None:
        result.problems.append(E_FILE)
        return result
    found = parse(lines, result.problems)
    check_values(found, result.problems)
    count = count_descriptors(descriptor_dir)
    if count is None:
        result.problems.append(E_DESCRIPTORS)
    else:
        result.descriptor_count = count
        if HEARTBEAT_URL in found and count == 0 and declared_hosts <= 0:
            result.problems.append(E_NO_HOST)
    return result


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(
        argument_spec={
            "credentials_path": {"type": "path", "required": True},
            "descriptor_dir": {"type": "path", "required": True},
            "declared_hosts": {"type": "int", "default": 0},
        },
        supports_check_mode=True,
    )
    credentials_path = str(module.params["credentials_path"])
    descriptor_dir = str(module.params["descriptor_dir"])
    if not os.path.isabs(credentials_path) or not os.path.isabs(descriptor_dir):
        module.fail_json(msg="mail_collector_inputs_check: both paths must be absolute")
    try:
        result = check_inputs(
            credentials_path, descriptor_dir, declared_hosts=int(module.params["declared_hosts"])
        )
    except OSError as error:
        # The errno name only: a fixed code finds the cause without naming a line.
        name = errno.errorcode.get(error.errno or 0, "UNKNOWN")
        module.fail_json(msg=f"mail_collector_inputs_check: io {name}")
    module.exit_json(
        changed=False,
        present=result.present,
        problems=result.problems,
        descriptor_count=result.descriptor_count,
    )


if __name__ == "__main__":
    main()
