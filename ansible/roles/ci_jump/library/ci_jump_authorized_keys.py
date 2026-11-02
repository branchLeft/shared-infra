#!/usr/bin/python
"""Read and judge the authorized_keys options of the CI jump account.

This is the one home of every rule about the jump account's key lines. It never writes: the
role writes the file with ansible.posix.authorized_key and asks this module to judge the
inputs before the write (plan) and the file after it (verify). A third action (report) only
describes what the host holds today, so a first run can be read before anything is enabled.

Everything it prints is built from a closed vocabulary: option names, a host name or address
and a port, a key type and a short fingerprint. Key bodies, comment fields and every other
option value are never printed, and no refusal carries a value, only a code and an entry
number. A last guard withholds any line that would read as a credential assignment to the
plan scan (SCAN_PATTERN), so the plan of a host is never withheld because of this module.
"""

import base64
import binascii
import dataclasses
import hashlib
import os
import pwd
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: ci_jump_authorized_keys
short_description: Judge the CI jump account's authorized_keys options
description:
  - C(report) lists every local account whose key files carry forwarding options, with the
    options, a key type and a short fingerprint per line. It needs no input and changes nothing.
  - C(plan) refuses inputs and a host the role must not write to, and shows the live lines
    against the wanted ones, destination by destination.
  - C(verify) reads the file back after the write and compares it with the wanted lines exactly.
  - Never writes. Never prints a key body, a comment or an option value other than the
    destinations.
version_added: "1.0.0"
author:
  - branchLeft
options:
  action:
    description: What to do.
    type: str
    required: true
    choices: [report, plan, verify]
  user:
    description: The jump account. Needed by plan and verify.
    type: str
    default: ""
  destinations:
    description: Host names or IPv4 addresses, with no port. Needed by plan and verify.
    type: list
    elements: raw
    default: []
  keys:
    description: Public keys, one per entry. Needed by plan and verify.
    type: list
    elements: raw
    default: []
  owned_accounts:
    description: Accounts another role owns, by role name. The jump account may not be one.
    type: dict
    default: {}
attributes:
  check_mode:
    support: full
    description: The module only reads.
  diff_mode:
    support: none
    description: No diff is produced.
"""

EXAMPLES = r"""
- name: Describe the forwarding options on the host
  ci_jump_authorized_keys:
    action: report
    owned_accounts: {root: root}
"""

RETURN = r"""
changed:
  description: Always false.
  returned: always
  type: bool
lines:
  description: The text to show in the plan, one entry per line.
  returned: success
  type: list
  elements: str
"""

# What the written lines are made of. The role's vars/main.yml holds the same two values for
# its template; ansible/checks/test_ci_jump_pins.py holds the two copies equal.
PINNED_PORT = 22
PINNED_FIXED_OPTIONS = ("restrict", "port-forwarding")
# A shell whose last path word is one of these cannot run a remote command.
REFUSED_SHELL_NAMES = frozenset(("nologin", "false"))
# The connection sshd -T evaluates Match blocks for. The jump key is used from runners that
# have no fixed address, so a Match block keyed on a real address is not seen (README).
STAND_IN_HOST = "ci-jump-check.invalid"
STAND_IN_ADDRESS = "192.0.2.1"
SSHD_PATH = "/usr/sbin/sshd"
DEFAULT_KEY_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")
MANAGED_KEY_FILE = ".ssh/authorized_keys"
MAX_FILE_BYTES = 1_000_000

# Copied from the plan scan of the gated apply: branchLeft/github-workflows,
# .github/actions/ssh-check-hosts/action.yml, the credential-assignment row of `patterns`
# (line 434 at tag v1.0.19), which that action applies with grep -Ei to each line of a host's
# plan. [[:space:]] is written \s. Drift from the original is unchecked until
# branchLeft/shared-infra#574 lands a test that holds the two equal; then this copy is
# replaced by an import of its constant.
SCAN_PATTERN = re.compile(
    r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
    r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
    re.IGNORECASE,
)
WITHHELD_LINE = "a line was withheld because it would read as a credential assignment"

# key type -> the length of each length-prefixed field after the type (None: any length).
KEY_FIELDS: Mapping[str, tuple[int | None, ...]] = {
    "ssh-ed25519": (32,),
    "ssh-rsa": (None, None),
    "ecdsa-sha2-nistp256": (None, None),
    "ecdsa-sha2-nistp384": (None, None),
    "ecdsa-sha2-nistp521": (None, None),
    "sk-ssh-ed25519@openssh.com": (32, None),
    "sk-ecdsa-sha2-nistp256@openssh.com": (None, None, None),
}
# Option names printed by name. Any other name is counted, and its name is not printed.
KNOWN_OPTIONS = frozenset(
    (
        "restrict",
        "port-forwarding",
        "no-port-forwarding",
        "permitopen",
        "permitlisten",
        "command",
        "environment",
        "from",
        "no-pty",
        "pty",
        "agent-forwarding",
        "no-agent-forwarding",
        "x11-forwarding",
        "no-x11-forwarding",
        "user-rc",
        "no-user-rc",
        "cert-authority",
        "principals",
        "tunnel",
        "expiry-time",
        "verify-required",
        "no-touch-required",
    )
)
USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
HOST_LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
BASE64_BODY = re.compile(r"[A-Za-z0-9+/]+={0,2}")
UNSAFE_PRINT = re.compile(r"[^A-Za-z0-9_./%@+-]")
OWNER_LABEL = re.compile(r"[a-z][a-z0-9_]{0,31}")


class RefusalError(Exception):
    """A refusal: a code, then words that carry no value from the inputs or the host."""

    def __init__(self, code: str, words: str) -> None:
        super().__init__(f"{code}: {words}")


class HostError(Exception):
    """The host could not answer (sshd -T failed). Carries no output."""


@dataclasses.dataclass(frozen=True)
class Account:
    """One local account, as the passwd database holds it."""

    name: str
    uid: int
    home: str
    shell: str


@dataclasses.dataclass(frozen=True)
class KeyLine:
    """One parsed key line. The key body is held only to fingerprint it and is never printed."""

    options_text: str
    options: tuple[tuple[str, str | None], ...]
    key_type: str
    body: str
    text: str


class Host(Protocol):
    """What the module needs from the machine it runs on, so a test can supply a fake."""

    def accounts(self) -> list[Account]:
        """Every local account."""
        ...

    def read(self, path: str) -> str | None:
        """The text of a file, or None when it is absent, too large or unreadable."""
        ...

    def sshd_test(self, user: str | None) -> dict[str, list[str]]:
        """The effective sshd settings, keyword to values, for a stand-in connection of user."""
        ...


# ---------------------------------------------------------------------------------------
# Printing: a closed vocabulary only.


def clean(value: str, limit: int = 80) -> str:
    """Return value with every character outside a small safe set replaced, and shortened."""
    return UNSAFE_PRINT.sub("?", value)[:limit]


def safe_line(line: str) -> str:
    """Return the line, or a fixed notice when the plan scan would read it as a credential."""
    return WITHHELD_LINE if SCAN_PATTERN.search(line) else line


def fingerprint(body: str) -> str:
    """Return twelve characters of the SHA-256 fingerprint of a key body, as ssh-keygen shows it."""
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return "unreadable"
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return digest[:12]


def _split_options(text: str) -> list[str]:
    """Split an option string on commas that are not inside double quotes."""
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\" and in_quote:
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            in_quote = not in_quote
        elif char == "," and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _option_token_end(line: str) -> int:
    """Return where the option string of a key line ends: the first space outside quotes."""
    in_quote = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and in_quote:
            escaped = True
        elif char == '"':
            in_quote = not in_quote
        elif char in " \t" and not in_quote:
            return index
    return len(line)


def parse_line(line: str) -> KeyLine | None:
    """Parse one authorized_keys line, or return None for a blank, a comment or a line this
    module does not understand."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    first = stripped.split(None, 1)[0]
    if first in KEY_FIELDS:
        options_text, rest = "", stripped
    else:
        end = _option_token_end(stripped)
        options_text, rest = stripped[:end], stripped[end:].strip()
    fields = rest.split(None, 2)
    if len(fields) < 2 or fields[0] not in KEY_FIELDS or not BASE64_BODY.fullmatch(fields[1]):
        return None
    options: list[tuple[str, str | None]] = []
    if options_text:
        for part in _split_options(options_text):
            name, separator, value = part.partition("=")
            if not name:
                return None
            quoted = value[1:-1] if value.startswith('"') and value.endswith('"') else value
            options.append((name.lower(), quoted if separator else None))
    return KeyLine(options_text, tuple(options), fields[0], fields[1], stripped)


def parse_file(text: str) -> tuple[list[KeyLine], int]:
    """Return the key lines of a file, and how many lines were neither blank, comment nor key."""
    found: list[KeyLine] = []
    not_understood = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parsed = parse_line(line)
        if parsed is None:
            not_understood += 1
        else:
            found.append(parsed)
    return found, not_understood


def permitopen_set(line: KeyLine) -> frozenset[str]:
    """The permitopen values of a line, as written."""
    return frozenset(value for name, value in line.options if name == "permitopen" and value)


def describe_options(line: KeyLine) -> str:
    """Name each option of a line. Only a permitopen or permitlisten value is shown, as a host
    and a port in words; the value of every other option is never shown."""
    shown: list[str] = []
    unknown = 0
    for name, value in line.options:
        if name in ("permitopen", "permitlisten"):
            host, _, port = (value or "").rpartition(":")
            shown.append(f"{name} {clean(host)} port {clean(port, 8)}")
        elif name in KNOWN_OPTIONS:
            shown.append(name)
        else:
            unknown += 1
    if unknown:
        shown.append(f"{unknown} option(s) with a name not in the vocabulary")
    return ", ".join(shown) if shown else "no options"


# ---------------------------------------------------------------------------------------
# The inputs.


def check_user(user: object, owned: Mapping[str, str]) -> str:
    """Return the account name, or refuse a name that is empty, malformed or owned elsewhere.

    Raises:
        RefusalError: for each of those.
    """
    if not isinstance(user, str) or not user:
        raise RefusalError("E-USER-EMPTY", "no jump account is named")
    if not USER_PATTERN.fullmatch(user):
        raise RefusalError("E-USER-SHAPE", "the jump account name is not a plain account name")
    if user in owned.values():
        raise RefusalError("E-USER-FORBIDDEN", "the jump account is owned by another role")
    return user


def _destination_shape(entry: str, number: int) -> None:
    """Refuse a destination that is not one host name or one IPv4 address with no port.

    Raises:
        RefusalError: with a code for each way a destination can be wrong.
    """
    where = f"destination {number}"
    if '"' in entry or "'" in entry or "\\" in entry:
        raise RefusalError("E-DEST-QUOTE", f"{where} holds a quote")
    if "*" in entry or "?" in entry:
        raise RefusalError("E-DEST-WILDCARD", f"{where} holds a wildcard")
    if "," in entry:
        raise RefusalError("E-DEST-COMMA", f"{where} holds a comma")
    if not entry.isprintable() or any(char.isspace() for char in entry):
        raise RefusalError("E-DEST-SPACE", f"{where} holds a space or a control character")
    if "[" in entry or "]" in entry or entry.count(":") > 1:
        raise RefusalError("E-DEST-IPV6", f"{where} is an IPv6 form, which the role does not take")
    if ":" in entry:
        raise RefusalError(
            "E-DEST-PORT", f"{where} holds a port; the role's own port is the only one"
        )
    labels = entry.split(".")
    numeric = all(label.isdigit() for label in labels)
    if numeric:
        if len(labels) != 4 or any(len(label) > 3 or int(label) > 255 for label in labels):
            raise RefusalError("E-DEST-SHAPE", f"{where} is not an IPv4 address or a host name")
    elif len(entry) > 253 or not all(HOST_LABEL.fullmatch(label) for label in labels):
        raise RefusalError("E-DEST-SHAPE", f"{where} is not an IPv4 address or a host name")


def check_destinations(destinations: object) -> list[str]:
    """Return the destinations, or refuse an empty list, a wrong entry or a duplicate.

    Raises:
        RefusalError: for each of those.
    """
    if not isinstance(destinations, list) or not destinations:
        raise RefusalError(
            "E-DEST-EMPTY", "the destination list is empty and is never read as allow-all"
        )
    found: list[str] = []
    for number, entry in enumerate(destinations, start=1):
        if not isinstance(entry, str):
            raise RefusalError("E-DEST-TYPE", f"destination {number} is not text")
        _destination_shape(entry, number)
        if entry.lower() in (previous.lower() for previous in found):
            raise RefusalError("E-DEST-DUPLICATE", f"destination {number} repeats an earlier one")
        found.append(entry)
    return found


def _key_parts(key: str) -> tuple[str, str] | None:
    """Return (type, body) for one plain public key line, or None for any other shape."""
    if not key.isascii() or not key.isprintable():
        return None
    fields = key.split(" ")
    if len(fields) < 2 or fields[0] not in KEY_FIELDS or not BASE64_BODY.fullmatch(fields[1]):
        return None
    key_type, body = fields[0], fields[1]
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None
    pieces: list[bytes] = []
    index = 0
    while index < len(raw):
        if index + 4 > len(raw):
            return None
        length = int.from_bytes(raw[index : index + 4], "big")
        index += 4
        if length > len(raw) - index:
            return None
        pieces.append(raw[index : index + length])
        index += length
    expected = KEY_FIELDS[key_type]
    if len(pieces) != len(expected) + 1 or pieces[0] != key_type.encode("ascii"):
        return None
    for piece, size in zip(pieces[1:], expected, strict=True):
        if not piece or (size is not None and len(piece) != size):
            return None
    if key_type.startswith("ecdsa-sha2-") and pieces[1] != key_type[len("ecdsa-sha2-") :].encode():
        return None
    return key_type, body


def check_keys(keys: object) -> list[tuple[str, str]]:
    """Return (type, body) for each key, or refuse an empty list, a wrong shape or a repeat.

    Raises:
        RefusalError: for each of those.
    """
    if not isinstance(keys, list) or not keys:
        raise RefusalError("E-KEY-EMPTY", "the key list is empty and is never read as remove-all")
    found: list[tuple[str, str]] = []
    for number, entry in enumerate(keys, start=1):
        if not isinstance(entry, str):
            raise RefusalError("E-KEY-TYPE", f"key {number} is not text")
        parts = _key_parts(entry)
        if parts is None:
            raise RefusalError("E-KEY-SHAPE", f"key {number} is not one public key of a known type")
        if parts in found:
            raise RefusalError("E-KEY-DUPLICATE", f"key {number} repeats an earlier one")
        found.append(parts)
    return found


def wanted_options(destinations: Sequence[str]) -> str:
    """The options of every line the role writes: the fixed pair, then one permitopen each."""
    return ",".join(
        [*PINNED_FIXED_OPTIONS, *(f'permitopen="{item}:{PINNED_PORT}"' for item in destinations)]
    )


def wanted_lines(destinations: Sequence[str], keys: Sequence[tuple[str, str]]) -> list[str]:
    """The exact lines the file must hold: options, key type, key body, nothing else."""
    options = wanted_options(destinations)
    return [f"{options} {key_type} {body}" for key_type, body in keys]


# ---------------------------------------------------------------------------------------
# The host.


def expand_key_file(token: str, account: Account) -> str | None:
    """Expand one AuthorizedKeysFile token for an account as sshd does, or None when it holds
    a token this module does not know."""
    out: list[str] = []
    index = 0
    while index < len(token):
        char = token[index]
        if char != "%":
            out.append(char)
            index += 1
            continue
        code = token[index + 1 : index + 2]
        replacement = {"%": "%", "h": account.home, "u": account.name, "U": str(account.uid)}.get(
            code
        )
        if replacement is None:
            return None
        out.append(replacement)
        index += 2
    path = "".join(out)
    return os.path.normpath(path if os.path.isabs(path) else os.path.join(account.home, path))


def key_files(settings: Mapping[str, list[str]], account: Account) -> list[str]:
    """The key files sshd reads for an account, from the AuthorizedKeysFile setting."""
    patterns = [
        pattern for line in settings.get("authorizedkeysfile", []) for pattern in line.split()
    ] or list(DEFAULT_KEY_FILES)
    paths: list[str] = []
    for pattern in patterns:
        if pattern == "none":
            continue
        path = expand_key_file(pattern, account)
        if path is not None and path not in paths:
            paths.append(path)
    return paths


def find_account(host: Host, name: str) -> Account | None:
    """The account with this name, or None."""
    for account in host.accounts():
        if account.name == name:
            return account
    return None


def check_account(account: Account | None) -> Account:
    """Refuse an account that is absent or has a shell that can run a command.

    Raises:
        RefusalError: for each of those.
    """
    if account is None:
        raise RefusalError(
            "E-USER-ABSENT", "the jump account is not on this host; the role never makes it"
        )
    if os.path.basename(account.shell) not in REFUSED_SHELL_NAMES:
        raise RefusalError(
            "E-USER-SHELL",
            "the jump account has a shell that can run a remote command; the role leaves it",
        )
    return account


def check_sshd(host: Host, account: Account) -> list[str]:
    """Refuse an sshd that would let a key line be bypassed or voided, and return the key files.

    Raises:
        RefusalError: for each way the effective settings for the account defeat the key line.
    """
    try:
        settings = host.sshd_test(account.name)
    except HostError:
        raise RefusalError("E-SSHD-UNAVAILABLE", "sshd -T could not be read") from None
    forwarding = settings.get("allowtcpforwarding", ["yes"])[-1].split()[0]
    disabled = settings.get("disableforwarding", ["no"])[-1].split()[0]
    if forwarding in ("no", "remote") or disabled == "yes":
        raise RefusalError(
            "E-SSHD-FORWARDING", "sshd switches TCP forwarding off for the jump account"
        )
    if [value.strip() for value in settings.get("authorizedkeyscommand", ["none"])] != ["none"]:
        raise RefusalError(
            "E-SSHD-KEYSCOMMAND",
            "sshd runs a keys command for the jump account, which could add keys",
        )
    if [value.strip() for value in settings.get("permitopen", ["any"])] != ["any"]:
        raise RefusalError(
            "E-SSHD-PERMITOPEN", "sshd sets a PermitOpen of its own; the key line is the one home"
        )
    files = key_files(settings, account)
    managed = os.path.normpath(os.path.join(account.home, MANAGED_KEY_FILE))
    if managed not in files:
        raise RefusalError("E-SSHD-FILE", "sshd does not read the file the role manages")
    for path in files:
        if path == managed:
            continue
        other = host.read(path)
        if other is not None and parse_file(other)[0]:
            raise RefusalError(
                "E-SSHD-KEYS2", "a second key file sshd reads for the jump account holds key lines"
            )
    return files


def plan_lines(
    account: Account,
    host: Host,
    destinations: Sequence[str],
    keys: Sequence[tuple[str, str]],
) -> list[str]:
    """Show the live key lines against the wanted ones, destination by destination."""
    managed = os.path.normpath(os.path.join(account.home, MANAGED_KEY_FILE))
    text = host.read(managed)
    live, not_understood = parse_file(text) if text is not None else ([], 0)
    wanted = wanted_options(destinations)
    out = [
        f"ci_jump plan for account {clean(account.name)}, every key line wanted with the options"
        f" {', '.join(PINNED_FIXED_OPTIONS)} and one permitopen per destination",
        f"live file has {len(live)} key line(s) and {not_understood} line(s) not understood"
        if text is not None
        else "live file is absent and would be created",
    ]
    live_destinations: list[str] = []
    for line in live:
        for value in sorted(permitopen_set(line)):
            host_part = value.rpartition(":")[0]
            if host_part not in live_destinations:
                live_destinations.append(host_part)
    for item in destinations:
        live_now = "yes" if item in live_destinations else "no"
        out.append(f"destination {item} port {PINNED_PORT} live {live_now} wanted yes")
    for item in live_destinations:
        if item not in destinations:
            out.append(f"destination {clean(item)} live yes wanted no, so it would be removed")
    wanted_fps = {fingerprint(body): (key_type, body) for key_type, body in keys}
    live_by_fp = {fingerprint(line.body): line for line in live}
    for fp, (key_type, _) in wanted_fps.items():
        found = live_by_fp.get(fp)
        if found is None:
            out.append(f"key {key_type} fingerprint {fp} live no wanted yes")
        else:
            same = found.options_text == wanted
            out.append(
                f"key {key_type} fingerprint {fp} live yes wanted yes, live options"
                f" {'match' if same else 'differ from'} the wanted options"
            )
    for fp, line in live_by_fp.items():
        if fp not in wanted_fps:
            out.append(
                f"key {line.key_type} fingerprint {fp} live yes wanted no, so it would be removed"
            )
    return [safe_line(item) for item in out]


def do_plan(
    host: Host, user: object, destinations: object, keys: object, owned: Mapping[str, str]
) -> list[str]:
    """Judge the inputs, then the host, and show live against wanted.

    Raises:
        RefusalError: for the first rule that is broken, inputs before host.
    """
    name = check_user(user, owned)
    dests = check_destinations(destinations)
    parsed_keys = check_keys(keys)
    account = check_account(find_account(host, name))
    check_sshd(host, account)
    return plan_lines(account, host, dests, parsed_keys)


def do_verify(
    host: Host, user: object, destinations: object, keys: object, owned: Mapping[str, str]
) -> list[str]:
    """Read the file back and compare it with the wanted lines exactly, and read sshd again.

    Raises:
        RefusalError: when the file is not exactly the wanted lines, or the host is refused.
    """
    name = check_user(user, owned)
    dests = check_destinations(destinations)
    parsed_keys = check_keys(keys)
    account = check_account(find_account(host, name))
    check_sshd(host, account)
    managed = os.path.normpath(os.path.join(account.home, MANAGED_KEY_FILE))
    text = host.read(managed)
    if text is None:
        raise RefusalError("E-READBACK-MISMATCH", "the managed file cannot be read back")
    live = sorted(line.strip() for line in text.splitlines() if line.strip())
    if live != sorted(wanted_lines(dests, parsed_keys)):
        raise RefusalError(
            "E-READBACK-MISMATCH", "the managed file is not exactly the wanted lines"
        )
    return [
        f"ci_jump read back {len(live)} key line(s) for account {clean(account.name)}, each exactly"
        f" the wanted options for {len(dests)} destination(s) on port {PINNED_PORT}"
    ]


# ---------------------------------------------------------------------------------------
# The report.


def _setting(settings: Mapping[str, list[str]], keyword: str, default: str, limit: int = 40) -> str:
    """One sshd setting as printable words: every value it printed, joined, and shortened."""
    words = " ".join(settings.get(keyword, [default])).split()
    return " ".join(clean(word, limit) for word in words)[:limit]


def _forwarding_summary(settings: Mapping[str, list[str]]) -> str:
    return (
        "sshd for this account"
        f" AuthorizedKeysCommand {_setting(settings, 'authorizedkeyscommand', 'none')},"
        f" AuthorizedKeysFile {_setting(settings, 'authorizedkeysfile', '', 160)},"
        f" AllowTcpForwarding {_setting(settings, 'allowtcpforwarding', 'yes', 12)},"
        f" DisableForwarding {_setting(settings, 'disableforwarding', 'no', 12)},"
        f" PermitOpen {_setting(settings, 'permitopen', 'any')}"
    )


def do_report(host: Host, owned: Mapping[str, str]) -> tuple[list[str], list[dict[str, object]]]:
    """Describe the accounts whose key lines carry forwarding options. Reads, never writes."""
    out = ["ci_jump report, read only, nothing was changed"]
    try:
        global_settings: dict[str, list[str]] = host.sshd_test(None)
    except HostError:
        global_settings = {}
        out.append("sshd -T could not be read, so the default key files are assumed")
    else:
        out.append(
            "sshd globally"
            f" AuthorizedKeysCommand {_setting(global_settings, 'authorizedkeyscommand', 'none')},"
            f" AuthorizedKeysFile {_setting(global_settings, 'authorizedkeysfile', '', 160)}"
        )
    owner_of = {name: role for role, name in owned.items()}
    structured: list[dict[str, object]] = []
    for account in sorted(host.accounts(), key=lambda item: item.name):
        carrying: list[tuple[str, KeyLine]] = []
        for path in key_files(global_settings, account):
            text = host.read(path)
            if text is None:
                continue
            lines, _ = parse_file(text)
            carrying.extend(
                (os.path.basename(path), line)
                for line in lines
                if {name for name, _ in line.options}
                & {"permitopen", "port-forwarding", "permitlisten"}
            )
        if not carrying:
            continue
        sets = {permitopen_set(line) for _, line in carrying}
        owner = owner_of.get(account.name, "none")
        shown = clean(account.name)
        out.append(
            f"account {shown} shell {clean(account.shell)} owned by role {clean(owner, 32)},"
            f" {len(carrying)} key line(s) with forwarding options"
        )
        for number, (label, line) in enumerate(carrying, start=1):
            out.append(
                f"account {shown} line {number} in {clean(label, 40)} key {line.key_type}"
                f" fingerprint {fingerprint(line.body)} options {describe_options(line)}"
            )
        same = "yes" if len(sets) == 1 else "no"
        out.append(f"account {shown} all key lines carry the same permitopen set {same}")
        try:
            out.append(_forwarding_summary(host.sshd_test(account.name)))
        except HostError:
            out.append("sshd could not be evaluated for this account")
        structured.append(
            {
                "account": account.name,
                "shell": account.shell,
                "owner": owner,
                "lines": len(carrying),
                "same_permitopen": len(sets) == 1,
            }
        )
    if not structured:
        out.append("no account has key lines with forwarding options")
    return [safe_line(item) for item in out], structured


# ---------------------------------------------------------------------------------------
# The real host and the module.


class RealHost:
    """The machine the module runs on."""

    def __init__(self, run: Callable[[list[str]], tuple[int, str]]) -> None:
        self._run = run

    def accounts(self) -> list[Account]:
        """Every account in the passwd database."""
        return [
            Account(item.pw_name, item.pw_uid, item.pw_dir, item.pw_shell)
            for item in pwd.getpwall()
        ]

    def read(self, path: str) -> str | None:
        """Read a file as text, or None when it is absent, too large or unreadable."""
        try:
            target = Path(path)
            if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
                return None
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def sshd_test(self, user: str | None) -> dict[str, list[str]]:
        """Run sshd -T, with a stand-in connection when a user is given.

        Raises:
            HostError: when sshd cannot print its settings.
        """
        command = [SSHD_PATH, "-T"]
        if user is not None:
            command += ["-C", f"user={user},host={STAND_IN_HOST},addr={STAND_IN_ADDRESS}"]
        code, output = self._run(command)
        if code != 0:
            raise HostError
        settings: dict[str, list[str]] = {}
        for line in output.splitlines():
            keyword, _, value = line.strip().partition(" ")
            if keyword:
                settings.setdefault(keyword.lower(), []).append(value.strip())
        return settings


ARGUMENT_SPEC: dict[str, dict[str, object]] = {
    "action": {"type": "str", "required": True, "choices": ["report", "plan", "verify"]},
    "user": {"type": "str", "default": ""},
    "destinations": {"type": "list", "elements": "raw", "default": []},
    "keys": {"type": "list", "elements": "raw", "default": [], "no_log": True},
    "owned_accounts": {"type": "dict", "default": {}},
}


def owned_from(value: object) -> dict[str, str]:
    """The owned-accounts mapping, with role names and account names held to a plain shape.

    Raises:
        RefusalError: when the mapping is not role name to account name.
    """
    if not isinstance(value, dict):
        raise RefusalError("E-OWNED-SHAPE", "owned_accounts is not a mapping")
    found: dict[str, str] = {}
    for role, name in value.items():
        if not isinstance(role, str) or not isinstance(name, str):
            raise RefusalError("E-OWNED-SHAPE", "owned_accounts holds a value that is not text")
        if not OWNER_LABEL.fullmatch(role) or not USER_PATTERN.fullmatch(name):
            raise RefusalError("E-OWNED-SHAPE", "owned_accounts holds a name of the wrong shape")
        found[role] = name
    return found


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)

    def run(command: list[str]) -> tuple[int, str]:
        code, stdout, _ = module.run_command(command, check_rc=False)
        return code, stdout

    host = RealHost(run)
    params = module.params
    try:
        owned = owned_from(params["owned_accounts"])
        action = params["action"]
        if action == "report":
            lines, accounts = do_report(host, owned)
            module.exit_json(changed=False, lines=lines, accounts=accounts)
        elif action == "plan":
            lines = do_plan(host, params["user"], params["destinations"], params["keys"], owned)
            module.exit_json(changed=False, lines=lines)
        else:
            lines = do_verify(host, params["user"], params["destinations"], params["keys"], owned)
            module.exit_json(changed=False, lines=lines)
    except RefusalError as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
