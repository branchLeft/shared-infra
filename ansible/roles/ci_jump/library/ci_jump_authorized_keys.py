#!/usr/bin/python
"""Read and judge what the CI jump account's sshd drop-in and root-owned key file must hold.

This is the one home of every rule about the jump account's key lines and its sshd Match block.
It never writes: the role writes the two files and asks this module to judge the inputs before
the write (plan) and the host after it (verify). A third action (report) only describes what
the host holds today, so a plan can be read before anything is enabled.

Everything it prints is built from a closed vocabulary: option names, a host name or address and
a port, a key type, a short fingerprint, a per-account index and the class of a shell. No account
name is ever printed (the name of the jump account is held out of the public log), key bodies,
comment fields and every other option value are never printed, and no refusal carries a value,
only a code and an entry number. A last guard withholds any line that would read as a credential
assignment to the plan scan (SCAN_PATTERN), so the plan of a host is never withheld because of
this module.
"""

import base64
import binascii
import dataclasses
import hashlib
import ipaddress
import os
import pwd
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: ci_jump_authorized_keys
short_description: Judge the CI jump account's sshd drop-in and key file
description:
  - C(report) describes, with no account name, the local accounts whose key files carry
    forwarding options, found per account with C(sshd -T -C), and says for each destination
    whether it is in the owner's list. It changes nothing.
  - C(plan) refuses inputs and a host the role must not write to, and shows the live key file
    and sshd settings against the wanted ones, destination by destination.
  - C(verify) reads both files back after the write, compares them with the wanted text
    exactly, and requires sshd's own answer for the account to be exactly what the role means.
  - Never writes. Never prints an account name, a key body, a comment or an option value other
    than the destinations.
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
    description: The jump account. Needed by plan and verify; never printed.
    type: str
    default: ""
  own_address:
    description: >-
      The jump host's own private IPv4 address. It is the address sshd -T -C is asked about,
      and it must be one of the destinations, because the runner reaches the jump host itself
      through the jump. Needed by plan and verify.
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
  legacy_files:
    description: >-
      The files of the earlier hand-made layout, as paths. Their paths are made from the account's
      name, so they are never printed, only counted. Used by plan (is a write owed, how many
      remain) and by verify when legacy_gone is set.
    type: list
    elements: str
    default: []
  legacy_gone:
    description: With verify, also require that none of legacy_files exists.
    type: bool
    default: false
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
pending:
  description: With plan, true when a write is owed (a file differs, or a legacy file remains).
  returned: success, with plan
  type: bool
"""

# What the written files are made of. The role's vars/main.yml holds the same values for its
# templates; ansible/checks/test_ci_jump_pins.py holds the two copies equal.
PINNED_PORT = 22
PINNED_FIXED_OPTIONS = ("restrict", "port-forwarding")
PINNED_COMMAND = "/usr/sbin/nologin"
# The names carry the role's purpose and never the account's name: the account's name is held out
# of this public repository and of every public log, and a path is printed by a lot of tooling.
# The drop-in sorts ahead of the earlier hand-made one (50-), so while both are on the host sshd
# already applies the new one and the read-back proves it before the old one is removed.
KEY_DIR = "/etc/ssh/authorized_keys.d"
KEY_FILE = "/etc/ssh/authorized_keys.d/branchleft-jump"
DROPIN_FILE = "/etc/ssh/sshd_config.d/40-branchleft-jump.conf"
# The files are root's and nobody else's to change: the account must never edit its own keys.
ROOT_FILE_MODE = 0o644
ROOT_DIR_MODE = 0o755
# A shell whose last path word is one of these cannot run a remote command.
REFUSED_SHELL_NAMES = frozenset(("nologin", "false"))
# The connection sshd -T -C evaluates Match blocks for, when the caller names no address of
# its own. The jump key is used from runners that have no fixed address, so a Match block keyed
# on a real runner address is not seen (README).
STAND_IN_HOST = "jump-check.invalid"
STAND_IN_ADDRESS = "192.0.2.1"
SSHD_PATH = "/usr/sbin/sshd"
DEFAULT_KEY_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")
MAX_FILE_BYTES = 1_000_000
# What sshd -T must say for the jump account once the drop-in is in place: keyword, then the
# one value it prints. permitopen is judged apart, as a set, because the owner's list is its value.
EXPECTED_EFFECTIVE = {
    "authenticationmethods": "publickey",
    "authorizedkeyscommand": "none",
    "authorizedkeysfile": KEY_FILE,
    "allowtcpforwarding": "local",
    "disableforwarding": "no",
    "gatewayports": "no",
    "allowagentforwarding": "no",
    "allowstreamlocalforwarding": "no",
    "x11forwarding": "no",
    "permittty": "no",
    "permittunnel": "no",
    "permituserrc": "no",
    "forcecommand": PINNED_COMMAND,
}
# The refusal each keyword has when sshd's answer differs. Remote forwarding is the one that
# matters most: a key line that allows port forwarding also allows -R unless sshd says local.
EFFECTIVE_CODES = {
    "allowtcpforwarding": "E-SSHD-FORWARDING",
    "disableforwarding": "E-SSHD-FORWARDING",
    "authorizedkeyscommand": "E-SSHD-KEYSCOMMAND",
    "authorizedkeysfile": "E-SSHD-FILE",
}

# Copied from the plan scan of the gated apply: branchLeft/github-workflows,
# .github/actions/ssh-check-hosts/action.yml, the credential-assignment row of `patterns`
# (line 434 at tag v1.0.19), which that action applies with grep -Ei to each line of a host's
# plan. [[:space:]] is written \s. The copy is not held equal to the original by any test yet;
# when one exists, this copy is replaced by an import of its constant.
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
# The jump host's own address is a private address (RFC 1918), or a loopback one for a test host:
# the runner reaches the jump host itself over the private network, and a public address typed
# here by mistake would make sshd evaluate the account's Match block for the wrong connection.
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(text)
    for text in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
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


@dataclasses.dataclass(frozen=True)
class FileInfo:
    """Who owns a path and how it can be changed, read without following a link."""

    uid: int
    gid: int
    mode: int
    regular: bool
    directory: bool


class Host(Protocol):
    """What the module needs from the machine it runs on, so a test can supply a fake."""

    def accounts(self) -> list[Account]:
        """Every local account."""
        ...

    def read(self, path: str) -> str | None:
        """The text of a regular file, or None when it is absent, a link, too large or
        unreadable."""
        ...

    def info(self, path: str) -> FileInfo | None:
        """The owner and mode of a path, or None when it is absent."""
        ...

    def sshd_test(self, user: str | None, address: str) -> dict[str, list[str]]:
        """The effective sshd settings, keyword to values, for a connection of user from
        address."""
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


def check_own_address(own: object, destinations: Sequence[str]) -> str:
    """Return the jump host's own address, or refuse one that is unset, not an IPv4 address, not in
    a private range, or not among the destinations.

    The runner reaches every host through the jump, the jump host itself included, so a list
    that lacks the jump host's own address fails the plan of every host and cannot be corrected
    by the pull it would block.

    Raises:
        RefusalError: for each of those.
    """
    if not isinstance(own, str) or not own:
        raise RefusalError("E-OWN-EMPTY", "the jump host's own address is not named")
    labels = own.split(".")
    if len(labels) != 4 or not all(
        label.isascii() and label.isdigit() and len(label) <= 3 and int(label) <= 255
        for label in labels
    ):
        raise RefusalError("E-OWN-SHAPE", "the jump host's own address is not an IPv4 address")
    address = ipaddress.ip_address(".".join(str(int(label)) for label in labels))
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise RefusalError("E-OWN-PRIVATE", "the jump host's own address is not a private address")
    if own.lower() not in (item.lower() for item in destinations):
        raise RefusalError(
            "E-DEST-OWN", "the destination list lacks the jump host's own address on port 22"
        )
    return own


def wanted_options(destinations: Sequence[str]) -> str:
    """The options of every line the role writes: the fixed pair, one permitopen each, then the
    forced command, in the order the runbook's hand-made line has."""
    return ",".join(
        [
            *PINNED_FIXED_OPTIONS,
            *(f'permitopen="{item}:{PINNED_PORT}"' for item in destinations),
            f'command="{PINNED_COMMAND}"',
        ]
    )


def wanted_lines(destinations: Sequence[str], keys: Sequence[tuple[str, str]]) -> list[str]:
    """The exact lines the key file must hold: options, key type, key body, nothing else."""
    options = wanted_options(destinations)
    return [f"{options} {key_type} {body}" for key_type, body in keys]


def wanted_dropin(user: str, destinations: Sequence[str]) -> str:
    """The exact text of the sshd drop-in: a Match block for the account, closed by Match all.

    The PermitOpen here and the permitopen of every key line are one list, the destinations.
    """
    permit = " ".join(f"{item}:{PINNED_PORT}" for item in destinations)
    return "\n".join(
        [
            "# Written by the ci_jump role. Change the owner's variables, not this file.",
            f"Match User {user}",
            f"    AuthorizedKeysFile {KEY_FILE}",
            "    AuthenticationMethods publickey",
            "    AllowTcpForwarding local",
            f"    PermitOpen {permit}",
            "    GatewayPorts no",
            "    AllowAgentForwarding no",
            "    AllowStreamLocalForwarding no",
            "    X11Forwarding no",
            "    PermitTTY no",
            "    PermitTunnel no",
            "    PermitUserRC no",
            f"    ForceCommand {PINNED_COMMAND}",
            "Match all",
            "",
        ]
    )


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


def shell_class(shell: str) -> str:
    """Name the kind of a login shell without naming the shell: nologin, false or login."""
    base = os.path.basename(shell)
    return base if base in REFUSED_SHELL_NAMES else "login"


def _sshd(host: Host, user: str, address: str) -> dict[str, list[str]]:
    """Ask sshd for the effective settings, or refuse when it cannot answer.

    Raises:
        RefusalError: when sshd -T fails.
    """
    try:
        return host.sshd_test(user, address)
    except HostError:
        raise RefusalError("E-SSHD-UNAVAILABLE", "sshd -T could not be read") from None


def _values(settings: Mapping[str, list[str]], keyword: str, default: str) -> list[str]:
    """Every word sshd printed for a keyword, lower-cased, or the default when it printed none."""
    return " ".join(settings.get(keyword, [default])).lower().split()


def check_unfixable(settings: Mapping[str, list[str]]) -> None:
    """Refuse, before anything is written, what the drop-in cannot put right.

    Raises:
        RefusalError: when forwarding is disabled outright or a keys command could add keys.
    """
    if _values(settings, "disableforwarding", "no") != ["no"]:
        raise RefusalError("E-SSHD-FORWARDING", "sshd disables all forwarding for the jump account")
    if _values(settings, "authorizedkeyscommand", "none") != ["none"]:
        raise RefusalError(
            "E-SSHD-KEYSCOMMAND",
            "sshd runs a keys command for the jump account, which could add keys",
        )


def check_effective(settings: Mapping[str, list[str]], destinations: Sequence[str]) -> None:
    """Refuse unless sshd's own answer for the jump account is exactly what the role means.

    Remote forwarding is refused here: a key line with port-forwarding allows ssh -R unless
    sshd says AllowTcpForwarding local for the account.

    Raises:
        RefusalError: with the code of the first setting that differs.
    """
    for keyword, expected in EXPECTED_EFFECTIVE.items():
        if _values(settings, keyword, "") != [expected.lower()]:
            code = EFFECTIVE_CODES.get(keyword, "E-SSHD-EFFECTIVE")
            raise RefusalError(
                code, f"sshd does not apply the wanted {keyword} to the jump account"
            )
    live = sorted(_values(settings, "permitopen", "any"))
    wanted = sorted(f"{item}:{PINNED_PORT}".lower() for item in destinations)
    if live != wanted:
        raise RefusalError(
            "E-SSHD-PERMITOPEN", "sshd's PermitOpen for the jump account is not the owner's list"
        )


def _root_owned(info: FileInfo | None, directory: bool) -> bool:
    """True when the path exists, is root's, and nobody else can change it."""
    if info is None or info.uid != 0 or info.gid != 0:
        return False
    if directory:
        return info.directory and info.mode == ROOT_DIR_MODE
    return info.regular and info.mode == ROOT_FILE_MODE


def _destinations_of(lines: Sequence[KeyLine]) -> list[str]:
    """The hosts the permitopen options of the lines name, in the order met."""
    found: list[str] = []
    for line in lines:
        for value in sorted(permitopen_set(line)):
            host_part = value.rpartition(":")[0]
            if host_part not in found:
                found.append(host_part)
    return found


def plan_lines(
    host: Host,
    user: str,
    settings: Mapping[str, list[str]],
    destinations: Sequence[str],
    keys: Sequence[tuple[str, str]],
    legacy_files: Sequence[str] = (),
) -> list[str]:
    """Show the live key file and sshd settings against the wanted ones, destination by
    destination. The account is never named, and neither is a path made from it: the files of
    the earlier hand-made layout are only counted."""
    text = host.read(KEY_FILE)
    live, not_understood = parse_file(text) if text is not None else ([], 0)
    wanted = wanted_options(destinations)
    out = [
        "ci_jump plan for the jump account: every key line is wanted with the options"
        f" {', '.join(PINNED_FIXED_OPTIONS)}, one permitopen per destination and a forced"
        " command, and sshd gets the same list as its PermitOpen",
        (
            f"key file has {len(live)} key line(s) and {not_understood} line(s) not understood,"
            f" root-owned {'yes' if _root_owned(host.info(KEY_FILE), False) else 'no'}"
            if text is not None
            else "key file is absent and would be created"
        ),
    ]
    dropin = host.read(DROPIN_FILE)
    if dropin is None:
        out.append("sshd drop-in is absent and would be created")
    elif dropin == wanted_dropin(user, destinations):
        out.append("sshd drop-in is identical to the wanted text")
    else:
        out.append("sshd drop-in differs from the wanted text and would be replaced")
    old = legacy_present(host, legacy_files)
    out.append(
        f"{old} file(s) of the earlier hand-made layout present"
        + (", removed once the new files read back" if old else "")
    )
    live_key_destinations = _destinations_of(live)
    live_sshd = [value.rpartition(":")[0] for value in _values(settings, "permitopen", "any")]
    for item in destinations:
        in_keys = "yes" if item in live_key_destinations else "no"
        in_sshd = "yes" if item in live_sshd else "no"
        out.append(
            f"destination {item} port {PINNED_PORT} key file live {in_keys} wanted yes,"
            f" sshd PermitOpen live {in_sshd} wanted yes"
        )
    for item in dict.fromkeys([*live_key_destinations, *live_sshd]):
        if item not in destinations and item != "any":
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


def _checked_inputs(
    user: object,
    own: object,
    destinations: object,
    keys: object,
    owned: Mapping[str, str],
) -> tuple[str, str, list[str], list[tuple[str, str]]]:
    """Judge every input, in the order that tells the owner the most: the account, the
    destinations, the jump host's own address, the keys.

    Raises:
        RefusalError: for the first rule that is broken.
    """
    name = check_user(user, owned)
    dests = check_destinations(destinations)
    return name, check_own_address(own, dests), dests, check_keys(keys)


def plan_result(
    host: Host,
    user: object,
    own: object,
    destinations: object,
    keys: object,
    owned: Mapping[str, str],
    legacy_files: Sequence[str] = (),
) -> tuple[list[str], bool]:
    """Judge the inputs, then the host, and show live against wanted. Also say whether a write
    is owed (is_pending).

    Raises:
        RefusalError: for the first rule that is broken, inputs before host.
    """
    name, own_address, dests, parsed_keys = _checked_inputs(user, own, destinations, keys, owned)
    account = check_account(find_account(host, name))
    settings = _sshd(host, account.name, own_address)
    check_unfixable(settings)
    lines = plan_lines(host, name, settings, dests, parsed_keys, legacy_files)
    return lines, is_pending(host, name, dests, parsed_keys, legacy_files)


def do_plan(
    host: Host,
    user: object,
    own: object,
    destinations: object,
    keys: object,
    owned: Mapping[str, str],
    legacy_files: Sequence[str] = (),
) -> list[str]:
    """Judge the inputs, then the host, and show live against wanted.

    Raises:
        RefusalError: for the first rule that is broken, inputs before host.
    """
    return plan_result(host, user, own, destinations, keys, owned, legacy_files)[0]


def check_files(
    host: Host, name: str, destinations: Sequence[str], keys: Sequence[tuple[str, str]]
) -> list[str]:
    """Compare both managed files with the wanted text exactly, and return the key lines.

    Raises:
        RefusalError: when the directory, either file or either text is not as wanted.
    """
    if not _root_owned(host.info(KEY_DIR), True):
        raise RefusalError("E-READBACK-MISMATCH", "the key directory is not root's at mode 0755")
    for path in (KEY_FILE, DROPIN_FILE):
        if not _root_owned(host.info(path), False):
            raise RefusalError(
                "E-READBACK-MISMATCH", "a managed file is not root's regular file at mode 0644"
            )
    text = host.read(KEY_FILE)
    if text is None:
        raise RefusalError("E-READBACK-MISMATCH", "the managed key file cannot be read back")
    live = sorted(line.strip() for line in text.splitlines() if line.strip())
    if live != sorted(wanted_lines(destinations, keys)):
        raise RefusalError(
            "E-READBACK-MISMATCH", "the managed key file is not exactly the wanted lines"
        )
    if host.read(DROPIN_FILE) != wanted_dropin(name, destinations):
        raise RefusalError(
            "E-READBACK-MISMATCH", "the managed sshd drop-in is not exactly the wanted text"
        )
    return live


def legacy_present(host: Host, legacy_files: Sequence[str]) -> int:
    """How many of the files of the earlier hand-made layout are still on the host. A path is
    only counted, never returned: the paths of that layout are made from the account's name."""
    return sum(1 for path in legacy_files if host.info(path) is not None)


def do_verify(
    host: Host,
    user: object,
    own: object,
    destinations: object,
    keys: object,
    owned: Mapping[str, str],
    legacy_files: Sequence[str] = (),
    legacy_gone: bool = False,
) -> list[str]:
    """Read both files back and compare them with the wanted text exactly, then require sshd's
    own answer for the account to be what the role means. With legacy_gone the files of the
    earlier hand-made layout must also be gone.

    Raises:
        RefusalError: when sshd's answer or either file is not exactly what was wanted, or when
            a legacy file the caller says must be gone is still there.
    """
    name, own_address, dests, parsed_keys = _checked_inputs(user, own, destinations, keys, owned)
    account = check_account(find_account(host, name))
    check_effective(_sshd(host, account.name, own_address), dests)
    live = check_files(host, name, dests, parsed_keys)
    if legacy_gone and legacy_present(host, legacy_files):
        raise RefusalError(
            "E-LEGACY-PRESENT", "a file of the earlier hand-made layout is still there"
        )
    return [
        f"ci_jump read back {len(live)} key line(s) and the sshd drop-in, each exactly the wanted"
        f" text for {len(dests)} destination(s) on port {PINNED_PORT}; sshd applies local"
        " forwarding only, with the same list as its PermitOpen"
    ]


def is_pending(
    host: Host,
    user: str,
    destinations: Sequence[str],
    keys: Sequence[tuple[str, str]],
    legacy_files: Sequence[str],
) -> bool:
    """True when a write is owed: a managed file is not exactly as wanted, or a file of the
    earlier hand-made layout is still there. It is the complement of what verify reads, so a
    host the role has finished with is never pending and the role's second run changes nothing."""
    try:
        check_files(host, user, destinations, keys)
    except RefusalError:
        return True
    return legacy_present(host, legacy_files) > 0


# ---------------------------------------------------------------------------------------
# The report. It names no account: the jump account's name is held out of the public log.


def _setting(settings: Mapping[str, list[str]], keyword: str, default: str, limit: int = 40) -> str:
    """One sshd setting as printable words: every value it printed, joined, and shortened."""
    words = " ".join(settings.get(keyword, [default])).split()
    return " ".join(clean(word, limit) for word in words)[:limit]


def _file_label(paths: Sequence[str]) -> str:
    """Say whether a key file is the managed one, without printing a path that could hold a name."""
    return "managed" if list(paths) == [KEY_FILE] else "other"


def _carrying_lines(host: Host, files: Sequence[str]) -> list[KeyLine]:
    """The key lines of the given files that carry a forwarding option."""
    found: list[KeyLine] = []
    for path in files:
        text = host.read(path)
        if text is None:
            continue
        lines, _ = parse_file(text)
        found.extend(
            line
            for line in lines
            if {name for name, _ in line.options}
            & {"permitopen", "port-forwarding", "permitlisten"}
        )
    return found


def _report_destinations(
    index: int,
    lines: Sequence[KeyLine],
    settings: Mapping[str, list[str]],
    listed: Sequence[str],
) -> list[str]:
    """One line per live destination, saying where it is live and whether the owner lists it."""
    in_keys = _destinations_of(lines)
    in_sshd = [
        value.rpartition(":")[0]
        for value in _values(settings, "permitopen", "any")
        if value != "any"
    ]
    out: list[str] = []
    for item in dict.fromkeys([*in_keys, *in_sshd]):
        out.append(
            f"account {index} destination {clean(item)} port {PINNED_PORT}"
            f" in key lines {'yes' if item in in_keys else 'no'},"
            f" in sshd PermitOpen {'yes' if item in in_sshd else 'no'},"
            f" in the owner's list {'yes' if item in listed else 'no'}"
        )
    out.extend(
        f"account {index} destination {clean(item)} is in the owner's list and not in its key lines"
        for item in listed
        if item not in in_keys
    )
    return out


def do_report(
    host: Host,
    owned: Mapping[str, str],
    listed: Sequence[str],
    address: str,
) -> tuple[list[str], list[dict[str, object]]]:
    """Describe the accounts whose key files carry forwarding options, found per account with
    sshd -T -C so a Match block's AuthorizedKeysFile is followed. Reads, never writes, and
    prints no account name: an account is its index in this report."""
    out = ["ci_jump report, read only, nothing was changed"]
    owner_of = {name: role for role, name in owned.items()}
    structured: list[dict[str, object]] = []
    examined = 0
    unanswered = 0
    for account in sorted(host.accounts(), key=lambda item: item.name):
        try:
            settings = host.sshd_test(account.name, address)
        except HostError:
            unanswered += 1
            continue
        examined += 1
        files = key_files(settings, account)
        carrying = _carrying_lines(host, files)
        if not carrying:
            continue
        index = len(structured) + 1
        owner = owner_of.get(account.name, "none")
        sets = {permitopen_set(line) for line in carrying}
        owned_by_root = all(
            _root_owned(host.info(path), False) for path in files if host.read(path)
        )
        out.append(
            f"account {index} shell class {shell_class(account.shell)} owned by role"
            f" {clean(owner, 32)}, {len(carrying)} key line(s) with forwarding options,"
            f" key file {_file_label(files)}, root-owned {'yes' if owned_by_root else 'no'}"
        )
        for number, line in enumerate(carrying, start=1):
            out.append(
                f"account {index} line {number} key {line.key_type}"
                f" fingerprint {fingerprint(line.body)} options {describe_options(line)}"
            )
        out.append(
            f"account {index} all key lines carry the same permitopen set"
            f" {'yes' if len(sets) == 1 else 'no'}"
        )
        out.extend(_report_destinations(index, carrying, settings, listed))
        out.append(
            f"account {index} sshd AuthorizedKeysCommand"
            f" {_setting(settings, 'authorizedkeyscommand', 'none')},"
            f" AuthorizedKeysFile {_file_label(files)},"
            f" AllowTcpForwarding {_setting(settings, 'allowtcpforwarding', 'yes', 12)},"
            f" DisableForwarding {_setting(settings, 'disableforwarding', 'no', 12)},"
            f" PermitOpen {len(_values(settings, 'permitopen', 'any'))} entr(ies)"
        )
        structured.append(
            {
                "index": index,
                "shell_class": shell_class(account.shell),
                "owner": owner,
                "lines": len(carrying),
                "same_permitopen": len(sets) == 1,
                "allowtcpforwarding": _values(settings, "allowtcpforwarding", "yes"),
            }
        )
    out.append(
        f"examined {examined} account(s), {unanswered} could not be evaluated by sshd,"
        f" {len(structured)} carry forwarding options in their key files"
    )
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
        """Read a regular file as text, or None when it is absent, a link, a pipe, too large or
        unreadable.

        The last part of the path is opened with O_NOFOLLOW, so a link there is refused, and
        O_NONBLOCK, so a pipe swapped in by a local account cannot hold the pull; the opened
        descriptor is then checked with fstat, so what is read is the regular file checked.
        """
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_FILE_BYTES:
                return None
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                return handle.read(MAX_FILE_BYTES + 1).decode("utf-8", errors="replace")
        except OSError:
            return None
        finally:
            os.close(descriptor)

    def info(self, path: str) -> FileInfo | None:
        """Who owns a path and its mode, read without following a link."""
        try:
            details = os.lstat(path)
        except OSError:
            return None
        return FileInfo(
            details.st_uid,
            details.st_gid,
            stat.S_IMODE(details.st_mode),
            stat.S_ISREG(details.st_mode),
            stat.S_ISDIR(details.st_mode),
        )

    def sshd_test(self, user: str | None, address: str) -> dict[str, list[str]]:
        """Run sshd -T, for a connection of user from address when a user is given.

        Raises:
            HostError: when sshd cannot print its settings.
        """
        command = [SSHD_PATH, "-T"]
        if user is not None:
            command += ["-C", f"user={user},host={STAND_IN_HOST},addr={address}"]
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
    "user": {"type": "str", "default": "", "no_log": True},
    "own_address": {"type": "str", "default": ""},
    "destinations": {"type": "list", "elements": "raw", "default": []},
    "keys": {"type": "list", "elements": "raw", "default": [], "no_log": True},
    "owned_accounts": {"type": "dict", "default": {}},
    "legacy_files": {"type": "list", "elements": "str", "default": [], "no_log": True},
    "legacy_gone": {"type": "bool", "default": False},
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
            lines, accounts = do_report(
                host,
                owned,
                [item for item in params["destinations"] if isinstance(item, str)],
                params["own_address"] or STAND_IN_ADDRESS,
            )
            module.exit_json(changed=False, lines=lines, accounts=accounts)
        elif action == "plan":
            lines, pending = plan_result(
                host,
                params["user"],
                params["own_address"],
                params["destinations"],
                params["keys"],
                owned,
                params["legacy_files"],
            )
            module.exit_json(changed=False, lines=lines, pending=pending)
        else:
            lines = do_verify(
                host,
                params["user"],
                params["own_address"],
                params["destinations"],
                params["keys"],
                owned,
                params["legacy_files"],
                params["legacy_gone"],
            )
            module.exit_json(changed=False, lines=lines)
    except RefusalError as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
