"""Reads and judges the files of the tenant_scrape_tunnel role that carry its security rules.

Nothing here is the role's own logic: the role renders its templates with Ansible and installs a
static unit. This module loads the real files, renders the real templates with jinja2 in strict
mode, and holds three validators that read the text of a key line, an sshd drop-in and a unit
and return one finding per broken rule. The tests run each validator on the real artifact, which
must give no finding, and on deliberately broken text, which must give the named finding. The
allowed destinations, the port, the bind address and the hardening are written out here from the
address plan and from the rules of the design, not copied from the files they judge.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[2]
REPOSITORY = ROLE.parents[2]
ADDRESS_PLAN = REPOSITORY / "hetzner-host" / "addressPlan.ts"
UNIT_FILE = ROLE / "files" / "branchleft-tenant-scrape.service"

Value = str | int | bool | list["Value"] | dict[str, "Value"]

EXPORTER_PORT = 9100
NOLOGIN = "/usr/sbin/nologin"
ALL_INTERFACES = str(ipaddress.IPv4Address(0))
KEY_TYPE = "ssh-ed25519"
IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
HOST_IPS_BLOCK = re.compile(r"export const HOST_IPS = \{(?P<body>.*?)\} as const;", re.S)
TENANTS_BLOCK = re.compile(r"export const TENANTS_HOST_IPS = \{(?P<body>.*?)\} as const;", re.S)
ADDRESS_ENTRY = re.compile(r"(?P<name>\w+):\s*'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'")

# The sshd directives the account's Match block may hold, and the value each must have. The
# permitted destinations are judged apart, as a set.
REQUIRED_DIRECTIVES = {
    "authenticationmethods": "publickey",
    "allowtcpforwarding": "local",
    "permitlisten": "none",
    "gatewayports": "no",
    "allowagentforwarding": "no",
    "allowstreamlocalforwarding": "no",
    "x11forwarding": "no",
    "permittty": "no",
    "permittunnel": "no",
    "permituserrc": "no",
    "forcecommand": NOLOGIN,
}
DROPIN_KEYWORDS = frozenset({*REQUIRED_DIRECTIVES, "authorizedkeysfile", "permitopen"})

# The only single-letter options the unit's ssh command may carry: no -R, -D, -W, -J or -g.
ALLOWED_SSH_FLAGS = frozenset({"-F", "-N", "-T", "-i", "-o", "-L"})
FLAGS_WITH_ARGUMENT = frozenset({"-F", "-i", "-o", "-L"})
# Every -o option the unit may set, lower-cased, and its value. The first group is a security
# rule and must be present with that value; the second is free to vary but is allowed.
REQUIRED_SSH_OPTIONS = {
    "identitiesonly": "yes",
    "identityagent": "none",
    "batchmode": "yes",
    "stricthostkeychecking": "yes",
    "updatehostkeys": "no",
    "globalknownhostsfile": "/dev/null",
    "exitonforwardfailure": "yes",
    "forwardagent": "no",
    "forwardx11": "no",
    "permitlocalcommand": "no",
    "controlmaster": "no",
    "controlpath": "none",
}
TUNING_SSH_OPTIONS = frozenset({"connecttimeout", "serveraliveinterval", "serveralivecountmax"})
HARDENING = {
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
    "RestrictNamespaces": "yes",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallArchitectures": "native",
    "CapabilityBoundingSet": "",
}


class RoleFileError(Exception):
    """A file of the role, or the address plan, is missing or is not in the shape the tests read."""

    def __init__(self, subject: str, problem: str) -> None:
        super().__init__(f"{subject}: {problem}")


def synthetic_key(label: str) -> str:
    """A public key made up for a test: the key type and 32 digest bytes; it has no private half."""
    blob = b"".join(
        len(part).to_bytes(4, "big") + part
        for part in (KEY_TYPE.encode("ascii"), hashlib.sha256(label.encode("utf-8")).digest())
    )
    return f"{KEY_TYPE} {base64.b64encode(blob).decode('ascii')}"


def _address_block(pattern: re.Pattern[str]) -> dict[str, str]:
    """The name to address entries of one block of the address plan.

    Raises:
        RoleFileError: when the plan or the block cannot be read, so an empty parse cannot pass.
    """
    if not ADDRESS_PLAN.is_file():
        raise RoleFileError(str(ADDRESS_PLAN), "is missing")
    block = pattern.search(ADDRESS_PLAN.read_text(encoding="utf-8"))
    if block is None:
        raise RoleFileError(str(ADDRESS_PLAN), f"has no block matching {pattern.pattern}")
    entries = {entry["name"]: entry["ip"] for entry in ADDRESS_ENTRY.finditer(block["body"])}
    if not entries:
        raise RoleFileError(str(ADDRESS_PLAN), f"the block matching {pattern.pattern} is empty")
    return entries


def tenant_addresses() -> dict[str, str]:
    """TENANTS_HOST_IPS of the address plan, by name."""
    return _address_block(TENANTS_BLOCK)


def edge1_address() -> str:
    """HOST_IPS.edge1 of the address plan: the address the scraper host listens on.

    Raises:
        RoleFileError: when HOST_IPS has no edge1.
    """
    host_ips = _address_block(HOST_IPS_BLOCK)
    if "edge1" not in host_ips:
        raise RoleFileError(str(ADDRESS_PLAN), "HOST_IPS has no edge1")
    return host_ips["edge1"]


def _value(raw: object) -> Value:
    """The YAML value, narrowed to the scalar, list and mapping shapes the role's variables use.

    Raises:
        RoleFileError: when the value is none of those.
    """
    if isinstance(raw, str | int | bool):
        return raw
    if isinstance(raw, list):
        return [_value(item) for item in raw]
    if isinstance(raw, dict):
        return {str(key): _value(item) for key, item in raw.items()}
    raise RoleFileError(type(raw).__name__, "is a kind of variable the tests do not read")


def environment() -> jinja2.Environment:
    """The jinja2 environment that renders a template the way Ansible's template module does.

    A name the template reads and the variables lack is an error, and the trailing newline stays.
    """
    return jinja2.Environment(
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        autoescape=jinja2.select_autoescape(enabled_extensions=(), default=False),
    )


def _resolve(value: Value, context: Mapping[str, Value]) -> Value:
    if isinstance(value, str):
        return environment().from_string(value).render(context) if "{{" in value else value
    if isinstance(value, list):
        return [_resolve(item, context) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, context) for key, item in value.items()}
    return value


def role_variables() -> dict[str, Value]:
    """The role's defaults and vars with every template in them rendered, vars over defaults.

    Raises:
        RoleFileError: when a file is missing or a value still holds a template after rendering.
    """
    merged: dict[str, Value] = {}
    for name in ("defaults", "vars"):
        path = ROLE / name / "main.yml"
        if not path.is_file():
            raise RoleFileError(str(path), "is missing")
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise RoleFileError(str(path), "is not a mapping")
        merged.update({str(key): _value(item) for key, item in document.items()})
    # Each pass renders against the previous one, so a variable made from another settles by
    # the depth of the longest chain.
    for _ in range(10):
        merged = {key: _resolve(item, merged) for key, item in merged.items()}
    if "{{" in repr(merged):
        raise RoleFileError("variables", "still hold a template after rendering")
    return merged


def text_variable(variables: Mapping[str, Value], name: str) -> str:
    """The string value of a role variable.

    Raises:
        RoleFileError: when the variable is absent or not a string.
    """
    value = variables.get(name)
    if not isinstance(value, str):
        raise RoleFileError(name, "is not a string variable of the role")
    return value


def destinations(variables: Mapping[str, Value]) -> list[dict[str, Value]]:
    """The role's destination list, each entry a mapping of name, address and local_port.

    Raises:
        RoleFileError: when the list is absent or an entry is not a mapping.
    """
    listed = variables.get("tenant_scrape_tunnel_destinations")
    if not isinstance(listed, list) or not all(isinstance(entry, dict) for entry in listed):
        raise RoleFileError("tenant_scrape_tunnel_destinations", "is not a list of mappings")
    return [entry for entry in listed if isinstance(entry, dict)]


def render_template(name: str, variables: Mapping[str, Value]) -> str:
    """The text of one of the role's templates, rendered in strict mode over the variables.

    Raises:
        RoleFileError: when the template is missing.
    """
    path = ROLE / "templates" / name
    if not path.is_file():
        raise RoleFileError(str(path), "is missing")
    return environment().from_string(path.read_text(encoding="utf-8")).render(variables)


def unit_text() -> str:
    """The text of the role's systemd unit.

    Raises:
        RoleFileError: when the file is missing.
    """
    if not UNIT_FILE.is_file():
        raise RoleFileError(str(UNIT_FILE), "is missing")
    return UNIT_FILE.read_text(encoding="utf-8")


def unit_sha256() -> str:
    """The sha256 of the unit's bytes."""
    return hashlib.sha256(UNIT_FILE.read_bytes()).hexdigest()


def split_outside_quotes(text: str, separator: str) -> list[str]:
    """Splits at each separator that is not between double quotes."""
    parts: list[str] = []
    current: list[str] = []
    inside = False
    for character in text:
        if character == '"':
            inside = not inside
        if character == separator and not inside:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def permit_set(addresses: Sequence[str], port: int = EXPORTER_PORT) -> set[str]:
    """The `address:port` destinations the account may open, one per address."""
    return {f"{address}:{port}" for address in addresses}


def key_line_findings(line: str, key: str, addresses: Sequence[str]) -> list[str]:
    """One finding per rule the authorized_keys line breaks; none when it is the one allowed line.

    The line is one line, then the options, then the key's type and body and nothing after:
    `restrict`, `port-forwarding`, one `permitopen` for each address at the exporter port, and
    the command that runs nothing, in that order.
    """
    body = line[:-1] if line.endswith("\n") else line
    if "\n" in body or "\r" in body:
        return ["the key file holds more than one line"]
    fields = split_outside_quotes(body, " ")
    if len(fields) != 3:
        return [f"want options, key type and key body, found {len(fields)} space-separated fields"]
    options_text, key_type, key_body = fields
    if f"{key_type} {key_body}" != key:
        return ["the key differs from the one the role was given"]
    options = split_outside_quotes(options_text, ",")
    wanted = [
        "restrict",
        "port-forwarding",
        *[f'permitopen="{item}"' for item in sorted(permit_set(addresses))],
        f'command="{NOLOGIN}"',
    ]
    findings: list[str] = []
    if "restrict" not in options:
        findings.append("the key line lacks restrict")
    if not any(option.startswith("command=") for option in options):
        findings.append("the key line lacks command=")
    findings.extend(f"unexpected option {option}" for option in options if option not in wanted)
    findings.extend(f"missing option {option}" for option in wanted if option not in options)
    for address in sorted(set(IPV4.findall(options_text)) - set(addresses)):
        findings.append(f"destination {address} is not a tenant exporter")
    for port in sorted(set(re.findall(r":(\d+)", options_text)) - {str(EXPORTER_PORT)}):
        findings.append(f"port {port} is not the exporter port")
    if not findings and options != wanted:
        findings.append("the options are not in the order of the contract")
    return findings


def _dropin_lines(text: str) -> list[str]:
    stripped = (line.strip() for line in text.splitlines())
    return [line for line in stripped if line and not line.startswith("#")]


def dropin_permit_set(text: str) -> set[str]:
    """The destinations of the drop-in's one PermitOpen line; empty when it has none."""
    tokens: list[str] = []
    for line in _dropin_lines(text):
        keyword, _, value = line.partition(" ")
        if keyword.lower() == "permitopen":
            tokens.extend(value.split())
    return set(tokens)


def dropin_findings(text: str, user: str, addresses: Sequence[str]) -> list[str]:
    """One finding per rule the sshd drop-in breaks.

    The block is `Match User <user>` and `Match all` around the directives of the contract and
    one PermitOpen line whose destinations are exactly the addresses at the exporter port.
    """
    lines = _dropin_lines(text)
    findings: list[str] = []
    if not lines or lines[0] != f"Match User {user}":
        findings.append(f"the drop-in does not open with Match User {user}")
    if len(lines) < 2 or lines[-1] != "Match all":
        findings.append("the drop-in does not end with Match all")
    if sum(line.lower().startswith("match ") for line in lines) != 2:
        findings.append("the drop-in does not hold exactly two Match lines")
    seen: dict[str, list[str]] = {}
    for line in lines:
        if line.lower().startswith("match "):
            continue
        keyword, _, value = line.partition(" ")
        seen.setdefault(keyword.lower(), []).append(value.strip())
    findings.extend(f"unexpected directive {name}" for name in sorted(set(seen) - DROPIN_KEYWORDS))
    for name, value in REQUIRED_DIRECTIVES.items():
        if seen.get(name) != [value]:
            findings.append(f"{name} is {seen.get(name)}, want [{value!r}]")
    if len(seen.get("permitopen", [])) != 1:
        findings.append("the drop-in does not hold exactly one PermitOpen line")
    tokens = [token for value in seen.get("permitopen", []) for token in value.split()]
    if len(tokens) != len(set(tokens)):
        findings.append("PermitOpen lists a destination twice")
    if set(tokens) != permit_set(addresses):
        findings.append(f"PermitOpen is {sorted(tokens)}, want {sorted(permit_set(addresses))}")
    return findings


@dataclass
class SshCommand:
    """The parts of the unit's ssh command line, as the command takes them."""

    binary: str
    flags: list[str] = field(default_factory=list)
    options: dict[str, str] = field(default_factory=dict)
    duplicate_options: list[str] = field(default_factory=list)
    forwards: list[str] = field(default_factory=list)
    identity: str = ""
    positional: list[str] = field(default_factory=list)
    refused_flags: list[str] = field(default_factory=list)


def parse_ssh(words: Sequence[str]) -> SshCommand:
    """Splits an ssh command line into its flags, its -o options, its forwards and its words.

    Raises:
        RoleFileError: when an option that takes an argument has none.
    """
    command = SshCommand(binary=words[0] if words else "")
    index = 1
    while index < len(words):
        word = words[index]
        index += 1
        if not word.startswith("-"):
            command.positional.append(word)
            continue
        if word not in ALLOWED_SSH_FLAGS:
            command.refused_flags.append(word)
            continue
        command.flags.append(word)
        if word not in FLAGS_WITH_ARGUMENT:
            continue
        if index >= len(words):
            raise RoleFileError(word, "has no argument")
        argument = words[index]
        index += 1
        if word == "-L":
            command.forwards.append(argument)
        elif word == "-i":
            command.identity = argument
        elif word == "-o":
            name, _, setting = argument.partition("=")
            if name.lower() in command.options:
                command.duplicate_options.append(name.lower())
            command.options[name.lower()] = setting
    return command


def unit_entries(text: str) -> dict[str, list[str]]:
    """The unit's settings by `Section.Key`, each key's values in order.

    A backslash at the end of a line joins the next line, as systemd reads it; comments and
    blank lines are dropped.
    """
    entries: dict[str, list[str]] = {}
    section = ""
    for line in text.replace("\\\n", " ").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        key, _, value = stripped.partition("=")
        entries.setdefault(f"{section}.{key}", []).append(value.strip())
    return entries


def unit_ssh_command(text: str) -> SshCommand:
    """The ssh command of the unit's one ExecStart line.

    Raises:
        RoleFileError: when the unit does not hold exactly one ExecStart.
    """
    starts = unit_entries(text).get("Service.ExecStart", [])
    if len(starts) != 1:
        raise RoleFileError("unit", f"has {len(starts)} ExecStart lines, want 1")
    return parse_ssh(shlex.split(starts[0]))


def _forward_findings(forwards: Sequence[str], bind: str, wanted: Mapping[int, str]) -> list[str]:
    findings: list[str] = []
    seen: dict[int, str] = {}
    for forward in forwards:
        parts = forward.split(":")
        if len(parts) != 4:
            findings.append(f"-L {forward} is not bind:port:host:port")
            continue
        bind_address, local_port, address, remote_port = parts
        if bind_address != bind:
            findings.append(f"-L {forward} binds {bind_address}, want {bind}")
        if remote_port != str(EXPORTER_PORT):
            findings.append(f"-L {forward} reaches port {remote_port}, want {EXPORTER_PORT}")
        if not local_port.isdigit() or wanted.get(int(local_port)) != address:
            findings.append(f"-L {forward} is not one of the contract's forwards")
        elif int(local_port) in seen:
            findings.append(f"-L {forward} repeats local port {local_port}")
        else:
            seen[int(local_port)] = address
    if len(forwards) != len(wanted):
        findings.append(f"the unit holds {len(forwards)} -L forwards, want {len(wanted)}")
    return findings


def unit_findings(
    text: str, bind: str, wanted: Mapping[int, str], rules: Mapping[str, str]
) -> list[str]:
    """One finding per rule the unit breaks.

    `wanted` maps each local port to the tenant address behind it. `rules` holds the values the
    role's variables give: user, environment_file, identity, known_hosts, alias and target_name.
    """
    entries = unit_entries(text)
    findings: list[str] = []
    starts = entries.get("Service.ExecStart", [])
    if len(starts) != 1:
        return [f"the unit has {len(starts)} ExecStart lines, want 1"]
    findings.extend(
        f"{key} runs a second command"
        for key in entries
        if key.startswith("Service.Exec") and key != "Service.ExecStart"
    )
    command = unit_ssh_command(text)
    if command.binary != "/usr/bin/ssh":
        findings.append(f"ExecStart runs {command.binary}, want /usr/bin/ssh")
    findings.extend(f"ssh flag {flag} is not allowed" for flag in command.refused_flags)
    findings.extend(_forward_findings(command.forwards, bind, wanted))
    if bind in (ALL_INTERFACES, "*", "", "::") or ALL_INTERFACES in text:
        findings.append("the unit binds or names every address")
    for name, value in REQUIRED_SSH_OPTIONS.items():
        if command.options.get(name) != value:
            findings.append(f"-o {name} is {command.options.get(name)!r}, want {value!r}")
    findings.extend(f"-o {name} is given twice" for name in command.duplicate_options)
    allowed = {*REQUIRED_SSH_OPTIONS, *TUNING_SSH_OPTIONS, "hostkeyalias", "userknownhostsfile"}
    findings.extend(f"-o {name} is not allowed" for name in sorted(set(command.options) - allowed))
    for name, key in (("hostkeyalias", "alias"), ("userknownhostsfile", "known_hosts")):
        if command.options.get(name) != rules[key]:
            findings.append(f"-o {name} is {command.options.get(name)!r}, want {rules[key]!r}")
    if command.identity != rules["identity"]:
        findings.append(f"-i is {command.identity!r}, want {rules['identity']!r}")
    destination = f"{rules['user']}@${{{rules['target_name']}}}"
    if command.positional != [destination]:
        findings.append(f"the ssh words are {command.positional}, want [{destination!r}]")
    for key, value in HARDENING.items():
        if entries.get(f"Service.{key}") != [value]:
            findings.append(f"{key} is {entries.get(f'Service.{key}')}, want [{value!r}]")
    pinned = {
        "Service.User": rules["user"],
        "Service.Group": rules["user"],
        "Service.EnvironmentFile": rules["environment_file"],
        "Service.Restart": "always",
    }
    for key, value in pinned.items():
        if entries.get(key) != [value]:
            findings.append(f"{key} is {entries.get(key)}, want [{value!r}]")
    return findings
