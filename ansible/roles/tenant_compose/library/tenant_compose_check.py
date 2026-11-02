#!/usr/bin/python
"""Judge rendered tenant compose text, before the role writes any of it.

The module is pure. It reads text it is given and returns a verdict; it opens no
file, runs no command and changes nothing, in check mode and out of it. The role
acts on the verdict. A refusal names a rule, a service or a key name, and never a
value, so the verdict is safe to print.
"""

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: tenant_compose_check
short_description: Judge rendered tenant compose text before it is delivered
description:
  - Reads the compose text a renderer produced, the secrets file it needs and the
    image pin, and returns every rule they break, as a list of plain sentences.
  - Two profiles. C(tenant) is one tenant's stack, whose image is C(${IMAGE}) and whose
    secrets come from a file. C(spool) is the host's one mail spool, whose image is pinned
    inline by digest and whose networks it owns.
  - The rules are a deliberately smaller list than the renderer's own. They are the ones that
    make delivering the file unsafe, not a second copy of the renderer's posture checks.
  - Compares a tenant's uid with the claims the volume program lists, when they are given.
  - Reads the firewall rules of the spool's drain bridge, when they are given, and refuses a
    host on which the bridge is not fenced in.
  - Opens no file, runs no command and changes nothing. A refusal never contains a value.
version_added: "1.0.0"
author:
  - branchLeft
requirements:
  - PyYAML on the host's python3, which ansible-core itself depends on.
options:
  profile:
    description: Which rules apply.
    type: str
    choices: [tenant, spool]
    default: tenant
  slug:
    description: The stack's name, which is also the C(name) of its compose file.
    type: str
    required: true
  uid:
    description: The tenant's uid. Required for the C(tenant) profile and ignored for C(spool).
    type: int
  compose_text:
    description: The compose file, as the renderer produced it.
    type: str
    required: true
  secrets_env_text:
    description:
      - The filled environment file for a C(tenant). Its values are secrets.
      - Never returned, written or logged by this module.
    type: str
    default: ''
  image_env_text:
    description: The C(IMAGE=) line for a C(tenant). The C(spool) derives its own.
    type: str
    default: ''
  claims_text:
    description:
      - The output of the volume program's C(--list-claims), one C(slug=uid) per line.
      - Unset means the claims are not compared.
    type: str
  require_isolation:
    description:
      - Whether the drain bridge's firewall rules must be present.
      - Only the C(spool) profile reads it.
      - When true and the rules text is unset, the verdict is a refusal.
    type: bool
    default: false
  iptables_input_text:
    description: The output of C(iptables -t filter -S INPUT).
    type: str
  iptables_docker_user_text:
    description: The output of C(iptables -t filter -S DOCKER-USER).
    type: str
attributes:
  check_mode:
    support: full
    description: The module changes nothing, so check mode and a real run give the same verdict.
  diff_mode:
    support: none
    description: Nothing is changed, so there is no diff.
"""

EXAMPLES = r"""
- name: Judge one tenant's rendered stack
  tenant_compose_check:
    profile: tenant
    slug: tenant-a
    uid: 30901
    compose_text: "{{ stack.compose_text }}"
    secrets_env_text: "{{ stack.secrets_env_text }}"
    image_env_text: "{{ stack.image_env_text }}"
    claims_text: "{{ claims.stdout }}"
  no_log: true
  register: verdict
"""

RETURN = r"""
slug:
  description: The slug the module was given, so a looped result can be matched to its stack.
  returned: always
  type: str
refusals:
  description:
    - Every rule broken, as plain sentences with no value in them, each starting with the slug.
    - Empty when nothing is refused.
  returned: always
  type: list
  elements: str
ok:
  description: True when C(refusals) is empty.
  returned: always
  type: bool
stamp:
  description:
    - SHA-256 of the compose text and the secrets text, a function of the inputs only.
    - Derived from a secret, so it is never printed.
  returned: always
  type: str
claim_state:
  description:
    - C(unchecked) when no claims were given.
    - Otherwise C(unclaimed), C(same) or C(conflict).
  returned: always
  type: str
image_env:
  description:
    - The exact content of the stack's image pin file, one C(IMAGE=) line ending in a newline.
    - Empty when anything is refused.
  returned: always
  type: str
"""

TENANT = "tenant"
SPOOL = "spool"
SPOOL_SLUG = "mail-spool"
SPOOL_BRIDGE = "br-mailspool"
SPOOL_PUBLISH_ADDRESS = "127.0.0.1"
SLUG_PATTERN = re.compile(r"[a-z]([a-z0-9-]*[a-z0-9])?")
SLUG_MAX_LENGTH = 26
UID_MIN = 30000
UID_MAX = 30999
IMAGE_VARIABLE = "${IMAGE}"
DIGEST_REFERENCE = r"[^\s@$]+@sha256:[0-9a-f]{64}"
INLINE_IMAGE_PATTERN = re.compile(DIGEST_REFERENCE)
IMAGE_LINE_PATTERN = re.compile(rf"IMAGE=({DIGEST_REFERENCE})")
SECRET_KEY_PATTERN = re.compile(r"GHOST_[A-Z0-9_]+")
SECRET_LINE_PATTERN = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)")
REFERENCE_PATTERN = re.compile(r"(?<!\$)\$\{?([A-Za-z_][A-Za-z0-9_]*)")
CLAIM_LINE_PATTERN = re.compile(r"([a-z][a-z0-9-]*)=([0-9]+)")
SPOOL_REFERENCE_NAMES = frozenset({"SHIM_DRAIN_TOKEN"})
# The addresses that mean every interface. The module refuses them; it binds nothing.
WILDCARD_ADDRESSES = frozenset({"", "0.0.0.0", "::", "0:0:0:0:0:0:0:0"})  # noqa: S104
TOP_LEVEL_KEYS = frozenset({"name", "services", "networks", "volumes"})
FORBIDDEN_SERVICE_KEYS = ("build", "extends", "network_mode", "cap_add", "devices")
DOCKER_SOCKET = "docker.sock"
BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"
CONNTRACK_STATES = "(?:ESTABLISHED,RELATED|RELATED,ESTABLISHED)"


class YamlMissingError(Exception):
    """PyYAML cannot be imported on the host."""

    def __init__(self) -> None:
        super().__init__(
            "PyYAML is not installed for this python3, and the module cannot read compose text"
        )


class NotYamlError(Exception):
    """The compose text is not YAML. Carries no part of the text."""


@dataclass(frozen=True)
class Params:
    """The module's parameters. Every secret has repr=False so no traceback prints it."""

    slug: str
    compose_text: str
    profile: str = TENANT
    uid: int | None = None
    secrets_env_text: str = field(default="", repr=False)
    image_env_text: str = ""
    claims_text: str | None = None
    require_isolation: bool = False
    iptables_input_text: str | None = None
    iptables_docker_user_text: str | None = None


@dataclass(frozen=True)
class Verdict:
    """What the text is judged to be. ``refusals`` holds no value."""

    refusals: tuple[str, ...]
    stamp: str
    claim_state: str
    image_env: str

    @property
    def ok(self) -> bool:
        """Whether nothing was refused."""
        return not self.refusals


ARGUMENT_SPEC: dict[str, dict[str, object]] = {
    "profile": {"type": "str", "choices": [TENANT, SPOOL], "default": TENANT},
    "slug": {"type": "str", "required": True},
    "uid": {"type": "int"},
    "compose_text": {"type": "str", "required": True},
    "secrets_env_text": {"type": "str", "default": "", "no_log": True},
    "image_env_text": {"type": "str", "default": ""},
    "claims_text": {"type": "str"},
    "require_isolation": {"type": "bool", "default": False},
    "iptables_input_text": {"type": "str"},
    "iptables_docker_user_text": {"type": "str"},
}


def _load_yaml(text: str) -> object:
    """Parse ``text`` as YAML, safely.

    Raises:
        YamlMissingError: when PyYAML cannot be imported.
        NotYamlError: when the text is not YAML.
    """
    try:
        import yaml  # type: ignore[import-untyped]  # noqa: PLC0415
    except ImportError as error:
        raise YamlMissingError from error
    try:
        loaded: object = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise NotYamlError from error
    return loaded


def _strings(node: object) -> Iterator[str]:
    """Yield every string in a parsed document, keys included."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, Mapping):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _published_address(entry: object) -> str | None:
    """Return the address a ``ports`` entry binds, or None when it names none."""
    if isinstance(entry, Mapping):
        address = entry.get("host_ip")
        return address if isinstance(address, str) else None
    if not isinstance(entry, str):
        return None
    text = entry.split("/", 1)[0]
    if text.startswith("["):
        close = text.find("]")
        if close < 0 or len(text[close + 1 :].lstrip(":").split(":")) != 2:
            return None
        return text[1:close]
    parts = text.split(":")
    return parts[0] if len(parts) == 3 else None


def _service_refusals(name: str, service: object, profile: str) -> list[str]:
    """Return the rules one service breaks, for either profile."""
    if not isinstance(service, Mapping):
        return [f"service {name} is not a mapping"]
    refusals = [f"service {name} sets {key}" for key in FORBIDDEN_SERVICE_KEYS if key in service]
    if service.get("privileged") not in (None, False):
        refusals.append(f"service {name} is privileged")
    image = service.get("image")
    if profile == TENANT and image != IMAGE_VARIABLE:
        refusals.append(f"service {name} image is not exactly {IMAGE_VARIABLE}")
    if profile == SPOOL and not (isinstance(image, str) and INLINE_IMAGE_PATTERN.fullmatch(image)):
        refusals.append(f"service {name} image is not pinned inline by digest")
    volumes = service.get("volumes", [])
    if isinstance(volumes, list) and any(DOCKER_SOCKET in text for text in _strings(volumes)):
        refusals.append(f"service {name} mounts the Docker socket")
    ports = service.get("ports", [])
    if not isinstance(ports, list):
        return [*refusals, f"service {name} ports is not a list"]
    for entry in ports:
        address = _published_address(entry)
        if address is None or address in WILDCARD_ADDRESSES:
            refusals.append(f"service {name} publishes a port without binding one address")
        elif profile == SPOOL and address != SPOOL_PUBLISH_ADDRESS:
            refusals.append(
                f"service {name} publishes a port on {address}, not {SPOOL_PUBLISH_ADDRESS}"
            )
    return refusals


def _network_refusals(networks: object, profile: str) -> list[str]:
    """Return the rules the top-level networks break."""
    if networks is None:
        return []
    if not isinstance(networks, Mapping):
        return ["networks is not a mapping"]
    refusals: list[str] = []
    for name, body in networks.items():
        if not isinstance(body, Mapping):
            refusals.append(f"network {name} has no body")
        elif profile == TENANT:
            if body.get("external") is not True:
                refusals.append(f"network {name} is not external")
        elif body.get("external") not in (None, False):
            refusals.append(f"network {name} is external")
        elif body.get("internal") is not True and not _is_drain_bridge(body):
            refusals.append(
                f"network {name} is neither internal nor the drain bridge {SPOOL_BRIDGE}"
            )
    return refusals


def _is_drain_bridge(body: Mapping[object, object]) -> bool:
    """Whether a network is the spool's one non-internal network, the named bridge."""
    options = body.get("driver_opts")
    return (
        body.get("driver") == "bridge"
        and isinstance(options, Mapping)
        and options.get(BRIDGE_NAME_OPTION) == SPOOL_BRIDGE
    )


def _volume_refusals(volumes: object) -> list[str]:
    """Return the rules the top-level volumes break: every one is external."""
    if volumes is None:
        return []
    if not isinstance(volumes, Mapping):
        return ["volumes is not a mapping"]
    return [
        f"volume {name} is not external"
        for name, body in volumes.items()
        if not (isinstance(body, Mapping) and body.get("external") is True)
    ]


def _reference_names(document: object) -> set[str]:
    """Return the name of every variable the document interpolates."""
    return {match for text in _strings(document) for match in REFERENCE_PATTERN.findall(text)}


def parse_secrets(text: str) -> tuple[dict[str, str], list[str]]:
    """Read a ``KEY=value`` file. Returns the pairs and the rules it breaks, none with a value."""
    pairs: dict[str, str] = {}
    refusals: list[str] = []
    for number, line in enumerate(text.split("\n"), start=1):
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in line):
            refusals.append(f"secrets line {number} holds a control character")
        elif line == "" or line.startswith("#"):
            continue
        else:
            match = SECRET_LINE_PATTERN.fullmatch(line)
            if match is None:
                refusals.append(f"secrets line {number} is not KEY=value")
            elif SECRET_KEY_PATTERN.fullmatch(match.group(1)) is None:
                refusals.append(f"secrets key {match.group(1)} does not start with GHOST_")
            elif match.group(1) in pairs:
                refusals.append(f"secrets key {match.group(1)} is given twice")
            else:
                pairs[match.group(1)] = match.group(2)
    return pairs, refusals


def _secret_refusals(references: set[str], text: str) -> list[str]:
    """Return the rules the secrets file breaks against the compose file's references."""
    pairs, refusals = parse_secrets(text)
    wanted = sorted(name for name in references if name.startswith("GHOST_"))
    refusals.extend(f"secrets file has no key {name}" for name in wanted if name not in pairs)
    refusals.extend(f"secrets key {name} is empty" for name in wanted if pairs.get(name) == "")
    return refusals


def _compose_refusals(params: Params, document: object) -> list[str]:
    """Return the rules the parsed compose file breaks, for the profile."""
    if not isinstance(document, Mapping):
        return ["compose text is not a mapping"]
    refusals = [
        f"compose has the top-level key {key}" for key in document if key not in TOP_LEVEL_KEYS
    ]
    if document.get("name") != params.slug:
        refusals.append("compose name is not the stack's slug")
    services = document.get("services")
    if not isinstance(services, Mapping) or not services:
        return [*refusals, "compose has no services"]
    for name, service in services.items():
        refusals.extend(_service_refusals(str(name), service, params.profile))
    refusals.extend(_network_refusals(document.get("networks"), params.profile))
    refusals.extend(_volume_refusals(document.get("volumes")))
    if params.profile == SPOOL:
        refusals.extend(_spool_refusals(document, services))
    return refusals


def _spool_refusals(
    document: Mapping[object, object], services: Mapping[object, object]
) -> list[str]:
    """Return the rules only the spool breaks: one service, one published port, no secret."""
    refusals: list[str] = []
    if len(services) != 1:
        refusals.append("the spool has more or fewer than one service")
    ports = [
        entry
        for service in services.values()
        if isinstance(service, Mapping) and isinstance(service.get("ports"), list)
        for entry in service["ports"]
    ]
    if len(ports) != 1:
        refusals.append("the spool does not publish exactly one port")
    refusals.extend(
        f"the spool refers to {name}, which the role does not supply"
        for name in sorted(_reference_names(document) - SPOOL_REFERENCE_NAMES)
    )
    return refusals


def _image_env_refusals(text: str) -> tuple[str, list[str]]:
    """Return the normalised pin file content and the rules the pin breaks."""
    lines = [line for line in text.split("\n") if line != ""]
    if len(lines) != 1 or IMAGE_LINE_PATTERN.fullmatch(lines[0]) is None:
        return "", ["image pin is not exactly one IMAGE=<name>@sha256:<64 hex digits> line"]
    return lines[0] + "\n", []


def _derived_image_env(document: object) -> str:
    """Return the pin file content derived from the spool's one inline image, or an empty string."""
    if not isinstance(document, Mapping) or not isinstance(document.get("services"), Mapping):
        return ""
    images = {
        service.get("image")
        for service in document["services"].values()
        if isinstance(service, Mapping)
    }
    only = next(iter(images)) if len(images) == 1 else None
    return (
        f"IMAGE={only}\n" if isinstance(only, str) and INLINE_IMAGE_PATTERN.fullmatch(only) else ""
    )


def _claim_state(params: Params) -> tuple[str, list[str]]:
    """Compare the tenant's uid with the claims. Returns the state and the rules it breaks."""
    if params.claims_text is None or params.profile != TENANT:
        return "unchecked", []
    claims: dict[str, int] = {}
    for line in params.claims_text.split("\n"):
        if line == "":
            continue
        match = CLAIM_LINE_PATTERN.fullmatch(line)
        if match is None:
            return "conflict", ["the volume program's claim list has a line that is not slug=uid"]
        claims[match.group(1)] = int(match.group(2))
    held_by = sorted(
        name for name, claimed in claims.items() if claimed == params.uid and name != params.slug
    )
    if held_by:
        return "conflict", [f"uid {params.uid} is already claimed by {held_by[0]}"]
    if params.slug not in claims:
        return "unclaimed", []
    if claims[params.slug] != params.uid:
        return "conflict", [
            f"{params.slug} already holds uid {claims[params.slug]}, not {params.uid}"
        ]
    return "same", []


def isolation_refusals(input_rules: str | None, docker_user_rules: str | None) -> list[str]:
    """Return the ways the drain bridge is not fenced in, read from ``iptables -S`` output."""
    if input_rules is None or docker_user_rules is None:
        return ["the drain bridge's firewall rules were not read"]
    bridge = re.escape(SPOOL_BRIDGE)
    named = [line for line in input_rules.splitlines() if re.search(rf" -i {bridge}( |$)", line)]
    accept = rf"-A INPUT -i {bridge} -m conntrack --ctstate {CONNTRACK_STATES} -j ACCEPT"
    drop = rf"-A INPUT -i {bridge} -j DROP"
    refusals: list[str] = []
    if not named or re.fullmatch(accept, named[0]) is None:
        refusals.append(
            f"INPUT does not begin its {SPOOL_BRIDGE} rules with the established-traffic accept"
        )
    if not any(re.fullmatch(drop, line) for line in named):
        refusals.append(f"INPUT does not drop what {SPOOL_BRIDGE} sends to the host")
    forward = rf"-A DOCKER-USER -i {bridge} ! -o {bridge} -j DROP"
    if not any(re.fullmatch(forward, line) for line in docker_user_rules.splitlines()):
        refusals.append(f"DOCKER-USER does not drop what {SPOOL_BRIDGE} forwards out")
    return refusals


def _slug_refusals(params: Params) -> list[str]:
    """Return the rules the slug and the uid break."""
    refusals: list[str] = []
    if SLUG_PATTERN.fullmatch(params.slug) is None or len(params.slug) > SLUG_MAX_LENGTH:
        refusals.append("slug is not lower-case letters, digits and hyphens, at most 26 characters")
    if params.profile == TENANT:
        if params.slug == SPOOL_SLUG:
            refusals.append(f"slug {SPOOL_SLUG} belongs to the mail spool")
        if params.uid is None or not UID_MIN <= params.uid <= UID_MAX:
            refusals.append(f"uid is not in {UID_MIN}-{UID_MAX}")
    elif params.slug != SPOOL_SLUG:
        refusals.append(f"the spool's slug is {SPOOL_SLUG}")
    return refusals


def judge(params: Params) -> Verdict:
    """Judge the text. A pure function: it reads nothing but ``params`` and writes nothing.

    Raises:
        YamlMissingError: when PyYAML cannot be imported.
    """
    refusals = _slug_refusals(params)
    stamp = hashlib.sha256(
        json.dumps(
            {"compose": params.compose_text, "secrets": params.secrets_env_text}, sort_keys=True
        ).encode()
    ).hexdigest()
    try:
        document = _load_yaml(params.compose_text)
    except NotYamlError:
        document = None
        refusals.append("compose text is not valid YAML")
    else:
        refusals.extend(_compose_refusals(params, document))
    image_env = ""
    if params.profile == TENANT:
        refusals.extend(_tenant_refusals(params, document))
        image_env, image_refusals = _image_env_refusals(params.image_env_text)
        refusals.extend(image_refusals)
    else:
        image_env = _derived_image_env(document)
        if params.secrets_env_text != "":
            refusals.append("the spool takes no secrets file")
        if params.require_isolation:
            refusals.extend(
                isolation_refusals(params.iptables_input_text, params.iptables_docker_user_text)
            )
    claim_state, claim_refusals = _claim_state(params)
    refusals.extend(claim_refusals)
    named = tuple(f"{params.slug}: {refusal}" for refusal in refusals)
    return Verdict(named, stamp, claim_state, "" if refusals else image_env)


def _tenant_refusals(params: Params, document: object) -> list[str]:
    """Return the rules about the secrets a tenant's references need."""
    references = _reference_names(document)
    unknown = sorted(
        name for name in references if name != "IMAGE" and not name.startswith("GHOST_")
    )
    refusals = [f"compose refers to {name}, which no file supplies" for name in unknown]
    return [*refusals, *_secret_refusals(references, params.secrets_env_text)]


def params_from_mapping(values: Mapping[str, object]) -> Params:
    """Build the typed parameters from the values AnsibleModule validated."""
    uid = values.get("uid")
    return Params(
        slug=str(values["slug"]),
        compose_text=str(values["compose_text"]),
        profile=str(values["profile"]),
        uid=uid if isinstance(uid, int) else None,
        secrets_env_text=str(values.get("secrets_env_text") or ""),
        image_env_text=str(values.get("image_env_text") or ""),
        claims_text=None if values.get("claims_text") is None else str(values["claims_text"]),
        require_isolation=values.get("require_isolation") is True,
        iptables_input_text=None
        if values.get("iptables_input_text") is None
        else str(values["iptables_input_text"]),
        iptables_docker_user_text=(
            None
            if values.get("iptables_docker_user_text") is None
            else str(values["iptables_docker_user_text"])
        ),
    )


def main() -> None:
    """Run as an Ansible module."""
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC, supports_check_mode=True)
    params = params_from_mapping(module.params)
    try:
        verdict = judge(params)
    except YamlMissingError as error:
        module.fail_json(msg=str(error))
    else:
        module.exit_json(
            changed=False,
            slug=params.slug,
            ok=verdict.ok,
            refusals=list(verdict.refusals),
            stamp=verdict.stamp,
            claim_state=verdict.claim_state,
            image_env=verdict.image_env,
        )


if __name__ == "__main__":
    main()
