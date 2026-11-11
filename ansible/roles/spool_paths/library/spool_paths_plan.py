#!/usr/bin/python
"""Work out which hosts ops1 holds a spool drain path to, from the descriptors it drains.

The collector drains the hosts its descriptor directory names and no others. A path is held to a
host only when a descriptor names it and the owner has also said where the host is. This module
reads the descriptor directory and the owner's table of far hosts, and returns the paths to hold,
the descriptors that name a host with no table row, the table rows that no descriptor names, and
the paths a past run wrote that nothing names now. It writes nothing and runs in check mode, so a
plan says what an apply will do.

The address a descriptor carries as `appHostIp` is the alias the path binds on ops1. It is the
descriptor's, not the table's, so the collector and the path cannot disagree about it.
"""

import ipaddress
import json
import re
from pathlib import Path
from typing import Final

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: spool_paths_plan
short_description: Derive the spool drain paths to hold from the collector's descriptors
description:
  - Reads every plain descriptor file in I(descriptor_dir) and pairs each with the owner's row in
    I(hosts) by slug. Only a descriptor that names a host with a row yields a path.
  - The path's alias is the descriptor's own I(appHostIp). It must be a private IPv4 address inside
    I(alias_block) and outside every block in I(reserved_blocks), and no two paths share one.
  - Lists the paths an earlier run wrote (a file in I(config_dir) that starts with I(marker)) that
    no descriptor names now, so the caller can take them down.
  - Writes nothing. A host that no descriptor names is never in the result's I(paths).
version_added: "1.0.0"
author:
  - branchLeft
options:
  descriptor_dir:
    description: The directory the collector reads descriptors from.
    type: path
    required: true
  config_dir:
    description: The directory the role writes one configuration file per path into.
    type: path
    required: true
  marker:
    description: The first line of a configuration file the role wrote.
    type: str
    required: true
  hosts:
    description: The owner's table of far hosts, one entry each.
    type: list
    elements: dict
    default: []
  alias_block:
    description: The IPv4 block every alias must sit in, empty while no path is built.
    type: str
    default: ''
  reserved_blocks:
    description: IPv4 blocks no alias may touch.
    type: list
    elements: str
    default: []
attributes:
  check_mode:
    support: full
    description: The module only reads.
  diff_mode:
    support: none
    description: The module changes nothing.
"""

EXAMPLES = r"""
- name: Work out the paths to hold
  spool_paths_plan:
    descriptor_dir: /etc/branchleft/mail-collector/descriptors
    config_dir: /etc/branchleft/spool-paths
    marker: '# Written by the spool_paths role.'
    hosts: '{{ spool_paths_hosts }}'
    alias_block: '{{ spool_paths_alias_block }}'
    reserved_blocks: '{{ spool_paths_reserved_blocks }}'
  register: spool_paths_plan_result
"""

RETURN = r"""
paths:
  description: One entry for each path to hold, sorted by slug.
  returned: success
  type: list
  elements: dict
unlisted:
  description: Slugs a descriptor names that have no table row. They get no path.
  returned: success
  type: list
  elements: str
unreached:
  description: Slugs the table lists that no descriptor names. They get no path.
  returned: success
  type: list
  elements: str
invalid:
  description: Descriptor file names that do not hold a usable descriptor. They get no path.
  returned: success
  type: list
  elements: str
stale:
  description: Slugs of configuration files the role wrote that no descriptor names now.
  returned: success
  type: list
  elements: str
"""

SLUG: Final = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
DESCRIPTOR_NAME: Final = re.compile(r"(?P<slug>[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)[.]json\Z")
CONFIG_NAME: Final = re.compile(r"(?P<slug>[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)[.]conf\Z")
HOST_NAME: Final = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
KEY_LINE: Final = re.compile(
    r"(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,3}\Z"
)
PRIVATE_BLOCKS: Final = tuple(
    ipaddress.IPv4Network(block) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
HOST_KEYS: Final = frozenset({"slug", "ssh_host", "spool_port", "host_key"})
HOST_OPTIONAL: Final = frozenset({"ssh_port", "jump"})
JUMP_KEYS: Final = frozenset({"host", "host_key"})
JUMP_OPTIONAL: Final = frozenset({"port"})
DEFAULT_PORT: Final = 22
MAX_PORT: Final = 65535


class Refusal(Exception):  # noqa: N818 - a refusal is not an error of the program
    """A refusal that names a place in the input, never a value."""


def whole_port(value: object) -> bool:
    """Return whether the value is a whole number from 1 to 65535 and not a boolean."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_PORT


def read_descriptors(directory: Path) -> tuple[dict[str, str], list[str]]:
    """Return slug to alias for every usable descriptor, and the names of the unusable ones.

    A file counts only when it is a regular file (not a link), its name is a slug and `.json`, it
    holds a JSON object whose `slug` is the file's own, and its `appHostIp` is a private IPv4
    address. Anything else is listed as invalid and yields no path.
    """
    usable: dict[str, str] = {}
    invalid: list[str] = []
    if not directory.is_dir():
        return usable, invalid
    for entry in sorted(directory.iterdir(), key=lambda item: item.name):
        named = DESCRIPTOR_NAME.match(entry.name)
        if named is None:
            continue
        slug = named.group("slug")
        alias = descriptor_alias(entry, slug)
        if alias is None:
            invalid.append(entry.name)
        else:
            usable[slug] = alias
    return usable, invalid


def descriptor_alias(entry: Path, slug: str) -> str | None:
    """Return the descriptor's address when the file is a usable descriptor, else None."""
    if entry.is_symlink() or not entry.is_file():
        return None
    try:
        document = json.loads(entry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict) or document.get("slug") != slug:
        return None
    alias = document.get("appHostIp")
    if not isinstance(alias, str):
        return None
    try:
        address = ipaddress.IPv4Address(alias)
    except ValueError:
        return None
    if str(address) != alias or not any(address in block for block in PRIVATE_BLOCKS):
        return None
    return alias


def check_jump(jump: object, where: str) -> dict[str, object]:
    """Return the jump entry when well formed.

    Raises:
        Refusal: when the entry is malformed, naming the row and never a value.
    """
    if not isinstance(jump, dict):
        message = f"{where}: jump must be a mapping"
        raise Refusal(message)
    keys = set(jump)
    if not JUMP_KEYS <= keys or not keys <= JUMP_KEYS | JUMP_OPTIONAL:
        message = f"{where}: jump must hold host and host_key, and port if it is not 22"
        raise Refusal(message)
    host, key, port = jump["host"], jump["host_key"], jump.get("port", DEFAULT_PORT)
    if not (isinstance(host, str) and HOST_NAME.match(host)):
        message = f"{where}: jump host is not a plain host name or address"
        raise Refusal(message)
    if not (isinstance(key, str) and KEY_LINE.match(key)):
        message = f"{where}: jump host_key must be one key type and its base64 body"
        raise Refusal(message)
    if not whole_port(port):
        message = f"{where}: jump port must be a whole number from 1 to 65535"
        raise Refusal(message)
    return {"host": host, "host_key": key, "port": port}


def check_row(row: object, position: int) -> dict[str, object]:
    """Return a normalised table row.

    Raises:
        Refusal: when the row is malformed, naming its place in the list and never a value.
    """
    where = f"host {position}"
    if not isinstance(row, dict):
        message = f"{where}: must be a mapping"
        raise Refusal(message)
    keys = set(row)
    if not HOST_KEYS <= keys or not keys <= HOST_KEYS | HOST_OPTIONAL:
        message = (
            f"{where}: must hold slug, ssh_host, spool_port, host_key; may hold ssh_port, jump"
        )
        raise Refusal(message)
    slug, host, key = row["slug"], row["ssh_host"], row["host_key"]
    if not (isinstance(slug, str) and SLUG.match(slug)):
        message = f"{where}: slug must be lowercase letters, digits and hyphens"
        raise Refusal(message)
    if not (isinstance(host, str) and HOST_NAME.match(host)):
        message = f"{where}: ssh_host is not a plain host name or address"
        raise Refusal(message)
    if not (isinstance(key, str) and KEY_LINE.match(key)):
        message = f"{where}: host_key must be one key type and its base64 body"
        raise Refusal(message)
    ssh_port = row.get("ssh_port", DEFAULT_PORT)
    if not whole_port(row["spool_port"]) or not whole_port(ssh_port):
        message = f"{where}: spool_port and ssh_port must be whole numbers from 1 to 65535"
        raise Refusal(message)
    jump = check_jump(row["jump"], where) if "jump" in row else {}
    return {
        "slug": slug,
        "ssh_host": host,
        "ssh_port": ssh_port,
        "spool_port": row["spool_port"],
        "host_key": key,
        "jump": jump,
    }


def check_blocks(alias_block: str, reserved: list[str]) -> ipaddress.IPv4Network | None:
    """Return the alias block as a network, or None while it is empty.

    Raises:
        Refusal: when a block is not an IPv4 network, the alias block is not private, or it
            overlaps a reserved block.
    """
    try:
        reserved_nets = [ipaddress.IPv4Network(block) for block in reserved]
        block = ipaddress.IPv4Network(alias_block) if alias_block else None
    except ValueError as error:
        message = "alias_block and reserved_blocks must be IPv4 networks in CIDR form"
        raise Refusal(message) from error
    if block is None:
        return None
    if not any(block.subnet_of(private) for private in PRIVATE_BLOCKS):
        message = "alias_block must sit inside 10/8, 172.16/12 or 192.168/16"
        raise Refusal(message)
    if any(block.overlaps(net) for net in reserved_nets):
        message = "alias_block overlaps a reserved block"
        raise Refusal(message)
    return block


def check_alias(slug: str, alias: str, block: ipaddress.IPv4Network | None) -> None:
    """Check that the alias is a usable address of the block.

    Raises:
        Refusal: when the block is empty, the address is outside it, or is its network or
            broadcast address. A block that overlaps a reserved one is refused before this.
    """
    address = ipaddress.IPv4Address(alias)
    if block is None:
        message = f"{slug}: a path is wanted but alias_block is empty"
        raise Refusal(message)
    if address not in block:
        message = f"{slug}: the descriptor's address is outside alias_block"
        raise Refusal(message)
    edges = (block.network_address, block.broadcast_address)
    if block.prefixlen < block.max_prefixlen - 1 and address in edges:
        message = f"{slug}: the descriptor's address is the block's network or broadcast address"
        raise Refusal(message)


def stale_slugs(config_dir: Path, marker: str, wanted: set[str]) -> list[str]:
    """Return slugs of marked configuration files in the directory that are not wanted."""
    found: list[str] = []
    if not config_dir.is_dir():
        return found
    for entry in sorted(config_dir.iterdir(), key=lambda item: item.name):
        named = CONFIG_NAME.match(entry.name)
        if named is None or entry.is_symlink() or not entry.is_file():
            continue
        try:
            first = entry.read_text(encoding="utf-8").split("\n", 1)[0]
        except (OSError, ValueError):
            continue
        if first == marker and named.group("slug") not in wanted:
            found.append(named.group("slug"))
    return found


def plan(
    hosts: list[object],
    alias_block: str,
    reserved_blocks: list[str],
    descriptor_dir: str,
    config_dir: str,
    marker: str,
) -> dict[str, object]:
    """Return the module's result for the given inputs.

    Raises:
        Refusal: when an input is malformed or two paths would collide.
    """
    rows = [check_row(row, position) for position, row in enumerate(hosts, start=1)]
    slugs = [str(row["slug"]) for row in rows]
    if len(set(slugs)) != len(slugs):
        message = "two hosts share a slug"
        raise Refusal(message)
    block = check_blocks(alias_block, reserved_blocks)
    descriptors, invalid = read_descriptors(Path(descriptor_dir))
    table = {str(row["slug"]): row for row in rows}
    paths: list[dict[str, object]] = []
    for slug in sorted(descriptors.keys() & table.keys()):
        check_alias(slug, descriptors[slug], block)
        paths.append({**table[slug], "alias": descriptors[slug]})
    aliases = [str(path["alias"]) for path in paths]
    if len(set(aliases)) != len(aliases):
        message = "two descriptors name one address, so two paths would bind it"
        raise Refusal(message)
    wanted = {str(path["slug"]) for path in paths}
    return {
        "paths": paths,
        "unlisted": sorted(descriptors.keys() - table.keys()),
        "unreached": sorted(table.keys() - descriptors.keys()),
        "invalid": invalid,
        "stale": stale_slugs(Path(config_dir), marker, wanted),
    }


def main() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec={
            "descriptor_dir": {"type": "path", "required": True},
            "config_dir": {"type": "path", "required": True},
            "marker": {"type": "str", "required": True},
            "hosts": {"type": "list", "elements": "dict", "default": []},
            "alias_block": {"type": "str", "default": ""},
            "reserved_blocks": {"type": "list", "elements": "str", "default": []},
        },
        supports_check_mode=True,
    )
    try:
        result = plan(
            list(module.params["hosts"]),
            str(module.params["alias_block"]),
            list(module.params["reserved_blocks"]),
            str(module.params["descriptor_dir"]),
            str(module.params["config_dir"]),
            str(module.params["marker"]),
        )
    except Refusal as refusal:
        module.fail_json(msg=str(refusal))
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
