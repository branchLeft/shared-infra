"""Check how the sweego_receiver role is wired to edge1, and what that lets through.

The role has two host ports it takes from the host's owner variables. This test holds them to the
three other places that decide who can reach a port on edge1: the edge's list of ports it may
proxy to (hetzner/edge/render.ts), the public cloud firewall (hetzner-host/firewalls.ts), and the
role's own place in the playbook and in the host's role list. The webhook port is one the edge
proxies to; the drain port is reachable from ops1 alone (the role's DOCKER-USER rules) and must
never become an edge upstream, nor be opened to the internet.
"""

from __future__ import annotations

import re
import unittest

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_ROLES_FILE, ROOT

ANSIBLE = ROOT / "ansible"
HOST = "edge1"
ROLE = "sweego_receiver"
WEBHOOK_KEY = "sweego_receiver_port"
DRAIN_KEY = "sweego_receiver_drain_port"
RENDER = ROOT / "hetzner" / "edge" / "render.ts"
FIREWALLS = ROOT / "hetzner-host" / "firewalls.ts"
ALLOWED_PORTS = re.compile(r"EDGE_HOST_ALLOWED_PORTS[^=]*=\s*new Set\(\[([^\]]*)\]\)")
FIREWALL_PORT = re.compile(r"port:\s*'(\d+)'")
# What the role needs before it can run: Docker (host_baseline), the NAT unit its rule unit is
# ordered after (egress_nat) and the shared compose unit (deploy_tooling).
PREREQUISITES = ("host_inputs", "host_baseline", "egress_nat", "deploy_tooling")


def _mapping(value: object) -> dict[str, object]:
    """Return the mapping with string keys.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"expected a mapping, found {type(value).__name__}"
        raise TypeError(message)
    return {str(key): item for key, item in value.items()}


def _owner_port(key: str) -> int:
    """Return the port the edge1 owner variables name for the key.

    Raises:
        TypeError: the value is missing or is not a whole number.
    """
    doc = _mapping(
        yaml.safe_load((ANSIBLE / "owner_vars" / f"{HOST}.yml").read_text(encoding="utf-8"))
    )
    value = doc.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{key} is not a whole number in owner_vars/{HOST}.yml"
        raise TypeError(message)
    return value


def _edge_upstream_ports() -> set[int]:
    """Return the ports on edge1 the edge may proxy to, read from the renderer's source.

    Raises:
        ValueError: the list cannot be found, which would make every test here vacuous.
    """
    match = ALLOWED_PORTS.search(RENDER.read_text(encoding="utf-8"))
    if match is None:
        message = "EDGE_HOST_ALLOWED_PORTS not found in hetzner/edge/render.ts"
        raise ValueError(message)
    return {int(item) for item in re.findall(r"\d+", match.group(1))}


def _firewall_ports() -> set[int]:
    return {int(item) for item in FIREWALL_PORT.findall(FIREWALLS.read_text(encoding="utf-8"))}


def _playbook_roles() -> list[str]:
    doc: object = yaml.safe_load(
        (ANSIBLE / "playbooks" / f"{HOST}.yml").read_text(encoding="utf-8")
    )
    if not isinstance(doc, list) or len(doc) != 1:
        message = f"{HOST}.yml is not a list of one play"
        raise TypeError(message)
    roles = _mapping(doc[0]).get("roles")
    if not isinstance(roles, list):
        message = f"{HOST}.yml has no roles list"
        raise TypeError(message)
    return [str(_mapping(entry)["role"]).rsplit("/", 1)[-1] for entry in roles]


def _host_roles() -> dict[str, list[str]]:
    doc = _mapping(yaml.safe_load((ANSIBLE / HOST_ROLES_FILE).read_text(encoding="utf-8")))
    return {
        host: [str(item) for item in roles]
        for host, roles in doc.items()
        if isinstance(roles, list)
    }


class Ports(unittest.TestCase):
    def test_the_two_ports_are_different_unprivileged_numbers(self) -> None:
        webhook, drain = _owner_port(WEBHOOK_KEY), _owner_port(DRAIN_KEY)
        self.assertNotEqual(webhook, drain)
        for port in (webhook, drain):
            self.assertGreaterEqual(port, 1024)
            self.assertLessEqual(port, 65535)

    def test_the_webhook_port_is_a_port_the_edge_may_proxy_to(self) -> None:
        self.assertIn(_owner_port(WEBHOOK_KEY), _edge_upstream_ports())

    def test_the_drain_port_is_never_a_port_the_edge_may_proxy_to(self) -> None:
        self.assertNotIn(_owner_port(DRAIN_KEY), _edge_upstream_ports())

    def test_the_edge_list_names_no_unexplained_port(self) -> None:
        # The pager's port and the webhook port, and nothing else: a new entry is a decision
        # that this test makes the author state.
        self.assertEqual(_edge_upstream_ports() - {_owner_port(WEBHOOK_KEY)}, {2586})

    def test_neither_port_is_open_in_the_public_firewall(self) -> None:
        public = _firewall_ports()
        self.assertTrue(public, "no port found in hetzner-host/firewalls.ts")
        self.assertFalse(public & {_owner_port(WEBHOOK_KEY), _owner_port(DRAIN_KEY)})


class Placement(unittest.TestCase):
    def test_the_role_is_on_edge1s_list_and_no_other_hosts(self) -> None:
        for host, roles in _host_roles().items():
            with self.subTest(host=host):
                self.assertEqual(ROLE in roles, host == HOST)

    def test_the_playbook_applies_the_role_once_and_last(self) -> None:
        roles = _playbook_roles()
        self.assertEqual(roles.count(ROLE), 1)
        self.assertEqual(roles[-1], ROLE)

    def test_the_playbook_applies_what_the_role_relies_on_first(self) -> None:
        roles = _playbook_roles()
        for needed in PREREQUISITES:
            with self.subTest(needed=needed):
                self.assertLess(roles.index(needed), roles.index(ROLE))


if __name__ == "__main__":
    unittest.main()
