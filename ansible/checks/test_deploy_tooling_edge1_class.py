"""Check that edge1 plays the deploy_tooling role as class gateway, and only edge1 does.

The role takes `deploy_tooling_host_class` with no default (ANS-7). The pull route has no
channel for a role input, so edge1's playbook sets it in the play's vars and the enrolment
checker pins that value per host in `HOST_PLAY_VARS` (R2). The value is therefore stated
twice by design: the playbook carries it and the checker's table decides it. This test reads
the real files and holds the two to each other and to the host's list in `host_roles.yml`, so a
change to one alone fails here.

The gateway class belongs to the gateway host. Other hosts may name their own class in their own
playbooks and table rows; none may name gateway.
"""

from __future__ import annotations

import unittest

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_PLAY_VARS, ROOT

ANSIBLE = ROOT / "ansible"
CLASS_KEY = "deploy_tooling_host_class"
ROLE = "deploy_tooling"
GATEWAY_HOST = "edge1"
OTHER_HOSTS = ("ops1", "app1", "db1")


def _mapping(value: object) -> dict[str, object]:
    """Return the mapping with string keys.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"expected a mapping, found {type(value).__name__}"
        raise TypeError(message)
    return {str(key): item for key, item in value.items()}


def _play(host: str) -> dict[str, object]:
    """Return the one play of the host's playbook.

    Raises:
        TypeError: the playbook is not a list of one play.
    """
    doc: object = yaml.safe_load(
        (ANSIBLE / "playbooks" / f"{host}.yml").read_text(encoding="utf-8")
    )
    if not isinstance(doc, list) or len(doc) != 1:
        message = f"{host}.yml is not a list of one play"
        raise TypeError(message)
    return _mapping(doc[0])


def _play_vars(host: str) -> dict[str, object]:
    return _mapping(_play(host).get("vars"))


class Edge1Class(unittest.TestCase):
    def test_the_playbook_sets_class_gateway(self) -> None:
        self.assertEqual(_play_vars(GATEWAY_HOST).get(CLASS_KEY), "gateway")

    def test_the_checker_table_says_gateway_for_edge1(self) -> None:
        self.assertEqual(HOST_PLAY_VARS[GATEWAY_HOST], {CLASS_KEY: "gateway"})

    def test_no_other_host_is_pinned_to_gateway(self) -> None:
        for host, pinned in HOST_PLAY_VARS.items():
            if host != GATEWAY_HOST:
                with self.subTest(host=host):
                    self.assertNotEqual(pinned.get(CLASS_KEY), "gateway")

    def test_no_other_playbook_sets_gateway(self) -> None:
        for host in OTHER_HOSTS:
            with self.subTest(host=host):
                self.assertNotEqual(_play_vars(host).get(CLASS_KEY), "gateway")

    def test_the_role_is_applied_on_edge1_in_the_bare_form(self) -> None:
        roles = _play(GATEWAY_HOST).get("roles")
        self.assertIsInstance(roles, list)
        self.assertIn({"role": f"../roles/{ROLE}"}, roles if isinstance(roles, list) else [])

    def test_the_role_is_on_edge1s_list(self) -> None:
        listed: object = yaml.safe_load(
            (ANSIBLE / "checks" / "host_roles.yml").read_text(encoding="utf-8")
        )
        edge1_roles = _mapping(listed)[GATEWAY_HOST]
        self.assertIn(ROLE, edge1_roles if isinstance(edge1_roles, list) else [])


if __name__ == "__main__":
    unittest.main()
