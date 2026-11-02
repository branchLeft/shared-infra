"""Check that each network has exactly one NAT gateway, and no other host plays that role.

The role installs the gateway half (the NAT reconciler and its unit) only when
`egress_nat_gateway_enabled` is true, and its default is false. A second gateway on one network
is a routing loop that takes that network's egress (`hetzner/provision/branchleft_nat.sh`), so
the switch is set in one place per network: the gateway's own play vars, pinned by
`HOST_PLAY_VARS` in the owner-only checks (R2). A network does not span hcloud projects, so the
estate's network (gateway edge1) and the tenants network (gateway edget, the server edge-t) each
have one. This test holds each playbook, the table, the host's list in `host_roles.yml` and
every other file under `ansible/` to that one home per network. A change to one alone fails
here, a host that names the switch without being a listed gateway is refused by name whichever
file it is written in, and a second gateway for a network that already has one is refused.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_PLAY_VARS, ROOT

ANSIBLE = ROOT / "ansible"
SWITCH = "egress_nat_gateway_enabled"
CLASS_KEY = "deploy_tooling_host_class"
ROLE = "egress_nat"
# Every host that may be a gateway, and the network it is the gateway of. A new gateway is a
# new row here, in the same owner-merged change that adds its pin to HOST_PLAY_VARS.
GATEWAYS = {"edge1": "estate", "edget": "tenants"}
# The role owns the switch (its default, spec, tasks and tests), and the checks own the pin.
# Anywhere else in ansible/, a file that names the switch is a second home for it, except a
# gateway's own playbook.
ROLE_DIR = ANSIBLE / "roles" / ROLE
CHECKS_DIR = ANSIBLE / "checks"
SWITCH_HOMES = {ANSIBLE / "playbooks" / f"{host}.yml" for host in GATEWAYS}


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


def _role_names(host: str) -> list[str]:
    roles = _play(host).get("roles")
    if not isinstance(roles, list):
        return []
    return [Path(str(_mapping(entry)["role"])).name for entry in roles]


def _listed_roles() -> dict[str, list[str]]:
    listed = _mapping(yaml.safe_load((CHECKS_DIR / "host_roles.yml").read_text(encoding="utf-8")))
    return {
        host: [str(name) for name in (names if isinstance(names, list) else [])]
        for host, names in listed.items()
    }


def _other_hosts() -> list[str]:
    """Every host with a playbook that is not a listed gateway."""
    stems = sorted(path.stem for path in (ANSIBLE / "playbooks").glob("*.yml"))
    return [stem for stem in stems if stem not in GATEWAYS]


def _files_naming_the_switch_outside_its_homes() -> list[str]:
    """The paths under ansible/ that name the switch outside its homes.

    Its homes are the role, the checks and each gateway's own playbook.

    Markdown is prose and is not read. Every other file is, so an inventory, a group or host
    variable file, an owner_vars or trust file, a pattern, another role or another playbook
    that sets the switch is found whatever its name.
    """
    found: list[str] = []
    for path in sorted(ANSIBLE.rglob("*")):
        if not path.is_file() or path.suffix == ".md" or path in SWITCH_HOMES:
            continue
        if ROLE_DIR in path.parents or CHECKS_DIR in path.parents:
            continue
        if SWITCH in path.read_text(encoding="utf-8", errors="ignore"):
            found.append(str(path.relative_to(ROOT)))
    return found


class EgressNatSingleGateway(unittest.TestCase):
    # (a) each gateway sets the switch, and the table pins it, exactly.
    def test_each_gateway_playbook_turns_the_gateway_on(self) -> None:
        for host in GATEWAYS:
            with self.subTest(host=host):
                self.assertIs(_play_vars(host).get(SWITCH), True)

    def test_the_checker_table_pins_edge1_to_the_class_and_the_switch(self) -> None:
        # The row also pins the two edge_firewall variables; test_edge_firewall_single_home.py
        # holds the whole row.
        row = HOST_PLAY_VARS["edge1"]
        self.assertEqual(
            {CLASS_KEY: row[CLASS_KEY], SWITCH: row[SWITCH]},
            {CLASS_KEY: "gateway", SWITCH: True},
        )
        self.assertEqual(
            set(row) - {CLASS_KEY, SWITCH},
            {"edge_firewall_nat_source", "edge_firewall_enforce"},
        )

    def test_the_checker_table_pins_edget_to_exactly_the_switch(self) -> None:
        self.assertEqual(HOST_PLAY_VARS["edget"], {SWITCH: True})

    # (b) one gateway per network, and no host outside the listed gateways.
    def test_no_network_has_two_gateways(self) -> None:
        self.assertEqual(len(set(GATEWAYS.values())), len(GATEWAYS))

    def test_the_hosts_pinned_to_the_switch_are_the_listed_gateways_exactly(self) -> None:
        pinned = {host for host, values in HOST_PLAY_VARS.items() if SWITCH in values}
        self.assertEqual(pinned, set(GATEWAYS))

    def test_no_other_playbook_sets_the_switch(self) -> None:
        for host in _other_hosts():
            with self.subTest(host=host):
                self.assertNotIn(SWITCH, _play_vars(host))

    def test_no_file_outside_the_role_the_checks_and_a_gateways_playbook_names_the_switch(
        self,
    ) -> None:
        self.assertEqual(_files_naming_the_switch_outside_its_homes(), [])

    # (c) the role is on the gateways' lists alone, and applied once on each, after host_baseline.
    def test_the_role_is_on_the_gateways_lists_alone(self) -> None:
        for host, names in _listed_roles().items():
            with self.subTest(host=host):
                if host in GATEWAYS:
                    self.assertEqual(names.count(ROLE), 1)
                else:
                    self.assertNotIn(ROLE, names)

    def test_each_gateway_applies_the_role_once_after_host_baseline(self) -> None:
        for host in GATEWAYS:
            with self.subTest(host=host):
                names = _role_names(host)
                self.assertEqual(names.count(ROLE), 1)
                self.assertLess(names.index("host_baseline"), names.index(ROLE))

    def test_edge1_applies_the_role_before_ci_login(self) -> None:
        names = _role_names("edge1")
        self.assertLess(names.index(ROLE), names.index("ci_login"))

    def test_no_other_playbook_applies_the_role(self) -> None:
        for host in _other_hosts():
            with self.subTest(host=host):
                self.assertNotIn(ROLE, _role_names(host))

    def test_the_role_entry_is_bare_so_the_switch_cannot_hide_in_it(self) -> None:
        for host in GATEWAYS:
            with self.subTest(host=host):
                roles = _play(host).get("roles")
                role_list = roles if isinstance(roles, list) else []
                self.assertIn({"role": f"../roles/{ROLE}"}, role_list)


if __name__ == "__main__":
    unittest.main()
