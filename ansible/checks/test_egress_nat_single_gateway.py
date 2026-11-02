"""Check that edge1 plays the egress_nat role as the estate's one NAT gateway, and only edge1 does.

The role installs the gateway half (the NAT reconciler and its unit) only when
`egress_nat_gateway_enabled` is true, and its default is false. A second gateway is a routing
loop that takes the estate's egress (`hetzner/provision/branchleft_nat.sh`), so the switch is
set in one place: edge1's play vars, pinned by `HOST_PLAY_VARS` in the owner-only checks (R2).
This test holds the playbook, the table, the host's list in `host_roles.yml` and every other
file under `ansible/` to that one home. A change to one alone fails here, and a second host that
names the switch is refused by name, whichever file it is written in.
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
GATEWAY_HOST = "edge1"
OTHER_HOSTS = ("ops1", "app1", "db1", "demo1")
# The role owns the switch (its default, spec, tasks and tests), and the checks own the pin.
# Anywhere else in ansible/, a file that names the switch is a second home for it.
ROLE_DIR = ANSIBLE / "roles" / ROLE
CHECKS_DIR = ANSIBLE / "checks"
SWITCH_HOME = ANSIBLE / "playbooks" / f"{GATEWAY_HOST}.yml"


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


def _files_naming_the_switch_outside_its_homes() -> list[str]:
    """The paths under ansible/ that name the switch outside its homes.

    Its homes are the role, the checks and edge1's playbook.

    Markdown is prose and is not read. Every other file is, so an inventory, a group or host
    variable file, an owner_vars or trust file, a pattern, another role or another playbook
    that sets the switch is found whatever its name.
    """
    found: list[str] = []
    for path in sorted(ANSIBLE.rglob("*")):
        if not path.is_file() or path.suffix == ".md" or path == SWITCH_HOME:
            continue
        if ROLE_DIR in path.parents or CHECKS_DIR in path.parents:
            continue
        if SWITCH in path.read_text(encoding="utf-8", errors="ignore"):
            found.append(str(path.relative_to(ROOT)))
    return found


class EgressNatSingleGateway(unittest.TestCase):
    # (a) edge1 sets the switch, and the table pins it, exactly.
    def test_the_playbook_turns_the_gateway_on_for_edge1(self) -> None:
        self.assertIs(_play_vars(GATEWAY_HOST).get(SWITCH), True)

    def test_the_checker_table_pins_edge1_to_exactly_the_class_and_the_switch(self) -> None:
        self.assertEqual(
            HOST_PLAY_VARS[GATEWAY_HOST],
            {CLASS_KEY: "gateway", SWITCH: True},
        )

    # (b) no other host can become a second gateway, by any file.
    def test_no_other_host_is_pinned_to_the_switch(self) -> None:
        for host, pinned in HOST_PLAY_VARS.items():
            if host != GATEWAY_HOST:
                with self.subTest(host=host):
                    self.assertNotIn(SWITCH, pinned)

    def test_no_other_playbook_sets_the_switch(self) -> None:
        for host in OTHER_HOSTS:
            with self.subTest(host=host):
                self.assertNotIn(SWITCH, _play_vars(host))

    def test_no_file_outside_the_role_the_checks_and_edge1s_playbook_names_the_switch(self) -> None:
        self.assertEqual(_files_naming_the_switch_outside_its_homes(), [])

    # (c) the role is on edge1's list alone, and applied once on edge1, after host_baseline.
    def test_the_role_is_on_edge1s_list_alone(self) -> None:
        for host, names in _listed_roles().items():
            with self.subTest(host=host):
                if host == GATEWAY_HOST:
                    self.assertEqual(names.count(ROLE), 1)
                else:
                    self.assertNotIn(ROLE, names)

    def test_edge1_applies_the_role_once_after_host_baseline_and_before_ci_login(self) -> None:
        names = _role_names(GATEWAY_HOST)
        self.assertEqual(names.count(ROLE), 1)
        self.assertLess(names.index("host_baseline"), names.index(ROLE))
        self.assertLess(names.index(ROLE), names.index("ci_login"))

    def test_no_other_playbook_applies_the_role(self) -> None:
        for host in OTHER_HOSTS:
            with self.subTest(host=host):
                self.assertNotIn(ROLE, _role_names(host))

    def test_the_role_entry_is_bare_so_the_switch_cannot_hide_in_it(self) -> None:
        roles = _play(GATEWAY_HOST).get("roles")
        self.assertIn({"role": f"../roles/{ROLE}"}, roles if isinstance(roles, list) else [])


if __name__ == "__main__":
    unittest.main()
