"""Pins on the hosts that apply the ci_jump role: edge1 and edge-t (the logical host edget).

The role is one: it writes the jump account's key options and the sshd Match block from one
destination list, and `molecule/default` proves over a real sshd that a destination not on the list
is refused. That proof covers every host only if the role has no branch on the host and every jump
host applies it as a plain role entry. This file holds both, and holds the two data rules the
pipeline's route rests on (the 2 Nov ruling, ws#2894):

* edge1's list may hold edge-t's public address and never a tenants private address, so the runner
  cannot be sent from edge1 straight to a tenants host and must go on through edge-t;
* edget's own address, once the owner sets it, is the one the address plan gives edge-t.

The tenants addresses are read from hetzner-host/addressPlan.ts (TENANTS_HOST_IPS), their one home,
and never copied here. Each pin is shown red on a sabotaged copy of the files it reads, and green
again on the copy left alone, which is also the real tree.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import JUMP_HOSTS, ROOT

ROLE_NAME = "ci_jump"
ROLE_ENTRY = f"../roles/{ROLE_NAME}"
ROLE_DIR = f"ansible/roles/{ROLE_NAME}"
OWNER_VARS = "ansible/owner_vars"
PLAYBOOKS = "ansible/playbooks"
ADDRESS_PLAN = "hetzner-host/addressPlan.ts"
# The two hosts the ruling names. JUMP_HOSTS may grow, but these two stay.
REQUIRED_HOSTS = frozenset(("edge1", "edget"))
# The names a role would use to behave differently on one host. A role that has none of them
# applies the same on every host, so the Molecule proof of the role is the proof for each.
HOST_SELECTORS = re.compile(
    r"\b(enrolled_host|inventory_hostname(_short)?|ansible_hostname|ansible_nodename"
    r"|ansible_fqdn|ansible_host|group_names|groups|hostvars)\b"
)
# The parts of the role that run on a host. Its tests and Molecule scenarios are not among them.
ROLE_PARTS = ("tasks", "templates", "vars", "defaults", "meta", "library", "handlers", "files")
# Tenants private addresses are read from this block of the address plan.
TENANTS_BLOCK = re.compile(r"export const TENANTS_HOST_IPS = \{(?P<body>.*?)\} as const;", re.S)
TENANTS_ENTRY = re.compile(r"(?P<name>\w+):\s*'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'")
TENANTS_NEEDED = ("edgeT", "dbT1")
DESTINATIONS = "ci_jump_destinations"
OWN_ADDRESS = "ci_jump_own_address"


def tenants_host_ips(root: Path) -> dict[str, str]:
    """TENANTS_HOST_IPS of the address plan under root, by name. Empty when it cannot be read."""
    path = root / ADDRESS_PLAN
    block = TENANTS_BLOCK.search(path.read_text(encoding="utf-8")) if path.is_file() else None
    if block is None:
        return {}
    return {entry["name"]: entry["ip"] for entry in TENANTS_ENTRY.finditer(block["body"])}


def _document(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None


def _mapping(value: object) -> dict[str, object]:
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}


def _text_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _role_entries(root: Path, host: str) -> list[object]:
    """The role entries of the one play of a host's playbook."""
    document = _document(root / PLAYBOOKS / f"{host}.yml")
    plays = document if isinstance(document, list) else []
    roles = _mapping(plays[0]).get("roles") if plays else None
    return list(roles) if isinstance(roles, list) else []


def _is_jump_entry(entry: object) -> bool:
    name = entry.get("role") if isinstance(entry, dict) else entry
    return isinstance(name, str) and name == ROLE_ENTRY


def _playbook_findings(root: Path, host: str) -> list[str]:
    """The host applies the role once, as a plain role entry that no condition or variable
    reaches."""
    entries = [entry for entry in _role_entries(root, host) if _is_jump_entry(entry)]
    if len(entries) != 1:
        return [f"playbooks/{host}.yml applies {ROLE_NAME} {len(entries)} times, want once"]
    entry = entries[0]
    extra = sorted(set(entry) - {"role"}) if isinstance(entry, dict) else []
    if extra:
        return [f"playbooks/{host}.yml: the {ROLE_NAME} entry carries {extra}, want a plain entry"]
    return []


def _role_findings(root: Path) -> list[str]:
    """No part of the role that runs on a host names the host, or a group of hosts."""
    found: list[str] = []
    role = root / ROLE_DIR
    if not role.is_dir():
        return [f"{ROLE_DIR} is missing"]
    for part in ROLE_PARTS:
        for path in sorted((role / part).rglob("*")) if (role / part).is_dir() else []:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in sorted({m[0] for m in HOST_SELECTORS.finditer(text)}):
                relative = path.relative_to(root / "ansible")
                found.append(f"{relative} reads {match}: the role must not branch on the host")
    return found


def _owner_values(root: Path, host: str) -> dict[str, object]:
    return _mapping(_document(root / OWNER_VARS / f"{host}.yml"))


def _data_findings(root: Path) -> list[str]:
    """The address rules on the owner's data, whatever it holds now or later."""
    found: list[str] = []
    tenants = tenants_host_ips(root)
    for name in TENANTS_NEEDED:
        if name not in tenants:
            found.append(f"{ADDRESS_PLAN}: TENANTS_HOST_IPS has no {name}, so it cannot be read")
    private = set(tenants.values())

    edge1 = _owner_values(root, "edge1")
    for address in _text_list(edge1.get(DESTINATIONS)):
        if address in private:
            found.append(
                f"owner_vars/edge1.yml: {DESTINATIONS} holds {address}, a tenants private "
                "address; edge1 may list edge-t's public address only"
            )

    edget = _owner_values(root, "edget")
    own = str(edget.get(OWN_ADDRESS) or "")
    if own and tenants.get("edgeT") != own:
        found.append(
            f"owner_vars/edget.yml: {OWN_ADDRESS} is {own}, want TENANTS_HOST_IPS.edgeT "
            f"({tenants.get('edgeT')})"
        )
    for host in sorted(JUMP_HOSTS):
        values = _owner_values(root, host)
        destinations = _text_list(values.get(DESTINATIONS))
        host_own = str(values.get(OWN_ADDRESS) or "")
        if destinations and host_own not in destinations:
            found.append(
                f"owner_vars/{host}.yml: {DESTINATIONS} is set but does not hold {OWN_ADDRESS}"
            )
    return found


def problems(root: Path) -> list[str]:
    """Return one finding per broken pin in the tree under ``root``."""
    found: list[str] = []
    missing = sorted(REQUIRED_HOSTS - JUMP_HOSTS)
    if missing:
        found.append(f"JUMP_HOSTS lacks {missing}, which the ruling names")
    for host in sorted(JUMP_HOSTS):
        found.extend(_playbook_findings(root, host))
    found.extend(_role_findings(root))
    found.extend(_data_findings(root))
    return found


class RealTree(unittest.TestCase):
    def test_the_two_jump_hosts_apply_the_one_role_and_hold_the_address_rules(self) -> None:
        self.assertEqual([], problems(ROOT))

    def test_the_jump_hosts_are_edge1_and_edge_t_at_least(self) -> None:
        self.assertLessEqual(REQUIRED_HOSTS, JUMP_HOSTS)

    def test_the_address_plan_is_read_and_holds_edge_t_and_the_tenants_database(self) -> None:
        # The control of the control: an empty parse would pass the edge1 rule for any list.
        tenants = tenants_host_ips(ROOT)
        for name in TENANTS_NEEDED:
            self.assertIn(name, tenants)
        self.assertEqual(len(tenants), len(set(tenants.values())))


class Sabotage(unittest.TestCase):
    """Each pin goes red on a copy of the tree with one thing broken. The copy is the files the
    pins read and nothing else."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        leave_out = shutil.ignore_patterns("molecule", "tests")
        shutil.copytree(ROOT / ROLE_DIR, self.root / ROLE_DIR, ignore=leave_out)
        for relative in (PLAYBOOKS, OWNER_VARS):
            shutil.copytree(ROOT / relative, self.root / relative)
        (self.root / ADDRESS_PLAN).parent.mkdir(parents=True)
        shutil.copy(ROOT / ADDRESS_PLAN, self.root / ADDRESS_PLAN)

    def _edit(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"the sabotage matched nothing in {relative}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def _expect(self, fragment: str) -> None:
        found = problems(self.root)
        self.assertTrue(any(fragment in line for line in found), f"{fragment!r} not in {found}")

    def test_the_copy_left_alone_is_green(self) -> None:
        self.assertEqual([], problems(self.root))

    def test_a_tenants_private_address_in_edge1s_list_is_red(self) -> None:
        tenants = tenants_host_ips(self.root)
        self._edit(
            f"{OWNER_VARS}/edge1.yml",
            f"{DESTINATIONS}: []",
            f"{DESTINATIONS}: ['{tenants['dbT1']}']",
        )
        self._expect("a tenants private address")

    def test_edge_ts_own_private_address_in_edge1s_list_is_red(self) -> None:
        tenants = tenants_host_ips(self.root)
        self._edit(
            f"{OWNER_VARS}/edge1.yml",
            f"{DESTINATIONS}: []",
            f"{DESTINATIONS}: ['{tenants['edgeT']}']",
        )
        self._expect("a tenants private address")

    def test_a_public_address_in_edge1s_list_is_green(self) -> None:
        # 192.0.2.0/24 is documentation space: the stand-in for edge-t's public address.
        self._edit(
            f"{OWNER_VARS}/edge1.yml", f"{DESTINATIONS}: []", f"{DESTINATIONS}: ['192.0.2.7']"
        )
        self.assertEqual([], [line for line in problems(self.root) if "tenants private" in line])

    def test_dropping_the_role_from_edget_is_red(self) -> None:
        self._edit(
            f"{PLAYBOOKS}/edget.yml", f"    - role: {ROLE_ENTRY} # noqa: role-name[path]\n", ""
        )
        self._expect("playbooks/edget.yml applies ci_jump 0 times")

    def test_a_condition_on_the_role_entry_is_red(self) -> None:
        self._edit(
            f"{PLAYBOOKS}/edget.yml",
            f"    - role: {ROLE_ENTRY} # noqa: role-name[path]\n",
            f"    - role: {ROLE_ENTRY} # noqa: role-name[path]\n      when: false\n",
        )
        self._expect("the ci_jump entry carries ['when']")

    def test_a_host_branch_in_the_role_is_red(self) -> None:
        path = self.root / ROLE_DIR / "tasks" / "main.yml"
        path.write_text(
            path.read_text(encoding="utf-8") + "  when: enrolled_host == 'edge1'\n",
            encoding="utf-8",
        )
        self._expect("reads enrolled_host")

    def test_a_host_branch_in_a_template_is_red(self) -> None:
        path = self.root / ROLE_DIR / "templates" / "authorized_keys.j2"
        path.write_text(
            "{% if inventory_hostname == 'edge1' %}{% endif %}\n"
            + path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self._expect("reads inventory_hostname")

    def test_a_wrong_own_address_on_edget_is_red(self) -> None:
        self._edit(f"{OWNER_VARS}/edget.yml", f"{OWN_ADDRESS}: ''", f"{OWN_ADDRESS}: '10.20.9.9'")
        self._expect("want TENANTS_HOST_IPS.edgeT")

    def test_edge_ts_own_address_from_the_plan_is_green(self) -> None:
        own = tenants_host_ips(self.root)["edgeT"]
        self._edit(f"{OWNER_VARS}/edget.yml", f"{OWN_ADDRESS}: ''", f"{OWN_ADDRESS}: '{own}'")
        self.assertEqual([], problems(self.root))

    def test_a_list_without_the_hosts_own_address_is_red(self) -> None:
        self._edit(
            f"{OWNER_VARS}/edget.yml", f"{DESTINATIONS}: []", f"{DESTINATIONS}: ['192.0.2.9']"
        )
        self._expect("does not hold ci_jump_own_address")

    def test_an_address_plan_that_cannot_be_read_is_red(self) -> None:
        # Without this an unreadable plan would let any list through the edge1 rule.
        self._edit(ADDRESS_PLAN, "export const TENANTS_HOST_IPS = {", "export const TENANTS = {")
        self._expect("TENANTS_HOST_IPS has no edgeT")


if __name__ == "__main__":
    unittest.main()
