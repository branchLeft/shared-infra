"""Pins on the tenant_scrape_tunnel role: its addresses and ports against their other homes.

The narrative is in test_tenant_scrape_tunnel_pins.md.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path, PurePosixPath

import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT
from test_ci_jump_hosts import tenants_host_ips

ROLE_NAME = "tenant_scrape_tunnel"
ROLE_ENTRY = f"../roles/{ROLE_NAME}"
ROLE_DIR = f"ansible/roles/{ROLE_NAME}"
VARS_FILE = f"{ROLE_DIR}/vars/main.yml"
PLAYBOOKS = "ansible/playbooks"
HOST_ROLES = "ansible/checks/host_roles"
ADDRESS_PLAN = "hetzner-host/addressPlan.ts"
TUNNEL_TS = "hetzner/monitoring/tenantTunnel.ts"
RENDER_TS = "hetzner/monitoring/render.ts"
COMPOSE_FILES = ("hetzner/monitoring/stack/compose.yml", "hetzner/edge/stack/compose.yml")
EDGE1_OWNER_VARS = "ansible/owner_vars/edge1.yml"
# The two hosts that apply the role: the scraper host and the target host.
HOSTS = ("edge1", "edget")
# The parts of the role that run on a host; its tests and Molecule scenarios are not among them.
ROLE_PARTS = ("tasks", "templates", "vars", "defaults", "meta", "files", "README.md")

HOST_IPS_BLOCK = re.compile(r"export const HOST_IPS = \{(?P<body>.*?)\} as const;", re.S)
HOST_ENTRY = re.compile(r"(?P<name>\w+):\s*'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'")
TUNNEL_ROW = re.compile(
    r"\{\s*name:\s*'(?P<name>[\w-]+)',\s*address:\s*TENANTS_HOST_IPS\.(?P<key>\w+),"
    r"[^{}]*?localPort:\s*(?P<port>\d+)\s*\}"
)
TUNNEL_BIND = re.compile(r"TENANT_TUNNEL_BIND_ADDRESS\s*=\s*HOST_IPS\.(?P<key>\w+);")
PORT_CONSTANT = re.compile(r"export const (?P<name>[A-Z0-9_]*PORT[A-Z0-9_]*) = (?P<port>\d+);")
# A path-like word of a file: it starts at a slash that does not follow a word or a colon.
PATH_WORD = re.compile(r"(?<![\w:./])/[\w./${}-]+")


def _read(root: Path, relative: str) -> str:
    path = root / relative
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _document(root: Path, relative: str) -> object:
    return yaml.safe_load(_read(root, relative)) if (root / relative).is_file() else None


def _mapping(value: object) -> dict[str, object]:
    return {str(key): item for key, item in value.items()} if isinstance(value, dict) else {}


def role_vars(root: Path) -> dict[str, object]:
    """The role's constants, as written in vars/main.yml."""
    return _mapping(_document(root, VARS_FILE))


def role_destinations(root: Path) -> list[dict[str, object]]:
    """The role's destination list: name, address and local_port of each."""
    listed = role_vars(root).get("tenant_scrape_tunnel_destinations")
    return [_mapping(entry) for entry in listed] if isinstance(listed, list) else []


def edge1_address(root: Path) -> str:
    """HOST_IPS.edge1 of the address plan under root, or an empty string when unreadable."""
    block = HOST_IPS_BLOCK.search(_read(root, ADDRESS_PLAN))
    if block is None:
        return ""
    entries = {item["name"]: item["ip"] for item in HOST_ENTRY.finditer(block["body"])}
    return entries.get("edge1", "")


def tunnel_rows(root: Path) -> dict[str, tuple[str, int]]:
    """The rows of TENANT_TUNNEL_TARGETS: the TENANTS_HOST_IPS key and local port, by name."""
    return {
        row["name"]: (row["key"], int(row["port"]))
        for row in TUNNEL_ROW.finditer(re.sub(r"//[^\n]*", "", _read(root, TUNNEL_TS)))
    }


def _address_findings(root: Path) -> list[str]:
    found: list[str] = []
    tenants = tenants_host_ips(root)
    if not tenants:
        return [f"{ADDRESS_PLAN}: TENANTS_HOST_IPS cannot be read, so the addresses are not held"]
    destinations = role_destinations(root)
    by_name = {str(entry.get("name")): str(entry.get("address")) for entry in destinations}
    wanted = {key.lower(): address for key, address in tenants.items()}
    if by_name != wanted:
        found.append(f"{VARS_FILE}: destinations are {by_name}, want {wanted} (TENANTS_HOST_IPS)")
    bind = str(role_vars(root).get("tenant_scrape_tunnel_bind_address"))
    if not edge1_address(root):
        found.append(f"{ADDRESS_PLAN}: HOST_IPS.edge1 cannot be read, so the bind is not held")
    elif bind != edge1_address(root):
        found.append(f"{VARS_FILE}: bind address is {bind}, want HOST_IPS.edge1")
    port = role_vars(root).get("tenant_scrape_tunnel_target_port")
    wanted_port = PORT_CONSTANT.findall(_read(root, RENDER_TS))
    exporter = next((int(value) for name, value in wanted_port if name == "NODE_EXPORTER_PORT"), 0)
    if port != exporter or not exporter:
        found.append(f"{VARS_FILE}: target port is {port}, want NODE_EXPORTER_PORT ({exporter})")
    return found


def _local_port_findings(root: Path) -> list[str]:
    """Each local port equals the one of the same host in TENANT_TUNNEL_TARGETS, and the TS bind
    is edge1's address."""
    rows = tunnel_rows(root)
    if len(rows) != len(role_destinations(root)) or not rows:
        return [f"{TUNNEL_TS}: {len(rows)} tunnel rows, the role has a different count or none"]
    found: list[str] = []
    ts_ports = {key.lower(): port for key, port in rows.values()}
    ts_names = {name.replace("-", "") for name in rows}
    for entry in role_destinations(root):
        name = str(entry.get("name"))
        if ts_ports.get(name) != entry.get("local_port"):
            found.append(
                f"{VARS_FILE}: {name} local port is {entry.get('local_port')}, "
                f"{TUNNEL_TS} has {ts_ports.get(name)}"
            )
        if name not in ts_names:
            found.append(f"{TUNNEL_TS} has no row named like {name}")
    bind = TUNNEL_BIND.search(_read(root, TUNNEL_TS))
    if bind is None or bind["key"] != "edge1":
        found.append(f"{TUNNEL_TS}: TENANT_TUNNEL_BIND_ADDRESS is not HOST_IPS.edge1")
    return found


def published_ports(root: Path) -> dict[int, str]:
    """Each port something on edge1 publishes or listens on, with where it is named."""
    taken: dict[int, str] = {}
    for name, value in PORT_CONSTANT.findall(_read(root, RENDER_TS)):
        taken[int(value)] = f"{RENDER_TS} {name}"
    for relative in COMPOSE_FILES:
        services = _mapping(_mapping(_document(root, relative)).get("services"))
        for service, definition in services.items():
            ports = _mapping(definition).get("ports")
            for item in ports if isinstance(ports, list) else []:
                text = str(item.get("published") if isinstance(item, dict) else item)
                host_side = text.split("/")[0].split(":")
                host_port = host_side[-2] if len(host_side) > 1 else host_side[0]
                low, _, high = host_port.partition("-")
                if low.isdigit():
                    for port in range(int(low), int(high or low) + 1):
                        taken[port] = f"{relative} {service}"
    for key, value in _mapping(_document(root, EDGE1_OWNER_VARS)).items():
        if key.endswith("_port") and isinstance(value, int):
            taken[value] = f"{EDGE1_OWNER_VARS} {key}"
    return taken


def _collision_findings(root: Path) -> list[str]:
    ports = [entry.get("local_port") for entry in role_destinations(root)]
    found: list[str] = []
    if not ports or not all(isinstance(port, int) for port in ports):
        return [f"{VARS_FILE}: the destinations have no integer local ports"]
    if len(set(ports)) != len(ports):
        found.append(f"{VARS_FILE}: two destinations share a local port: {ports}")
    taken = published_ports(root)
    if len(taken) < 10:
        found.append(f"only {len(taken)} published ports were read, so a collision is not held")
    for port in ports:
        if isinstance(port, int) and port in taken:
            found.append(f"local port {port} is also {taken[port]}")
    return found


def _applications(node: object) -> list[str]:
    """Every string in a playbook that names the role, by its last path part."""
    if isinstance(node, str):
        return [node] if PurePosixPath(node).name == ROLE_NAME else []
    if isinstance(node, dict):
        children = list(node.values())
    elif isinstance(node, list):
        children = node
    else:
        return []
    return [text for child in children for text in _applications(child)]


def _playbook_findings(root: Path, host: str) -> list[str]:
    """The host applies the role once, in the play's roles, as an entry that holds no other key."""
    document = _document(root, f"{PLAYBOOKS}/{host}.yml")
    play = _mapping(document[0]) if isinstance(document, list) and document else {}
    roles = play.get("roles")
    entries = roles if isinstance(roles, list) else []
    plain = [entry for entry in entries if entry in (ROLE_ENTRY, {"role": ROLE_ENTRY})]
    total = len(_applications(document))
    if total != 1 or len(plain) != 1:
        return [
            f"playbooks/{host}.yml applies {ROLE_NAME} {total} times, "
            f"{len(plain)} as a plain role entry; want once, as a plain role entry"
        ]
    return []


def _listing_findings(root: Path, host: str) -> list[str]:
    listed = _document(root, f"{HOST_ROLES}/{host}.yml")
    if not isinstance(listed, list) or ROLE_NAME not in listed:
        return [f"checks/host_roles/{host}.yml does not list {ROLE_NAME}"]
    return []


def _path_findings(root: Path) -> list[str]:
    """No path under the role, and no path written in the role, holds the account's name."""
    account = str(role_vars(root).get("tenant_scrape_tunnel_user") or "")
    role = root / ROLE_DIR
    if not account or not role.is_dir():
        return [f"{VARS_FILE}: the account name cannot be read, so its paths are not held"]
    found: list[str] = []
    for part in ROLE_PARTS:
        base = role / part
        files = sorted(base.rglob("*")) if base.is_dir() else [base] if base.is_file() else []
        for path in files:
            relative = path.relative_to(root)
            if account in str(path.relative_to(role)):
                found.append(f"{relative}: the path holds the account name")
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for word in sorted(set(PATH_WORD.findall(text))):
                if account in word:
                    found.append(f"{relative}: {word} holds the account name")
    return found


def problems(root: Path) -> list[str]:
    """Return one finding per broken pin in the tree under ``root``."""
    found = _address_findings(root) + _local_port_findings(root) + _collision_findings(root)
    found.extend(_path_findings(root))
    for host in HOSTS:
        found.extend(_playbook_findings(root, host))
        found.extend(_listing_findings(root, host))
    return found


class RealTree(unittest.TestCase):
    def test_the_role_agrees_with_the_address_plan_the_tunnel_generator_and_the_hosts(self) -> None:
        self.assertEqual([], problems(ROOT))

    def test_the_address_plan_and_the_tunnel_rows_are_read(self) -> None:
        # The control of the control: an empty parse would pass every pin above.
        self.assertEqual(3, len(tenants_host_ips(ROOT)))
        self.assertEqual(3, len(tunnel_rows(ROOT)))
        self.assertTrue(edge1_address(ROOT))
        self.assertEqual(3, len(role_destinations(ROOT)))

    def test_the_published_ports_are_read_from_every_source(self) -> None:
        taken = published_ports(ROOT)
        self.assertIn(9090, taken)
        self.assertIn(9100, taken)
        self.assertIn(6060, taken)
        self.assertIn(80, taken)
        self.assertTrue(any(RENDER_TS in where for where in taken.values()))
        self.assertTrue(any("compose.yml" in where for where in taken.values()))
        self.assertTrue(any(EDGE1_OWNER_VARS in where for where in taken.values()))


class Sabotage(unittest.TestCase):
    """Each pin goes red on a copy of the tree with one thing broken: the files it reads only."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(
            ROOT / ROLE_DIR,
            self.root / ROLE_DIR,
            ignore=shutil.ignore_patterns("tests", "molecule"),
        )
        for relative in (
            ADDRESS_PLAN,
            TUNNEL_TS,
            RENDER_TS,
            EDGE1_OWNER_VARS,
            *COMPOSE_FILES,
            *(f"{PLAYBOOKS}/{host}.yml" for host in HOSTS),
            *(f"{HOST_ROLES}/{host}.yml" for host in HOSTS),
        ):
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, self.root / relative)

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

    def test_a_changed_destination_address_is_red(self) -> None:
        dbt1 = tenants_host_ips(self.root)["dbT1"]
        self._edit(VARS_FILE, f"address: {dbt1}", "address: 192.0.2.1")
        self._expect("want {'dbt1'")

    def test_a_fourth_destination_is_red(self) -> None:
        self._edit(
            VARS_FILE,
            "  - name: edget\n",
            "  - name: extra\n    address: 192.0.2.1\n    local_port: 19103\n  - name: edget\n",
        )
        self._expect("destinations are")

    def test_a_changed_bind_address_is_red(self) -> None:
        self._edit(VARS_FILE, f"bind_address: {edge1_address(self.root)}", "bind_address: 0.0.0.0")
        self._expect("bind address is 0.0.0.0")

    def test_a_changed_target_port_is_red(self) -> None:
        self._edit(VARS_FILE, "target_port: 9100", "target_port: 9104")
        self._expect("target port is 9104")

    def test_a_local_port_that_differs_from_the_generators_is_red(self) -> None:
        self._edit(VARS_FILE, "local_port: 19101", "local_port: 19111")
        self._expect("appt1 local port is 19111")

    def test_a_generator_row_that_is_gone_is_red(self) -> None:
        self._edit(TUNNEL_TS, "  { name: 'edge-t'", "  // { name: 'edge-t'")
        self._expect("tunnel rows")

    def test_a_generator_bind_that_is_not_edge1_is_red(self) -> None:
        self._edit(TUNNEL_TS, "HOST_IPS.edge1", "HOST_IPS.mon1")
        self._expect("TENANT_TUNNEL_BIND_ADDRESS is not HOST_IPS.edge1")

    def test_a_local_port_on_a_published_port_is_red(self) -> None:
        self._edit(VARS_FILE, "local_port: 19100", "local_port: 9090")
        self._expect("local port 9090 is also")

    def test_two_destinations_on_one_local_port_are_red(self) -> None:
        self._edit(VARS_FILE, "local_port: 19101", "local_port: 19100")
        self._expect("share a local port")

    def test_a_local_port_on_the_sweego_port_is_red(self) -> None:
        self._edit(VARS_FILE, "local_port: 19100", "local_port: 18080")
        self._expect(f"local port 18080 is also {EDGE1_OWNER_VARS}")

    def test_a_local_port_on_a_compose_port_is_red(self) -> None:
        self._edit(VARS_FILE, "local_port: 19100", "local_port: 2586")
        self._expect("local port 2586 is also hetzner/monitoring/stack/compose.yml")

    def test_a_conditional_role_entry_is_red(self) -> None:
        self._edit(
            f"{PLAYBOOKS}/edget.yml",
            f"    - role: {ROLE_ENTRY} # noqa: role-name[path]\n",
            f"    - role: {ROLE_ENTRY} # noqa: role-name[path]\n      when: true\n",
        )
        self._expect("playbooks/edget.yml applies tenant_scrape_tunnel")

    def test_a_missing_role_entry_is_red(self) -> None:
        self._edit(
            f"{PLAYBOOKS}/edge1.yml", f"    - role: {ROLE_ENTRY} # noqa: role-name[path]\n", ""
        )
        self._expect("playbooks/edge1.yml applies tenant_scrape_tunnel 0 times")

    def test_an_include_role_of_the_role_is_red(self) -> None:
        self._edit(
            f"{PLAYBOOKS}/edget.yml",
            "  pre_tasks:\n",
            f"  pre_tasks:\n    - ansible.builtin.include_role:\n        name: {ROLE_ENTRY}\n",
        )
        self._expect("playbooks/edget.yml applies tenant_scrape_tunnel 2 times")

    def test_a_host_roles_list_without_the_role_is_red(self) -> None:
        self._edit(f"{HOST_ROLES}/edget.yml", f"- {ROLE_NAME}\n", "")
        self._expect("checks/host_roles/edget.yml does not list")

    def test_a_path_made_from_the_account_name_is_red(self) -> None:
        self._edit(
            VARS_FILE,
            "tenant_scrape_tunnel_key_dir: /etc/branchleft/tenant-scrape",
            "tenant_scrape_tunnel_key_dir: /etc/branchleft/scrapetunnel",
        )
        self._expect("holds the account name")

    def test_a_file_named_after_the_account_is_red(self) -> None:
        (self.root / ROLE_DIR / "files" / "scrapetunnel.conf").write_text("x\n", encoding="utf-8")
        self._expect("the path holds the account name")

    def test_an_unreadable_address_plan_is_red(self) -> None:
        self._edit(ADDRESS_PLAN, "export const TENANTS_HOST_IPS = {", "export const TENANTS = {")
        self._expect("TENANTS_HOST_IPS cannot be read")


if __name__ == "__main__":
    unittest.main()
