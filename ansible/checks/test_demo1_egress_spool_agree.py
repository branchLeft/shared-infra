"""The demo1_egress_spool role and the rest of demo1's roles agree, and each path has one owner.

The role is the only owner of the egress program, its unit, the mail spool's Compose file, its
image pin file and the drain token path. The slot networks it lets the spool join are the slot
table of demo1_build, written separately. The playbook that applies the role does not apply
egress_nat to the demo host, whose containers must not reach the network, nor host_baseline or
broker_deploy, which are the host's own steps. The cross-role
references are not allowed (ANS-12), so each copy stays and this test keeps them in step.
"""

from __future__ import annotations

import io
import ipaddress
import re
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn, cast

from check_pins import load_yaml
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
ROLE = "demo1_egress_spool"
BUILD = "demo1_build"
PLAYBOOK = ROOT / "ansible" / "playbooks" / "demo1.yml"
# The directories of a role that run on a host. The scenarios and the README name paths to
# test them or to explain them, which writes nothing.
HOST_DIRS = ("defaults", "vars", "tasks", "handlers", "templates", "files", "meta")
HOST_SUFFIXES = (".yml", ".yaml", ".j2", ".service", ".sh", ".py", ".conf", ".timer")
# Where a role keeps its copy of files taken from ghost-platform, under files/.
VENDORED = ("files", "ghost-platform")
SLOT_NAMES = re.compile(r"default\(\[([^\]]*)\]\)")
# The rendered Compose file the role carries, at its path from the ghost-platform root.
GOLDEN = ROLES / ROLE / Path(*VENDORED) / "render-core/test/golden/mail-spool-compose.demo1.yml"
SERVICE = "mail-spool"
# The environment key that tells the shim which address its drain listener binds to.
DRAIN_HOST_KEY = "SHIM_DRAIN_HOST"
DRAIN_PORT_KEY = "SHIM_DRAIN_PORT"
OWNED = (
    "demo1_egress_spool_egress_script_dest",
    "demo1_egress_spool_egress_unit_dest",
    "demo1_egress_spool_project_dir",
    "demo1_egress_spool_compose_dest",
    "demo1_egress_spool_image_env_path",
    "demo1_egress_spool_override_dest",
    "demo1_egress_spool_dropin_dest",
    "demo1_egress_spool_token_path",
)
NAT_ROLE = "egress_nat"
# The roles demo1's playbook must not apply, with the reason each is held off. The list in
# checks/host_roles.yml holds the same three off a pushed playbook (R2); this keeps the reasons.
EXCLUDED = {
    NAT_ROLE: "which would give the demo containers a route out",
    "host_baseline": "which is the host's own step, under its own enrolment decision",
    "broker_deploy": "which would repoint a broker the owner installed by hand",
}
ORDER = (BUILD, ROLE)
# What the role README says about the spool's image reaching the host.
UNDECIDED = re.compile(r"is not decided yet", re.IGNORECASE)
ROUTE_HEADING = "How the spool's image gets onto the host"
ROUTE_NAMES = ("docker load", "spool_image_gate")


class SpoolAgreeError(Exception):
    """A file the check reads is missing, unparseable or not in the shape it needs."""


def refuse(message: str) -> NoReturn:
    """Stop the check with a message.

    Raises:
        SpoolAgreeError: always, carrying the message.
    """
    raise SpoolAgreeError(message)


def yaml_of(path: Path) -> object:
    """Return the parsed YAML of a file.

    Raises:
        SpoolAgreeError: when the file cannot be read as YAML.
    """
    document, problem = load_yaml(path)
    if problem is not None:
        raise SpoolAgreeError(problem)
    return document


def mapping_of(value: object) -> dict[str, object]:
    """Return a YAML mapping.

    Raises:
        SpoolAgreeError: when the value is not a mapping.
    """
    if not isinstance(value, dict):
        refuse("expected a YAML mapping")
    return cast("dict[str, object]", value)


def is_vendored(path: Path, role: Path) -> bool:
    """Return whether a path is under the role's copy of files taken from ghost-platform."""
    return path.relative_to(role).parts[: len(VENDORED)] == VENDORED


def host_text(role: Path) -> str:
    """Return the text of every file of a role that runs on a host, in a fixed order.

    The role's vendored copies of ghost-platform's files are left out: they are upstream's
    text, held to their pins, and not the role's own statement of what it owns.
    """
    parts: list[str] = []
    for name in HOST_DIRS:
        base = role / name
        if base.is_dir():
            parts.extend(
                path.read_text(encoding="utf-8")
                for path in sorted(base.rglob("*"))
                if path.is_file() and path.suffix in HOST_SUFFIXES and not is_vendored(path, role)
            )
    return "\n".join(parts)


def slot_names(build_defaults: dict[str, object]) -> list[str]:
    """Return the slot names demo1_build defaults to.

    Raises:
        SpoolAgreeError: when the default is not a list of bare digit strings.
    """
    expression = str(build_defaults["demo1_build_slot_names"])
    found = SLOT_NAMES.search(expression)
    if found is None:
        refuse("demo1_build_slot_names must default to a list written in the file")
    names = [item.strip().strip("'\"") for item in found.group(1).split(",")]
    if not names or not all(name.isdigit() for name in names):
        refuse("demo1_build_slot_names must default to bare digit strings")
    return names


def playbook_roles(root: Path = ROOT) -> list[str]:
    """Return the names of the roles demo1's playbook applies, in order.

    Raises:
        SpoolAgreeError: when the playbook is not one play with a role list.
    """
    document = yaml_of(root / PLAYBOOK.relative_to(ROOT))
    plays = document if isinstance(document, list) else []
    if len(plays) != 1:
        refuse("demo1.yml must hold exactly one play")
    entries = mapping_of(plays[0]).get("roles")
    if not isinstance(entries, list):
        refuse("the play in demo1.yml must list roles")
    return [Path(str(mapping_of(entry)["role"])).name for entry in entries]


def facts(root: Path = ROOT) -> dict[str, object]:
    """Read every fact the roles and the playbook state about the spool and the egress policy.

    Raises:
        SpoolAgreeError: when a file the check reads is not in the expected shape.
    """
    roles = root / ROLES.relative_to(ROOT)
    spool_vars = mapping_of(yaml_of(roles / ROLE / "vars" / "main.yml"))
    build_vars = mapping_of(yaml_of(roles / BUILD / "vars" / "main.yml"))
    build_defaults = mapping_of(yaml_of(roles / BUILD / "defaults" / "main.yml"))
    others = {
        role.name: host_text(role)
        for role in sorted(roles.iterdir())
        if role.is_dir() and role.name != ROLE
    }
    return {
        "owned": {key: str(spool_vars[key]) for key in OWNED},
        "others": others,
        "slot_networks": [
            str(name)
            for name in cast("list[object]", spool_vars["demo1_egress_spool_slot_networks"])
        ],
        "slot_uid_base": int(str(build_vars["demo1_build_slot_uid_base"])),
        "slot_names": slot_names(build_defaults),
        "playbook_roles": playbook_roles(root),
    }


def disagreements(f: dict[str, object]) -> list[str]:
    """Return one line for each way the roles and the playbook disagree."""
    found: list[str] = []
    owned = cast("dict[str, str]", f["owned"])
    others = cast("dict[str, str]", f["others"])
    for role, text in others.items():
        found.extend(
            f"{role} names {path!r}, which {ROLE} owns ({key})"
            for key, path in owned.items()
            if path in text
        )
    # demo1_build does not pin the egress program or its unit, so this role is their only pin.
    found.extend(
        f"{BUILD} names {marker!r}: the egress program and unit must be pinned by {ROLE} alone"
        for marker in ("branchleft_demo_egress", "branchleft-demo-egress")
        if marker in others.get(BUILD, "")
    )
    base = cast("int", f["slot_uid_base"])
    expected = [
        f"branchleft-mail-{base + int(name)}" for name in cast("list[str]", f["slot_names"])
    ]
    networks = cast("list[str]", f["slot_networks"])
    if networks != expected:
        found.append(
            f"demo1_egress_spool_slot_networks = {networks!r} "
            f"but the {BUILD} slot table gives {expected!r}"
        )
    applied = cast("list[str]", f["playbook_roles"])
    found.extend(
        f"demo1.yml applies {role}, {reason}"
        for role, reason in EXCLUDED.items()
        if role in applied
    )
    for role in ORDER:
        if applied.count(role) != 1:
            times = applied.count(role)
            found.append(f"demo1.yml must apply {role} exactly once, and applies it {times} times")
    if all(applied.count(role) == 1 for role in ORDER):
        positions = [applied.index(role) for role in ORDER]
        if positions != sorted(positions):
            found.append(
                f"demo1.yml must apply {', '.join(ORDER)} in that order, and applies {applied!r}"
            )
    return found


def image_route_problems(readme: str) -> list[str]:
    """Return one line for each way the role README fails to state how the spool's image arrives.

    The host never pulls, so the README is the one place the route is written. It must not say
    the route is undecided, and it must name the primitive that loads the image and the tool that
    gates it, or the route is a sentence nobody can act on.
    """
    found: list[str] = []
    if UNDECIDED.search(readme):
        found.append("the README still says how the image reaches the host is not decided")
    if ROUTE_HEADING not in readme:
        found.append(f"the README has no section called {ROUTE_HEADING!r}")
    found.extend(
        f"the README does not name {name!r} in the image route"
        for name in ROUTE_NAMES
        if name not in readme
    )
    return found


def as_map(value: object) -> dict[str, object]:
    """Return the value when it is a mapping, and an empty mapping when it is anything else."""
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def drain_address_problems(address: object) -> list[str]:
    """Return one line for each way the drain listener's address cannot be a fixed bind address."""
    if address is None:
        return [f"{DRAIN_HOST_KEY} is missing from the spool's environment"]
    try:
        parsed = ipaddress.IPv4Address(str(address))
    except ValueError:
        return [f"{DRAIN_HOST_KEY} {address!r} is not an IPv4 address"]
    if parsed.is_unspecified:
        return [f"{DRAIN_HOST_KEY} is {parsed}, which binds the drain listener to every interface"]
    if parsed.is_loopback:
        return [f"{DRAIN_HOST_KEY} is {parsed}, a loopback address no published port can reach"]
    return []


def drain_network_problems(
    declared: dict[str, object], address: object, drain_network: str
) -> list[str]:
    """Return one line for each way the drain network's pool fails to hold the drain address."""
    pools = as_map(declared.get("ipam")).get("config")
    if not isinstance(pools, list) or len(pools) != 1:
        return [f"{drain_network} must declare exactly one ipam pool"]
    pool = as_map(pools[0])
    try:
        subnet = ipaddress.IPv4Network(str(pool.get("subnet")))
        gateway = ipaddress.IPv4Address(str(pool.get("gateway")))
    except ValueError:
        return [f"{drain_network}'s ipam pool needs an IPv4 subnet and an IPv4 gateway"]
    found: list[str] = []
    if gateway not in subnet:
        found.append(f"{drain_network}'s gateway {gateway} is outside its subnet {subnet}")
    try:
        bound = ipaddress.IPv4Address(str(address))
    except ValueError:
        return found
    if bound not in subnet:
        found.append(f"the drain address {bound} is outside {drain_network}'s subnet {subnet}")
    elif bound in (gateway, subnet.network_address, subnet.broadcast_address):
        found.append(f"the drain address {bound} is the gateway, network or broadcast address")
    return found


def drain_service_problems(
    service: dict[str, object], drain_network: str, slot_networks: list[str], container_port: int
) -> tuple[list[str], object]:
    """Return the findings on the spool service, and the drain address it names (or None)."""
    environment = as_map(service.get("environment"))
    address = environment.get(DRAIN_HOST_KEY)
    found = drain_address_problems(address)
    if str(environment.get(DRAIN_PORT_KEY)) != str(container_port):
        found.append(f"{DRAIN_PORT_KEY} is not the container port {container_port}")
    published = {
        str(entry).rsplit(":", 1)[-1] for entry in cast("list[object]", service.get("ports") or [])
    }
    if published != {str(container_port)}:
        found.append(f"the published ports reach {sorted(published)}, not the container port")
    networks = service.get("networks")
    if not isinstance(networks, dict):
        found.append(
            "the spool's networks are a list: a map is needed to give the drain network an address"
        )
        return found, address
    if sorted(networks) != sorted([drain_network, *slot_networks]):
        found.append("the spool's networks are not exactly the drain network and the slot networks")
    drain_entry = as_map(networks.get(drain_network))
    if "ipv4_address" not in drain_entry:
        found.append(f"{drain_network} has no ipv4_address on the spool")
    elif address is not None and str(drain_entry["ipv4_address"]) != str(address):
        found.append(
            f"{drain_network} ipv4_address {drain_entry['ipv4_address']!r} differs from "
            f"{DRAIN_HOST_KEY} {address!r}"
        )
    found.extend(
        f"slot network {name} declares an ipv4_address: the address belongs on {drain_network} only"
        for name in slot_networks
        if "ipv4_address" in as_map(networks.get(name))
    )
    return found, address


def drain_golden_problems(
    compose_text: str, drain_network: str, slot_networks: list[str], container_port: int
) -> list[str]:
    """Return one line for each way the rendered Compose file loses the fixed drain address.

    The drain listener binds to the address in SHIM_DRAIN_HOST, so that address must be one the
    spool holds on the drain network, in a pool the file declares. The checks are relations
    between lines of the file and the role's own constants, so no address is written here.
    """
    try:
        document = YAML(typ="safe").load(compose_text)
    except YAMLError as error:
        return [f"the Compose file cannot be read as YAML: {type(error).__name__}"]
    root = as_map(document)
    service = as_map(as_map(root.get("services")).get(SERVICE))
    if not service:
        return [f"the Compose file does not define the {SERVICE} service"]
    found, address = drain_service_problems(service, drain_network, slot_networks, container_port)
    declared = as_map(as_map(root.get("networks")).get(drain_network))
    if not declared:
        found.append(f"the Compose file does not declare the {drain_network} network")
    else:
        found.extend(drain_network_problems(declared, address, drain_network))
    for name in slot_networks:
        if "ipv4_address" in as_map(as_map(root.get("networks")).get(name)):
            found.append(f"top-level slot network {name} declares an ipv4_address")
    return found


def role_drain_constants() -> tuple[str, list[str], int]:
    """Return the drain network, the slot networks and the container port the role declares."""
    spool_vars = mapping_of(yaml_of(ROLES / ROLE / "vars" / "main.yml"))
    return (
        str(spool_vars["demo1_egress_spool_drain_network"]),
        [
            str(name)
            for name in cast("list[object]", spool_vars["demo1_egress_spool_slot_networks"])
        ],
        int(str(spool_vars["demo1_egress_spool_container_port"])),
    )


def mutated_golden(change: Callable[[dict[str, object]], None]) -> list[str]:
    """Return the findings for the vendored file after one change to its parsed form."""
    document = mapping_of(YAML(typ="safe").load(GOLDEN.read_text(encoding="utf-8")))
    change(document)
    out = io.StringIO()
    YAML(typ="safe").dump(document, out)
    return drain_golden_problems(out.getvalue(), *role_drain_constants())


def service_of(document: dict[str, object]) -> dict[str, object]:
    """Return the spool service of a parsed Compose file."""
    return as_map(as_map(document["services"])[SERVICE])


class SpoolAgreeTest(unittest.TestCase):
    def test_the_real_tree_agrees(self) -> None:
        self.assertEqual([], disagreements(facts()))

    def test_the_readme_states_the_image_route(self) -> None:
        readme = (ROLES / ROLE / "README.md").read_text(encoding="utf-8")
        self.assertEqual([], image_route_problems(readme))

    def test_a_readme_that_leaves_the_image_route_undecided_is_named(self) -> None:
        old = (
            "How the image gets onto the host is not decided yet. **Until it is, step 4 "
            "refuses on a host that does not hold the image**."
        )
        found = image_route_problems(old)
        self.assertTrue(any("not decided" in line for line in found), found)
        self.assertTrue(any("docker load" in line for line in found), found)
        self.assertTrue(any("spool_image_gate" in line for line in found), found)

    def test_a_readme_that_drops_the_section_or_a_name_is_named(self) -> None:
        readme = (ROLES / ROLE / "README.md").read_text(encoding="utf-8")
        for removed in (ROUTE_HEADING, *ROUTE_NAMES):
            with self.subTest(removed=removed):
                found = image_route_problems(readme.replace(removed, "REDACTED"))
                self.assertTrue(any(removed in line for line in found), found)

    def test_a_path_named_by_a_second_role_is_named(self) -> None:
        base = facts()
        owned = cast("dict[str, str]", base["owned"])
        for key, path in owned.items():
            with self.subTest(key=key):
                others = dict(
                    cast("dict[str, str]", base["others"]), host_baseline=f"dest: {path}\n"
                )
                found = disagreements(dict(base, others=others))
                self.assertTrue(
                    any(key in line and "host_baseline" in line for line in found), found
                )

    def test_an_egress_pin_in_demo1_build_is_named(self) -> None:
        base = facts()
        for marker in ("branchleft_demo_egress.sh", "branchleft-demo-egress.service"):
            with self.subTest(marker=marker):
                others = dict(cast("dict[str, str]", base["others"]))
                others[BUILD] += f"\n  - path: demo-host/provision/{marker}\n"
                found = disagreements(dict(base, others=others))
                self.assertTrue(any("pinned by" in line for line in found), found)

    def test_a_slot_network_that_drifts_from_the_slot_table_is_named(self) -> None:
        base = facts()
        networks = cast("list[str]", base["slot_networks"])
        for changed in (
            networks[:-1],
            [*networks, "branchleft-mail-30008"],
            ["branchleft-mail-30009", *networks[1:]],
        ):
            with self.subTest(networks=changed):
                found = disagreements(dict(base, slot_networks=changed))
                self.assertTrue(any("slot_networks" in line for line in found), found)

    def test_a_moved_uid_base_or_slot_table_is_named(self) -> None:
        base = facts()
        for key, value in (("slot_uid_base", 40001), ("slot_names", ["0", "1", "2"])):
            with self.subTest(key=key):
                found = disagreements(dict(base, **{key: value}))
                self.assertTrue(any("slot_networks" in line for line in found), found)

    def test_a_role_held_off_demo1_is_named(self) -> None:
        base = facts()
        for role in EXCLUDED:
            with self.subTest(role=role):
                roles = [*cast("list[str]", base["playbook_roles"]), role]
                found = disagreements(dict(base, playbook_roles=roles))
                self.assertTrue(any(f"applies {role}" in line for line in found), found)

    def test_the_roles_in_the_wrong_order_or_missing_are_named(self) -> None:
        base = facts()
        for roles in (
            [ROLE, BUILD],
            [BUILD],
            [ROLE],
            [BUILD, ROLE, ROLE],
        ):
            with self.subTest(roles=roles):
                found = disagreements(dict(base, playbook_roles=roles))
                self.assertTrue(found)

    def test_a_vendored_file_is_not_the_roles_own_statement(self) -> None:
        owned = cast("dict[str, str]", facts()["owned"])
        path = next(iter(owned.values()))
        with tempfile.TemporaryDirectory() as tmp:
            role = Path(tmp)
            (role / "files" / "ghost-platform").mkdir(parents=True)
            (role / "tasks").mkdir()
            (role / "files" / "ghost-platform" / "upstream.sh").write_text(f"dest: {path}\n")
            self.assertNotIn(path, host_text(role))
            (role / "tasks" / "main.yml").write_text(f"dest: {path}\n")
            self.assertIn(path, host_text(role))

    def test_the_vendored_golden_binds_the_drain_listener_to_a_fixed_drain_address(self) -> None:
        found = drain_golden_problems(GOLDEN.read_text(encoding="utf-8"), *role_drain_constants())
        self.assertEqual([], found)

    def test_each_way_to_lose_the_fixed_drain_address_is_named(self) -> None:
        drain, slots, _ = role_drain_constants()

        def drain_entry(document: dict[str, object]) -> dict[str, object]:
            return as_map(as_map(service_of(document)["networks"])[drain])

        def environment(document: dict[str, object]) -> dict[str, object]:
            return as_map(service_of(document)["environment"])

        def drop_host(document: dict[str, object]) -> None:
            del environment(document)[DRAIN_HOST_KEY]

        def every_interface(document: dict[str, object]) -> None:
            environment(document)[DRAIN_HOST_KEY] = "0.0.0.0"  # noqa: S104

        def loopback(document: dict[str, object]) -> None:
            environment(document)[DRAIN_HOST_KEY] = "127.0.0.1"

        def drop_pool(document: dict[str, object]) -> None:
            del as_map(as_map(document["networks"])[drain])["ipam"]

        def outside_subnet(document: dict[str, object]) -> None:
            moved = str(ipaddress.IPv4Address(str(environment(document)[DRAIN_HOST_KEY])) + 256)
            environment(document)[DRAIN_HOST_KEY] = moved
            drain_entry(document)["ipv4_address"] = moved

        def address_differs(document: dict[str, object]) -> None:
            held = ipaddress.IPv4Address(str(drain_entry(document)["ipv4_address"]))
            drain_entry(document)["ipv4_address"] = str(held + 1)

        def no_address_on_drain(document: dict[str, object]) -> None:
            drain_entry(document).clear()

        def networks_as_list(document: dict[str, object]) -> None:
            service_of(document)["networks"] = [drain, *slots]

        def address_on_a_slot(document: dict[str, object]) -> None:
            networks = as_map(service_of(document)["networks"])
            as_map(networks[slots[0]])["ipv4_address"] = "10.0.0.9"

        def extra_network(document: dict[str, object]) -> None:
            as_map(service_of(document)["networks"])["bridge"] = {}

        def wrong_drain_port(document: dict[str, object]) -> None:
            environment(document)[DRAIN_PORT_KEY] = 9999

        def gateway_is_the_address(document: dict[str, object]) -> None:
            declared = as_map(as_map(document["networks"])[drain])
            pools = cast("list[object]", as_map(declared["ipam"])["config"])
            as_map(pools[0])["gateway"] = environment(document)[DRAIN_HOST_KEY]

        cases: tuple[tuple[Callable[[dict[str, object]], None], str], ...] = (
            (drop_host, f"{DRAIN_HOST_KEY} is missing"),
            (every_interface, "every interface"),
            (loopback, "loopback"),
            (drop_pool, "exactly one ipam pool"),
            (outside_subnet, "outside"),
            (address_differs, "differs from"),
            (no_address_on_drain, "has no ipv4_address"),
            (networks_as_list, "are a list"),
            (address_on_a_slot, "belongs on"),
            (extra_network, "not exactly the drain network"),
            (wrong_drain_port, f"{DRAIN_PORT_KEY} is not the container port"),
            (gateway_is_the_address, "gateway, network or broadcast"),
        )
        self.assertEqual([], mutated_golden(lambda document: None))
        for change, expected in cases:
            with self.subTest(change=change.__name__):
                found = mutated_golden(change)
                self.assertTrue(any(expected in line for line in found), found)

    def test_a_compose_file_that_cannot_be_read_or_has_no_spool_is_named(self) -> None:
        constants = role_drain_constants()
        self.assertTrue(drain_golden_problems("a: [", *constants))
        self.assertTrue(drain_golden_problems("services: {}\n", *constants))

    def test_the_slot_table_is_seven_slots_from_30001(self) -> None:
        base = facts()
        self.assertEqual(30001, base["slot_uid_base"])
        self.assertEqual([str(n) for n in range(7)], base["slot_names"])


if __name__ == "__main__":
    unittest.main()
