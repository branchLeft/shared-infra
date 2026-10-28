"""The demo1_egress_spool role and the rest of demo1's roles agree, and each path has one owner.

The role is the only owner of the egress program, its unit, the mail spool's Compose file, its
image pin file and the drain token path. The slot networks it lets the spool join are the slot
table of demo1_build, written separately. The playbook that applies the role does not apply
egress_nat to the demo host, whose containers must not reach the network. The cross-role
references are not allowed (ANS-12), so each copy stays and this test keeps them in step.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import NoReturn, cast

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
ROLE = "demo1_egress_spool"
BUILD = "demo1_build"
PLAYBOOK = ROOT / "ansible" / "playbooks" / "demo1.yml"
# The directories of a role that run on a host. The scenarios and the README name paths to
# test them or to explain them, which writes nothing.
HOST_DIRS = ("defaults", "vars", "tasks", "handlers", "templates", "files", "meta")
HOST_SUFFIXES = (".yml", ".yaml", ".j2", ".service", ".sh", ".py", ".conf", ".timer")
SLOT_NAMES = re.compile(r"default\(\[([^\]]*)\]\)")
OWNED = (
    "demo1_egress_spool_egress_script_dest",
    "demo1_egress_spool_egress_unit_dest",
    "demo1_egress_spool_project_dir",
    "demo1_egress_spool_compose_dest",
    "demo1_egress_spool_image_env_path",
    "demo1_egress_spool_token_path",
)
NAT_ROLE = "egress_nat"
ORDER = (BUILD, "host_baseline", ROLE)


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


def host_text(role: Path) -> str:
    """Return the text of every file of a role that runs on a host, in a fixed order."""
    parts: list[str] = []
    for name in HOST_DIRS:
        base = role / name
        if base.is_dir():
            parts.extend(
                path.read_text(encoding="utf-8")
                for path in sorted(base.rglob("*"))
                if path.is_file() and path.suffix in HOST_SUFFIXES
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
    if NAT_ROLE in applied:
        found.append(
            f"demo1.yml applies {NAT_ROLE}, which would give the demo containers a route out"
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


class SpoolAgreeTest(unittest.TestCase):
    def test_the_real_tree_agrees(self) -> None:
        self.assertEqual([], disagreements(facts()))

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

    def test_egress_nat_on_demo1_is_named(self) -> None:
        base = facts()
        roles = [*cast("list[str]", base["playbook_roles"]), NAT_ROLE]
        found = disagreements(dict(base, playbook_roles=roles))
        self.assertTrue(any(NAT_ROLE in line for line in found), found)

    def test_the_roles_in_the_wrong_order_or_missing_are_named(self) -> None:
        base = facts()
        for roles in (
            [ROLE, "host_baseline", BUILD],
            [BUILD, ROLE, "host_baseline"],
            [BUILD, ROLE],
            [BUILD, "host_baseline", ROLE, ROLE],
        ):
            with self.subTest(roles=roles):
                found = disagreements(dict(base, playbook_roles=roles))
                self.assertTrue(found)

    def test_the_slot_table_is_seven_slots_from_30001(self) -> None:
        base = facts()
        self.assertEqual(30001, base["slot_uid_base"])
        self.assertEqual([str(n) for n in range(7)], base["slot_names"])


if __name__ == "__main__":
    unittest.main()
