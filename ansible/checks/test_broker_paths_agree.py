"""The broker's directory paths, owner and modes agree between demo1_build and broker_deploy.

broker_deploy creates the broker's directories and its unit declares the state directory;
demo1_build reads them and asserts they are what it expects. The two sides are written
separately, so a change to one alone would pass each role's own tests. Each fact below is
read from its file, and disagreements() names every pair that differs. The cross-role
references are not allowed (ANS-12), so the copies stay and this test keeps them in step.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import NoReturn, cast

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "ansible" / "roles" / "demo1_build"
BROKER = ROOT / "ansible" / "roles" / "broker_deploy"
UNIT = BROKER / "files" / "branchleft-broker.service"
SYSTEMD_STATE_ROOT = "/var/lib/"
JINJA_NAME = re.compile(r"\{\{\s*(\w+)\s*\}\}")
MODE_IN_ASSERT = re.compile(r"\.mode == '([0-7]{4})'")


class BrokerPathsError(Exception):
    """A file the check reads is missing, unparseable or not in the shape it needs."""


def refuse(message: str) -> NoReturn:
    """Stop the check with a message.

    Raises:
        BrokerPathsError: always, carrying the message.
    """
    raise BrokerPathsError(message)


def yaml_of(path: Path) -> object:
    """Return the parsed YAML of a file.

    Raises:
        BrokerPathsError: when the file cannot be read as YAML.
    """
    document, problem = load_yaml(path)
    if problem is not None:
        raise BrokerPathsError(problem)
    return document


def mapping_of(value: object) -> dict[str, object]:
    """Return a YAML mapping.

    Raises:
        BrokerPathsError: when the value is not a mapping.
    """
    if not isinstance(value, dict):
        refuse("expected a YAML mapping")
    return cast("dict[str, object]", value)


def task_named(path: Path, name: str) -> dict[str, object]:
    """Return the one task called name in a task file.

    A renamed task raises here rather than letting the check pass on nothing.

    Raises:
        BrokerPathsError: when the file does not hold exactly one task of that name.
    """
    document = yaml_of(path)
    tasks = document if isinstance(document, list) else []
    matches = [t for t in tasks if isinstance(t, dict) and t.get("name") == name]
    if len(matches) != 1:
        refuse(f"{path.name} must hold exactly one task named {name!r}")
    return mapping_of(matches[0])


def unit_value(text: str, key: str) -> str:
    """Return the value of one key in the unit file's text.

    Raises:
        BrokerPathsError: when the unit does not set the key exactly once.
    """
    found = re.findall(rf"^{key}=(.+)$", text, flags=re.MULTILINE)
    if len(found) != 1:
        refuse(f"the unit must set {key} exactly once")
    return str(found[0]).strip()


def facts(root: Path = ROOT) -> dict[str, str]:
    """Read every fact the two roles and the unit state about the broker's directories.

    Raises:
        BrokerPathsError: when a file the check reads is not in the expected shape.
    """
    demo_vars = mapping_of(yaml_of(root / DEMO.relative_to(ROOT) / "vars" / "main.yml"))
    broker_defaults = mapping_of(yaml_of(root / BROKER.relative_to(ROOT) / "defaults" / "main.yml"))
    broker_slots_task = mapping_of(
        task_named(
            root / BROKER.relative_to(ROOT) / "tasks" / "main.yml",
            "Create the broker's own slots directory",
        )["ansible.builtin.file"]
    )
    demo_state_task = mapping_of(
        task_named(
            root / DEMO.relative_to(ROOT) / "tasks" / "_dirs.yml",
            "Create the broker's state directory",
        )["ansible.builtin.file"]
    )
    precondition = mapping_of(
        task_named(
            root / DEMO.relative_to(ROOT) / "tasks" / "_preconditions.yml",
            "Refuse a broker slots directory that is not broker's, mode 0755",
        )["ansible.builtin.assert"]
    )
    slots_modes = [
        mode
        for condition in cast("list[object]", precondition["that"])
        for mode in MODE_IN_ASSERT.findall(str(condition))
    ]
    if len(slots_modes) != 1:
        refuse("the slots-directory refusal must test one mode")

    unit_text = (root / UNIT.relative_to(ROOT)).read_text(encoding="utf-8")
    broker_user = str(broker_defaults["broker_deploy_user"])
    demo_names = {key: str(value) for key, value in demo_vars.items()}
    broker_names = {"broker_deploy_user": broker_user}

    def resolve(value: object, names: dict[str, str]) -> str:
        return JINJA_NAME.sub(lambda m: names[m.group(1)], str(value))

    return {
        "demo1_build_broker_slots_dir": str(demo_vars["demo1_build_broker_slots_dir"]),
        "demo1_build_broker_state_dir": str(demo_vars["demo1_build_broker_state_dir"]),
        "demo1_build_flag_dir": str(demo_vars["demo1_build_flag_dir"]),
        "demo1_build_broker_user": str(demo_vars["demo1_build_broker_user"]),
        "demo1_build_broker_group": str(demo_vars["demo1_build_broker_group"]),
        "demo1_build_slots_dir_mode": slots_modes[0],
        "demo1_build_state_dir_owner": resolve(demo_state_task["owner"], demo_names),
        "demo1_build_state_dir_group": resolve(demo_state_task["group"], demo_names),
        "demo1_build_state_dir_mode": str(demo_state_task["mode"]),
        "broker_deploy_slots_dir": str(broker_defaults["broker_deploy_slots_dir"]),
        "broker_deploy_user": broker_user,
        "broker_deploy_user_home": str(broker_defaults["broker_deploy_user_home"]),
        "broker_deploy_slots_dir_owner": resolve(broker_slots_task["owner"], broker_names),
        "broker_deploy_slots_dir_group": resolve(broker_slots_task["group"], broker_names),
        "broker_deploy_slots_dir_mode": str(broker_slots_task["mode"]),
        "unit_state_dir": SYSTEMD_STATE_ROOT + unit_value(unit_text, "StateDirectory"),
        "unit_state_dir_mode": unit_value(unit_text, "StateDirectoryMode"),
        "unit_user": unit_value(unit_text, "User"),
        "unit_group": unit_value(unit_text, "Group"),
    }


PAIRS = [
    ("demo1_build_broker_slots_dir", "broker_deploy_slots_dir"),
    ("demo1_build_broker_state_dir", "broker_deploy_user_home"),
    ("demo1_build_broker_state_dir", "unit_state_dir"),
    ("demo1_build_broker_user", "broker_deploy_user"),
    ("demo1_build_broker_user", "unit_user"),
    ("demo1_build_broker_group", "broker_deploy_user"),
    ("demo1_build_broker_group", "unit_group"),
    ("demo1_build_state_dir_owner", "unit_user"),
    ("demo1_build_state_dir_group", "unit_group"),
    ("demo1_build_state_dir_mode", "unit_state_dir_mode"),
    ("demo1_build_slots_dir_mode", "broker_deploy_slots_dir_mode"),
    ("broker_deploy_slots_dir_owner", "broker_deploy_user"),
    ("broker_deploy_slots_dir_group", "broker_deploy_user"),
]


def disagreements(f: dict[str, str]) -> list[str]:
    """Return one line for each pair of copies that differ, naming both sides."""
    found = [
        f"{left} = {f[left]!r} but {right} = {f[right]!r}"
        for left, right in PAIRS
        if f[left] != f[right]
    ]
    flag, state = f["demo1_build_flag_dir"], f["demo1_build_broker_state_dir"]
    if not flag.startswith(state.rstrip("/") + "/"):
        found.append(
            f"demo1_build_flag_dir {flag!r} is not inside demo1_build_broker_state_dir {state!r}"
        )
    return found


class BrokerPathsAgreeTest(unittest.TestCase):
    def test_the_real_tree_agrees(self) -> None:
        self.assertEqual([], disagreements(facts()))

    def test_a_path_moved_on_one_side_alone_is_named(self) -> None:
        base = facts()
        for key in (
            "demo1_build_broker_slots_dir",
            "demo1_build_broker_state_dir",
            "demo1_build_flag_dir",
        ):
            with self.subTest(key=key):
                changed = dict(base, **{key: "/MOVED/" + base[key].lstrip("/")})
                found = disagreements(changed)
                self.assertTrue(any(key in line for line in found), found)

    def test_an_owner_or_mode_changed_on_one_side_alone_is_named(self) -> None:
        base = facts()
        for key in (
            "demo1_build_slots_dir_mode",
            "broker_deploy_slots_dir_mode",
            "demo1_build_state_dir_mode",
            "unit_state_dir_mode",
            "broker_deploy_slots_dir_owner",
            "demo1_build_broker_user",
            "unit_user",
            "unit_group",
            "demo1_build_broker_group",
        ):
            with self.subTest(key=key):
                found = disagreements(dict(base, **{key: "MOVED"}))
                self.assertTrue(any(key in line for line in found), found)

    def test_the_unit_state_directory_is_the_broker_home_and_the_demo_state_dir(self) -> None:
        base = facts()
        self.assertEqual("/var/lib/branchleft-broker", base["unit_state_dir"])
        self.assertEqual("0750", base["unit_state_dir_mode"])


if __name__ == "__main__":
    unittest.main()
