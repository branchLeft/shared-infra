"""The spool path roles agree with the roles on each side of them.

The collector dials an alias that `spool_paths` binds on `ops1`. The path logs in to an account
that `spool_path_account` makes on the far host and reaches the port the spool publishes. No role
may import another (ANS-12), so each shared value is copied into the role that needs it and this
test keeps the copies equal: the collector's shim port and descriptor directory, the far account's
name and loopback address, and the demo spool's drain port. It also holds the order the two roles
run in.

Each control a test names was run red on a sabotaged copy and green on the file as shipped.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
PLAYBOOKS = ROOT / "ansible" / "playbooks"


def role_value(role: str, folder: str, key: str) -> object:
    """Return one variable from a role's defaults or vars file.

    Raises:
        AssertionError: when the file cannot be read.
    """
    document, problem = load_yaml(ROLES / role / folder / "main.yml")
    if problem is not None:
        raise AssertionError(problem)
    return cast("dict[str, object]", document)[key]


def role_names(host: str) -> list[str]:
    """Return the roles a host's playbook applies, in order.

    Raises:
        AssertionError: when the playbook cannot be read.
    """
    document, problem = load_yaml(PLAYBOOKS / f"{host}.yml")
    if problem is not None:
        raise AssertionError(problem)
    play = cast("list[dict[str, object]]", document)[0]
    entries = cast("list[dict[str, str]]", play["roles"])
    return [Path(entry["role"]).name for entry in entries]


class SharedValues(unittest.TestCase):
    """Each value two roles share is one value."""

    # Control: the collector dials the shim port the alias binds. Red when either default moves.
    def test_the_alias_port_is_the_collectors_shim_port(self) -> None:
        self.assertEqual(
            role_value("spool_paths", "defaults", "spool_paths_shim_port"),
            role_value("mail_collector", "defaults", "mail_collector_shim_port"),
        )

    # Control: the path reads the directory the collector reads, so the drain list is one list.
    def test_the_descriptor_directory_is_the_collectors(self) -> None:
        self.assertEqual(
            role_value("spool_paths", "vars", "spool_paths_descriptor_dir"),
            role_value("mail_collector", "vars", "mail_collector_descriptor_dir"),
        )

    # Control: the path dials the account the far role makes.
    def test_the_account_the_path_dials_is_the_one_the_far_role_makes(self) -> None:
        self.assertEqual(
            role_value("spool_paths", "vars", "spool_paths_far_user"),
            role_value("spool_path_account", "vars", "spool_path_account_user"),
        )

    def test_the_forward_lands_on_the_loopback_the_key_may_open(self) -> None:
        self.assertEqual(
            role_value("spool_paths", "vars", "spool_paths_far_loopback"),
            role_value("spool_path_account", "vars", "spool_path_account_loopback"),
        )

    # Control: the key may open the port the demo spool publishes on the loopback address.
    def test_the_account_opens_the_demo_spools_drain_port(self) -> None:
        self.assertEqual(
            role_value("spool_path_account", "defaults", "spool_path_account_spool_port"),
            role_value("demo1_egress_spool", "defaults", "demo1_egress_spool_drain_port"),
        )


class Order(unittest.TestCase):
    """Each role runs after the role whose work it reads."""

    def test_the_paths_follow_the_collector_on_ops1(self) -> None:
        names = role_names("ops1")
        self.assertLess(names.index("mail_collector"), names.index("spool_paths"))

    def test_the_account_follows_the_spool_on_demo1(self) -> None:
        names = role_names("demo1")
        self.assertLess(names.index("demo1_egress_spool"), names.index("spool_path_account"))

    def test_neither_role_is_on_the_other_hosts(self) -> None:
        self.assertNotIn("spool_path_account", role_names("ops1"))
        self.assertNotIn("spool_paths", role_names("demo1"))


if __name__ == "__main__":
    unittest.main()
