"""Tests that hold the path unit, its client configuration and the alias files to the design.

The design makes the unit supervise one ssh forward, keeps the alias on an interface the network
manager owns so a downed path is refused at once, and pins both hops' host keys. These tests read
the shipped unit and the files the role writes, ask ssh itself what it would do with the
configuration (`ssh -G`, which connects to nothing), and hold the names the unit, the vars and the
other files share to one value. They touch no host.

Each control a test names was run red on a sabotaged copy and green on the file as shipped (the
pull request records both).
"""

import shutil
import subprocess
import unittest
from pathlib import Path
from typing import cast

from ruamel.yaml import YAML
from test_spool_paths_files import KEY, Scratch

ROLE = Path(__file__).resolve().parents[2]
UNIT = ROLE / "files" / "branchleft-spool-path@.service"
NETDEV = ROLE / "files" / "branchleft-spool-paths.netdev"
RUN_SECONDS = 30
TENANT = {
    "slug": "tenant1",
    "ssh_host": "10.20.1.50",
    "spool_port": 8095,
    "host_key": KEY,
    "jump": {"host": "192.0.2.20", "host_key": KEY, "port": 2222},
}
DEMO = {"slug": "demo1", "ssh_host": "192.0.2.10", "spool_port": 8095, "host_key": KEY}


def role_vars() -> dict[str, object]:
    """Return the role's constants."""
    loaded = YAML(typ="safe").load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
    return cast("dict[str, object]", loaded)


def unit_lines() -> dict[str, list[str]]:
    """Return the unit's settings, each name with every value it is given, in order."""
    found: dict[str, list[str]] = {}
    for line in UNIT.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith(("#", "[")):
            continue
        name, _, value = line.partition("=")
        found.setdefault(name, []).append(value)
    return found


def effective(config: Path, host: str) -> dict[str, list[str]]:
    """Return what ssh would use for the host, as `ssh -G` prints it, name to values.

    Raises:
        AssertionError: when ssh is not installed, which is a failure and never a skip.
    """
    ssh = shutil.which("ssh")
    if ssh is None:
        message = "ssh is needed for this test and was not found"
        raise AssertionError(message)
    done = subprocess.run(  # noqa: S603 - argv list, a program found by name, scratch paths
        [ssh, "-G", "-F", str(config), host],
        capture_output=True,
        text=True,
        check=True,
        timeout=RUN_SECONDS,
    )
    found: dict[str, list[str]] = {}
    for line in done.stdout.splitlines():
        name, _, value = line.partition(" ")
        found.setdefault(name, []).append(normal(value))
    return found


def normal(value: str) -> str:
    """Return the value as every ssh version prints it alike.

    Versions differ on yes and true, no and false, and on bracketing an address in a forward.
    """
    spelled = {"true": "yes", "false": "no"}
    return spelled.get(value, value.replace("[", "").replace("]", ""))


class TheUnit(unittest.TestCase):
    """The unit is one supervised ssh, restarted with a backoff, that starts only when set up."""

    # Control: the unit restarts without limit and with a growing delay. Red when the limit is
    # restored or the backoff removed: a path that stays failed is mail that is never collected.
    def test_it_restarts_forever_with_a_backoff(self) -> None:
        lines = unit_lines()
        self.assertEqual(lines["Restart"], ["always"])
        self.assertEqual(lines["StartLimitIntervalSec"], ["0"])
        self.assertEqual(lines["RestartSec"], ["5"])
        self.assertEqual(lines["RestartSteps"], ["6"])
        self.assertEqual(lines["RestartMaxDelaySec"], ["120"])

    def test_it_runs_one_ssh_with_the_instances_file_and_no_command(self) -> None:
        text = UNIT.read_text(encoding="utf-8")
        self.assertEqual(
            unit_lines()["ExecStart"],
            ["/usr/bin/ssh -F /etc/branchleft/spool-paths/%i.conf -N %i"],
        )
        for forbidden in ("ExecStartPre", "ExecStartPost", "ExecStop", "ip addr", "ip link"):
            self.assertNotIn(forbidden, text)

    # Control: the alias is owned by no path unit, so ssh exiting leaves the address in place and
    # nothing listening. Red when the unit makes, binds to or depends on the address.
    def test_it_owns_no_address_and_is_bound_to_no_device(self) -> None:
        lines = unit_lines()
        for name in ("BindsTo", "PartOf", "Requires", "Upholds", "ExecStartPre"):
            self.assertNotIn(name, lines)

    def test_it_starts_only_when_the_configuration_the_pins_and_the_key_are_there(self) -> None:
        self.assertEqual(
            unit_lines()["ConditionPathExists"],
            [
                "/etc/branchleft/spool-paths/%i.conf",
                "/etc/branchleft/spool-paths/%i.known_hosts",
                "/etc/branchleft/spool-paths/%i.key",
            ],
        )

    def test_it_is_confined(self) -> None:
        lines = unit_lines()
        for name, value in (
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateDevices", "yes"),
            ("CapabilityBoundingSet", ""),
        ):
            with self.subTest(name):
                self.assertEqual(lines[name], [value])

    def test_the_names_the_unit_shares_with_the_vars_are_one_value(self) -> None:
        constants = role_vars()
        text = UNIT.read_text(encoding="utf-8")
        self.assertEqual(constants["spool_paths_dir"], "/etc/branchleft/spool-paths")
        self.assertEqual(constants["spool_paths_unit"], UNIT.name)
        self.assertEqual(
            f"{constants['spool_paths_instance_prefix']}x.service",
            "branchleft-spool-path@x.service",
        )
        self.assertIn(str(constants["spool_paths_ssh"]), text)
        self.assertEqual(constants["spool_paths_conf_suffix"], ".conf")
        self.assertEqual(constants["spool_paths_known_hosts_suffix"], ".known_hosts")
        self.assertEqual(constants["spool_paths_key_suffix"], ".key")

    def test_the_alias_interface_is_a_dummy_the_network_manager_owns(self) -> None:
        constants = role_vars()
        text = NETDEV.read_text(encoding="utf-8")
        self.assertIn(f"Name={constants['spool_paths_interface']}", text)
        self.assertIn("Kind=dummy", text)
        self.assertEqual(
            constants["spool_paths_netdev_file"],
            f"{constants['spool_paths_networkd_dir']}/05-branchleft-spool-paths.netdev",
        )


class TheClientConfiguration(unittest.TestCase):
    """What ssh itself reports it would do with the file the role writes."""

    def written(self, hosts: list[dict[str, object]], slug: str) -> Path:
        """Have the role write its files for the host table, and return the slug's configuration."""
        scratch = Scratch(self)
        for row in hosts:
            scratch.descriptor(
                str(row["slug"]), "10.250.0.11" if row["slug"] == "demo1" else "10.250.0.12"
            )
        done = scratch.run(hosts)
        self.assertFalse(done.failed, done.output)
        self.scratch = scratch
        return scratch.dir / f"{slug}.conf"

    def test_the_options_the_design_names_are_in_force(self) -> None:
        config = self.written([DEMO], "demo1")
        report = effective(config, "demo1")
        expected = {
            "exitonforwardfailure": ["yes"],
            "serveraliveinterval": ["10"],
            "serveralivecountmax": ["3"],
            "batchmode": ["yes"],
            "identitiesonly": ["yes"],
            "stricthostkeychecking": ["yes"],
            "identityagent": ["none"],
            "forwardagent": ["no"],
            "passwordauthentication": ["no"],
            "preferredauthentications": ["publickey"],
            "user": ["spoolpath"],
            "port": ["22"],
            "hostname": ["192.0.2.10"],
            "globalknownhostsfile": ["/dev/null"],
            "controlmaster": ["no"],
        }
        for name, value in expected.items():
            with self.subTest(name):
                self.assertEqual(report[name], value)
        self.assertEqual(report["localforward"], ["10.250.0.11:8080 127.0.0.1:8095"])
        self.assertEqual(report["identityfile"], [f"{self.scratch.dir}/demo1.key"])
        self.assertEqual(report["userknownhostsfile"], [f"{self.scratch.dir}/demo1.known_hosts"])

    # Control: the path offers no key but its own and trusts no host key but the pinned one. Red
    # when IdentitiesOnly or StrictHostKeyChecking is dropped.
    def test_no_default_key_no_agent_and_no_unpinned_host(self) -> None:
        report = effective(self.written([DEMO], "demo1"), "demo1")
        self.assertEqual(report["identitiesonly"], ["yes"])
        self.assertEqual(report["stricthostkeychecking"], ["yes"])
        self.assertEqual(report["identityagent"], ["none"])
        self.assertEqual(len(report["identityfile"]), 1)

    def test_a_direct_path_has_no_jump(self) -> None:
        report = effective(self.written([DEMO], "demo1"), "demo1")
        self.assertNotIn("proxyjump", report)

    def test_a_jump_path_goes_through_its_own_stanza_with_its_own_key(self) -> None:
        config = self.written([TENANT], "tenant1")
        report = effective(config, "tenant1")
        self.assertEqual(report["proxyjump"], ["tenant1-jump"])
        hop = effective(config, "tenant1-jump")
        self.assertEqual(hop["hostname"], ["192.0.2.20"])
        self.assertEqual(hop["port"], ["2222"])
        self.assertEqual(hop["identityfile"], [f"{self.scratch.dir}/tenant1.jump.key"])
        self.assertEqual(hop["identitiesonly"], ["yes"])
        self.assertEqual(hop["stricthostkeychecking"], ["yes"])
        self.assertNotIn("localforward", hop)

    def test_the_jump_account_comes_from_the_owners_file_and_is_not_in_the_role(self) -> None:
        config = self.written([TENANT], "tenant1")
        self.assertNotIn(
            "user", " ".join(effective(config, "tenant1-jump").get("user", [])).replace("root", "")
        )
        placed = self.scratch.dir / "tenant1.jump.user"
        placed.write_text("User jumpaccount-stand-in\n", encoding="utf-8")
        self.assertEqual(effective(config, "tenant1-jump")["user"], ["jumpaccount-stand-in"])
        self.assertEqual(effective(config, "tenant1")["user"], ["spoolpath"])
        self.assertNotIn("jumpaccount", config.read_text(encoding="utf-8"))

    def test_a_non_default_port_is_written_in_the_known_hosts_form(self) -> None:
        self.written([TENANT], "tenant1")
        lines = (self.scratch.dir / "tenant1.known_hosts").read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[1:], [f"10.20.1.50 {KEY}", f"[192.0.2.20]:2222 {KEY}"])


if __name__ == "__main__":
    unittest.main()
