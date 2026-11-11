"""Tests that hold what the role writes to the derived list, with Ansible and no host.

These run the role's own tasks that decide what is on disk (the derived list, the per-path files,
the jump conditions, the alias file and the removals), taken from `tasks/main.yml` as shipped, with
Ansible on this machine against a scratch directory. The tasks that start and stop units need
systemd and are left to the Molecule scenario. The directories are then read the way the unit and
the network manager read them.

Each control a test names was run red on a sabotaged copy and green on the file as shipped (the
pull request records both).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
MARKER = "# Written by the spool_paths role. Change the role inputs, not this file."
BLOCK = "10.250.0.0/24"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"
# The tasks that decide what is on disk, by the start of their names, in the order the role runs
# them. The unit-handling tasks, the ssh client check and the key listing are not part of it.
TASK_STARTS = (
    "Refuse a host table",
    "Work out which hosts",
    "Make the role's directory",
    "Install the path unit",
    "Remove the files of each path",
    "Remove the jump conditions of each path no descriptor",
    "Write the client configuration",
    "Write the pinned host keys",
    "Make the drop-in directory",
    "Write the jump conditions",
    "Remove the jump conditions of each path that no longer",
    "Make the network manager's directory",
    "Write the dummy interface",
    "Write the alias address",
    "Remove the interface files",
)
RUN_SECONDS = 120
UNIT = "branchleft-spool-path@.service"
DEMO = {"slug": "demo1", "ssh_host": "192.0.2.10", "spool_port": 8095, "host_key": KEY}
TENANT = {
    "slug": "tenant1",
    "ssh_host": "10.20.1.50",
    "spool_port": 8095,
    "host_key": KEY,
    "jump": {"host": "192.0.2.20", "host_key": KEY},
}
IDLE = {"slug": "idle1", "ssh_host": "192.0.2.30", "spool_port": 8095, "host_key": KEY}


def ansible_playbook() -> str:
    """Return the ansible-playbook that belongs to the interpreter running the tests.

    Raises:
        AssertionError: when there is none, which is a failure and never a skip.
    """
    beside = Path(sys.executable).parent / "ansible-playbook"
    found = str(beside) if beside.is_file() else shutil.which("ansible-playbook")
    if found is None:
        message = "no ansible-playbook beside the interpreter or on the path"
        raise AssertionError(message)
    return found


def play_tasks() -> list[dict[str, object]]:
    """Return the file-writing tasks as shipped, without the owner a scratch run cannot set."""
    loaded = cast(
        "list[dict[str, object]]", YAML(typ="safe").load(TASKS.read_text(encoding="utf-8"))
    )
    picked = [task for task in loaded if str(task.get("name", "")).startswith(TASK_STARTS)]
    for task in picked:
        task.pop("notify", None)
        for value in task.values():
            if isinstance(value, dict):
                value.pop("owner", None)
                value.pop("group", None)
                source = value.get("src")
                if isinstance(source, str):
                    source = source.replace("{{ spool_paths_unit }}", UNIT)
                    folder = "templates" if source.endswith(".j2") else "files"
                    value["src"] = str(ROLE / folder / source)
    return picked


class Result:
    """What one run of the play did."""

    def __init__(self, returncode: int, output: str) -> None:
        self.returncode = returncode
        self.output = output

    @property
    def failed(self) -> bool:
        """Whether the run stopped."""
        return self.returncode != 0

    def recap(self, name: str) -> int:
        """Return the number in the recap line for the name, such as changed."""
        recap = [line for line in self.output.splitlines() if line.startswith("localhost ")][-1]
        return int(recap.split(f"{name}=", 1)[1].split()[0])


class Scratch:
    """A scratch tree standing in for ops1, and the play that runs the role's tasks against it."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="spool-paths-files-"))
        test.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.descriptors = self.home / "descriptors"
        self.dir = self.home / "spool-paths"
        self.units = self.home / "units"
        self.networkd = self.home / "network"
        for folder in (self.descriptors, self.units):
            folder.mkdir()

    def descriptor(self, slug: str, alias: str) -> None:
        """Write a descriptor the way the collector role writes one."""
        document = {"slug": slug, "kind": "tenant", "appHostIp": alias, "expiresAt": None}
        (self.descriptors / f"{slug}.json").write_text(json.dumps(document), encoding="utf-8")

    def run(self, hosts: list[dict[str, object]], block: str = BLOCK) -> Result:
        """Run the play once with the table and block, and return what it did."""
        variables = {
            "spool_paths_hosts": hosts,
            "spool_paths_alias_block": block,
            "spool_paths_descriptor_dir": str(self.descriptors),
            "spool_paths_dir": str(self.dir),
            "spool_paths_unit_dir": str(self.units),
            "spool_paths_networkd_dir": str(self.networkd),
            "spool_paths_netdev_file": str(self.networkd / "05-branchleft-spool-paths.netdev"),
            "spool_paths_network_file": str(self.networkd / "05-branchleft-spool-paths.network"),
        }
        writer = YAML()
        writer.default_flow_style = False
        play = [
            {
                "name": "Spool paths",
                "hosts": "localhost",
                "connection": "local",
                "gather_facts": False,
                "vars_files": [
                    str(ROLE / "defaults" / "main.yml"),
                    str(ROLE / "vars" / "main.yml"),
                ],
                "tasks": play_tasks(),
            }
        ]
        with (self.home / "play.yml").open("w", encoding="utf-8") as handle:
            writer.dump(play, handle)
        with (self.home / "vars.json").open("w", encoding="utf-8") as handle:
            json.dump(variables, handle)
        environment = {
            **os.environ,
            "ANSIBLE_LIBRARY": str(ROLE / "library"),
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_HOME": str(self.home / "ansible-home"),
            "ANSIBLE_LOCAL_TEMP": str(self.home / "tmp"),
            "ANSIBLE_NOCOLOR": "1",
        }
        done = subprocess.run(  # noqa: S603 - argv list, a path from the interpreter's own prefix
            [
                ansible_playbook(),
                "-i",
                "localhost,",
                "-e",
                f"@{self.home / 'vars.json'}",
                str(self.home / "play.yml"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=RUN_SECONDS,
            env=environment,
            cwd=self.home,
        )
        return Result(done.returncode, done.stdout + done.stderr)

    def names(self, folder: Path) -> list[str]:
        """Return the file names in a folder, sorted, or none when it is not there."""
        return sorted(item.name for item in folder.iterdir()) if folder.is_dir() else []


class WhatIsWritten(unittest.TestCase):
    """The files exist for a host a descriptor names, and for no other."""

    # Control: a host with no descriptor gets no configuration, no known_hosts file, no drop-in
    # and no alias, whatever the table holds. Red when the table alone decides.
    def test_a_host_no_descriptor_names_gets_nothing(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        done = scratch.run([DEMO, IDLE, TENANT])
        self.assertFalse(done.failed, done.output)
        self.assertEqual(scratch.names(scratch.dir), ["demo1.conf", "demo1.known_hosts"])
        network = (scratch.networkd / "05-branchleft-spool-paths.network").read_text(
            encoding="utf-8"
        )
        self.assertIn("Address=10.250.0.11/32", network)
        self.assertEqual(network.count("[Address]"), 1)
        self.assertEqual(scratch.names(scratch.units), ["branchleft-spool-path@.service"])

    def test_no_descriptor_means_no_file_and_no_interface(self) -> None:
        scratch = Scratch(self)
        done = scratch.run([DEMO, IDLE])
        self.assertFalse(done.failed, done.output)
        self.assertEqual(scratch.names(scratch.dir), [])
        self.assertEqual(scratch.names(scratch.networkd), [])

    def test_the_configuration_forwards_the_alias_to_the_far_loopback(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        self.assertFalse(scratch.run([DEMO]).failed)
        text = (scratch.dir / "demo1.conf").read_text(encoding="utf-8")
        self.assertEqual(text.splitlines()[0], MARKER)
        self.assertIn("LocalForward 10.250.0.11:8080 127.0.0.1:8095", text)
        self.assertIn("HostName 192.0.2.10", text)
        self.assertNotIn("ProxyJump", text)

    def test_the_known_hosts_file_pins_each_hop(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("tenant1", "10.250.0.12")
        self.assertFalse(scratch.run([TENANT]).failed)
        lines = (scratch.dir / "tenant1.known_hosts").read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[1:], [f"10.20.1.50 {KEY}", f"192.0.2.20 {KEY}"])

    def test_a_jump_path_has_its_conditions_and_a_direct_path_has_none(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("tenant1", "10.250.0.12")
        scratch.descriptor("demo1", "10.250.0.11")
        self.assertFalse(scratch.run([DEMO, TENANT]).failed)
        dropin = scratch.units / "branchleft-spool-path@tenant1.service.d" / "jump.conf"
        text = dropin.read_text(encoding="utf-8")
        self.assertIn(f"ConditionPathExists={scratch.dir}/tenant1.jump.key", text)
        self.assertIn(f"ConditionPathExists={scratch.dir}/tenant1.jump.user", text)
        self.assertFalse((scratch.units / "branchleft-spool-path@demo1.service.d").exists())

    def test_a_second_run_changes_nothing(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        scratch.descriptor("tenant1", "10.250.0.12")
        self.assertFalse(scratch.run([DEMO, TENANT]).failed)
        again = scratch.run([DEMO, TENANT])
        self.assertFalse(again.failed, again.output)
        self.assertEqual(again.recap("changed"), 0)

    def test_the_files_name_no_account_and_no_key(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("tenant1", "10.250.0.12")
        self.assertFalse(scratch.run([TENANT]).failed)
        text = (scratch.dir / "tenant1.conf").read_text(encoding="utf-8")
        self.assertIn("Include", text)
        self.assertNotIn("AAAA", text)
        self.assertEqual(
            [line for line in text.splitlines() if line.strip().startswith("User ")],
            ["    User spoolpath"],
        )


class Teardown(unittest.TestCase):
    """A path comes down when its descriptor goes, and nothing the role did not write does."""

    # Control: once the descriptor is gone the path's files go, and the alias with them. Red when
    # the stale list is left unread.
    def test_removing_a_descriptor_removes_its_files_and_its_alias(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        scratch.descriptor("tenant1", "10.250.0.12")
        self.assertFalse(scratch.run([DEMO, TENANT]).failed)
        (scratch.descriptors / "tenant1.json").unlink()
        done = scratch.run([DEMO, TENANT])
        self.assertFalse(done.failed, done.output)
        self.assertEqual(scratch.names(scratch.dir), ["demo1.conf", "demo1.known_hosts"])
        network = (scratch.networkd / "05-branchleft-spool-paths.network").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("10.250.0.12", network)
        self.assertFalse(
            (scratch.units / "branchleft-spool-path@tenant1.service.d" / "jump.conf").exists()
        )

    def test_removing_the_last_descriptor_removes_the_interface_files(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        self.assertFalse(scratch.run([DEMO]).failed)
        (scratch.descriptors / "demo1.json").unlink()
        self.assertFalse(scratch.run([DEMO]).failed)
        self.assertEqual(scratch.names(scratch.networkd), [])
        self.assertEqual(scratch.names(scratch.dir), [])

    # Control: the owner's keys and a file the role did not write survive every run, including one
    # that takes a path down.
    def test_a_key_and_a_foreign_file_are_never_removed(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        self.assertFalse(scratch.run([DEMO]).failed)
        kept = {
            "demo1.key": "PRIVATE-KEY-STAND-IN",
            "demo1.jump.key": "PRIVATE-KEY-STAND-IN",
            "demo1.jump.user": "User stand-in",
            "hand.conf": "Host hand\n",
            "notes.txt": "a note",
        }
        for name, text in kept.items():
            (scratch.dir / name).write_text(text, encoding="utf-8")
        (scratch.descriptors / "demo1.json").unlink()
        done = scratch.run([DEMO])
        self.assertFalse(done.failed, done.output)
        self.assertEqual(scratch.names(scratch.dir), sorted(kept))
        for name, text in kept.items():
            self.assertEqual((scratch.dir / name).read_text(encoding="utf-8"), text)

    def test_a_path_that_loses_its_jump_loses_its_conditions(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("tenant1", "10.250.0.12")
        self.assertFalse(scratch.run([TENANT]).failed)
        direct = {key: value for key, value in TENANT.items() if key != "jump"}
        self.assertFalse(scratch.run([direct]).failed)
        self.assertFalse(
            (scratch.units / "branchleft-spool-path@tenant1.service.d" / "jump.conf").exists()
        )
        self.assertNotIn("ProxyJump", (scratch.dir / "tenant1.conf").read_text(encoding="utf-8"))


class Refusals(unittest.TestCase):
    """A refused input stops the run before anything is written."""

    def test_an_alias_outside_the_block_writes_nothing(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.20.1.101")
        done = scratch.run([DEMO])
        self.assertTrue(done.failed)
        self.assertIn("outside alias_block", done.output)
        self.assertEqual(scratch.names(scratch.networkd), [])
        self.assertEqual(scratch.names(scratch.units), [])

    def test_a_refusal_prints_no_address_from_the_table(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        bad = {**DEMO, "ssh_host": "bad host name"}
        done = scratch.run([bad])
        self.assertTrue(done.failed)
        self.assertNotIn("bad host name", done.output)


if __name__ == "__main__":
    unittest.main()
