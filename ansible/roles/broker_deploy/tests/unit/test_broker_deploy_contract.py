"""What the broker_deploy files must agree on, read from the files.

The behaviour tests run the release tasks; these hold the facts that no run of them shows:
the pins are well formed and have their files, the Molecule release is the one its pins name,
the readiness port is the environment file's port, and the pin check comes before any task
that writes to the host.
"""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
SHARDS = ROLE / "molecule" / "default"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\Z")
DIGEST = re.compile(r"^[0-9a-f]{64}\Z")
# The zone paying tenants render under: D10, render-core's demo-tenant descriptor and goldens,
# and ghost-platform's services/broker/systemd/broker.env.example, which has its own test that
# the example's zone is render-core's. Another repo, so the copy stays and this holds the
# template to it.
TENANT_PLATFORM_ZONE = "sites.publicpress.co.uk"
PLAIN_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
# Modules that only read, decide or refuse: a task of any other module is a write to the host.
READ_ONLY_MODULES = frozenset(
    {
        "ansible.builtin.assert",
        "ansible.builtin.find",
        "ansible.builtin.stat",
        "ansible.builtin.set_fact",
        "ansible.builtin.include_tasks",
    }
)


def load(path: Path) -> object:
    """Return the parsed YAML of a file."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def mapping(path: Path) -> dict[str, object]:
    """Return a YAML file that must hold a mapping.

    Raises:
        TypeError: the file does not hold a mapping.
    """
    document = load(path)
    if not isinstance(document, dict):
        message = f"{path.name} is not a mapping"
        raise TypeError(message)
    return cast("dict[str, object]", document)


def tasks(path: Path) -> list[dict[str, object]]:
    """Return a task file's tasks.

    Raises:
        TypeError: the file does not hold a list.
    """
    document = load(path)
    if not isinstance(document, list):
        message = f"{path.name} is not a task list"
        raise TypeError(message)
    return cast("list[dict[str, object]]", document)


def sha256(path: Path) -> str:
    """Return the sha256 of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files_under(directory: Path) -> set[str]:
    """Return the relative paths of the files under a directory."""
    return {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}


class Pins(unittest.TestCase):
    """The pinned releases."""

    def setUp(self) -> None:
        """Read the defaults and the spec."""
        self.defaults = mapping(ROLE / "defaults" / "main.yml")
        self.pins = cast("dict[str, dict[str, str]]", self.defaults["broker_deploy_release_pins"])
        specs = mapping(ROLE / "meta" / "argument_specs.yml")
        main = cast("dict[str, dict[str, object]]", specs["argument_specs"])["main"]
        self.options = cast("dict[str, dict[str, object]]", main["options"])

    def test_every_pin_is_a_version_of_plain_paths_with_lower_case_sha256(self) -> None:
        for version, files in self.pins.items():
            with self.subTest(version=version):
                self.assertRegex(version, VERSION)
                self.assertIn("broker.mjs", files)
                for path, digest in files.items():
                    self.assertRegex(path, PLAIN_PATH)
                    self.assertNotIn("..", path.split("/"))
                    self.assertRegex(digest, DIGEST)

    def test_the_default_version_is_empty_or_pinned(self) -> None:
        version = self.defaults["broker_deploy_release_version"]
        self.assertTrue(version == "" or version in self.pins)

    def test_the_spec_defaults_are_the_defaults(self) -> None:
        for name in (
            "broker_deploy_release_version",
            "broker_deploy_release_pins",
            "broker_deploy_release_dir",
        ):
            with self.subTest(name=name):
                self.assertEqual(self.options[name]["default"], self.defaults[name])

    def test_a_release_the_role_carries_is_pinned_exactly(self) -> None:
        carried = ROLE / "files" / "releases"
        if not carried.is_dir():
            return
        for release in sorted(carried.iterdir()):
            with self.subTest(release=release.name):
                self.assertTrue(release.is_dir() and not release.is_symlink())
                self.assertIn(release.name, self.pins)
                self.assertEqual(files_under(release), set(self.pins[release.name]))
                for path, digest in self.pins[release.name].items():
                    self.assertEqual(sha256(release / path), digest)

    def test_every_pinned_version_has_its_files(self) -> None:
        carried = ROLE / "files" / "releases"
        for version in self.pins:
            with self.subTest(version=version):
                self.assertTrue((carried / version).is_dir())


class MoleculeRelease(unittest.TestCase):
    """The stand-in release the container test installs is the one its converge pins."""

    def test_the_converge_pins_are_the_stand_in_files(self) -> None:
        converge = cast("list[dict[str, object]]", load(SHARDS / "converge.yml"))
        play_vars = cast("dict[str, object]", converge[0]["vars"])
        version = cast("str", play_vars["broker_deploy_release_version"])
        pins = cast("dict[str, dict[str, str]]", play_vars["broker_deploy_release_pins"])[version]
        release = SHARDS / "files" / "release" / version
        self.assertEqual(files_under(release), set(pins))
        for path, digest in pins.items():
            with self.subTest(path=path):
                self.assertEqual(sha256(release / path), digest)


class Agreements(unittest.TestCase):
    """The few values the role holds in two files."""

    def test_the_readiness_port_is_the_environment_files_port(self) -> None:
        constants = mapping(ROLE / "vars" / "main.yml")
        template = (ROLE / "templates" / "broker.env.j2").read_text(encoding="utf-8")
        ports = re.findall(r"^PORT=([0-9]+)$", template, re.MULTILINE)
        self.assertEqual(ports, [str(constants["broker_deploy_port"])])

    def test_the_platform_zone_is_the_tenant_zone_and_inside_an_owned_domain(self) -> None:
        template = (ROLE / "templates" / "broker.env.j2").read_text(encoding="utf-8")
        zones = re.findall(r"^BROKER_PLATFORM_ZONE=(\S+)$", template, re.MULTILINE)
        self.assertEqual(zones, [TENANT_PLATFORM_ZONE])
        owned = re.findall(r"^BROKER_OWNED_DOMAINS=(\S+)$", template, re.MULTILINE)
        self.assertEqual(len(owned), 1)
        domains = owned[0].split(",")
        self.assertTrue(any(zones[0] == d or zones[0].endswith("." + d) for d in domains))

    def test_the_unit_name_is_the_units_file_name(self) -> None:
        constants = mapping(ROLE / "vars" / "main.yml")
        defaults = mapping(ROLE / "defaults" / "main.yml")
        unit_path = Path(str(defaults["broker_deploy_unit_path"]))
        self.assertEqual(constants["broker_deploy_unit_name"], unit_path.name)
        self.assertTrue((ROLE / "files" / str(constants["broker_deploy_unit_name"])).is_file())


class Order(unittest.TestCase):
    """The pin check comes before anything is written."""

    def test_only_reads_and_refusals_come_before_the_pin_check(self) -> None:
        main = tasks(ROLE / "tasks" / "main.yml")
        names = [task.get("name") for task in main]
        at = names.index("Hold the release files to their pinned sha256")
        self.assertEqual(main[at].get("ansible.builtin.include_tasks"), "_release_pin.yml")
        for task in main[:at]:
            modules = {key for key in task if key.startswith("ansible.builtin.")}
            with self.subTest(task=task.get("name")):
                self.assertTrue(modules <= READ_ONLY_MODULES, f"{task.get('name')} writes first")

    def test_the_pin_check_reads_and_refuses_and_writes_nothing(self) -> None:
        for task in tasks(ROLE / "tasks" / "_release_pin.yml"):
            modules = {key for key in task if key.startswith("ansible.builtin.")}
            with self.subTest(task=task.get("name")):
                self.assertTrue(modules <= READ_ONLY_MODULES)

    def test_the_restart_follows_every_input_the_broker_reads(self) -> None:
        main = tasks(ROLE / "tasks" / "main.yml")
        fact = next(
            t
            for t in main
            if str(t.get("name", "")).startswith("Work out whether what the broker runs changed")
        )
        expression = str(
            cast("dict[str, str]", fact["ansible.builtin.set_fact"])["broker_deploy_inputs_changed"]
        )
        registered = {
            str(task["register"])
            for name in ("main.yml", "_release.yml")
            for task in tasks(ROLE / "tasks" / name)
            if "register" in task
        }
        for register in (
            "broker_deploy_release_copy",
            "broker_deploy_link_result",
            "broker_deploy_key_result",
            "broker_deploy_env_result",
            "broker_deploy_unit_result",
        ):
            with self.subTest(register=register):
                self.assertIn(register, expression)
                self.assertIn(register, registered)


if __name__ == "__main__":
    unittest.main()
