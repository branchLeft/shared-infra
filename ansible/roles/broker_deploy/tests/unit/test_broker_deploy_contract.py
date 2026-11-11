"""What the broker_deploy files must agree on, read from the files.

The behaviour tests run the release tasks; these hold the facts that no run of them shows:
the pins are well formed and have their files, the Molecule release is the one its pin names
and is what its source directory holds, the readiness port is the environment file's port,
and the pin check comes before any task that writes to the host.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import tarfile
import unittest
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
SHARDS = ROLE / "molecule" / "default"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\Z")
DIGEST = re.compile(r"^[0-9a-f]{64}\Z")
TARBALL = re.compile(r"^broker-bundle-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz\Z")
# Modules that only read, decide or refuse: a task of any other module is a write to the host.
READ_ONLY_MODULES = frozenset(
    {
        "ansible.builtin.assert",
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


def sha256(data: bytes) -> str:
    """Return the sha256 of the bytes."""
    return hashlib.sha256(data).hexdigest()


class Pins(unittest.TestCase):
    """The pinned releases."""

    def setUp(self) -> None:
        """Read the defaults, the constants and the spec."""
        self.defaults = mapping(ROLE / "defaults" / "main.yml")
        self.pins = cast("dict[str, str]", self.defaults["broker_deploy_release_pins"])
        specs = mapping(ROLE / "meta" / "argument_specs.yml")
        options = cast(
            "dict[str, dict[str, object]]",
            cast("dict[str, dict[str, object]]", specs["argument_specs"])["main"]["options"],
        )
        self.options = options

    def test_every_pin_is_a_version_with_a_lower_case_sha256(self) -> None:
        self.assertTrue(self.pins)
        for version, digest in self.pins.items():
            with self.subTest(version=version):
                self.assertRegex(version, VERSION)
                self.assertRegex(digest, DIGEST)

    def test_the_default_version_is_pinned(self) -> None:
        self.assertIn(self.defaults["broker_deploy_release_version"], self.pins)

    def test_the_spec_defaults_are_the_defaults(self) -> None:
        for name in (
            "broker_deploy_release_version",
            "broker_deploy_release_pins",
            "broker_deploy_release_dir",
        ):
            with self.subTest(name=name):
                self.assertEqual(self.options[name]["default"], self.defaults[name])

    def test_a_release_the_role_carries_is_pinned_and_is_the_pinned_bytes(self) -> None:
        carried = ROLE / "files" / "releases"
        if not carried.is_dir():
            return
        for path in sorted(carried.iterdir()):
            with self.subTest(file=path.name):
                found = TARBALL.match(path.name)
                if found is None:
                    self.fail("a file that is not a release tarball")
                self.assertTrue(path.is_file() and not path.is_symlink())
                self.assertEqual(sha256(path.read_bytes()), self.pins.get(found.group(1)))


class MoleculeRelease(unittest.TestCase):
    """The release the container test installs is the stand-in bundle, packed, and its pin."""

    def setUp(self) -> None:
        """Read the converge play's pin and the tarball."""
        converge = cast("list[dict[str, object]]", load(SHARDS / "converge.yml"))
        play_vars = cast("dict[str, object]", converge[0]["vars"])
        self.version = cast("str", play_vars["broker_deploy_release_version"])
        self.pin = cast("dict[str, str]", play_vars["broker_deploy_release_pins"])[self.version]
        self.path = SHARDS / "files" / "release" / f"broker-bundle-{self.version}.tar.gz"

    def test_the_tarball_is_the_one_the_converge_pins(self) -> None:
        self.assertEqual(sha256(self.path.read_bytes()), self.pin)

    def test_the_tarball_holds_exactly_the_stand_in_bundle_with_root_owner_and_plain_modes(
        self,
    ) -> None:
        source = SHARDS / "files" / "bundle"
        expected = {str(p.relative_to(source)): p for p in source.rglob("*")}
        with tarfile.open(
            fileobj=io.BytesIO(gzip.decompress(self.path.read_bytes())), mode="r:"
        ) as archive:
            members = {member.name.rstrip("/"): member for member in archive.getmembers()}
            self.assertEqual(set(members), set(expected))
            for name, member in members.items():
                with self.subTest(member=name):
                    self.assertEqual((member.uid, member.gid), (0, 0))
                    if expected[name].is_dir():
                        self.assertTrue(member.isdir())
                        self.assertEqual(member.mode, 0o755)
                    else:
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            self.fail(f"{name} is not a regular member")
                        self.assertEqual(extracted.read(), expected[name].read_bytes())
                        self.assertEqual(member.mode, 0o644)


class Agreements(unittest.TestCase):
    """The few values the role holds in two files."""

    def test_the_readiness_port_is_the_environment_files_port(self) -> None:
        constants = mapping(ROLE / "vars" / "main.yml")
        template = (ROLE / "templates" / "broker.env.j2").read_text(encoding="utf-8")
        ports = re.findall(r"^PORT=([0-9]+)$", template, re.MULTILINE)
        self.assertEqual(ports, [str(constants["broker_deploy_port"])])

    def test_the_unit_name_is_the_units_file_name(self) -> None:
        constants = mapping(ROLE / "vars" / "main.yml")
        defaults = mapping(ROLE / "defaults" / "main.yml")
        self.assertEqual(
            constants["broker_deploy_unit_name"],
            Path(str(defaults["broker_deploy_unit_path"])).name,
        )
        self.assertTrue((ROLE / "files" / str(constants["broker_deploy_unit_name"])).is_file())


class Order(unittest.TestCase):
    """The pin check comes before anything is written."""

    def test_only_reads_and_refusals_come_before_the_pin_check(self) -> None:
        main = tasks(ROLE / "tasks" / "main.yml")
        names = [task.get("name") for task in main]
        at = names.index("Hold the release tarball to its pinned sha256")
        self.assertEqual(main[at].get("ansible.builtin.include_tasks"), "_release_pin.yml")
        for task in main[:at]:
            modules = set(task) & {key for key in task if key.startswith("ansible.builtin.")}
            with self.subTest(task=task.get("name")):
                self.assertTrue(
                    modules <= READ_ONLY_MODULES, f"{task.get('name')} writes before the pin check"
                )

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
            "broker_deploy_unpacked",
            "broker_deploy_unpack_report",
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
