"""Behaviour of the release tasks of broker_deploy, run for real with ansible-playbook on localhost.

The pin check and the release delivery are task files, so they are run, not read: a small play
in a scratch directory includes them with every path of the role moved into the scratch tree and
the owner set to the account that runs the test. Nothing here touches a host or a container. They
prove what a read of the YAML cannot: that a release whose files are not exactly the pinned ones
stops the run before anything is written, that a plan writes nothing, that an apply delivers the
files once and links the release, and that the next run changes nothing.

A missing ansible-playbook is a failure, not a skip: the suite of a role is a control.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
SCENARIO_RELEASE = ROLE / "molecule" / "default" / "files" / "release"
SCENARIO_KEY = ROLE / "molecule" / "default" / "files" / "verify-key-stand-in.bin"
VERSION = "0.0.1"
REFUSED = "are not exactly the files pinned"


@dataclass
class Outcome:
    """What one run of ansible-playbook did."""

    code: int
    output: str

    @property
    def changed(self) -> int:
        """Return the recap's changed count."""
        found = re.search(r"changed=(\d+)", self.output)
        return int(found.group(1)) if found else -1


def ansible_playbook() -> Path:
    """Return the ansible-playbook beside the interpreter that runs the tests.

    Raises:
        AssertionError: the interpreter's environment has no ansible-playbook.
    """
    found = Path(sys.executable).parent / "ansible-playbook"
    if not found.exists():
        message = f"{found} is missing: run these tests with the pinned tool environment"
        raise AssertionError(message)
    return found


def sha256(path: Path) -> str:
    """Return the sha256 of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pins_of(release: Path) -> dict[str, str]:
    """Return the pins of every file under a release directory, by relative path."""
    return {
        str(path.relative_to(release)): sha256(path)
        for path in sorted(release.rglob("*"))
        if path.is_file()
    }


class Lab(unittest.TestCase):
    """A scratch tree holding the carried release, the releases directory and a runner."""

    def setUp(self) -> None:
        """Copy the scenario's stand-in release into a scratch release directory."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.release_dir = self.root / "carried"
        self.carried = self.release_dir / VERSION
        shutil.copytree(SCENARIO_RELEASE / VERSION, self.carried)
        self.releases = self.root / "opt" / "releases"
        self.current = self.root / "opt" / "current"
        self.pins = {VERSION: pins_of(self.carried)}
        self.key = self.root / "verify-key.bin"
        shutil.copyfile(SCENARIO_KEY, self.key)
        self.key_sha256 = sha256(self.key)
        self.play = self.root / "play.yml"
        self.play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {ROLE / 'defaults' / 'main.yml'}\n"
            f"    - {ROLE / 'vars' / 'main.yml'}\n"
            "  tasks:\n"
            f"    - ansible.builtin.include_tasks: {ROLE / 'tasks' / '_release_pin.yml'}\n"
            f"    - ansible.builtin.include_tasks: {ROLE / 'tasks' / '_release.yml'}\n",
            encoding="utf-8",
        )

    def run_role(
        self,
        version: str = VERSION,
        *,
        check: bool = False,
        pins: dict[str, dict[str, str]] | None = None,
        key_sha256: str | None = None,
    ) -> Outcome:
        """Run the pin check and the release tasks once."""
        variables: dict[str, object] = {
            "broker_deploy_release_version": version,
            "broker_deploy_release_pins": self.pins if pins is None else pins,
            "broker_deploy_release_dir": str(self.release_dir),
            "broker_deploy_verify_key_src": str(self.key),
            "broker_deploy_verify_key_sha256": (
                self.key_sha256 if key_sha256 is None else key_sha256
            ),
            "broker_deploy_releases_dir": str(self.releases),
            "broker_deploy_current_link": str(self.current),
            "broker_deploy_release_owner": pwd.getpwuid(os.getuid()).pw_name,
            "broker_deploy_release_group": grp.getgrgid(os.getgid()).gr_name,
            "ansible_python_interpreter": sys.executable,
        }
        extra = self.root / "extra.json"
        extra.write_text(json.dumps(variables), encoding="utf-8")
        command = [str(ansible_playbook()), "-i", "localhost,", "-e", f"@{extra}"]
        if check:
            command.append("--check")
        command.append(str(self.play))
        environment = {
            **os.environ,
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(self.root / "ansible-home"),
        }
        # The command is built here from fixed paths and the scratch tree.
        done = subprocess.run(  # noqa: S603
            command, capture_output=True, text=True, check=False, env=environment, timeout=180
        )
        return Outcome(done.returncode, done.stdout + done.stderr)


class PlanAndApply(Lab):
    """What the plan shows and what the apply does."""

    def test_a_plan_writes_nothing(self) -> None:
        outcome = self.run_role(check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertGreaterEqual(outcome.changed, 1)
        self.assertFalse(self.releases.exists())
        self.assertFalse(self.current.exists())

    def test_the_apply_delivers_the_files_and_points_the_link_at_them(self) -> None:
        outcome = self.run_role()
        self.assertEqual(outcome.code, 0, outcome.output)
        release = self.releases / VERSION
        for relative in self.pins[VERSION]:
            self.assertEqual(sha256(release / relative), self.pins[VERSION][relative])
            self.assertEqual((release / relative).stat().st_mode & 0o022, 0)
        self.assertTrue(self.current.is_symlink())
        self.assertEqual(self.current.resolve(), release.resolve())

    def test_the_next_run_and_the_next_plan_change_nothing(self) -> None:
        first = self.run_role()
        self.assertEqual(first.code, 0, first.output)
        second = self.run_role()
        self.assertEqual(second.code, 0, second.output)
        self.assertEqual(second.changed, 0, second.output)
        plan = self.run_role(check=True)
        self.assertEqual(plan.code, 0, plan.output)
        self.assertEqual(plan.changed, 0, plan.output)

    def test_a_byte_changed_on_the_host_is_put_back_and_the_plan_shows_it(self) -> None:
        self.assertEqual(self.run_role().code, 0)
        installed = self.releases / VERSION / "broker.mjs"
        installed.write_text("// changed on the host\n", encoding="utf-8")
        plan = self.run_role(check=True)
        self.assertEqual(plan.code, 0, plan.output)
        self.assertGreaterEqual(plan.changed, 1)
        self.assertEqual(installed.read_text(encoding="utf-8"), "// changed on the host\n")
        self.assertEqual(self.run_role().code, 0)
        self.assertEqual(sha256(installed), self.pins[VERSION]["broker.mjs"])

    def test_a_new_version_gets_its_own_directory_and_the_old_one_stays(self) -> None:
        self.assertEqual(self.run_role().code, 0)
        newer = self.release_dir / "0.0.2"
        newer.mkdir()
        (newer / "broker.mjs").write_text("// release 0.0.2\n", encoding="utf-8")
        pins = {**self.pins, "0.0.2": pins_of(newer)}
        outcome = self.run_role("0.0.2", pins=pins)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(self.current.resolve(), (self.releases / "0.0.2").resolve())
        self.assertEqual(
            (self.releases / "0.0.2" / "broker.mjs").read_text(encoding="utf-8"),
            "// release 0.0.2\n",
        )
        old = self.releases / VERSION / "broker.mjs"
        self.assertEqual(sha256(old), self.pins[VERSION]["broker.mjs"])


class Refusals(Lab):
    """Each refusal stops the run with its message before anything is written."""

    def refused(self, outcome: Outcome, fragment: str) -> None:
        """Assert the run failed with the fragment and nothing was written."""
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(fragment, outcome.output)
        self.assertFalse(self.releases.exists(), "a release directory was made")
        self.assertFalse(self.current.exists(), "the current link was made")

    def test_a_file_that_is_not_the_pinned_one_is_refused(self) -> None:
        (self.carried / "broker.mjs").write_text("// not the pinned bytes\n", encoding="utf-8")
        self.refused(self.run_role(), "does not have its pinned sha256")

    def test_a_pinned_file_that_is_missing_is_refused(self) -> None:
        (self.carried / "plugins" / "stand-in-plugin.mjs").unlink()
        self.refused(self.run_role(), REFUSED)

    def test_a_file_that_is_not_pinned_is_refused(self) -> None:
        (self.carried / "plugins" / "extra.mjs").write_text("// not pinned\n", encoding="utf-8")
        self.refused(self.run_role(), REFUSED)

    def test_a_hidden_file_that_is_not_pinned_is_refused(self) -> None:
        (self.carried / ".hidden").write_text("// not pinned\n", encoding="utf-8")
        self.refused(self.run_role(), REFUSED)

    def test_a_link_in_the_release_is_refused(self) -> None:
        real = self.root / "elsewhere.mjs"
        real.write_bytes((self.carried / "broker.mjs").read_bytes())
        (self.carried / "broker.mjs").unlink()
        (self.carried / "broker.mjs").symlink_to(real)
        self.refused(self.run_role(), REFUSED)

    def test_a_release_directory_that_is_missing_is_refused(self) -> None:
        shutil.rmtree(self.carried)
        self.refused(self.run_role(), REFUSED)

    def test_a_check_mode_run_refuses_too(self) -> None:
        (self.carried / "broker.mjs").write_text("// not the pinned bytes\n", encoding="utf-8")
        self.refused(self.run_role(check=True), "does not have its pinned sha256")

    def test_a_version_that_is_not_a_plain_version_is_refused(self) -> None:
        for version in ("0.1", "../0.0.1", "0.0.1\n0.0.2", "v0.0.1", ""):
            with self.subTest(version=version):
                self.refused(self.run_role(version), "must be MAJOR.MINOR.PATCH")

    def test_a_version_with_no_pins_is_refused(self) -> None:
        cases: list[dict[str, dict[str, str]]] = [
            {},
            {VERSION: {}},
            {VERSION: {"plugins/stand-in-plugin.mjs": "0" * 64}},
        ]
        for pins in cases:
            with self.subTest(pins=pins):
                self.refused(self.run_role(pins=pins), "must be MAJOR.MINOR.PATCH")

    def test_a_path_or_pin_of_the_wrong_shape_is_refused(self) -> None:
        good = self.pins[VERSION]["broker.mjs"]
        bad = {
            "uppercase digest": {"broker.mjs": good.upper()},
            "short digest": {"broker.mjs": good[:-1]},
            "prefixed digest": {"broker.mjs": "sha256:" + good},
            "dot-dot path": {"broker.mjs": good, "../broker.mjs": good},
            "absolute path": {"broker.mjs": good, "/etc/passwd": good},
            "leading dot": {"broker.mjs": good, ".hidden": good},
        }
        for name, pins in bad.items():
            with self.subTest(name):
                self.refused(
                    self.run_role(pins={VERSION: pins}),
                    "A pinned path must be a plain relative path",
                )

    def test_a_verify_key_with_no_pin_is_refused(self) -> None:
        for digest in ("", "0" * 63, self.key_sha256.upper(), "sha256:" + self.key_sha256):
            with self.subTest(digest=digest):
                self.refused(self.run_role(key_sha256=digest), "No verify key is pinned")

    def test_a_verify_key_that_is_not_the_pinned_one_is_refused(self) -> None:
        self.key.write_bytes(b"\x01" * 32)
        self.refused(self.run_role(), "is not a plain 32-byte file with its pinned sha256")

    def test_a_verify_key_of_the_wrong_length_is_refused_even_with_its_own_pin(self) -> None:
        self.key.write_bytes(b"\x00" * 31)
        self.refused(
            self.run_role(key_sha256=sha256(self.key)),
            "is not a plain 32-byte file with its pinned sha256",
        )

    def test_a_verify_key_that_is_missing_or_a_link_is_refused(self) -> None:
        real = self.root / "elsewhere.bin"
        real.write_bytes(self.key.read_bytes())
        self.key.unlink()
        self.refused(self.run_role(), "is not a plain 32-byte file with its pinned sha256")
        self.key.symlink_to(real)
        self.refused(self.run_role(), "is not a plain 32-byte file with its pinned sha256")

    def test_a_check_mode_run_refuses_an_unpinned_key_too(self) -> None:
        self.refused(self.run_role(check=True, key_sha256=""), "No verify key is pinned")


if __name__ == "__main__":
    unittest.main()
