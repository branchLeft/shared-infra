"""Behaviour of the release tasks of broker_deploy, run for real with ansible-playbook on localhost.

The pin check and the release delivery are task files, so they are run, not read: a small play
in a scratch directory includes them with every path of the role moved into the scratch tree and
the owner set to the account that runs the test. Nothing here touches a host or a container. They
prove what a read of the YAML cannot: that a tarball that is not the pinned one stops the run
before anything is written, that a plan shows the unpack and writes nothing, that an apply unpacks
once and links the release, and that the next run changes nothing.

A missing ansible-playbook is a failure, not a skip: the suite of a role is a control.
"""

from __future__ import annotations

import grp
import gzip
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
FIXTURE_VERSION = "0.0.1"
FIXTURE = (
    ROLE / "molecule" / "default" / "files" / "release" / f"broker-bundle-{FIXTURE_VERSION}.tar.gz"
)
REPORT = "Report in check mode that the pinned release would be unpacked"
TASK_LINE = re.compile(r"^TASK \[(?P<name>.*?)\] \*+$")
RESULT_LINE = re.compile(r"^(?P<status>ok|changed|skipping|fatal|failed): \[localhost\]")


@dataclass
class Outcome:
    """What one run of ansible-playbook did."""

    code: int
    output: str
    statuses: dict[str, str]

    @property
    def changed(self) -> int:
        """Return the recap's changed count."""
        found = re.search(r"changed=(\d+)", self.output)
        return int(found.group(1)) if found else -1

    def status_of(self, fragment: str) -> str:
        """Return the status of the one task whose name contains the fragment.

        Raises:
            AssertionError: there is not exactly one such task.
        """
        names = [name for name in self.statuses if fragment in name]
        if len(names) != 1:
            message = f"expected one task named like {fragment!r}, found {names}"
            raise AssertionError(message)
        return self.statuses[names[0]]


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


def parse(output: str) -> dict[str, str]:
    """Return each task's last status from the default callback's text."""
    statuses: dict[str, str] = {}
    current = ""
    for line in output.splitlines():
        task = TASK_LINE.match(line)
        if task:
            current = task.group("name")
            continue
        result = RESULT_LINE.match(line)
        if result and current:
            statuses[current] = result.group("status")
    return statuses


def sha256(path: Path) -> str:
    """Return the sha256 of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has_gnu_tar() -> bool:
    """Return whether the tar the unarchive module would pick is GNU tar, which it requires."""
    for name in ("gtar", "tar"):
        found = shutil.which(name)
        if found:
            # The command is a fixed name from the PATH with a fixed flag.
            done = subprocess.run([found, "--version"], capture_output=True, text=True, check=False)  # noqa: S603
            return "GNU tar" in done.stdout
    return False


GNU_TAR = has_gnu_tar()
NEEDS_GNU_TAR = unittest.skipUnless(
    GNU_TAR, "the unarchive module needs GNU tar; the shards run on Linux, where it is the default"
)


def other_release(version_text: str) -> bytes:
    """Return a small release tarball whose entry point says which version it is."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        data = f"// release {version_text}\n".encode()
        info = tarfile.TarInfo("broker.mjs")
        info.size = len(data)
        info.mtime = 0
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


class Lab(unittest.TestCase):
    """A scratch tree holding the release directory, the releases directory and a runner."""

    def setUp(self) -> None:
        """Make the scratch tree with the fixture release in the role's release directory."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.release_dir = self.root / "carried"
        self.release_dir.mkdir()
        self.releases = self.root / "opt" / "releases"
        self.current = self.root / "opt" / "current"
        self.tarball = self.release_dir / f"broker-bundle-{FIXTURE_VERSION}.tar.gz"
        self.tarball.write_bytes(FIXTURE.read_bytes())
        self.pins = {FIXTURE_VERSION: sha256(FIXTURE)}
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
        version: str = FIXTURE_VERSION,
        *,
        check: bool = False,
        pins: dict[str, str] | None = None,
    ) -> Outcome:
        """Run the pin check and the release tasks once."""
        variables: dict[str, object] = {
            "broker_deploy_release_version": version,
            "broker_deploy_release_pins": self.pins if pins is None else pins,
            "broker_deploy_release_dir": str(self.release_dir),
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
        output = done.stdout + done.stderr
        return Outcome(done.returncode, output, parse(output))


class PlanAndApply(Lab):
    """What the plan shows and what the apply does."""

    def test_a_plan_shows_the_unpack_and_writes_nothing(self) -> None:
        outcome = self.run_role(check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(outcome.status_of(REPORT), "changed")
        self.assertFalse(self.releases.exists())
        self.assertFalse(self.current.exists())

    @NEEDS_GNU_TAR
    def test_the_apply_unpacks_the_release_and_points_the_link_at_it(self) -> None:
        outcome = self.run_role()
        self.assertEqual(outcome.code, 0, outcome.output)
        release = self.releases / FIXTURE_VERSION
        self.assertTrue((release / "broker.mjs").is_file())
        self.assertTrue((release / "plugins" / "stand-in-plugin.mjs").is_file())
        self.assertTrue(self.current.is_symlink())
        self.assertEqual(self.current.resolve(), release.resolve())
        self.assertEqual(outcome.status_of(REPORT), "skipping")

    @NEEDS_GNU_TAR
    def test_the_next_run_and_the_next_plan_change_nothing(self) -> None:
        first = self.run_role()
        self.assertEqual(first.code, 0, first.output)
        second = self.run_role()
        self.assertEqual(second.code, 0, second.output)
        self.assertEqual(second.changed, 0, second.output)
        plan = self.run_role(check=True)
        self.assertEqual(plan.code, 0, plan.output)
        self.assertEqual(plan.changed, 0, plan.output)
        self.assertEqual(plan.status_of(REPORT), "skipping")

    @NEEDS_GNU_TAR
    def test_a_new_version_gets_its_own_directory_and_the_old_one_stays(self) -> None:
        self.assertEqual(self.run_role().code, 0)
        newer = self.release_dir / "broker-bundle-0.0.2.tar.gz"
        newer.write_bytes(other_release("0.0.2"))
        pins = {**self.pins, "0.0.2": sha256(newer)}
        outcome = self.run_role("0.0.2", pins=pins)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(self.current.resolve(), (self.releases / "0.0.2").resolve())
        self.assertTrue((self.releases / FIXTURE_VERSION / "broker.mjs").is_file())
        self.assertEqual(
            (self.releases / "0.0.2" / "broker.mjs").read_text(encoding="utf-8"),
            "// release 0.0.2\n",
        )


class Refusals(Lab):
    """Each refusal stops the run with its message before anything is written."""

    def refused(self, outcome: Outcome, fragment: str) -> None:
        """Assert the run failed with the fragment and nothing was written."""
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(fragment, outcome.output)
        self.assertFalse(self.releases.exists(), "a release directory was made")
        self.assertFalse(self.current.exists(), "the current link was made")

    def test_a_tarball_that_is_not_the_pinned_one_is_refused(self) -> None:
        self.tarball.write_bytes(self.tarball.read_bytes() + b"\0")
        self.refused(self.run_role(), "does not have its pinned sha256")

    def test_a_tarball_that_is_missing_is_refused(self) -> None:
        self.tarball.unlink()
        self.refused(self.run_role(), "is missing from the role's release")

    def test_a_tarball_that_is_a_link_is_refused(self) -> None:
        real = self.root / "elsewhere.tar.gz"
        real.write_bytes(FIXTURE.read_bytes())
        self.tarball.unlink()
        self.tarball.symlink_to(real)
        self.refused(self.run_role(), "does not have its pinned sha256")

    def test_a_check_mode_run_refuses_too(self) -> None:
        self.tarball.write_bytes(b"not the release")
        self.refused(self.run_role(check=True), "does not have its pinned sha256")

    def test_a_version_that_is_not_a_plain_version_is_refused(self) -> None:
        for version in ("0.1", "../0.0.1", "0.0.1\n0.0.2", "v0.0.1", ""):
            with self.subTest(version=version):
                self.refused(self.run_role(version), "must be MAJOR.MINOR.PATCH")

    def test_a_version_with_no_pin_is_refused(self) -> None:
        self.refused(self.run_role("0.0.2"), "must be MAJOR.MINOR.PATCH")

    def test_a_pin_that_is_not_a_lower_case_sha256_is_refused(self) -> None:
        for pin in (
            self.pins[FIXTURE_VERSION].upper(),
            self.pins[FIXTURE_VERSION][:-1],
            "sha256:" + self.pins[FIXTURE_VERSION],
        ):
            with self.subTest(pin=pin):
                self.refused(
                    self.run_role(pins={FIXTURE_VERSION: pin}), "must be MAJOR.MINOR.PATCH"
                )


if __name__ == "__main__":
    unittest.main()
