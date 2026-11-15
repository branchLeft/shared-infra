"""Behaviour of the verify key tasks of broker_deploy, run for real on localhost.

The key is carried as a text file of 64 hex digits and the host gets the 32 raw bytes they spell.
The two task files are run, not read: a small play in a scratch directory includes them with the
key's destination moved into the scratch tree and its owner set to the account that runs the test.
They prove what a read of the YAML cannot: that the bytes on the host are the pinned ones, byte for
byte, including the bytes that are not text, and that a key file or pin that is not exactly right
stops the run before anything is written, in a plan too.

A missing ansible-playbook is a failure, not a skip: the suite of a role is a control.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_broker_deploy_release import Outcome, ansible_playbook

ROLE = Path(__file__).resolve().parents[2]
CARRIED_KEY = ROLE / "files" / "broker-verify-key.hex"
STAND_IN_KEY = ROLE / "molecule" / "default" / "files" / "verify-key-stand-in.hex"
DIGEST = re.compile(r"^[0-9a-f]{64}\Z")
NOT_PINNED = "do not have the pinned sha256"
NOT_HEX = "exactly 64 lower-case hex digits"
NO_PIN = "No verify key is pinned"
NOT_A_FILE = "is missing or is not a plain file"


def sha256_hex(data: bytes) -> str:
    """Return the sha256 of some bytes."""
    return hashlib.sha256(data).hexdigest()


def default_pin() -> str:
    """Return the pin the role carries by default, read from its defaults file.

    Raises:
        AssertionError: the defaults file has no such line.
    """
    text = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    found = re.search(r"^broker_deploy_verify_key_sha256: '([0-9a-f]{64})'$", text, re.MULTILINE)
    if found is None:
        message = "the defaults hold no pinned verify key digest"
        raise AssertionError(message)
    return found.group(1)


class Lab(unittest.TestCase):
    """A scratch tree holding a key file, the host's key path and a runner."""

    def setUp(self) -> None:
        """Copy the carried key file into a scratch tree and write the play."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.key_file = self.root / "key.hex"
        self.key_file.write_bytes(CARRIED_KEY.read_bytes())
        self.host_key = self.root / "etc" / "broker-verify-key.bin"
        self.host_key.parent.mkdir()
        self.play = self.root / "play.yml"
        self.play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {ROLE / 'defaults' / 'main.yml'}\n"
            f"    - {ROLE / 'vars' / 'main.yml'}\n"
            "  tasks:\n"
            f"    - ansible.builtin.include_tasks: {ROLE / 'tasks' / '_verify_key_pin.yml'}\n"
            f"    - ansible.builtin.include_tasks: {ROLE / 'tasks' / '_verify_key.yml'}\n",
            encoding="utf-8",
        )

    def pinned(self) -> str:
        """Return the sha256 of the 32 bytes the scratch key file spells."""
        return sha256_hex(bytes.fromhex(self.key_file.read_text(encoding="ascii").strip()))

    def run_role(
        self, *, check: bool = False, key_file: Path | None = None, sha256: str | None = None
    ) -> Outcome:
        """Run the pin check and the install once."""
        variables: dict[str, object] = {
            "broker_deploy_verify_key_src": str(key_file or self.key_file),
            "broker_deploy_verify_key_sha256": self.pinned() if sha256 is None else sha256,
            "broker_deploy_verify_key": str(self.host_key),
            "broker_deploy_verify_key_owner": pwd.getpwuid(os.getuid()).pw_name,
            "broker_deploy_user": grp.getgrgid(os.getgid()).gr_name,
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
    """What the plan shows and what the apply puts on the host."""

    def test_the_host_gets_the_pinned_bytes_of_the_carried_key(self) -> None:
        """The carried key has bytes that are not text, the case that loses a byte first."""
        raw = bytes.fromhex(CARRIED_KEY.read_text(encoding="ascii").strip())
        self.assertEqual(len(raw), 32)
        with self.assertRaises(UnicodeDecodeError):
            raw.decode("utf-8")
        outcome = self.run_role(sha256=default_pin())
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(self.host_key.read_bytes(), raw)
        self.assertEqual(sha256_hex(self.host_key.read_bytes()), default_pin())
        self.assertEqual(self.host_key.stat().st_mode & 0o777, 0o640)

    def test_the_host_gets_the_stand_in_bytes_the_container_test_pins(self) -> None:
        self.key_file.write_bytes(STAND_IN_KEY.read_bytes())
        outcome = self.run_role()
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(self.host_key.read_bytes(), b"\x00" * 32)

    def test_every_byte_value_survives(self) -> None:
        """All 256 byte values, 32 at a time, come out as they went in."""
        for start in range(0, 256, 32):
            raw = bytes(range(start, start + 32))
            with self.subTest(first=start):
                self.key_file.write_text(raw.hex() + "\n", encoding="ascii")
                self.host_key.unlink(missing_ok=True)
                outcome = self.run_role()
                self.assertEqual(outcome.code, 0, outcome.output)
                self.assertEqual(self.host_key.read_bytes(), raw)

    def test_a_key_file_with_no_line_feed_is_accepted(self) -> None:
        self.key_file.write_bytes(CARRIED_KEY.read_bytes().rstrip(b"\n"))
        outcome = self.run_role(sha256=default_pin())
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertEqual(sha256_hex(self.host_key.read_bytes()), default_pin())

    def test_a_plan_writes_nothing_and_shows_the_change(self) -> None:
        outcome = self.run_role(check=True)
        self.assertEqual(outcome.code, 0, outcome.output)
        self.assertGreaterEqual(outcome.changed, 1)
        self.assertFalse(self.host_key.exists())

    def test_the_next_run_and_the_next_plan_change_nothing(self) -> None:
        self.assertEqual(self.run_role().code, 0)
        second = self.run_role()
        self.assertEqual(second.code, 0, second.output)
        self.assertEqual(second.changed, 0, second.output)
        plan = self.run_role(check=True)
        self.assertEqual(plan.code, 0, plan.output)
        self.assertEqual(plan.changed, 0, plan.output)

    def test_a_key_changed_on_the_host_is_put_back_and_the_plan_shows_it(self) -> None:
        self.assertEqual(self.run_role().code, 0)
        self.host_key.write_bytes(b"\x01" * 32)
        plan = self.run_role(check=True)
        self.assertEqual(plan.code, 0, plan.output)
        self.assertGreaterEqual(plan.changed, 1)
        self.assertEqual(self.host_key.read_bytes(), b"\x01" * 32)
        self.assertEqual(self.run_role().code, 0)
        self.assertEqual(
            self.host_key.read_bytes(), bytes.fromhex(self.key_file.read_text().strip())
        )


class Refusals(Lab):
    """Each refusal stops the run with its message before anything is written."""

    def refused(self, outcome: Outcome, fragment: str) -> None:
        """Assert the run failed with the fragment and the host's key was not written."""
        self.assertNotEqual(outcome.code, 0, outcome.output)
        self.assertIn(fragment, outcome.output)
        self.assertFalse(self.host_key.exists(), "the host's key was written")

    def test_one_hex_digit_changed_is_refused(self) -> None:
        """The sabotage: the pinned key with one digit flipped does not have the pinned digest."""
        pin = self.pinned()
        text = self.key_file.read_text(encoding="ascii")
        flipped = ("0" if text[0] != "0" else "1") + text[1:]
        self.key_file.write_text(flipped, encoding="ascii")
        self.refused(self.run_role(sha256=pin), NOT_PINNED)

    def test_a_pin_of_another_key_is_refused(self) -> None:
        self.refused(self.run_role(sha256=sha256_hex(b"\x01" * 32)), NOT_PINNED)

    def test_a_pin_of_the_wrong_shape_is_refused(self) -> None:
        good = self.pinned()
        for digest in ("", "0" * 63, good.upper(), "sha256:" + good, good + "0"):
            with self.subTest(digest=digest):
                self.refused(self.run_role(sha256=digest), NO_PIN)

    def test_a_file_that_is_not_exactly_64_lower_case_hex_digits_is_refused(self) -> None:
        good = self.key_file.read_text(encoding="ascii").strip()
        bad = {
            "63 digits": good[:-1] + "\n",
            "65 digits": good + "0\n",
            "upper case": good.upper() + "\n",
            "a space inside": good[:32] + " " + good[33:] + "\n",
            "not hex": "g" + good[1:] + "\n",
            "two line feeds": good + "\n\n",
            "carriage return": good + "\r\n",
            "a leading space": " " + good,
            "0x prefix": "0x" + good[2:] + "\n",
            "empty": "",
            "two lines": good[:32] + "\n" + good[32:] + "\n",
        }
        for name, text in bad.items():
            with self.subTest(name=name):
                self.key_file.write_text(text, encoding="ascii", newline="")
                self.refused(self.run_role(sha256=sha256_hex(bytes(range(32)))), NOT_HEX)

    def test_a_key_file_that_is_missing_or_a_link_is_refused(self) -> None:
        pin = self.pinned()
        real = self.root / "elsewhere.hex"
        real.write_bytes(self.key_file.read_bytes())
        self.key_file.unlink()
        self.refused(self.run_role(sha256=pin), NOT_A_FILE)
        self.key_file.symlink_to(real)
        self.refused(self.run_role(sha256=pin), NOT_A_FILE)

    def test_a_check_mode_run_refuses_too(self) -> None:
        self.refused(self.run_role(check=True, sha256=sha256_hex(b"\x01" * 32)), NOT_PINNED)
        self.refused(self.run_role(check=True, sha256=""), NO_PIN)


if __name__ == "__main__":
    unittest.main()
