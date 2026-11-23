"""Unit tests for the media_backup role's pins, units and gates.

The Molecule scenario proves the role on a host. These hold the things it
cannot see cheaply: the shape of every pin, the order and hardening of the
service unit, the one home of the request ceiling, and that no task reads a
secret.
"""

import re
import unittest
from pathlib import Path
from typing import Any

import yaml

ROLE = Path(__file__).resolve().parents[2]


def _load(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((ROLE / name).read_text())
    return loaded


DEFAULTS = _load("defaults/main.yml")
VARS = _load("vars/main.yml")
SERVICE = (ROLE / "templates" / "branchleft-media-backup.service.j2").read_text()
TIMER = (ROLE / "templates" / "branchleft-media-backup.timer.j2").read_text()
TASKS = (ROLE / "tasks" / "main.yml").read_text()


class PinTests(unittest.TestCase):
    def test_the_commit_is_a_full_sha(self) -> None:
        self.assertRegex(str(DEFAULTS["media_backup_source_sha"]), r"\A[0-9a-f]{40}\Z")

    def test_every_file_has_a_checksum_and_the_release_holds_what_the_program_needs(self) -> None:
        files = DEFAULTS["media_backup_release_files"]
        paths = [f["path"] for f in files]
        self.assertEqual(len(paths), len(set(paths)))
        for f in files:
            self.assertRegex(f["sha256"], r"\A[0-9a-f]{64}\Z", f["path"])
        self.assertEqual(set(VARS["media_backup_required_paths"]), set(paths))

    def test_the_program_imports_only_files_in_the_release(self) -> None:
        # The program, its restore module, the storage shim, the recipients module and the
        # signer it loads by path: the five files, no more. A sixth import means a sixth pin.
        self.assertEqual(len(VARS["media_backup_required_paths"]), 5)


class UnitTests(unittest.TestCase):
    def test_the_check_runs_before_the_run(self) -> None:
        self.assertLess(SERVICE.index("ExecStartPre="), SERVICE.index("ExecStart="))
        self.assertIn("--check", SERVICE.split("ExecStartPre=")[1].splitlines()[0])
        self.assertNotIn("--check", SERVICE.split("\nExecStart=")[1].splitlines()[0])

    def test_the_service_is_hardened_like_the_nightly_worker(self) -> None:
        for line in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "CapabilityBoundingSet=",
            "UMask=0077",
            "TimeoutStartSec=12h",
        ):
            self.assertIn(line, SERVICE)

    def test_the_service_runs_as_the_service_account_not_root(self) -> None:
        self.assertRegex(SERVICE, r"(?m)^User=\{\{ media_backup_account \}\}$")
        self.assertNotRegex(SERVICE, r"(?m)^User=root")

    def test_no_value_is_in_the_unit(self) -> None:
        # The settings and the keys are in the owner-placed file. Only two names are set here, and
        # neither is a key.
        names = re.findall(r"(?m)^Environment=([A-Z_]+)=", SERVICE)
        self.assertEqual(
            sorted(names),
            ["MEDIA_BACKUP_MANIFEST_SIGNING_KEY_FILE", "MEDIA_BACKUP_MAX_REQUESTS_PER_SECOND"],
        )

    def test_the_timer_is_weekly_and_catches_up(self) -> None:
        self.assertIn("Persistent=true", TIMER)
        self.assertTrue(str(DEFAULTS["media_backup_calendar"]).startswith("Sun "))


class CeilingTests(unittest.TestCase):
    def test_the_default_is_inside_the_range_the_program_accepts(self) -> None:
        # media_backup_weekly.py refuses outside 1..400 and the provider allows 750.
        self.assertEqual(VARS["media_backup_rate_max"], 400)
        rate = DEFAULTS["media_backup_max_requests_per_second"]
        self.assertTrue(1 <= rate <= 400)


class GateTests(unittest.TestCase):
    def test_no_task_reads_a_file_or_a_secret(self) -> None:
        forbidden = ("ansible.builtin.slurp", "lookup('file'", "lookup('ansible.builtin.file'")
        for text in (*forbidden, "ansible.builtin.shell"):
            self.assertNotIn(text, TASKS)

    def test_the_timer_task_is_held_by_the_disable_variable(self) -> None:
        block = TASKS.split("- name: Hold the weekly timer")[1]
        held = "media_backup_timer_enabled | bool or media_backup_timer_may_disable | bool"
        self.assertIn(held, block)

    def test_enabling_is_refused_for_each_file_the_program_needs(self) -> None:
        names = (
            "media_backup_env_file",
            "media_backup_folders_file",
            "media_backup_recipients_file",
            "media_backup_signing_key_file",
        )
        for name in names:
            self.assertIn("- '{{ " + name + " }}'", TASKS)

    def test_the_role_never_writes_the_recipients_file(self) -> None:
        files = VARS["media_backup_private_files"]
        self.assertNotIn("media_backup_recipients_file", " ".join(str(f["path"]) for f in files))

    def test_the_two_owner_files_are_closed(self) -> None:
        by_path = {str(f["path"]): f for f in VARS["media_backup_private_files"]}
        env = by_path["{{ media_backup_env_file }}"]
        folders = by_path["{{ media_backup_folders_file }}"]
        self.assertEqual((env["owner"], env["group"], env["mode"]), ("root", "root", "0600"))
        self.assertEqual((folders["owner"], folders["mode"]), ("root", "0640"))


if __name__ == "__main__":
    unittest.main()
