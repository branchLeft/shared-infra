"""Hold the hand installers to a frozen list: a new host-state script must be listed with a reason.

A script is a hand installer when it sits under a directory named ``provision`` or under
``hetzner/scripts``. Each one must appear in ``hand_installers.yml`` with a reason, and each entry
must name a script that still exists.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path("ansible/checks/hand_installers.yml")
REASONS = ("stays-as-code", "pending-role")
ROLE = re.compile(r"[a-z][a-z0-9_]*")
PRUNED = frozenset((".git", "node_modules"))


def installers(root: Path) -> set[str]:
    """Return the repo-relative path of every ``*.sh`` in scope under ``root``."""
    found: set[str] = set()
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in PRUNED]
        for name in files:
            if not name.endswith(".sh"):
                continue
            rel = Path(directory, name).relative_to(root)
            parts = rel.parts
            if "provision" in parts[:-1] or parts[:2] == ("hetzner", "scripts"):
                found.add(rel.as_posix())
    return found


def check(root: Path) -> list[str]:
    """Return one finding per unlisted installer, per stale entry and per malformed entry."""
    try:
        document = YAML(typ="safe").load((root / ALLOWLIST).read_text(encoding="utf-8"))
    except (OSError, YAMLError) as error:
        return [f"{ALLOWLIST} cannot be read as YAML: {type(error).__name__}"]
    if document is None:
        document = {}
    if not isinstance(document, dict):
        return [f"{ALLOWLIST} must map each script path to its entry"]
    findings: list[str] = []
    for name, entry in document.items():
        findings.extend(_entry_findings(str(name), entry))
    listed = {str(name) for name in document}
    found = installers(root)
    for name in sorted(found - listed):
        findings.append(f"{name} is a hand installer and is not in {ALLOWLIST}: list it")
    for name in sorted(listed - found):
        findings.append(f"{name} is in {ALLOWLIST} but no such script is in scope: remove it")
    return findings


def _entry_findings(name: str, entry: object) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{name}: the entry must be a mapping with a reason"]
    findings = [f"{name}: unknown key {key}" for key in entry if key not in ("reason", "role")]
    reason = entry.get("reason")
    if reason not in REASONS:
        findings.append(f"{name}: reason must be one of {', '.join(REASONS)}")
    elif reason == "pending-role":
        role = entry.get("role")
        if not isinstance(role, str) or not ROLE.fullmatch(role):
            findings.append(f"{name}: pending-role must name its role, [a-z][a-z0-9_]*")
    elif "role" in entry:
        findings.append(f"{name}: stays-as-code takes no role")
    return findings


class RealTree(unittest.TestCase):
    def test_every_hand_installer_is_listed_with_a_reason(self) -> None:
        self.assertEqual(check(ROOT), [])

    def test_the_scan_reaches_nested_and_mail_scripts(self) -> None:
        found = installers(ROOT)
        self.assertIn("hetzner/scripts/lib/docker-pull.sh", found)
        self.assertIn("mail/provision/run-all.sh", found)
        self.assertGreaterEqual(len(found), 30)


class Tree(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def _write(self, relative: str, text: str = "echo\n") -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _list(self, *entries: str) -> None:
        self._write(str(ALLOWLIST), "".join(entries))

    def test_a_listed_script_passes(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list("hetzner/provision/a.sh:\n  reason: stays-as-code\n")
        self.assertEqual(check(self.root), [])

    def test_an_unlisted_script_fails_naming_it(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list()
        self.assertEqual(
            check(self.root),
            [f"hetzner/provision/a.sh is a hand installer and is not in {ALLOWLIST}: list it"],
        )

    def test_a_new_script_is_red_until_it_is_listed(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self.assertEqual(check(self.root), [])
        self._write("hetzner/provision/new-installer.sh")
        self.assertEqual(len(check(self.root)), 1)
        self.assertIn("new-installer.sh", check(self.root)[0])
        self._list(
            "hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n",
            "hetzner/provision/new-installer.sh:\n  reason: pending-role\n  role: docker_host\n",
        )
        self.assertEqual(check(self.root), [])

    def test_a_provision_directory_anywhere_is_walked(self) -> None:
        self._write("mail/provision/b.sh")
        self._list()
        self.assertEqual(len(check(self.root)), 1)
        self.assertIn("mail/provision/b.sh", check(self.root)[0])

    def test_hetzner_scripts_are_walked_into_subdirectories(self) -> None:
        self._write("hetzner/scripts/lib/c.sh")
        self._list()
        self.assertIn("hetzner/scripts/lib/c.sh", check(self.root)[0])

    def test_scripts_outside_scope_and_non_shell_files_are_not_walked(self) -> None:
        self._write("scripts/d.sh")
        self._write("hetzner/provision/e.py")
        self._write("ansible/roles/x/provision.sh")
        self._list()
        self.assertEqual(check(self.root), [])

    def test_a_stale_entry_fails_naming_the_gone_file(self) -> None:
        self._list("hetzner/provision/gone.sh:\n  reason: stays-as-code\n")
        self.assertEqual(
            check(self.root),
            [
                f"hetzner/provision/gone.sh is in {ALLOWLIST} "
                "but no such script is in scope: remove it"
            ],
        )

    def test_a_pending_role_entry_without_a_role_fails(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list("hetzner/provision/a.sh:\n  reason: pending-role\n")
        self.assertEqual(
            check(self.root),
            ["hetzner/provision/a.sh: pending-role must name its role, [a-z][a-z0-9_]*"],
        )

    def test_an_entry_without_a_known_reason_fails(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list("hetzner/provision/a.sh:\n  reason: later\n")
        self.assertEqual(
            check(self.root),
            ["hetzner/provision/a.sh: reason must be one of stays-as-code, pending-role"],
        )

    def test_a_stays_as_code_entry_with_a_role_fails(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list("hetzner/provision/a.sh:\n  reason: stays-as-code\n  role: host_baseline\n")
        self.assertEqual(check(self.root), ["hetzner/provision/a.sh: stays-as-code takes no role"])

    def test_an_entry_that_is_not_a_mapping_fails(self) -> None:
        self._write("hetzner/provision/a.sh")
        self._list("hetzner/provision/a.sh: stays-as-code\n")
        self.assertEqual(
            check(self.root),
            ["hetzner/provision/a.sh: the entry must be a mapping with a reason"],
        )

    def test_a_missing_or_unreadable_allowlist_fails(self) -> None:
        self._write("hetzner/provision/a.sh")
        self.assertEqual(
            check(self.root),
            [f"{ALLOWLIST} cannot be read as YAML: FileNotFoundError"],
        )


if __name__ == "__main__":
    unittest.main()
