"""Tests for check_vendored_ghost_platform: one flipped byte is named, and a faithful copy passes."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import check_vendored_ghost_platform as check

ROLE = "demo1_build"
PATH = "demo-host/provision/tool.py"
CONTENT = b"#!/usr/bin/env python3\nprint('upstream')\n"
GIT = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def git(repo: Path, *args: str) -> str:
    """Run git in ``repo``, fail the test on error, and return stdout."""
    done = subprocess.run(  # noqa: S603
        ["git", *GIT, "-C", str(repo), *args],  # noqa: S607
        capture_output=True,
        check=True,
        text=True,
    )
    return done.stdout.strip()


class VendoredCheckTest(unittest.TestCase):
    """Build a small upstream repository and a role that carries a copy of one of its files."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="vendored-test-")
        self.addCleanup(scratch.cleanup)
        self.tmp = Path(scratch.name)
        self.upstream = self.tmp / "upstream"
        (self.upstream / PATH).parent.mkdir(parents=True)
        (self.upstream / PATH).write_bytes(CONTENT)
        git(self.upstream, "init", "--quiet")
        git(self.upstream, "add", "-A")
        git(self.upstream, "commit", "--quiet", "-m", "pinned")
        self.sha = git(self.upstream, "rev-parse", "HEAD")
        self.role_dir = self.tmp / "repo" / check.ROLES_DIR / ROLE
        self.copy = self.role_dir / check.VENDORED / PATH
        self.copy.parent.mkdir(parents=True)
        self.copy.write_bytes(CONTENT)
        (self.role_dir / "defaults").mkdir()
        self.write_pin(self.sha)

    def write_pin(self, sha: str) -> None:
        """Write the role's defaults with ``sha`` as its source pin."""
        (self.role_dir / "defaults" / "main.yml").write_text(
            f"---\n# a comment\n{ROLE}_source_sha: {sha}\n", encoding="utf-8"
        )

    def findings(self) -> list[str]:
        """Compare the role with the upstream repository."""
        return check.compare_role(self.role_dir, ROLE, self.upstream)

    def test_a_faithful_copy_passes(self) -> None:
        self.assertEqual(self.findings(), [])

    def test_one_flipped_byte_is_named(self) -> None:
        flipped = bytearray(CONTENT)
        flipped[-3] ^= 0x01
        self.copy.write_bytes(bytes(flipped))
        self.assertEqual(
            self.findings(), [f"{ROLE}: {PATH} differs from ghost-platform at {self.sha}"]
        )

    def test_a_line_ending_change_is_a_difference(self) -> None:
        self.copy.write_bytes(CONTENT.replace(b"\n", b"\r\n"))
        self.assertEqual(len(self.findings()), 1)

    def test_a_file_upstream_does_not_have_is_named(self) -> None:
        extra = self.role_dir / check.VENDORED / "demo-host/provision/extra.py"
        extra.write_bytes(b"x\n")
        self.assertEqual(
            self.findings(),
            [f"{ROLE}: demo-host/provision/extra.py is not in ghost-platform at {self.sha}"],
        )

    def test_a_pin_the_upstream_lacks_fails(self) -> None:
        self.write_pin("0" * 40)
        self.assertEqual(
            self.findings(), [f"{ROLE}: commit {'0' * 40} is not in the upstream repository"]
        )

    def test_a_pin_that_moved_with_the_file_fails(self) -> None:
        """The case the role's own sha256 pin cannot see: file and pin edited together."""
        self.copy.write_bytes(CONTENT + b"# edited\n")
        self.assertEqual(len(self.findings()), 1)

    def test_a_role_with_no_vendored_file_fails(self) -> None:
        self.copy.unlink()
        self.assertEqual(
            self.findings(), [f"{ROLE}: no file under {check.VENDORED}, so nothing was compared"]
        )

    def test_a_malformed_pin_is_refused(self) -> None:
        self.write_pin("main")
        with self.assertRaises(check.VendoredCheckError):
            check.read_pin(self.role_dir, ROLE)

    def test_the_command_line_exits_one_on_a_difference(self) -> None:
        other = "demo1_egress_spool"
        egress = self.tmp / "repo" / check.ROLES_DIR / other
        (egress / check.VENDORED / PATH).parent.mkdir(parents=True)
        (egress / check.VENDORED / PATH).write_bytes(CONTENT)
        (egress / "defaults").mkdir()
        (egress / "defaults" / "main.yml").write_text(
            f"{other}_source_sha: {self.sha}\n", encoding="utf-8"
        )
        argv = [
            "--root",
            str(self.tmp / "repo"),
            "--upstream",
            f"{ROLE}={self.upstream}",
            "--upstream",
            f"{other}={self.upstream}",
        ]
        self.assertEqual(check.main(argv), 0)
        self.copy.write_bytes(CONTENT + b"x")
        self.assertEqual(check.main(argv), 1)

    def test_the_real_pins_are_well_formed(self) -> None:
        """Both roles in this repository carry one 40-hex pin and at least one vendored file."""
        for role in check.ROLES:
            role_dir = check.REPO_ROOT / check.ROLES_DIR / role
            check.read_pin(role_dir, role)
            self.assertTrue(check.vendored_files(role_dir), role)


if __name__ == "__main__":
    unittest.main()
