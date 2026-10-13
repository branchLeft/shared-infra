#!/usr/bin/env python3
"""Unit tests for 50-install-stack-sync.sh.

The script writes root's authorized_keys on a production host, so what it
writes is pinned here: the forced command, the dropped comment, the one managed
line, and the lines it must leave alone. `SBIN_DIR` and `AUTHORIZED_KEYS` are
redirected into a scratch directory, the same override style as
test_00_harden_ssh.py.
"""

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

PROVISION = pathlib.Path(__file__).resolve().parent
SCRIPT = PROVISION / "50-install-stack-sync.sh"
MARKER = "branchleft-stack-sync:monitoring"


def keygen(directory, name, comment="ci@example"):
    path = pathlib.Path(directory) / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
        check=True,
    )
    return pathlib.Path(f"{path}.pub")


def blob(pub):
    return pathlib.Path(pub).read_text().split()[1]


class InstallStackSyncTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.sbin = self.tmp / "sbin"
        self.keys = self.tmp / "ssh" / "authorized_keys"

    def run_script(self, *args):
        env = dict(os.environ, SBIN_DIR=str(self.sbin), AUTHORIZED_KEYS=str(self.keys))
        return subprocess.run(
            ["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True, check=False
        )

    def lines(self):
        return self.keys.read_text().splitlines()

    def managed(self):
        return [line for line in self.lines() if line.split()[-1] == MARKER]

    def test_installs_the_wrapper_executable_and_identical_to_the_source(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapper = self.sbin / "branchleft-sync-stack"
        self.assertEqual(wrapper.read_bytes(), (PROVISION / "branchleft_sync_stack.py").read_bytes())
        self.assertEqual(stat.S_IMODE(wrapper.stat().st_mode), 0o755)
        self.assertFalse(self.keys.exists(), "no key is granted unless asked for")

    def test_a_second_run_is_a_no_op(self):
        pub = keygen(self.tmp, "k1")
        self.run_script("--grant-key", str(pub))
        before = self.keys.read_bytes()
        result = self.run_script("--grant-key", str(pub))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.keys.read_bytes(), before)
        self.assertIn("already up to date", result.stdout)

    def test_the_granted_line_forces_the_command_and_nothing_else(self):
        pub = keygen(self.tmp, "k1")
        result = self.run_script("--grant-key", str(pub))
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (
            f'restrict,command="{self.sbin}/branchleft-sync-stack monitoring" '
            f"ssh-ed25519 {blob(pub)} {MARKER}"
        )
        self.assertEqual(self.lines(), [expected])
        self.assertEqual(stat.S_IMODE(self.keys.stat().st_mode), 0o600)

    def test_a_hostile_key_comment_never_reaches_the_file(self):
        pub = keygen(self.tmp, "k1", comment='x" ssh-ed25519 AAAA evil')
        self.run_script("--grant-key", str(pub))
        text = self.keys.read_text()
        self.assertNotIn("evil", text)
        self.assertEqual(len(self.lines()), 1)

    def test_other_keys_are_kept_and_a_lookalike_marker_is_not_mistaken_for_ours(self):
        self.keys.parent.mkdir()
        self.keys.write_text(
            "ssh-ed25519 AAAAowner owner@laptop\n"
            f"ssh-ed25519 AAAAother mentions {MARKER} in the middle of its comment\n"
        )
        pub = keygen(self.tmp, "k1")
        self.run_script("--grant-key", str(pub))
        self.assertEqual(self.lines()[:2], [
            "ssh-ed25519 AAAAowner owner@laptop",
            f"ssh-ed25519 AAAAother mentions {MARKER} in the middle of its comment",
        ])
        self.assertEqual(len(self.managed()), 1)

    def test_granting_a_new_key_replaces_the_old_managed_line_only(self):
        old, new = keygen(self.tmp, "old"), keygen(self.tmp, "new")
        self.keys.parent.mkdir()
        self.keys.write_text("ssh-ed25519 AAAAowner owner@laptop\n")
        self.run_script("--grant-key", str(old))
        self.run_script("--grant-key", str(new))
        self.assertEqual(len(self.managed()), 1)
        self.assertIn(blob(new), self.managed()[0])
        self.assertNotIn(blob(old), self.keys.read_text())
        self.assertIn("owner@laptop", self.keys.read_text())

    def test_revoke_removes_the_managed_line_and_keeps_the_rest(self):
        pub = keygen(self.tmp, "k1")
        self.keys.parent.mkdir()
        self.keys.write_text("ssh-ed25519 AAAAowner owner@laptop\n")
        self.run_script("--grant-key", str(pub))
        result = self.run_script("--revoke-key")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), ["ssh-ed25519 AAAAowner owner@laptop"])

    def test_revoke_with_no_file_creates_nothing(self):
        result = self.run_script("--revoke-key")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.keys.exists())

    def test_refuses_a_key_that_is_not_ed25519(self):
        rsa = self.tmp / "rsa"
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(rsa)], check=True)
        result = self.run_script("--grant-key", f"{rsa}.pub")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only ssh-ed25519", result.stderr)
        self.assertFalse(self.keys.exists())

    def test_refuses_a_file_with_more_than_one_line_or_garbage_or_a_missing_file(self):
        two = self.tmp / "two.pub"
        pub = keygen(self.tmp, "k1")
        two.write_text(pub.read_text() * 2)
        junk = self.tmp / "junk.pub"
        junk.write_text("not a key\n")
        for target in (two, junk, self.tmp / "absent.pub"):
            with self.subTest(target=target.name):
                result = self.run_script("--grant-key", str(target))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.keys.exists())

    def test_refuses_unknown_and_conflicting_arguments(self):
        pub = keygen(self.tmp, "k1")
        for args in (["--nope"], ["--grant-key"], ["--grant-key", str(pub), "--revoke-key"]):
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args).returncode, 2)


if __name__ == "__main__":
    unittest.main()
