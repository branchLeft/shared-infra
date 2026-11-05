"""Tests for the public-key-only check that guards a CI account's key files.

Three groups: a corpus of bad inputs that must each be refused with its own reason code, and
the same corpus run against a stand-in that accepts everything to show each case would go red if
the guard were removed; the exact command-line invocation the runbook prints; and a leak test that
plants a private key block and scans every output. The shape constants are held to the ci_login
role they are copied from.
"""

from __future__ import annotations

import base64
import contextlib
import io
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

import pubkey_only as tool
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
TOOL = Path(tool.__file__).resolve()
CI_LOGIN_VARS = ROOT / "ansible" / "roles" / "ci_login" / "vars" / "main.yml"

PRIVATE_SENTINEL = "SENTINELPRIVATEKEYBODYDONOTPRINT"
PRIVATE_BLOCK = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    f"b3BlbnNzaC1rZXktdjEAAAAA{PRIVATE_SENTINEL}\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)

Check = Callable[[bytes, str | None], tool.KeyCheck]


def string_field(blob: bytes) -> bytes:
    return struct.pack(">I", len(blob)) + blob


def ed25519_line(fill: int = 1, comment: str = "ci@test") -> str:
    """A well-formed ed25519 public key line; the key bytes are a repeated fill byte."""
    blob = string_field(b"ssh-ed25519") + string_field(bytes([fill]) * 32)
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}".rstrip()


def rsa_line() -> str:
    blob = string_field(b"ssh-rsa") + bytes(range(256))[:142]
    return f"ssh-rsa {base64.b64encode(blob).decode()} rsa@test"


def refusal_of(check: Check, data: bytes, want_type: str | None) -> str:
    return check(data, want_type).reason


def accept_everything(data: bytes, want_type: str | None) -> tool.KeyCheck:
    """A stand-in for the guard with the mechanism removed."""
    return tool.KeyCheck(reason="", key_type="ssh-ed25519", body="x", fingerprint="SHA256:x")


GOOD = ed25519_line(1)
OTHER = ed25519_line(2)
# Each bad input, the type asked for, and the reason code it must be refused with.
BAD: dict[str, tuple[bytes, str | None, str]] = {
    "private key block": (PRIVATE_BLOCK.encode(), None, "private_key"),
    "private key magic": (b"openssh-key-v1\x00\x00\x00\x00", None, "private_key"),
    "two lines": (f"{GOOD}\n{OTHER}\n".encode(), None, "several_lines"),
    "option in front": (f'command="id" {GOOD}\n'.encode(), None, "options_in_front"),
    "restrict in front": (f"restrict {GOOD}\n".encode(), None, "options_in_front"),
    "truncated body": (GOOD[:-20].encode(), None, "bad_shape"),
    "empty file": (b"", None, "empty"),
    "only a line break": (b"\n", None, "empty"),
    "over two kibibytes": (b"#" * 3000, None, "too_large"),
    "not text": (b"\xff\xfe\x00", None, "not_text"),
    "body does not name its type": (
        f"ssh-ed25519 {base64.b64encode(b'x' * 51).decode()}\n".encode(),
        None,
        "bad_shape",
    ),
    "wrong type for the caller": (f"{rsa_line()}\n".encode(), "ssh-ed25519", "wrong_type"),
}


class PubkeyOnly(unittest.TestCase):
    def assert_corpus_refused(self, check: Check) -> None:
        for name, (data, want_type, reason) in BAD.items():
            with self.subTest(name):
                self.assertEqual(refusal_of(check, data, want_type), reason)

    def test_refuses_each_bad_input_and_accepts_a_real_key(self) -> None:
        self.assert_corpus_refused(tool.check_text)
        good = tool.check_text(f"{GOOD}\n".encode(), "ssh-ed25519")
        self.assertTrue(good.ok)
        self.assertEqual(good.key_type, "ssh-ed25519")
        self.assertRegex(good.fingerprint, r"^SHA256:[A-Za-z0-9+/]{43}$")
        self.assertTrue(tool.check_text(GOOD.encode(), None).ok, "no trailing break is fine")
        self.assertTrue(tool.check_text(f"{rsa_line()}\n".encode(), None).ok)

    def test_corpus_has_teeth(self) -> None:
        for name, (data, want_type, reason) in BAD.items():
            with self.subTest(name):
                self.assertTrue(accept_everything(data, want_type).ok)
                with self.assertRaises(AssertionError):
                    self.assertEqual(refusal_of(accept_everything, data, want_type), reason)

    def test_a_key_made_by_ssh_keygen_is_accepted(self) -> None:
        keygen = shutil.which("ssh-keygen")
        if keygen is None:
            self.skipTest("ssh-keygen is not installed")
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "id"
            subprocess.run(  # noqa: S603 - this repository's own tool or ssh-keygen, run with fixed arguments
                [keygen, "-q", "-t", "ed25519", "-N", "", "-C", "ci@test", "-f", str(key)],
                check=True,
            )
            ours = tool.check_file(Path(f"{key}.pub"), "ssh-ed25519")
            theirs = subprocess.run(  # noqa: S603 - this repository's own tool or ssh-keygen, run with fixed arguments
                [keygen, "-l", "-f", f"{key}.pub"], check=True, capture_output=True, text=True
            ).stdout.split()[1]
            self.assertTrue(ours.ok)
            self.assertEqual(ours.fingerprint, theirs)
            self.assertEqual(tool.check_file(key, "ssh-ed25519").reason, "private_key")

    def test_a_missing_file_is_unreadable(self) -> None:
        self.assertEqual(tool.check_file(Path("/nonexistent/key.pub")).reason, "unreadable")

    def test_shapes_equal_the_ci_login_role(self) -> None:
        role = yaml.safe_load(CI_LOGIN_VARS.read_text(encoding="utf-8"))
        self.assertEqual(list(tool.KEY_SHAPES), role["ci_login_key_shapes"])
        rendered = role["ci_login_key_pattern"].replace(
            '{{ ci_login_key_shapes | join("|") }}', "|".join(role["ci_login_key_shapes"])
        )
        self.assertEqual("^" + tool.KEY_PATTERN.pattern, rendered)


class CommandLine(unittest.TestCase):
    """The invocation the runbook prints: the venv's python in isolated mode, a path, a type."""

    def run_tool(self, folder: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - this repository's own tool or ssh-keygen, run with fixed arguments
            [sys.executable, "-I", str(TOOL), "check", *args],
            cwd=folder,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_runbook_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            pub = Path(folder) / "check.pub"
            pub.write_text(f"{GOOD}\n", encoding="utf-8")
            done = self.run_tool(Path(folder), str(pub), "--type", "ssh-ed25519")
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertRegex(
                done.stdout, r"^pubkey=ok type=ssh-ed25519 fingerprint=SHA256:[A-Za-z0-9+/]{43}\n$"
            )
            pub.write_text(f"{OTHER[:-9]}\n", encoding="utf-8")
            refused = self.run_tool(Path(folder), str(pub), "--type", "ssh-ed25519")
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(refused.stdout, "pubkey=REFUSED reason=bad_shape\n")

    def test_no_output_carries_a_private_key_or_an_argument(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder) / "id"
            private.write_text(PRIVATE_BLOCK, encoding="utf-8")
            done = self.run_tool(Path(folder), str(private), "--type", "ssh-ed25519")
            self.assertEqual(done.returncode, 1)
            self.assertEqual(done.stdout, "pubkey=REFUSED reason=private_key\n")
            self.assertEqual(done.stderr, "")
            stray = self.run_tool(Path(folder), str(private), "--unknown", PRIVATE_SENTINEL)
            self.assertEqual(stray.returncode, 2)
            self.assertNotIn(PRIVATE_SENTINEL, stray.stdout + stray.stderr)

    def test_in_process_main_prints_nothing_but_the_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder) / "id"
            private.write_text(PRIVATE_BLOCK, encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = tool.main(["check", str(private)])
            self.assertEqual(code, 1)
            self.assertNotIn(PRIVATE_SENTINEL, out.getvalue() + err.getvalue())
            self.assertTrue(re.fullmatch(r"pubkey=REFUSED reason=[a-z_]+\n", out.getvalue()))


if __name__ == "__main__":
    unittest.main()
