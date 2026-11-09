"""Unit tests for monitoring_stack_envfile_digest: the digest, the refusals, the read-only promise.

Run from the role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. Every secret here is a throwaway made for the test.
"""

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import monitoring_stack_envfile_digest as digest_module
from ansible.module_utils.testing import patch_module_args

MARKER = "THROWAWAY_DIGEST_MARKER_0001"
KEY = "SNDS_DATA_URL"
BODY = (
    "SMTP_USERNAME=throwaway-user\n"
    f"SMTP_PASSWORD={MARKER}\n"
    f"{KEY}=https://example.invalid/throwaway?token={MARKER}\n"
    "GRAFANA_ADMIN_PASSWORD=throwaway-grafana\n"
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_main(
    path: str, skip_key: str, check_mode: bool = False
) -> tuple[bool, dict[str, object], str]:
    """Run main as Ansible would; return (failed, the JSON it printed, the raw text)."""
    args = {"path": path, "skip_key": skip_key, "_ansible_check_mode": check_mode}
    buffer = io.StringIO()
    with patch_module_args(args), contextlib.redirect_stdout(buffer):
        try:
            digest_module.main()
        except SystemExit:
            pass
    raw = buffer.getvalue()
    document = json.loads(raw)
    return bool(document.get("failed")), document, raw


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_bytes(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path


class DigestTest(Workdir):
    def test_the_digest_is_of_the_lines_that_are_left(self) -> None:
        path = self.write_bytes("monitoring.env", BODY.encode())
        expected = "".join(
            line for line in BODY.splitlines(keepends=True) if not line.startswith(f"{KEY}=")
        )
        self.assertEqual(sha(expected.encode()), digest_module.digest_without_key(str(path), KEY))

    def test_a_file_without_the_key_is_hashed_whole(self) -> None:
        data = b"A=1\nB=2\n"
        path = self.write_bytes("plain.env", data)
        self.assertEqual(sha(data), digest_module.digest_without_key(str(path), KEY))

    def test_a_final_line_without_a_line_break_is_kept_as_it_is(self) -> None:
        path = self.write_bytes("tail.env", b"A=1\nB=2")
        self.assertEqual(sha(b"A=1\nB=2"), digest_module.digest_without_key(str(path), KEY))

    def test_a_final_line_that_is_the_key_leaves_the_rest_intact(self) -> None:
        path = self.write_bytes("last.env", f"A=1\n{KEY}=x".encode())
        self.assertEqual(sha(b"A=1\n"), digest_module.digest_without_key(str(path), KEY))

    def test_only_a_line_that_starts_with_the_key_and_an_equals_sign_is_left_out(self) -> None:
        near = [
            f"{KEY}_OLD=kept\n",
            f"  {KEY}=kept\n",
            f"X{KEY}=kept\n",
            f"{KEY.lower()}=kept\n",
            f"{KEY}\n",
        ]
        data = "".join(near).encode()
        path = self.write_bytes("near.env", data)
        self.assertEqual(sha(data), digest_module.digest_without_key(str(path), KEY))

    def test_a_second_occurrence_of_the_key_is_left_out_too(self) -> None:
        path = self.write_bytes("twice.env", f"{KEY}=1\nA=2\n{KEY}=3\n".encode())
        self.assertEqual(sha(b"A=2\n"), digest_module.digest_without_key(str(path), KEY))

    def test_bytes_that_are_not_text_are_hashed_as_they_are(self) -> None:
        data = b"A=\xff\xfe\n" + f"{KEY}=x\n".encode() + b"\x00B=\r\n"
        path = self.write_bytes("bytes.env", data)
        self.assertEqual(
            sha(b"A=\xff\xfe\n\x00B=\r\n"), digest_module.digest_without_key(str(path), KEY)
        )

    def test_an_empty_file_has_the_digest_of_nothing(self) -> None:
        path = self.write_bytes("empty.env", b"")
        self.assertEqual(sha(b""), digest_module.digest_without_key(str(path), KEY))

    def test_a_value_change_outside_the_key_changes_the_digest(self) -> None:
        path = self.write_bytes("change.env", BODY.encode())
        before = digest_module.digest_without_key(str(path), KEY)
        path.write_bytes(BODY.replace("throwaway-grafana", "throwaway-other").encode())
        self.assertNotEqual(before, digest_module.digest_without_key(str(path), KEY))

    def test_a_value_change_on_the_key_does_not_change_the_digest(self) -> None:
        path = self.write_bytes("rotate.env", BODY.encode())
        before = digest_module.digest_without_key(str(path), KEY)
        rotated = BODY.replace(
            f"{KEY}=https://example.invalid/throwaway?token={MARKER}",
            f"{KEY}=https://example.invalid/rotated",
        )
        self.assertNotEqual(BODY, rotated)
        path.write_bytes(rotated.encode())
        self.assertEqual(before, digest_module.digest_without_key(str(path), KEY))


class RefusalTest(Workdir):
    def test_a_key_that_is_not_a_plain_name_is_refused(self) -> None:
        path = self.write_bytes("key.env", b"A=1\n")
        for key in ("", "snds_data_url", "1SNDS", "SNDS DATA", "SNDS=", "SNDS\n", "SNDS-URL"):
            with self.subTest(key=key), self.assertRaises(digest_module.DigestError):
                digest_module.digest_without_key(str(path), key)

    def test_a_missing_file_is_refused_and_the_message_names_only_the_path(self) -> None:
        missing = self.root / "missing.env"
        with self.assertRaises(digest_module.DigestError) as caught:
            digest_module.digest_without_key(str(missing), KEY)
        self.assertIn(str(missing), str(caught.exception))

    def test_a_directory_is_refused(self) -> None:
        with self.assertRaises(digest_module.DigestError):
            digest_module.digest_without_key(str(self.root), KEY)

    def test_a_refusal_holds_no_line_of_the_file(self) -> None:
        path = self.write_bytes("secret.env", f"{MARKER}\n".encode())
        path.chmod(0o000)
        self.addCleanup(path.chmod, 0o600)
        if os.geteuid() == 0:
            self.skipTest("root reads a file whatever its mode, so the refusal cannot be shown")
        failed, document, raw = run_main(str(path), KEY)
        self.assertTrue(failed)
        self.assertNotIn(MARKER, raw)


class ModuleTest(Workdir):
    def test_the_module_returns_the_digest_and_no_change(self) -> None:
        path = self.write_bytes("monitoring.env", BODY.encode())
        failed, document, raw = run_main(str(path), KEY)
        self.assertFalse(failed)
        self.assertFalse(document["changed"])
        self.assertEqual(digest_module.digest_without_key(str(path), KEY), document["digest"])

    def test_the_output_holds_no_value_and_no_line(self) -> None:
        path = self.write_bytes("monitoring.env", BODY.encode())
        _failed, document, raw = run_main(str(path), KEY)
        self.assertNotIn(MARKER, raw)
        self.assertEqual({"changed", "digest"}, set(document))

    def test_a_second_run_gives_the_same_digest_and_no_change(self) -> None:
        path = self.write_bytes("monitoring.env", BODY.encode())
        _f1, first, _r1 = run_main(str(path), KEY)
        _f2, second, _r2 = run_main(str(path), KEY)
        self.assertEqual(first["digest"], second["digest"])
        self.assertFalse(second["changed"])

    def test_check_mode_gives_the_same_digest_and_leaves_the_file_as_it_was(self) -> None:
        data = BODY.encode()
        path = self.write_bytes("monitoring.env", data)
        mode = path.stat().st_mode
        _f, apply_run, _r = run_main(str(path), KEY)
        _f, check_run, _r = run_main(str(path), KEY, check_mode=True)
        self.assertEqual(apply_run["digest"], check_run["digest"])
        self.assertFalse(check_run["changed"])
        self.assertEqual(data, path.read_bytes())
        self.assertEqual(mode, path.stat().st_mode)

    def test_a_missing_file_fails_in_both_modes(self) -> None:
        missing = str(self.root / "absent.env")
        for check_mode in (False, True):
            with self.subTest(check_mode=check_mode):
                failed, document, raw = run_main(missing, KEY, check_mode=check_mode)
                self.assertTrue(failed)
                self.assertNotIn("digest", document)
                self.assertNotIn(MARKER, raw)

    def test_a_bad_key_fails_with_the_named_message(self) -> None:
        path = self.write_bytes("monitoring.env", BODY.encode())
        failed, document, raw = run_main(str(path), "snds")
        self.assertTrue(failed)
        self.assertIn("skip_key must be", str(document["msg"]))
        self.assertNotIn(MARKER, raw)


if __name__ == "__main__":
    unittest.main()
