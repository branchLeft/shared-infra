#!/usr/bin/env python3
"""Unit tests for rotate_admin_credential.py. main()'s orchestration is
exercised against a fake JMAP layer (FakeStalwart, standing in for
_can_authenticate/_jmap_call) so no network call or live server is needed.
Deliberately not covered: the raw HTTP mechanics in _request itself -- a
thin, non-branching wrapper around urllib -- same line
test_provision_mailboxes.py's ReconcileAccountsOrderingTests draws for the
identical wrapper shape.
Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""
from __future__ import annotations

import contextlib
import io
import os
import stat
import tempfile
import unittest
from unittest import mock

import rotate_admin_credential as rac

USERNAME = "admin"
OLD_SECRET = "distinctive-old-secret-do-not-print"
NEW_SECRET = "distinctive-new-secret-do-not-print"


class FakeStalwart:
    """Stands in for _can_authenticate/_jmap_call together: tracks whichever
    secret currently authenticates and, unless told not to, applies the
    x:AccountPassword/set update the moment it arrives -- mirroring what a
    real server does. `confirm` controls whether the JMAP call reports the
    update as applied; `apply` controls whether it actually takes effect,
    letting tests separate "server says yes" from "server means it".
    """

    def __init__(self, username, secret, confirm=True, apply=True):
        self.username = username
        self.secret = secret
        self.confirm = confirm
        self.apply = apply
        self.jmap_calls = []

    def can_authenticate(self, auth):
        return auth == (self.username, self.secret)

    def jmap_call(self, auth, method, args):
        self.jmap_calls.append((auth, method, args))
        if not self.confirm:
            return {"notUpdated": {"singleton": "simulated: server rejected the update"}}
        if self.apply:
            self.secret = args["update"]["singleton"]["secret"]
        return {"updated": {"singleton": None}}


def _write_creds_file(path, username, secret, mode=0o600):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{username}:{secret}\n")
    os.chmod(path, mode)


def _read_creds_file(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _assert_no_secret_leaked(*texts):
    combined = "\n".join(str(t) for t in texts)
    if OLD_SECRET in combined or NEW_SECRET in combined:
        raise AssertionError(f"a secret leaked into captured output: {combined!r}")


@contextlib.contextmanager
def _patched_rotation(fake, creds_path, mint=NEW_SECRET):
    """Patches the three seams main() touches: the credentials path, the
    JMAP layer (via `fake`), and the minted secret. Covers the majority of
    tests below; the few that need a bare Mock (to assert a call never
    happened) or a raising token_urlsafe patch their own seams instead.
    """
    with mock.patch.multiple(rac, CREDENTIALS_PATH=creds_path), \
         mock.patch.object(rac, "_can_authenticate", side_effect=fake.can_authenticate), \
         mock.patch.object(rac, "_jmap_call", side_effect=fake.jmap_call), \
         mock.patch.object(rac.secrets, "token_urlsafe", return_value=mint):
        yield


class RotationHappyPathTests(unittest.TestCase):
    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)

    def test_returns_zero_and_credentials_file_carries_the_new_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET)
            fake = FakeStalwart(USERNAME, OLD_SECRET)
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 0)
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{NEW_SECRET}\n")

    def test_old_secret_no_longer_appears_anywhere_in_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET)
            fake = FakeStalwart(USERNAME, OLD_SECRET)
            with _patched_rotation(fake, creds_path):
                rac.main()

            self.assertNotIn(OLD_SECRET, _read_creds_file(creds_path))


class FileWriteSafetyTests(unittest.TestCase):
    """The 0600 mode is the control this script exists to protect; these
    tests pin the end state and the write mechanics that produce it.
    """

    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        self.stderr = stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)

    def test_credentials_file_ends_at_mode_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o600)
            fake = FakeStalwart(USERNAME, OLD_SECRET)
            with _patched_rotation(fake, creds_path):
                rac.main()

            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)

    def test_credentials_file_ends_at_0600_even_if_it_started_more_permissive(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o644)
            fake = FakeStalwart(USERNAME, OLD_SECRET)
            with _patched_rotation(fake, creds_path):
                rac.main()

            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)

    def test_new_secret_never_observed_at_the_pre_rotation_mode(self):
        # The write-then-chmod window is closed: the file that lands at
        # CREDENTIALS_PATH is renamed into place already at 0600, via
        # os.replace, so there is no gap where the new secret sits at
        # whatever (possibly looser) mode the file carried before.
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o644)
            fake = FakeStalwart(USERNAME, OLD_SECRET)

            observed_source_modes = []
            real_replace = os.replace

            def spying_replace(src, dst, *args, **kwargs):
                observed_source_modes.append(stat.S_IMODE(os.stat(src).st_mode))
                real_replace(src, dst, *args, **kwargs)

            with _patched_rotation(fake, creds_path), \
                 mock.patch("os.replace", side_effect=spying_replace):
                result = rac.main()

            self.assertEqual(result, 0)
            # whatever was renamed onto creds_path already carried 0600 --
            # the real path's mode never regresses to the pre-rotation one
            self.assertEqual(observed_source_modes, [0o600])
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)

    def test_a_write_failure_leaves_the_old_credential_completely_untouched(self):
        # Closes the non-atomic-truncate gap: a failure while building the
        # replacement (here, at fsync) must never touch CREDENTIALS_PATH
        # at all, so the old credential survives intact rather than being
        # destroyed by an in-place truncate.
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o600)
            fake = FakeStalwart(USERNAME, OLD_SECRET)

            with _patched_rotation(fake, creds_path), \
                 mock.patch("os.fsync", side_effect=OSError("simulated: disk full mid-write")):
                with self.assertRaises(OSError) as ctx:
                    rac.main()

            # the old credential is completely intact, at its original mode
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)
            # no leftover temp file from the failed write
            self.assertEqual(os.listdir(tmp), ["creds"])
            _assert_no_secret_leaked(str(ctx.exception), self.stdout.getvalue(), self.stderr.getvalue())


class WriteCredentialAtomicTests(unittest.TestCase):
    """Direct tests of the write primitive itself, mirroring
    render_shim_env.py's WriteEnvFileAtomicTests for its sibling
    write_env_file_atomic.
    """

    def test_writes_the_given_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(_read_creds_file(path), f"{USERNAME}:{NEW_SECRET}\n")

    def test_file_mode_is_0600_when_no_file_existed_before(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_overwrites_a_more_permissive_existing_file_completely(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            _write_creds_file(path, USERNAME, OLD_SECRET, mode=0o644)
            rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(_read_creds_file(path), f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_temp_file_is_already_0600_before_it_is_ever_renamed_into_place(self):
        # Proves there is no mode window at all: whatever gets renamed
        # onto `path` is already 0600 the moment it exists on disk, not
        # chmod'd into place after the fact.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            _write_creds_file(path, USERNAME, OLD_SECRET, mode=0o644)
            observed_source_modes = []
            real_replace = os.replace

            def spying_replace(src, dst, *args, **kwargs):
                observed_source_modes.append(stat.S_IMODE(os.stat(src).st_mode))
                real_replace(src, dst, *args, **kwargs)

            with mock.patch("os.replace", side_effect=spying_replace):
                rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")

            self.assertEqual(observed_source_modes, [0o600])

    def test_no_leftover_temp_file_after_a_successful_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(os.listdir(tmp), ["creds"])

    def test_a_failure_during_write_leaves_no_temp_file_and_the_target_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            _write_creds_file(path, USERNAME, OLD_SECRET, mode=0o600)
            with mock.patch("os.fsync", side_effect=OSError("simulated: disk full")):
                with self.assertRaises(OSError):
                    rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(os.listdir(tmp), ["creds"])
            self.assertEqual(_read_creds_file(path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_a_failure_in_replace_leaves_the_target_completely_untouched(self):
        # Simulated failure at the final atomic step -- the target must
        # never observe a partial or intermediate state.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "creds")
            _write_creds_file(path, USERNAME, OLD_SECRET, mode=0o600)
            with mock.patch("os.replace", side_effect=OSError("simulated: cross-device or disk full")):
                with self.assertRaises(OSError):
                    rac._write_credential_atomic(path, f"{USERNAME}:{NEW_SECRET}\n")
            self.assertEqual(_read_creds_file(path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            # the failed temp file was cleaned up -- only the real file remains
            self.assertEqual(os.listdir(tmp), ["creds"])


class TokenNeverLeaksTests(unittest.TestCase):
    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        self.stderr = stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)

    def _assert_neither_secret_printed(self):
        _assert_no_secret_leaked(self.stdout.getvalue(), self.stderr.getvalue())

    def test_secret_never_printed_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET)
            fake = FakeStalwart(USERNAME, OLD_SECRET)
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 0)
            self.assertIn("ROTATED", self.stdout.getvalue())
            self._assert_neither_secret_printed()

    def test_secret_never_printed_when_the_current_credential_is_already_dead(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET)
            # fake's real secret differs from what's in the file
            fake = FakeStalwart(USERNAME, "some-other-secret-entirely")
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 1)
            self.assertIn("FAILED", self.stdout.getvalue())
            self._assert_neither_secret_printed()

    def test_secret_never_printed_when_the_jmap_update_is_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET)
            fake = FakeStalwart(USERNAME, OLD_SECRET, confirm=False)
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 1)
            self.assertIn("FAILED", self.stdout.getvalue())
            self._assert_neither_secret_printed()

    def test_secret_never_printed_when_verification_disagrees_with_a_reported_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET)
            # server reports the update as applied but doesn't actually apply it
            fake = FakeStalwart(USERNAME, OLD_SECRET, apply=False)
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 1)
            self.assertIn("FAILED", self.stdout.getvalue())
            self._assert_neither_secret_printed()


class FailurePathsLeaveTheFileUntouchedTests(unittest.TestCase):
    def setUp(self):
        stdout_patcher = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout_patcher.start()
        self.addCleanup(stdout_patcher.stop)
        stderr_patcher = mock.patch("sys.stderr", new_callable=io.StringIO)
        self.stderr = stderr_patcher.start()
        self.addCleanup(stderr_patcher.stop)

    def test_dead_current_credential_returns_1_and_leaves_the_file_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o600)
            fake = FakeStalwart(USERNAME, "some-other-secret-entirely")
            with mock.patch.multiple(rac, CREDENTIALS_PATH=creds_path), \
                 mock.patch.object(rac, "_can_authenticate", side_effect=fake.can_authenticate), \
                 mock.patch.object(rac, "_jmap_call") as jmap_mock:
                result = rac.main()

            jmap_mock.assert_not_called()
            self.assertEqual(result, 1)
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)

    def test_unconfirmed_jmap_update_returns_1_and_leaves_the_file_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o600)
            fake = FakeStalwart(USERNAME, OLD_SECRET, confirm=False)
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 1)
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)

    def test_post_rotation_verification_mismatch_returns_1_and_leaves_the_file_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o600)
            fake = FakeStalwart(USERNAME, OLD_SECRET, apply=False)
            with _patched_rotation(fake, creds_path):
                result = rac.main()

            self.assertEqual(result, 1)
            # the file is untouched precisely because the write happens
            # after verification, not before
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)

    def test_missing_credentials_file_raises_without_writing_anything(self):
        # Also stands in for a missing parent directory -- open() raises the
        # same FileNotFoundError either way, on the same line, before any
        # network call or mint.
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "does-not-exist")
            with mock.patch.multiple(rac, CREDENTIALS_PATH=creds_path), \
                 mock.patch.object(rac, "_can_authenticate") as auth_mock, \
                 mock.patch.object(rac, "_jmap_call") as jmap_mock:
                with self.assertRaises(FileNotFoundError) as ctx:
                    rac.main()

            auth_mock.assert_not_called()
            jmap_mock.assert_not_called()
            self.assertFalse(os.path.exists(creds_path))
            _assert_no_secret_leaked(str(ctx.exception), self.stdout.getvalue(), self.stderr.getvalue())

    def test_minting_failure_raises_before_any_jmap_call_and_leaves_the_file_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            creds_path = os.path.join(tmp, "creds")
            _write_creds_file(creds_path, USERNAME, OLD_SECRET, mode=0o600)
            fake = FakeStalwart(USERNAME, OLD_SECRET)
            with mock.patch.multiple(rac, CREDENTIALS_PATH=creds_path), \
                 mock.patch.object(rac, "_can_authenticate", side_effect=fake.can_authenticate), \
                 mock.patch.object(rac, "_jmap_call") as jmap_mock, \
                 mock.patch.object(rac.secrets, "token_urlsafe", side_effect=OSError("simulated: urandom unavailable")):
                with self.assertRaises(OSError) as ctx:
                    rac.main()

            jmap_mock.assert_not_called()
            self.assertEqual(_read_creds_file(creds_path), f"{USERNAME}:{OLD_SECRET}\n")
            self.assertEqual(stat.S_IMODE(os.stat(creds_path).st_mode), 0o600)
            _assert_no_secret_leaked(str(ctx.exception), self.stdout.getvalue(), self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
