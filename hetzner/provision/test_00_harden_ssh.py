#!/usr/bin/env python3
"""Unit tests for 00-harden-ssh.sh.

This is the check that decides whether a freshly created host is considered
hardened, and a false failure here aborts `run-all.sh` before the three
scripts that install unattended upgrades, fail2ban, Docker and the deploy
tooling ever run -- so its pass/fail behaviour is covered directly rather
than only smoke-tested by a real provisioning run.

The script itself talks to the live `sshd` and `systemctl` and writes into
`/etc/ssh/sshd_config.d/`, none of which a test process may do. Both are
substituted: `sshd` and `systemctl` are replaced by fakes earlier on `PATH`,
and the drop-in path is redirected with the `DROPIN` environment variable
the script reads as an override.
"""

import os
import stat
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "00-harden-ssh.sh")

FAKE_SSHD = """#!/usr/bin/env bash
case "$1" in
    -T)
        printf '%s\\n' "$FAKE_SSHD_T_OUTPUT"
        ;;
    -t)
        exit "${FAKE_SSHD_T_EXIT:-0}"
        ;;
    *)
        exit 0
        ;;
esac
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
exit 0
"""


def effective_config(permitrootlogin="prohibit-password"):
    """The sshd -T lines this script inspects, for a host where only our
    drop-in has taken effect."""
    return "\n".join(
        [
            "passwordauthentication no",
            "kbdinteractiveauthentication no",
            f"permitrootlogin {permitrootlogin}",
            "pubkeyauthentication yes",
        ]
    )


class HardenSshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "sshd"), FAKE_SSHD)
        self._write_fake(os.path.join(bin_dir, "systemctl"), FAKE_SYSTEMCTL)
        self.bin_dir = bin_dir

        dropin_dir = os.path.join(self.tmp.name, "sshd_config.d")
        os.makedirs(dropin_dir)
        self.dropin = os.path.join(dropin_dir, "01-branchleft-hardening.conf")

    @staticmethod
    def _write_fake(path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_script(self, sshd_t_output, dropin=None, sshd_t_exit="0"):
        env = dict(os.environ)
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        env["DROPIN"] = dropin if dropin is not None else self.dropin
        env["FAKE_SSHD_T_OUTPUT"] = sshd_t_output
        env["FAKE_SSHD_T_EXIT"] = sshd_t_exit
        return subprocess.run(
            ["bash", SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_effective_without_password_passes(self):
        result = self.run_script(effective_config("without-password"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sshd reloaded, effective config verified", result.stdout)
        self.assertNotIn("outranks", result.stderr)

    def test_effective_prohibit_password_passes(self):
        result = self.run_script(effective_config("prohibit-password"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sshd reloaded, effective config verified", result.stdout)
        self.assertNotIn("outranks", result.stderr)

    def test_genuinely_different_value_fails_and_reports_competing_dropin(self):
        result = self.run_script(effective_config("yes"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "effective permitrootlogin is 'yes', expected 'prohibit-password'",
            result.stderr,
        )
        self.assertIn("outranks", result.stderr)

    def test_non_aliased_keyword_mismatch_still_fails(self):
        # A change in a spelling-immune keyword must still be caught -- the
        # alias tolerance is scoped to permitrootlogin only.
        config = effective_config().replace(
            "passwordauthentication no", "passwordauthentication yes"
        )
        result = self.run_script(config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "effective passwordauthentication is 'yes', expected 'no'",
            result.stderr,
        )
        self.assertIn("outranks", result.stderr)

    def test_our_dropin_cannot_be_written_aborts_before_verifying_anything(self):
        # DROPIN points into a directory that does not exist, so `install`
        # fails. The drop-in write is the assertion that our configuration
        # is actually present -- a failure there must abort loudly rather
        # than fall through to comparing sshd -T output regardless.
        missing_parent = os.path.join(self.tmp.name, "does-not-exist", "dropin.conf")
        result = self.run_script(
            effective_config("without-password"), dropin=missing_parent
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("sshd reloaded, effective config verified", result.stdout)

    def test_sshd_config_error_aborts_before_reload(self):
        result = self.run_script(
            effective_config("without-password"), sshd_t_exit="1"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sshd -t reported a config error", result.stderr)
        self.assertNotIn("sshd reloaded, effective config verified", result.stdout)


if __name__ == "__main__":
    unittest.main()
