#!/usr/bin/env python3
"""Unit tests for run-all.sh: the order of the base sequence and stop-on-failure.

run-all.sh finds its children through its own directory, so each test copies it
into a temp directory beside logging fakes for the scripts it calls. Nothing
here touches a host: the real child scripts never run, and no command is read
from PATH beyond what bash itself needs.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "run-all.sh")

BASE_SEQUENCE = [
    "00-harden-ssh.sh",
    "05-configure-host-egress.sh",
    "10-harden-updates-fail2ban.sh",
    "20-install-docker.sh",
    "30-install-deploy-tooling.sh",
]
NAT_GATEWAY = "nat-gateway.sh"

FAKE_CHILD = """#!/usr/bin/env bash
name="$(basename "$0")"
echo "$name" >> "$FAKE_CALL_LOG"
if [[ "$name" == "${FAIL_AT:-}" ]]; then
    exit "${FAIL_CODE:-1}"
fi
exit 0
"""


class RunAllTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "provision")
        os.mkdir(self.dir)
        self.call_log = os.path.join(self.tmp.name, "calls.log")
        open(self.call_log, "w").close()

        shutil.copy(SCRIPT, os.path.join(self.dir, "run-all.sh"))
        for name in BASE_SEQUENCE + [NAT_GATEWAY]:
            path = os.path.join(self.dir, name)
            with open(path, "w") as fh:
                fh.write(FAKE_CHILD)
            os.chmod(path, 0o755)

    def run_script(self, fail_at=None, fail_code=None):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "FAKE_CALL_LOG": self.call_log,
            "HOME": self.tmp.name,
        }
        if fail_at is not None:
            env["FAIL_AT"] = fail_at
        if fail_code is not None:
            env["FAIL_CODE"] = str(fail_code)
        result = subprocess.run(
            ["bash", os.path.join(self.dir, "run-all.sh")],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        with open(self.call_log) as fh:
            calls = [line.strip() for line in fh if line.strip()]
        return result, calls

    def remove_child(self, name):
        os.remove(os.path.join(self.dir, name))

    def test_runs_the_base_scripts_in_the_listed_order(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, BASE_SEQUENCE)
        self.assertIn("=== base provisioning complete ===", result.stdout)

    def test_the_egress_script_runs_before_the_first_apt_script(self):
        _, calls = self.run_script()
        self.assertLess(
            calls.index("05-configure-host-egress.sh"),
            calls.index("10-harden-updates-fail2ban.sh"),
            "egress must run before the first apt-using script, which a private-only host needs",
        )

    def test_leaves_nat_gateway_out_and_says_so(self):
        result, calls = self.run_script()
        self.assertNotIn(NAT_GATEWAY, calls, "nat-gateway.sh is role-specific and must not run here")
        self.assertIn("nat-gateway.sh has to be run as well", result.stdout)

    def test_a_failing_script_stops_the_run_and_runs_nothing_after_it(self):
        result, calls = self.run_script(fail_at="05-configure-host-egress.sh")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, BASE_SEQUENCE[:2], "no script after the failing one may run")
        self.assertNotIn("base provisioning complete", result.stdout)

    def test_a_failure_in_the_first_script_runs_nothing_else(self):
        result, calls = self.run_script(fail_at="00-harden-ssh.sh")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["00-harden-ssh.sh"])

    def test_a_failure_in_the_last_script_still_fails_the_run(self):
        result, calls = self.run_script(fail_at="30-install-deploy-tooling.sh")
        self.assertEqual(calls, BASE_SEQUENCE, "every script before the last one must have run")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("base provisioning complete", result.stdout)

    def test_the_failing_scripts_exit_code_is_the_run_exit_code(self):
        result, _ = self.run_script(fail_at="10-harden-updates-fail2ban.sh", fail_code=7)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)

    def test_a_missing_script_stops_the_run(self):
        self.remove_child("10-harden-updates-fail2ban.sh")
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, BASE_SEQUENCE[:2], "a missing script must stop the run before anything after it")
        self.assertNotIn("base provisioning complete", result.stdout)


if __name__ == "__main__":
    unittest.main()
