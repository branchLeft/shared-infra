#!/usr/bin/env python3
"""Unit tests for nat-gateway.sh, the NAT reconciler install.

The script's destinations are absolute paths with no override, so these tests
cover what a clean host shows: the first-run branch, the order of the system
calls, and the failure exits. `install` and `systemctl` are logging stubs on
PATH and nothing is written. The no-op and rewrite branches need the real
destinations to exist, which only a host can show, so they are not tested here.
"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.abspath(os.path.dirname(__file__))
SCRIPT = os.path.join(HERE, "nat-gateway.sh")

RECONCILER = "/usr/local/sbin/branchleft-nat"
UNIT = "/etc/systemd/system/branchleft-nat.service"
UNIT_NAME = "branchleft-nat.service"

# Each stub appends its argv to the call log. FAKE_INSTALL_EXIT and
# FAKE_STATUS_EXIT choose a failure for the install and the status check.
INSTALL_STUB = """#!/usr/bin/env bash
echo "install $*" >> "$FAKE_CALL_LOG"
exit "${FAKE_INSTALL_EXIT:-0}"
"""

SYSTEMCTL_STUB = """#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_CALL_LOG"
case " $* " in
    *" status "*) exit "${FAKE_STATUS_EXIT:-0}" ;;
esac
exit 0
"""


def _stub(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


@unittest.skipIf(
    os.path.exists(RECONCILER) or os.path.exists(UNIT),
    "a real NAT reconciler or unit already exists on this host; the first-run branch needs them absent",
)
class NatGatewayTests(unittest.TestCase):
    script = SCRIPT

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.bin = os.path.join(root, "bin")
        os.mkdir(self.bin)
        self.call_log = os.path.join(root, "calls.log")
        open(self.call_log, "w", encoding="utf-8").close()
        _stub(os.path.join(self.bin, "install"), INSTALL_STUB)
        _stub(os.path.join(self.bin, "systemctl"), SYSTEMCTL_STUB)
        self.src = os.path.dirname(self.script)

    def run_script(self, install_exit=0, status_exit=0):
        env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CALL_LOG": self.call_log,
            "FAKE_INSTALL_EXIT": str(install_exit),
            "FAKE_STATUS_EXIT": str(status_exit),
            "HOME": self.tmp.name,
        }
        result = subprocess.run(
            ["bash", self.script],
            check=False,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        with open(self.call_log, encoding="utf-8") as fh:
            calls = fh.read().splitlines()
        return result, calls

    def expected_success_calls(self):
        return [
            f"install -m 0755 -o root -g root {self.src}/branchleft_nat.sh {RECONCILER}",
            f"install -m 0644 -o root -g root {self.src}/{UNIT_NAME} {UNIT}",
            "systemctl daemon-reload",
            f"systemctl enable {UNIT_NAME}",
            f"systemctl restart {UNIT_NAME}",
            f"systemctl --no-pager --lines=0 status {UNIT_NAME}",
        ]

    def test_success_installs_both_files_enables_restarts_and_checks(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, self.expected_success_calls())
        self.assertIn("nat-gateway: done", result.stdout)

    def test_reconciler_is_installed_root_owned_with_mode_0755(self):
        # systemd runs the reconciler as root at every boot, so owner and mode are the control.
        result, calls = self.run_script()
        self.assertIn(
            f"install -m 0755 -o root -g root {self.src}/branchleft_nat.sh {RECONCILER}",
            calls,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unit_is_installed_root_owned_with_mode_0644(self):
        result, calls = self.run_script()
        self.assertIn(
            f"install -m 0644 -o root -g root {self.src}/{UNIT_NAME} {UNIT}",
            calls,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unit_is_restarted_not_started(self):
        # The unit is a RemainAfterExit oneshot, so `start` would be a no-op after a first success.
        result, calls = self.run_script()
        self.assertIn(f"systemctl restart {UNIT_NAME}", calls)
        self.assertNotIn(f"systemctl start {UNIT_NAME}", calls)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_failed_install_stops_the_run_before_any_systemctl_call(self):
        result, calls = self.run_script(install_exit=1)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            calls,
            [
                f"install -m 0755 -o root -g root {self.src}/branchleft_nat.sh {RECONCILER}"
            ],
        )
        self.assertNotIn("nat-gateway: done", result.stdout)

    def test_a_failed_status_check_fails_the_run(self):
        result, calls = self.run_script(status_exit=3)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"systemctl restart {UNIT_NAME}", calls)
        self.assertNotIn("nat-gateway: done", result.stdout)


if __name__ == "__main__":
    unittest.main()
