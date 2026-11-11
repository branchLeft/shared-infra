"""Unit tests for 05-configure-host-egress.sh.

The script writes three files under fixed absolute paths (/usr/local/sbin and
/etc/systemd/system) with no environment seam, so these tests cover only the
fresh-host path: those destinations are absent, so every install runs. The
no-op and rewrite branches need a destination that already exists, which this
file cannot create without writing outside a temp dir; they are not covered.

install, systemctl and cmp are logging stubs on PATH. Nothing touches the host.
"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
SCRIPT = os.path.join(HERE, "05-configure-host-egress.sh")
SCRIPT_DIR = HERE

RECONCILER = "/usr/local/sbin/branchleft-host-egress"
UNIT = "/etc/systemd/system/branchleft-host-egress.service"
TIMER = "/etc/systemd/system/branchleft-host-egress.timer"

LOGGING_STUB = """#!/usr/bin/env bash
echo "$(basename "$0") $*" >> "$FAKE_CALL_LOG"
exit 0
"""

FAILING_INSTALL_STUB = """#!/usr/bin/env bash
echo "install $*" >> "$FAKE_CALL_LOG"
for arg in "$@"; do
    if [[ "$arg" == "$FAKE_FAIL_DST" ]]; then
        exit 1
    fi
done
exit 0
"""


def _stub(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


def _destinations_absent():
    return not any(os.path.exists(p) for p in (RECONCILER, UNIT, TIMER))


@unittest.skipUnless(
    _destinations_absent(),
    "a destination file already exists on this host; the fresh-host tests would take the no-op branch",
)
class EgressProvisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.bin = os.path.join(root, "bin")
        os.mkdir(self.bin)
        self.call_log = os.path.join(root, "calls.log")
        open(self.call_log, "w").close()
        _stub(os.path.join(self.bin, "install"), LOGGING_STUB)
        _stub(os.path.join(self.bin, "systemctl"), LOGGING_STUB)
        _stub(os.path.join(self.bin, "cmp"), LOGGING_STUB)

    def run_script(self, script=SCRIPT, fail_dst=None, install_body=None):
        if install_body is not None:
            _stub(os.path.join(self.bin, "install"), install_body)
        env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CALL_LOG": self.call_log,
            "FAKE_FAIL_DST": fail_dst or "",
            "HOME": self.tmp.name,
        }
        result = subprocess.run(
            ["bash", script],
            check=False,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        with open(self.call_log) as fh:
            calls = [line.rstrip("\n") for line in fh if line.strip()]
        return result, calls

    def test_reconciler_is_installed_root_owned_and_mode_0755(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"install -m 0755 -o root -g root {SCRIPT_DIR}/branchleft_host_egress.sh {RECONCILER}",
            calls,
        )

    def test_unit_and_timer_are_installed_root_owned_and_mode_0644(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"install -m 0644 -o root -g root {SCRIPT_DIR}/branchleft-host-egress.service {UNIT}",
            calls,
        )
        self.assertIn(
            f"install -m 0644 -o root -g root {SCRIPT_DIR}/branchleft-host-egress.timer {TIMER}",
            calls,
        )

    def test_cmp_is_not_consulted_when_no_destination_exists(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(
            [c for c in calls if c.startswith("cmp ")],
            "cmp must be reached only behind an existing destination",
        )

    def test_daemon_reload_follows_each_unit_file_written(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        unit_write = next(
            i
            for i, c in enumerate(calls)
            if c.startswith("install") and c.endswith(UNIT)
        )
        timer_write = next(
            i
            for i, c in enumerate(calls)
            if c.startswith("install") and c.endswith(TIMER)
        )
        reloads = [i for i, c in enumerate(calls) if c == "systemctl daemon-reload"]
        self.assertEqual(len(reloads), 2, calls)
        self.assertLess(unit_write, reloads[0], calls)
        self.assertLess(reloads[0], timer_write, calls)
        self.assertLess(timer_write, reloads[1], calls)

    def test_units_are_restarted_not_started(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("systemctl restart branchleft-host-egress.service", calls)
        self.assertIn("systemctl restart branchleft-host-egress.timer", calls)
        self.assertNotIn("systemctl start branchleft-host-egress.service", calls)
        self.assertNotIn("systemctl start branchleft-host-egress.timer", calls)

    def test_units_are_enabled_before_they_are_restarted(self):
        result, calls = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        enable_service = calls.index("systemctl enable branchleft-host-egress.service")
        enable_timer = calls.index("systemctl enable branchleft-host-egress.timer")
        restart_service = calls.index(
            "systemctl restart branchleft-host-egress.service"
        )
        restart_timer = calls.index("systemctl restart branchleft-host-egress.timer")
        self.assertLess(
            max(enable_service, enable_timer),
            min(restart_service, restart_timer),
            calls,
        )
        self.assertLess(restart_service, restart_timer, calls)

    def test_success_path_reports_each_write_and_done(self):
        result, _ = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"05-configure-host-egress: wrote {RECONCILER}", result.stdout)
        self.assertIn(
            f"05-configure-host-egress: wrote {UNIT} and reloaded systemd",
            result.stdout,
        )
        self.assertIn(
            f"05-configure-host-egress: wrote {TIMER} and reloaded systemd",
            result.stdout,
        )
        self.assertTrue(
            result.stdout.rstrip().endswith("05-configure-host-egress: done"),
            result.stdout,
        )

    def test_a_failed_reconciler_install_stops_before_systemd_is_touched(self):
        result, calls = self.run_script(
            fail_dst=RECONCILER, install_body=FAILING_INSTALL_STUB
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(
            [c for c in calls if c.startswith("systemctl")],
            "no unit may be written or enabled after the reconciler failed to install",
        )
        self.assertNotIn("05-configure-host-egress: done", result.stdout)


if __name__ == "__main__":
    unittest.main()
