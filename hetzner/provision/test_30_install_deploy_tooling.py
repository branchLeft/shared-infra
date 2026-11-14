#!/usr/bin/env python3
"""Unit tests for 30-install-deploy-tooling.sh, the deploy wrapper and unit install.

The script's destinations are absolute paths with no override, so these tests
cover what a clean host shows: the first-run branch, the order of the system
calls, and the refusal when the sudoers drop-in is absent. `install`,
`systemctl` and `visudo` are logging stubs on PATH and nothing is written.
The sudoers-present path (the `visudo -c` check and the no-op and rewrite
branches) needs the real destinations to exist, which only a host can show,
so it is not tested here.
"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.abspath(os.path.dirname(__file__))
SCRIPT = os.path.join(HERE, "30-install-deploy-tooling.sh")

WRAPPER = "/usr/local/sbin/branchleft-deploy"
UNIT = "/etc/systemd/system/branchleft-compose@.service"
SUDOERS = "/etc/sudoers.d/50-branchleft-deploy"

# Each stub appends its argv to the call log. FAKE_INSTALL_EXIT chooses a
# failure for the install calls.
INSTALL_STUB = """#!/usr/bin/env bash
echo "install $*" >> "$FAKE_CALL_LOG"
exit "${FAKE_INSTALL_EXIT:-0}"
"""

SYSTEMCTL_STUB = """#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_CALL_LOG"
exit 0
"""

VISUDO_STUB = """#!/usr/bin/env bash
echo "visudo $*" >> "$FAKE_CALL_LOG"
exit 0
"""


def _stub(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


@unittest.skipIf(
    os.path.exists(WRAPPER) or os.path.exists(UNIT) or os.path.exists(SUDOERS),
    "the wrapper, unit or sudoers drop-in already exists on this host; the first-run branch needs them absent",
)
class InstallDeployToolingTests(unittest.TestCase):
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
        _stub(os.path.join(self.bin, "visudo"), VISUDO_STUB)
        self.src = os.path.dirname(self.script)

    def run_script(self, install_exit=0):
        env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CALL_LOG": self.call_log,
            "FAKE_INSTALL_EXIT": str(install_exit),
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

    def expected_install_calls(self):
        return [
            "install -d -m 0755 -o root -g root /etc/branchleft /opt/branchleft",
            f"install -m 0755 -o root -g root {self.src}/branchleft_deploy.py {WRAPPER}",
            f"install -m 0644 -o root -g root {self.src}/branchleft-compose@.service {UNIT}",
            "systemctl daemon-reload",
        ]

    def test_wrapper_is_installed_root_owned_with_mode_0755(self):
        # sudo runs the wrapper as root for the deploy account, so owner and mode are the control.
        _, calls = self.run_script()
        self.assertIn(
            f"install -m 0755 -o root -g root {self.src}/branchleft_deploy.py {WRAPPER}",
            calls,
        )
        self.assertNotIn(
            f"install -m 0777 -o root -g root {self.src}/branchleft_deploy.py {WRAPPER}",
            calls,
        )

    def test_unit_is_installed_then_systemd_reloaded(self):
        _, calls = self.run_script()
        self.assertIn(
            f"install -m 0644 -o root -g root {self.src}/branchleft-compose@.service {UNIT}",
            calls,
        )
        self.assertLess(
            calls.index(
                f"install -m 0644 -o root -g root {self.src}/branchleft-compose@.service {UNIT}"
            ),
            calls.index("systemctl daemon-reload"),
        )

    def test_missing_sudoers_drop_in_refuses_after_installing_and_never_runs_visudo(
        self,
    ):
        # visudo is the only safe check on the drop-in, so with no file there is nothing to check
        # and the run must fail loudly rather than report success.
        result, calls = self.run_script()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, self.expected_install_calls())
        self.assertNotIn("visudo", " ".join(calls))
        self.assertIn(f"{SUDOERS} missing", result.stderr)
        self.assertNotIn("30-install-deploy-tooling: done", result.stdout)

    def test_a_failed_install_stops_the_run_before_any_systemctl_call(self):
        result, calls = self.run_script(install_exit=1)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            calls,
            ["install -d -m 0755 -o root -g root /etc/branchleft /opt/branchleft"],
        )
        self.assertNotIn("30-install-deploy-tooling: done", result.stdout)


if __name__ == "__main__":
    unittest.main()
