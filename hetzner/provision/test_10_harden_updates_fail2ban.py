#!/usr/bin/env python3
"""Unit tests for 10-harden-updates-fail2ban.sh (the apt and fail2ban paths).

The script writes fixed /etc paths and has no environment seam for them, so
every system command is a logging stub on PATH, mktemp runs in a temp dir, and
each install payload is captured there. The config-file no-op branches are
reached only when a target already exists and matches byte for byte, which
these tests cannot arrange without touching /etc, so they are not covered.
HARDEN_SCRIPT_UNDER_TEST points the tests at a sabotaged copy of the script.
"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(__file__)
SCRIPT = os.environ.get(
    "HARDEN_SCRIPT_UNDER_TEST", os.path.join(HERE, "10-harden-updates-fail2ban.sh")
)

AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
ORIGINS = "/etc/apt/apt.conf.d/51branchleft-unattended-origins"
JAIL_LOCAL = "/etc/fail2ban/jail.local"
PACKAGES = ["unattended-upgrades", "apt-listchanges", "fail2ban"]

EXPECTED_AUTO_UPGRADES = (
    'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
)
EXPECTED_ORIGINS = (
    "Unattended-Upgrade::Origins-Pattern {\n"
    '        "origin=Docker";\n'
    "};\n"
)
EXPECTED_JAIL = (
    "[sshd]\n"
    "enabled = true\n"
    "port = ssh\n"
    "backend = systemd\n"
    "maxretry = 5\n"
    "findtime = 10m\n"
    "bantime = 1h\n"
    "ignoreip = 127.0.0.1/8 ::1 10.20.1.10\n"
)

DPKG_STUB = """#!/usr/bin/env bash
echo "dpkg $*" >> "$FAKE_CALL_LOG"
pkg="$2"
for missing in $FAKE_MISSING; do
    if [[ "$missing" == "$pkg" ]]; then
        exit 1
    fi
done
exit 0
"""

APT_GET_STUB = """#!/usr/bin/env bash
echo "apt-get $*" >> "$FAKE_CALL_LOG"
exit "${FAKE_APT_GET_RC:-0}"
"""

APT_CONFIG_STUB = """#!/usr/bin/env bash
echo "apt-config $*" >> "$FAKE_CALL_LOG"
exit "${FAKE_APT_CONFIG_RC:-0}"
"""

SYSTEMCTL_STUB = """#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_CALL_LOG"
if [[ "$1" == "reload" && -n "${FAKE_RELOAD_FAILS:-}" ]]; then
    exit 1
fi
exit 0
"""

RM_STUB = """#!/usr/bin/env bash
echo "rm $*" >> "$FAKE_CALL_LOG"
exit 0
"""

INSTALL_STUB = """#!/usr/bin/env bash
echo "install $*" >> "$FAKE_CALL_LOG"
src=""
dst=""
for arg in "$@"; do
    src="$dst"
    dst="$arg"
done
cp "$src" "$FAKE_OUT/$(printf '%s' "$dst" | tr / _)"
"""


def _stub(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


def _install_targets(calls):
    """Map each install destination to its mode, from the logged install calls."""
    targets = {}
    for line in calls.splitlines():
        parts = line.split()
        if parts[:1] == ["install"]:
            targets[parts[-1]] = parts[2]
    return targets


class HardenUpdatesFail2banTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.bin = os.path.join(root, "bin")
        self.out = os.path.join(root, "out")
        self.scratch = os.path.join(root, "scratch")
        for path in (self.bin, self.out, self.scratch):
            os.mkdir(path)
        self.call_log = os.path.join(root, "calls.log")
        open(self.call_log, "w", encoding="utf-8").close()

        stubs = {
            "dpkg": DPKG_STUB,
            "apt-get": APT_GET_STUB,
            "apt-config": APT_CONFIG_STUB,
            "systemctl": SYSTEMCTL_STUB,
            "rm": RM_STUB,
            "install": INSTALL_STUB,
        }
        for name, body in stubs.items():
            _stub(os.path.join(self.bin, name), body)

    def run_script(self, missing=(), apt_get_rc=0, apt_config_rc=0, reload_fails=False):
        env = {
            "PATH": self.bin + os.pathsep + "/usr/bin:/bin",
            "TMPDIR": self.scratch,
            "HOME": self.tmp.name,
            "FAKE_CALL_LOG": self.call_log,
            "FAKE_OUT": self.out,
            "FAKE_MISSING": " ".join(missing),
            "FAKE_APT_GET_RC": str(apt_get_rc),
            "FAKE_APT_CONFIG_RC": str(apt_config_rc),
        }
        if reload_fails:
            env["FAKE_RELOAD_FAILS"] = "1"
        result = subprocess.run(
            ["bash", SCRIPT], env=env, capture_output=True, text=True, timeout=60
        )
        with open(self.call_log, encoding="utf-8") as fh:
            calls = fh.read()
        return result, calls

    def payload(self, dst):
        """The bytes the script handed to install for dst, captured by the stub."""
        path = os.path.join(self.out, dst.replace("/", "_"))
        if not os.path.exists(path):
            self.fail(f"the script never installed a file to {dst}")
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_success_installs_all_three_packages_when_none_are_present(self):
        result, calls = self.run_script(missing=PACKAGES)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("apt-get update -qq", calls)
        self.assertIn("apt-get install -yqq " + " ".join(PACKAGES), calls)
        self.assertIn("installed " + " ".join(PACKAGES), result.stdout)
        self.assertIn("systemctl enable --now unattended-upgrades", calls)
        self.assertIn("systemctl enable --now fail2ban", calls)
        self.assertIn("done", result.stdout)

    def test_writes_auto_upgrades_drop_in_with_mode_644(self):
        _, calls = self.run_script(missing=PACKAGES)
        self.assertEqual(self.payload(AUTO_UPGRADES), EXPECTED_AUTO_UPGRADES)
        self.assertEqual(_install_targets(calls).get(AUTO_UPGRADES), "644")

    def test_writes_docker_origin_drop_in_with_mode_644(self):
        _, calls = self.run_script(missing=PACKAGES)
        self.assertEqual(self.payload(ORIGINS), EXPECTED_ORIGINS)
        self.assertEqual(_install_targets(calls).get(ORIGINS), "644")

    def test_writes_sshd_jail_with_mode_644_and_reloads_fail2ban(self):
        result, calls = self.run_script(missing=PACKAGES)
        self.assertEqual(self.payload(JAIL_LOCAL), EXPECTED_JAIL)
        self.assertEqual(_install_targets(calls).get(JAIL_LOCAL), "644")
        self.assertIn("systemctl reload fail2ban", calls)
        self.assertNotIn("systemctl restart fail2ban", calls)
        self.assertIn("systemctl enable --now fail2ban", calls)

    def test_reload_falls_back_to_restart_when_reload_fails(self):
        result, calls = self.run_script(missing=PACKAGES, reload_fails=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("systemctl restart fail2ban", calls)

    def test_second_run_skips_apt_when_all_packages_are_present(self):
        result, calls = self.run_script(missing=())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("already installed, no-op", result.stdout)
        self.assertNotIn("apt-get", calls)

    def test_refuses_and_removes_origins_drop_in_when_apt_rejects_it(self):
        result, calls = self.run_script(missing=PACKAGES, apt_config_rc=1)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("apt rejected", result.stderr)
        self.assertIn("removing it", result.stderr)
        self.assertIn(f"rm -f {ORIGINS}", calls)
        self.assertNotIn(JAIL_LOCAL, _install_targets(calls))
        self.assertNotIn("systemctl enable --now fail2ban", calls)

    def test_stops_before_any_write_when_apt_update_fails(self):
        result, calls = self.run_script(missing=PACKAGES, apt_get_rc=1)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("apt-get install", calls)
        self.assertEqual(_install_targets(calls), {})


if __name__ == "__main__":
    unittest.main()
