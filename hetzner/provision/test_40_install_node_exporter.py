#!/usr/bin/env python3
"""Unit tests for 40-install-node-exporter.sh.

This is the installer `RUNBOOK-monitoring.md` runs against ops1, and its two
silent failure modes are exactly the ones worth a test rather
than a smoke check: a corrupted or substituted download getting installed
anyway, and a host with no estate-private address getting node_exporter
bound to its public interface -- the one thing every exporter in this
estate's firewall posture (hetzner-host/firewalls.ts) depends on never
happening.

The script talks to the network (`curl`), the package/user database
(`useradd`, `id`) and `systemctl`, none of which a test process may touch for
real, and it chowns installed files to `root:root`, which a non-root test
process cannot do either. All four are substituted: `curl`, `useradd`, `id`,
`ip` and `systemctl` are fakes earlier on `PATH`, `NODE_EXPORTER_OWNER`/
`_GROUP` are overridden to the test's own user so `install -o/-g` succeeds,
and every filesystem destination is redirected into a temporary directory via
the script's own override variables.
"""

import hashlib
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "40-install-node-exporter.sh")
UNIT = os.path.join(os.path.dirname(__file__), "node-exporter.service")

VERSION = "1.12.1"
FAKE_NODE_EXPORTER_BODY = f"""#!/usr/bin/env bash
if [[ "$1" == "--version" ]]; then
    echo "node_exporter, version {VERSION} (branch: HEAD, revision: test)"
    exit 0
fi
echo "fake node_exporter running: $*"
"""

FAKE_CURL = """#!/usr/bin/env bash
# Minimal -o parser -- this script only ever calls curl one way.
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
cp "$FAKE_TARBALL_PATH" "$out"
"""

FAKE_ID = """#!/usr/bin/env bash
if [[ "$1" == "-u" ]]; then
    if [[ "${FAKE_USER_EXISTS:-0}" == "1" ]]; then
        echo 999
        exit 0
    fi
    exit 1
fi
exit 1
"""

FAKE_USERADD = """#!/usr/bin/env bash
echo "useradd $*" >> "$FAKE_CALL_LOG"
exit 0
"""

FAKE_IP = """#!/usr/bin/env bash
printf '%s\\n' "$FAKE_IP_OUTPUT"
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
echo "systemctl $*" >> "$FAKE_CALL_LOG"
if [[ "$1" == "is-active" ]]; then
    exit "${FAKE_SYSTEMCTL_IS_ACTIVE_EXIT:-0}"
fi
exit 0
"""

# A real address in the estate's private subnet, alongside a public one --
# proves the script picks the private one out of more than a single-line
# `ip` output, not merely a coincidental match.
IP_OUTPUT_WITH_PRIVATE = "\n".join(
    [
        '2: eth0    inet 167.233.1.2/32 brd 167.233.1.2 scope global eth0\\       valid_lft forever preferred_lft forever',
        '3: eth1    inet 10.20.1.50/32 brd 10.20.1.50 scope global eth1\\       valid_lft forever preferred_lft forever',
    ]
)
IP_OUTPUT_NO_PRIVATE = (
    '2: eth0    inet 167.233.1.2/32 brd 167.233.1.2 scope global eth0\\       valid_lft forever preferred_lft forever'
)


def _write_fake(path, content):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _build_tarball(dest_path, version=VERSION, body=FAKE_NODE_EXPORTER_BODY):
    """A real tar.gz with the exact layout the real upstream release carries
    -- `node_exporter-<version>.linux-amd64/node_exporter` -- built with the
    real `tarfile` module rather than faked, so the script's real `tar -xzf`
    call is exercised for real."""
    with tempfile.TemporaryDirectory() as staging:
        member_dir = os.path.join(staging, f"node_exporter-{version}.linux-amd64")
        os.makedirs(member_dir)
        binary_path = os.path.join(member_dir, "node_exporter")
        _write_fake(binary_path, body)
        with tarfile.open(dest_path, "w:gz") as tar:
            tar.add(member_dir, arcname=f"node_exporter-{version}.linux-amd64")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class InstallNodeExporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "fakebin")
        os.makedirs(bin_dir)
        for name, content in (
            ("curl", FAKE_CURL),
            ("id", FAKE_ID),
            ("useradd", FAKE_USERADD),
            ("ip", FAKE_IP),
            ("systemctl", FAKE_SYSTEMCTL),
        ):
            _write_fake(os.path.join(bin_dir, name), content)
        self.bin_dir = bin_dir

        self.call_log = os.path.join(self.tmp.name, "calls.log")
        self.tarball_path = os.path.join(self.tmp.name, "node_exporter.tar.gz")
        _build_tarball(self.tarball_path)
        self.real_sha256 = _sha256(self.tarball_path)

        self.install_root = os.path.join(self.tmp.name, "installed")
        self.bin_path = os.path.join(self.install_root, "usr/local/bin/node_exporter")
        self.unit_path = os.path.join(self.install_root, "etc/systemd/system/node_exporter.service")
        self.env_file = os.path.join(self.install_root, "etc/default/node-exporter")
        os.makedirs(os.path.dirname(self.bin_path))
        # Production installs the unit into /etc/systemd/system, which
        # always exists -- the script itself never creates it. Only this
        # test's redirected path needs it made ahead of time.
        os.makedirs(os.path.dirname(self.unit_path))

    def run_script(
        self,
        ip_output=IP_OUTPUT_WITH_PRIVATE,
        sha256=None,
        user_exists="0",
        systemctl_is_active_exit="1",
        extra_env=None,
    ):
        env = dict(os.environ)
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        env["FAKE_TARBALL_PATH"] = self.tarball_path
        env["FAKE_IP_OUTPUT"] = ip_output
        env["FAKE_USER_EXISTS"] = user_exists
        env["FAKE_CALL_LOG"] = self.call_log
        env["FAKE_SYSTEMCTL_IS_ACTIVE_EXIT"] = systemctl_is_active_exit
        env["NODE_EXPORTER_SHA256"] = sha256 if sha256 is not None else self.real_sha256
        env["NODE_EXPORTER_BIN_PATH"] = self.bin_path
        env["NODE_EXPORTER_UNIT_PATH"] = self.unit_path
        env["NODE_EXPORTER_ENV_FILE"] = self.env_file
        # This process's own uid/gid -- `install -o/-g` succeeds chowning to
        # yourself with no privilege; it cannot chown to root without one.
        env["NODE_EXPORTER_OWNER"] = str(os.getuid())
        env["NODE_EXPORTER_GROUP"] = str(os.getgid())
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=os.path.dirname(SCRIPT),
        )

    def calls(self):
        if not os.path.exists(self.call_log):
            return []
        with open(self.call_log, encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]

    # --- Fresh install -------------------------------------------------

    def test_fresh_install_downloads_verifies_installs_and_starts(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertTrue(os.path.isfile(self.bin_path))
        version_check = subprocess.run(
            [self.bin_path, "--version"], capture_output=True, text=True, check=False
        )
        self.assertIn(f"node_exporter, version {VERSION}", version_check.stdout)

        self.assertTrue(os.path.isfile(self.unit_path))
        with open(self.unit_path, encoding="utf-8") as handle, open(UNIT, encoding="utf-8") as committed:
            self.assertEqual(handle.read(), committed.read())

        self.assertTrue(os.path.isfile(self.env_file))
        with open(self.env_file, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "NODE_EXPORTER_LISTEN_ADDRESS=10.20.1.50\n")

        self.assertIn(f"installed {self.bin_path} at version {VERSION}", result.stdout)
        self.assertIn("created system user", result.stdout)
        self.assertIn(f"wrote {self.env_file} (10.20.1.50)", result.stdout)
        self.assertIn(f"wrote {self.unit_path} and reloaded systemd", result.stdout)
        self.assertIn("(re)started node_exporter.service", result.stdout)

        calls = self.calls()
        self.assertTrue(any(call.startswith("useradd") for call in calls))
        self.assertIn("systemctl daemon-reload", calls)
        self.assertIn("systemctl enable node_exporter.service", calls)
        self.assertIn("systemctl restart node_exporter.service", calls)

    # --- Idempotency -----------------------------------------------------

    def test_rerun_with_nothing_changed_is_a_full_no_op(self):
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)

        # Clear the call log so the second run's calls are isolated, and
        # report the service as already active -- the state a real re-run
        # against an already-healthy host is in.
        os.remove(self.call_log)
        second = self.run_script(user_exists="1", systemctl_is_active_exit="0")
        self.assertEqual(second.returncode, 0, second.stderr)

        self.assertIn(f"{self.bin_path} already at version {VERSION}, no-op", second.stdout)
        self.assertIn("already exists, no-op", second.stdout)
        self.assertIn("already carries 10.20.1.50, no-op", second.stdout)
        self.assertIn(f"{self.unit_path} already up to date, no-op", second.stdout)
        self.assertIn("already running and up to date, no-op", second.stdout)
        self.assertNotIn("(re)started", second.stdout)

        calls = self.calls()
        self.assertNotIn("systemctl daemon-reload", calls)
        self.assertNotIn("systemctl restart node_exporter.service", calls)
        # Still reconciled every run, cheaply, the same discipline every
        # other reconciler in this directory uses.
        self.assertIn("systemctl enable node_exporter.service", calls)

    def test_unit_content_change_forces_reload_and_restart_even_if_active(self):
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)

        # Simulates a committed unit file edit landing between two runs.
        with open(self.unit_path, "a", encoding="utf-8") as handle:
            handle.write("\n# drifted\n")

        os.remove(self.call_log)
        second = self.run_script(user_exists="1", systemctl_is_active_exit="0")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn(f"wrote {self.unit_path} and reloaded systemd", second.stdout)
        self.assertIn("(re)started node_exporter.service", second.stdout)
        with open(self.unit_path, encoding="utf-8") as handle, open(UNIT, encoding="utf-8") as committed:
            self.assertEqual(handle.read(), committed.read())

    # --- Failure modes -----------------------------------------------------

    def test_checksum_mismatch_refuses_to_install_anything(self):
        result = self.run_script(sha256="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the pinned checksum", result.stderr)
        self.assertFalse(os.path.exists(self.bin_path))

    def test_no_private_subnet_address_refuses_rather_than_binding_public(self):
        result = self.run_script(ip_output=IP_OUTPUT_NO_PRIVATE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no address in 10.20.1.0/24", result.stderr)
        self.assertFalse(os.path.exists(self.bin_path))
        self.assertFalse(os.path.exists(self.env_file))


if __name__ == "__main__":
    unittest.main()
