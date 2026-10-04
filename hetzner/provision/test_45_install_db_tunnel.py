#!/usr/bin/env python3
"""Unit tests for 45-install-db-tunnel.sh and the unit it installs.

See 45-install-db-tunnel.md.
"""

import base64
import os
import re
import stat
import struct
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "45-install-db-tunnel.sh")
UNIT = os.path.join(HERE, "branchleft-db-tunnel.service")

FAKE_GETENT = """#!/usr/bin/env bash
[[ -n "${FAKE_GETENT_LINE:-}" ]] || exit 2
printf '%s\\n' "$FAKE_GETENT_LINE"
"""
FAKE_LOGGED = """#!/usr/bin/env bash
echo "$(basename "$0") $*" >> "$FAKE_CALL_LOG"
if [[ "$(basename "$0")" == systemctl && "$1" == is-active ]]; then
    exit "${FAKE_IS_ACTIVE_EXIT:-1}"
fi
exit 0
"""
FAKE_IP = """#!/usr/bin/env bash
printf '%s\\n' "$FAKE_IP_OUTPUT"
"""
IP_DB1 = "\n".join(
    [
        "2: eth0    inet 10.20.1.20/32 brd 10.20.1.20 scope global eth0",
        "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0",
    ]
)
IP_ELSEWHERE = "2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0"

REPLICA = "198.51.100.30"


def host_key() -> str:
    blob = b"".join(struct.pack(">I", len(f)) + f for f in (b"ssh-ed25519", bytes(range(32))))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def _write_fake(path, content):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRWXU)


class InstallDbTunnelTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.bin_dir = os.path.join(self.root, "fakebin")
        os.makedirs(self.bin_dir)
        _write_fake(os.path.join(self.bin_dir, "getent"), FAKE_GETENT)
        _write_fake(os.path.join(self.bin_dir, "ip"), FAKE_IP)
        for name in ("useradd", "systemctl"):
            _write_fake(os.path.join(self.bin_dir, name), FAKE_LOGGED)
        self.call_log = os.path.join(self.root, "calls.log")
        self.dir = os.path.join(self.root, "etc/branchleft/db-tunnel")
        self.unit_path = os.path.join(self.root, "branchleft-db-tunnel.service")

    def run_script(self, *args, getent_line="", ip_output=IP_DB1, is_active_exit="1"):
        env = dict(os.environ)
        env.update(
            PATH=self.bin_dir + os.pathsep + env.get("PATH", ""),
            FAKE_GETENT_LINE=getent_line,
            FAKE_IP_OUTPUT=ip_output,
            FAKE_IS_ACTIVE_EXIT=is_active_exit,
            FAKE_CALL_LOG=self.call_log,
            DB_TUNNEL_DIR=self.dir,
            DB_TUNNEL_UNIT_PATH=self.unit_path,
            DB_TUNNEL_OWNER=str(os.getuid()),
            DB_TUNNEL_GROUP=str(os.getgid()),
            DB_TUNNEL_KEY_OWNER=f"{os.getuid()}:{os.getgid()}",
        )
        return subprocess.run(
            ["bash", SCRIPT, *args], env=env, capture_output=True, text=True, check=False
        )

    def calls(self):
        if not os.path.exists(self.call_log):
            return []
        with open(self.call_log, encoding="utf-8") as handle:
            return [line.strip() for line in handle]

    def read(self, name):
        with open(os.path.join(self.dir, name), encoding="utf-8") as handle:
            return handle.read()

    def keygen(self):
        result = self.run_script("keygen")
        self.assertEqual(result.returncode, 0, result.stderr)
        os.remove(self.call_log)
        return result

    # --- keygen ----------------------------------------------------------

    def test_keygen_creates_the_user_and_a_private_key_only_its_owner_reads(self):
        result = self.run_script("keygen")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("useradd --system --no-create-home --home-dir /nonexistent "
                      "--shell /usr/sbin/nologin dbtunnel", self.calls())
        key = os.path.join(self.dir, "id_ed25519")
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        printed = result.stdout.strip().splitlines()[-1]
        self.assertRegex(printed, r"^ssh-ed25519 [A-Za-z0-9+/]{68} db1-replica-tunnel$")
        self.assertEqual(printed, self.read("id_ed25519.pub").strip())

    def test_keygen_twice_keeps_the_first_key(self):
        first = self.keygen().stdout.strip().splitlines()[-1]
        again = self.run_script("keygen", getent_line="dbtunnel:x:996:996::/nonexistent:/usr/sbin/nologin")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already exists, keeping it", again.stdout)
        self.assertEqual(again.stdout.strip().splitlines()[-1], first)
        self.assertFalse(any(call.startswith("useradd") for call in self.calls()))

    def test_an_existing_user_with_a_shell_is_refused(self):
        result = self.run_script("keygen", getent_line="dbtunnel:x:1000:1000::/home/dbtunnel:/bin/bash")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to reuse it", result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "id_ed25519")))

    # --- install: refusals ------------------------------------------------

    def test_install_refuses_a_malformed_replica_address(self):
        self.keygen()
        for value in ("256.1.1.1", "1.2.3", "01.2.3.4", "1.2.3.4.5", "host.example", "1.2.3.4/32"):
            with self.subTest(value=value):
                result = self.run_script("install", value, host_key())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("is not an IPv4 address", result.stderr)

    def test_install_refuses_a_replica_address_the_nat_cannot_reach_it_by(self):
        self.keygen()
        for value in ("10.20.1.30", "172.16.0.5", "192.168.0.1", "127.0.0.1", "100.64.0.1",
                      "169.254.1.1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(value=value):
                result = self.run_script("install", value, host_key())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("is not a public address", result.stderr)

    def test_install_refuses_anything_but_a_bare_ed25519_host_key(self):
        self.keygen()
        for value in (host_key() + " root@db-t1", "ssh-rsa " + host_key().split()[1],
                      host_key()[:-1], f"{REPLICA} {host_key()}", ""):
            with self.subTest(value=value):
                result = self.run_script("install", REPLICA, value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("host key must be", result.stderr)

    def test_install_before_keygen_is_refused(self):
        result = self.run_script("install", REPLICA, host_key())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run '", result.stderr)

    def test_install_off_db1_is_refused(self):
        self.keygen()
        result = self.run_script("install", REPLICA, host_key(), ip_output=IP_ELSEWHERE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is this db1?", result.stderr)
        self.assertFalse(os.path.exists(self.unit_path))

    def test_usage_errors(self):
        for args in ((), ("install", REPLICA), ("keygen", "extra"), ("remove",)):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("usage:", result.stderr)

    # --- install: success and idempotency ----------------------------------

    def test_install_pins_the_host_key_names_the_source_and_starts_the_unit(self):
        self.keygen()
        result = self.run_script("install", REPLICA, host_key())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read("known_hosts"), f"{REPLICA} {host_key()}\n")
        self.assertEqual(
            self.read("target.env"),
            f"DB_TUNNEL_REPLICA_HOST={REPLICA}\nDB_TUNNEL_SOURCE_ADDRESS=10.20.1.20\n",
        )
        with open(self.unit_path, encoding="utf-8") as installed, open(UNIT, encoding="utf-8") as committed:
            self.assertEqual(installed.read(), committed.read())
        calls = self.calls()
        self.assertIn("systemctl daemon-reload", calls)
        self.assertIn("systemctl enable branchleft-db-tunnel.service", calls)
        self.assertIn("systemctl restart branchleft-db-tunnel.service", calls)
        self.assertIn("10.20.1.20:9105", result.stdout)

    def test_rerun_on_a_running_tunnel_does_not_restart_it(self):
        self.keygen()
        self.run_script("install", REPLICA, host_key())
        os.remove(self.call_log)
        result = self.run_script(
            "install", REPLICA, host_key(),
            getent_line="dbtunnel:x:996:996::/nonexistent:/usr/sbin/nologin", is_active_exit="0",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("systemctl restart branchleft-db-tunnel.service", self.calls())
        self.assertIn("already running and up to date", result.stdout)

    def test_rerun_on_a_stopped_tunnel_starts_it(self):
        self.keygen()
        self.run_script("install", REPLICA, host_key())
        os.remove(self.call_log)
        self.run_script("install", REPLICA, host_key(), is_active_exit="3")
        self.assertIn("systemctl restart branchleft-db-tunnel.service", self.calls())

    def test_a_new_replica_host_rewrites_the_pin_and_restarts(self):
        self.keygen()
        self.run_script("install", REPLICA, host_key())
        os.remove(self.call_log)
        result = self.run_script("install", "198.51.100.31", host_key(), is_active_exit="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.read("known_hosts").startswith("198.51.100.31 "))
        self.assertIn("systemctl restart branchleft-db-tunnel.service", self.calls())


class UnitContractTests(unittest.TestCase):
    """The options the tunnel's safety and restart behaviour rest on."""

    @classmethod
    def setUpClass(cls):
        with open(UNIT, encoding="utf-8") as handle:
            cls.text = handle.read()
        cls.exec_start = re.search(r"^ExecStart=(.*?)(?<!\\)$", cls.text, re.M | re.S).group(1)

    def test_db1_dials_out_with_exactly_two_forwards(self):
        self.assertIn("-R 127.0.0.1:13306:${DB_TUNNEL_SOURCE_ADDRESS}:3306", self.exec_start)
        self.assertIn("-L ${DB_TUNNEL_SOURCE_ADDRESS}:9105:127.0.0.1:9104", self.exec_start)
        self.assertEqual(len(re.findall(r"(?<!\S)-[RLD] ", self.exec_start)), 2)
        self.assertTrue(self.exec_start.rstrip().endswith("dbtunnel@${DB_TUNNEL_REPLICA_HOST}"))

    def test_a_forward_failure_or_dead_link_ends_the_process(self):
        for option in ("ExitOnForwardFailure=yes", "ServerAliveInterval=10", "ServerAliveCountMax=3"):
            self.assertIn(f"-o {option}", self.exec_start)

    def test_only_the_pinned_key_and_host_are_trusted(self):
        for option in ("StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "IdentityAgent=none",
                       "BatchMode=yes", "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no",
                       "ForwardAgent=no"):
            self.assertIn(f"-o {option}", self.exec_start)
        self.assertIn("-F none", self.exec_start)
        self.assertNotIn("GatewayPorts", self.exec_start)

    def test_systemd_restarts_it_forever_with_backoff(self):
        for line in ("Restart=always", "StartLimitIntervalSec=0", "RestartSec=5",
                     "RestartSteps=6", "RestartMaxDelaySec=120", "User=dbtunnel"):
            self.assertIn(f"\n{line}\n", self.text)


if __name__ == "__main__":
    unittest.main()
