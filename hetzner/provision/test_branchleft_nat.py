#!/usr/bin/env python3
"""Unit tests for branchleft_nat.sh.

The script is the whole difference between a host with no public address
reaching the internet and not reaching it, and the rules it writes are a
forwarding decision on the one host that terminates public traffic. Two of its
behaviours are therefore asserted directly rather than smoke-tested by a real
run: that the return direction is accepted only for flows conntrack already
knows, and that it refuses to run on a host whose default route is itself the
private network -- which is the configuration that would loop the estate's
egress back into the subnet it came from.

The script talks to the live routing table, netfilter and sysctl, none of
which a test process may do. All three are replaced by fakes earlier on
`PATH`, and the sysctl drop-in path is redirected with the environment
variable the script reads as an override. `PATH` is set to the fake directory
plus `/usr/bin` and `/bin` only: `iptables` and `ip` live in `/usr/sbin` on a
real Linux host, and leaving that directory out is what makes the
missing-iptables case testable on a machine that has iptables.
"""

import os
import stat
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "branchleft_nat.sh")

FAKE_IP = """#!/usr/bin/env bash
for arg in "$@"; do
    case "$arg" in
        route) printf '%s\\n' "$FAKE_IP_ROUTE"; exit 0 ;;
        addr) printf '%s\\n' "$FAKE_IP_ADDR"; exit 0 ;;
    esac
done
exit 0
"""

FAKE_IPTABLES = """#!/usr/bin/env bash
args="$*"
printf '%s\\n' "$args" >> "$FAKE_IPTABLES_LOG"
case "$args" in
    *"-S DOCKER-USER"*) exit "${FAKE_IPTABLES_DOCKER_USER_EXIT:-1}" ;;
    *" -C "*) exit "${FAKE_IPTABLES_CHECK_EXIT:-1}" ;;
esac
exit 0
"""

FAKE_SYSCTL = """#!/usr/bin/env bash
exit 0
"""

# `ip -4 route show default` on a host whose default route leaves through the
# public interface, and `ip -4 -o addr show scope global` on the same host.
PUBLIC_DEFAULT_ROUTE = "default via 172.31.1.1 dev eth0 proto dhcp src 203.0.113.10 metric 100"
EDGE_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
    ]
)


class NatGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "ip"), FAKE_IP)
        self._write_fake(os.path.join(bin_dir, "iptables"), FAKE_IPTABLES)
        self._write_fake(os.path.join(bin_dir, "sysctl"), FAKE_SYSCTL)
        self.bin_dir = bin_dir

        self.sysctl_conf = os.path.join(self.tmp.name, "99-branchleft-nat.conf")
        self.iptables_log = os.path.join(self.tmp.name, "iptables.log")

    @staticmethod
    def _write_fake(path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_script(
        self,
        route=PUBLIC_DEFAULT_ROUTE,
        addresses=EDGE_ADDRESSES,
        docker_user=True,
        rule_present=False,
        subnet=None,
        drop_iptables=False,
    ):
        if drop_iptables:
            os.remove(os.path.join(self.bin_dir, "iptables"))
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ROUTE": route,
                "FAKE_IP_ADDR": addresses,
                "FAKE_IPTABLES_LOG": self.iptables_log,
                "FAKE_IPTABLES_DOCKER_USER_EXIT": "0" if docker_user else "1",
                "FAKE_IPTABLES_CHECK_EXIT": "0" if rule_present else "1",
                "BRANCHLEFT_NAT_SYSCTL_CONF": self.sysctl_conf,
            }
        )
        if subnet is not None:
            env["BRANCHLEFT_NAT_SUBNET"] = subnet
        return subprocess.run(
            ["bash", SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def iptables_calls(self):
        if not os.path.exists(self.iptables_log):
            return []
        with open(self.iptables_log, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def inserted(self):
        return [call for call in self.iptables_calls() if " -I " in call]

    def test_installs_the_three_rules_the_path_needs(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.inserted(),
            [
                "-t nat -I POSTROUTING 1 -s 10.20.1.0/24 -o eth0 -j MASQUERADE",
                "-t filter -I DOCKER-USER 1 -s 10.20.1.0/24 -o eth0 -j ACCEPT",
                "-t filter -I DOCKER-USER 1 -d 10.20.1.0/24 -i eth0 "
                "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            ],
        )

    def test_masquerade_is_scoped_to_the_subnet_and_the_uplink(self):
        # An unscoped MASQUERADE would launder any source this host can be
        # made to forward through its public address.
        self.run_script()
        masquerade = [call for call in self.inserted() if "MASQUERADE" in call]
        self.assertEqual(len(masquerade), 1)
        self.assertIn("-s 10.20.1.0/24", masquerade[0])
        self.assertIn("-o eth0", masquerade[0])

    def test_the_return_direction_is_accepted_only_for_established_flows(self):
        self.run_script()
        inbound = [call for call in self.inserted() if " -i eth0" in call]
        self.assertEqual(len(inbound), 1)
        self.assertIn("--ctstate ESTABLISHED,RELATED", inbound[0])

    def test_uses_the_forward_chain_when_docker_is_not_installed(self):
        result = self.run_script(docker_user=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        filtered = [call for call in self.inserted() if call.startswith("-t filter")]
        self.assertEqual(len(filtered), 2)
        self.assertTrue(all("-I FORWARD 1" in call for call in filtered))
        self.assertIn("filtered in FORWARD", result.stdout)

    def test_adds_nothing_when_the_rules_are_already_present(self):
        result = self.run_script(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertEqual(len([c for c in self.iptables_calls() if " -C " in c]), 3)

    def test_enables_forwarding_persistently(self):
        self.run_script()
        with open(self.sysctl_conf, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "net.ipv4.ip_forward = 1\n")

    def test_leaves_an_already_correct_sysctl_drop_in_alone(self):
        with open(self.sysctl_conf, "w", encoding="utf-8") as handle:
            handle.write("net.ipv4.ip_forward = 1\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already up to date", result.stdout)

    def test_refuses_a_host_whose_default_route_holds_no_public_address(self):
        # The routing loop: a private-only host's default route is the network
        # gateway, so masquerading there sends every forwarded packet back
        # into the subnet it arrived from.
        result = self.run_script(
            route="default via 10.20.1.1 dev enp7s0 proto dhcp metric 100",
            addresses="3: enp7s0    inet 10.20.1.20/32 brd 10.20.1.20 scope global dynamic enp7s0",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("holds no public address", result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertFalse(os.path.exists(self.sysctl_conf))

    def test_refuses_a_host_with_no_default_route(self):
        result = self.run_script(route="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no default route", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_refuses_a_host_that_is_not_on_the_private_network(self):
        result = self.run_script(
            addresses="2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("holds no address in 10.20.1.0/24", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_refuses_a_subnet_it_cannot_test_membership_of(self):
        # The membership test is a string prefix, which is only a subnet match
        # at /24. A widened range must fail rather than silently narrow it.
        result = self.run_script(subnet="10.20.0.0/16")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only a /24 subnet is understood", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_reports_a_missing_iptables_rather_than_failing_as_a_broken_unit(self):
        result = self.run_script(drop_iptables=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iptables is not installed", result.stderr)

    def test_follows_the_uplink_rather_than_assuming_an_interface_name(self):
        result = self.run_script(
            route="default via 192.0.2.1 dev ens3 proto dhcp src 192.0.2.10 metric 100",
            addresses="\n".join(
                [
                    "2: ens3    inet 192.0.2.10/32 brd 192.0.2.10 scope global dynamic ens3",
                    "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
                ]
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all("ens3" in call for call in self.inserted()))


if __name__ == "__main__":
    unittest.main()
