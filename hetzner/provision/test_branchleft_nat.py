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
import re
import stat
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "branchleft_nat.sh")
RUNBOOK = os.path.join(
    os.path.dirname(__file__), "..", "RUNBOOK-provision-host.md"
)

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
    *" -I "*) exit "${FAKE_IPTABLES_INSERT_EXIT:-0}" ;;
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
        insert_exit="0",
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
                "FAKE_IPTABLES_INSERT_EXIT": insert_exit,
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

    def test_refuses_a_public_host_whose_default_route_leaves_the_private_nic(self):
        # The discriminating case for the guard's scoping. This host *does*
        # hold a public address, so a check of the weaker form -- "is there a
        # public address anywhere on this host" -- would pass it and rebuild
        # the routing loop. Publicness has to be a property of the interface
        # the default route actually leaves through.
        result = self.run_script(
            route="default via 10.20.1.1 dev enp7s0 proto dhcp metric 100",
            addresses="\n".join(
                [
                    "2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0",
                    "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
                ]
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("holds no public address", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_fails_when_a_rule_cannot_be_inserted(self):
        # `set -e` is what carries this, so a host that half-applied its rules
        # has to exit non-zero rather than print its closing summary and let
        # the unit go active with no egress behind it.
        result = self.run_script(insert_exit="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("forwarding 10.20.1.0/24", result.stdout)

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


def _extract_gateway_check_patterns():
    """Pull the three `grep` invocations out of RUNBOOK-provision-host.md's
    "Confirm the gateway is forwarding" block, so the test below runs the
    exact command an operator pastes rather than a paraphrase of it."""
    with open(RUNBOOK, encoding="utf-8") as handle:
        text = handle.read()
    section = text.split("### 3. Confirm the gateway is forwarding", 1)[1]
    block = section.split("```bash", 1)[1].split("```", 1)[0]
    matches = re.findall(r'grep( -E)? -- "([^"]+)"', block)
    if len(matches) != 3:
        raise AssertionError(
            "expected 3 grep patterns in the runbook's gateway-check block, "
            f"found {len(matches)}"
        )
    return [(flag == " -E", pattern) for flag, pattern in matches]


# The two DOCKER-USER lines are copied verbatim from a real `iptables -S`
# capture taken against edge1 in its known-correct state. The POSTROUTING
# line is not itself a capture, but it is not a free guess either: iptables
# renders an insert's flags back in the order they were given, with no
# reordering possible for a rule that carries only one flag of each kind --
# which is exactly what `branchleft_nat.sh` passes for the masquerade rule.
NAT_POSTROUTING_SNAPSHOT = "-A POSTROUTING -s 10.20.1.0/24 -o eth0 -j MASQUERADE\n"
DOCKER_USER_SNAPSHOT = (
    "-A DOCKER-USER -d 10.20.1.0/24 -i eth0 -m conntrack "
    "--ctstate RELATED,ESTABLISHED -j ACCEPT\n"
    "-A DOCKER-USER -s 10.20.1.0/24 -o eth0 -j ACCEPT\n"
)


class RunbookGatewayCheckTests(unittest.TestCase):
    """§3 of RUNBOOK-provision-host.md is pasted into an operator's shell
    verbatim, so these run the same `grep` invocations against a real
    `iptables -S` capture. The fake `iptables` above echoes back whatever
    arguments it is given, so it cannot catch a pattern that only fails
    against genuine kernel output -- which is what happened to the
    conntrack-state check this class covers.
    """

    def setUp(self):
        patterns = _extract_gateway_check_patterns()
        self.masquerade_flag, self.masquerade_pattern = patterns[0]
        self.outbound_flag, self.outbound_pattern = patterns[1]
        self.return_flag, self.return_pattern = patterns[2]

    @staticmethod
    def _grep(extended, pattern, text):
        args = ["grep"]
        if extended:
            args.append("-E")
        args += ["--", pattern]
        result = subprocess.run(
            args, input=text, capture_output=True, text=True, check=False
        )
        return result.returncode

    def test_masquerade_pattern_matches_a_real_postrouting_capture(self):
        self.assertEqual(
            self._grep(
                self.masquerade_flag, self.masquerade_pattern, NAT_POSTROUTING_SNAPSHOT
            ),
            0,
        )

    def test_outbound_accept_pattern_matches_a_real_docker_user_capture(self):
        self.assertEqual(
            self._grep(self.outbound_flag, self.outbound_pattern, DOCKER_USER_SNAPSHOT),
            0,
        )

    def test_return_accept_pattern_matches_the_order_iptables_actually_renders(self):
        # This is the regression: `iptables -S` renders the ctstate bitmask
        # `branchleft_nat.sh` sets as `RELATED,ESTABLISHED`, not the order
        # the script passed it in, and the old pattern only accepted the
        # order the script passed.
        self.assertEqual(
            self._grep(self.return_flag, self.return_pattern, DOCKER_USER_SNAPSHOT), 0
        )

    def test_return_accept_pattern_also_matches_the_order_the_script_passes(self):
        alternate = DOCKER_USER_SNAPSHOT.replace(
            "RELATED,ESTABLISHED", "ESTABLISHED,RELATED"
        )
        self.assertEqual(self._grep(self.return_flag, self.return_pattern, alternate), 0)

    def test_return_accept_pattern_does_not_match_a_missing_rule(self):
        broken = "-A DOCKER-USER -s 10.20.1.0/24 -o eth0 -j ACCEPT\n"
        self.assertNotEqual(
            self._grep(self.return_flag, self.return_pattern, broken), 0
        )


def _extract_scp_commands():
    """Pull every provisioning `scp` line out of RUNBOOK-provision-host.md."""
    with open(RUNBOOK, encoding="utf-8") as handle:
        lines = handle.readlines()
    return [line.strip() for line in lines if line.strip().startswith("scp ")]


class RunbookScpCommandTests(unittest.TestCase):
    """RUNBOOK-provision-host.md's `scp` commands copy hetzner/provision/
    onto a host that may already carry a copy from an earlier run, and scp's
    own semantics make the exact command shape the whole difference between
    refreshing that copy in place and nesting a stale one under it. A test
    process cannot exercise real scp/SFTP semantics without a real sshd, so
    this asserts the command shape itself rather than the copy behaviour.
    """

    def test_every_scp_site_copies_provision_dot_to_a_slash_free_destination(self):
        commands = _extract_scp_commands()
        self.assertEqual(len(commands), 3, commands)
        for command in commands:
            tokens = command.split()
            source = next(t for t in tokens if t.startswith("hetzner/provision"))
            destination = tokens[-1]
            self.assertTrue(
                source.endswith("provision/."),
                f"source must copy the directory's contents, not itself: {command}",
            )
            self.assertFalse(
                destination.endswith("/"),
                "a destination trailing slash makes scp fail outright in "
                f"SFTP mode when the destination does not yet exist: {command}",
            )


if __name__ == "__main__":
    unittest.main()
