#!/usr/bin/env python3
"""Unit tests for branchleft_nat.sh.

The script writes forwarding rules on the host that terminates public traffic,
so the return-path rule and the refusal on a private default route are
asserted directly. Routing, netfilter and sysctl are faked on PATH; PATH omits
/usr/sbin, where the real iptables and ip live, so the missing-iptables case
is testable on any machine.
"""

import os
import re
import stat
import subprocess
import tempfile
import unittest

from runbook_sections import runbook_section

SCRIPT = os.path.join(os.path.dirname(__file__), "branchleft_nat.sh")
UNIT = os.path.join(os.path.dirname(__file__), "branchleft-nat.service")
HAND_INSTALLER = os.path.join(os.path.dirname(__file__), "nat-gateway.sh")
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

# -C on the nat table is the legacy masquerade lookup, and is answered on its own
# variable; every other -C is a forwarding accept.
FAKE_IPTABLES = """#!/usr/bin/env bash
args="$*"
printf '%s\\n' "$args" >> "$FAKE_IPTABLES_LOG"
case "$args" in
    *"-S DOCKER-USER"*) exit "${FAKE_IPTABLES_DOCKER_USER_EXIT:-1}" ;;
    "-t nat -C "*) exit "${FAKE_IPTABLES_LEGACY_MASQ_EXIT:-1}" ;;
    *" -C "*) exit "${FAKE_IPTABLES_CHECK_EXIT:-1}" ;;
    *" -I "*) exit "${FAKE_IPTABLES_INSERT_EXIT:-0}" ;;
esac
exit 0
"""

# `nft list table ip branchleft_edge_nat` answers with the captured kernel text when the table is
# there and fails like the kernel does when it is not.
FAKE_NFT = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_NFT_LOG"
case "$*" in
    "list table ip branchleft_edge_nat")
        if [[ "${FAKE_NFT_TABLE:-1}" == "1" ]]; then
            printf '%s' "$FAKE_NFT_TABLE_TEXT"
            exit 0
        fi
        echo "Error: No such file or directory" >&2
        exit 1
        ;;
esac
exit 0
"""

# The runtime value of net.ipv4.ip_forward. The reconciler only reads it; any other sysctl call
# is logged so that a test can show it never writes one.
FAKE_SYSCTL = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_SYSCTL_LOG"
case "$*" in
    "-n net.ipv4.ip_forward") printf '%s\\n' "${FAKE_SYSCTL_FORWARD:-1}"; exit 0 ;;
esac
exit 0
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
case "$*" in
    "is-active --quiet docker.service") exit "${FAKE_SYSTEMCTL_DOCKER_ACTIVE_EXIT:-1}" ;;
esac
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

# A real capture: `nft list table ip branchleft_edge_nat` from nftables v1.1.3 on Debian 13, taken in
# a container after loading the table the edge_firewall role renders, with the uplink named eth0.
NFT_NAT_TABLE_CAPTURE = (
    "table ip branchleft_edge_nat {\n"
    "\tchain postrouting {\n"
    "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
    '\t\tip saddr 10.20.1.0/24 oifname "eth0" masquerade\n'
    "\t}\n"
    "}\n"
)


class NatGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "ip"), FAKE_IP)
        self._write_fake(os.path.join(bin_dir, "iptables"), FAKE_IPTABLES)
        self._write_fake(os.path.join(bin_dir, "nft"), FAKE_NFT)
        self._write_fake(os.path.join(bin_dir, "sysctl"), FAKE_SYSCTL)
        self._write_fake(os.path.join(bin_dir, "systemctl"), FAKE_SYSTEMCTL)
        self.bin_dir = bin_dir

        self.iptables_log = os.path.join(self.tmp.name, "iptables.log")
        self.nft_log = os.path.join(self.tmp.name, "nft.log")
        self.sysctl_log = os.path.join(self.tmp.name, "sysctl.log")

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
        docker_active=False,
        rule_present=False,
        subnet=None,
        drop_iptables=False,
        drop_nft=False,
        insert_exit="0",
        nft_table=True,
        legacy_masquerade=False,
        forwarding="1",
        nat_table_text=NFT_NAT_TABLE_CAPTURE,
    ):
        if drop_iptables:
            os.remove(os.path.join(self.bin_dir, "iptables"))
        if drop_nft:
            os.remove(os.path.join(self.bin_dir, "nft"))
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ROUTE": route,
                "FAKE_IP_ADDR": addresses,
                "FAKE_IPTABLES_LOG": self.iptables_log,
                "FAKE_IPTABLES_DOCKER_USER_EXIT": "0" if docker_user else "1",
                "FAKE_IPTABLES_CHECK_EXIT": "0" if rule_present else "1",
                "FAKE_IPTABLES_LEGACY_MASQ_EXIT": "0" if legacy_masquerade else "1",
                "FAKE_IPTABLES_INSERT_EXIT": insert_exit,
                "FAKE_NFT_LOG": self.nft_log,
                "FAKE_NFT_TABLE": "1" if nft_table else "0",
                "FAKE_NFT_TABLE_TEXT": nat_table_text,
                "FAKE_SYSCTL_LOG": self.sysctl_log,
                "FAKE_SYSCTL_FORWARD": forwarding,
                "FAKE_SYSTEMCTL_DOCKER_ACTIVE_EXIT": "0" if docker_active else "1",
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

    def sysctl_calls(self):
        if not os.path.exists(self.sysctl_log):
            return []
        with open(self.sysctl_log, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def test_installs_the_two_forwarding_accepts_and_nothing_else(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.inserted(),
            [
                "-t filter -I DOCKER-USER 1 -s 10.20.1.0/24 -o eth0 -j ACCEPT",
                "-t filter -I DOCKER-USER 1 -d 10.20.1.0/24 -i eth0 "
                "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            ],
        )

    def test_inserts_no_masquerade_and_writes_no_sysctl(self):
        # The masquerade and the forwarding sysctl have one home each, the edge_firewall role.
        # The reconciler may look for the masquerade and read the forwarding value; it must
        # never add the one or set the other. Red if either returns to this script.
        result = self.run_script(nft_table=False, legacy_masquerade=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c for c in self.inserted() if "MASQUERADE" in c], [])
        self.assertEqual([c for c in self.iptables_calls() if " -A " in c], [])
        self.assertEqual([c for c in self.sysctl_calls() if "-w" in c.split()], [])
        self.assertEqual([c for c in self.sysctl_calls() if "ip_forward=" in c], [])

    def test_the_return_direction_is_accepted_only_for_established_flows(self):
        self.run_script()
        inbound = [call for call in self.inserted() if " -i eth0" in call]
        self.assertEqual(len(inbound), 1)
        self.assertIn("--ctstate ESTABLISHED,RELATED", inbound[0])

    def test_uses_the_forward_chain_when_docker_is_not_installed(self):
        result = self.run_script(docker_user=False, docker_active=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        filtered = [call for call in self.inserted() if call.startswith("-t filter")]
        self.assertEqual(len(filtered), 2)
        self.assertTrue(all("-I FORWARD 1" in call for call in filtered))
        self.assertIn("filtered in FORWARD", result.stdout)

    def test_uses_docker_user_when_docker_runs_the_iptables_backend(self):
        # The iptables backend is what dockerd has always done: it creates
        # DOCKER-USER at startup, so the daemon being active and the chain
        # existing are the same fact seen twice. Confirms the new active-
        # daemon check does not second-guess a state that is already correct.
        result = self.run_script(docker_user=True, docker_active=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        filtered = [call for call in self.inserted() if call.startswith("-t filter")]
        self.assertTrue(all("-I DOCKER-USER 1" in call for call in filtered))

    def test_refuses_when_docker_is_active_but_docker_user_is_absent(self):
        # This is what Docker's nftables firewall backend looks like from
        # here: the daemon is up, but it never created DOCKER-USER, because
        # under nftables it is not iptables it enforces through at all.
        # Falling back to FORWARD would write a rule Docker's own chains
        # never consult and report success while doing it.
        result = self.run_script(docker_user=False, docker_active=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no DOCKER-USER chain", result.stderr)
        self.assertIn("not a safe substitute", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_adds_nothing_when_the_rules_are_already_present(self):
        result = self.run_script(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertEqual(
            len([c for c in self.iptables_calls() if " -C " in c and "-t filter" in c]), 2
        )

    # A gateway with the forwarding accepts and no masquerade passes every check of its own and
    # has no outbound internet. These are the guard against that, each red if its refusal goes.
    def test_accepts_the_masquerade_in_the_nftables_table(self):
        result = self.run_script(nft_table=True, legacy_masquerade=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("masqueraded by the edge_firewall nftables table", result.stdout)

    def test_accepts_the_legacy_masquerade_rule_while_the_table_is_not_there_yet(self):
        # The order of a migration: the role loads and confirms its table before it removes the
        # legacy rule, so a host may carry either; never neither.
        result = self.run_script(nft_table=False, legacy_masquerade=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("masqueraded by the legacy iptables rule", result.stdout)

    def test_refuses_when_no_masquerade_exists_anywhere(self):
        result = self.run_script(nft_table=False, legacy_masquerade=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no masquerade for 10.20.1.0/24 exists", result.stderr)
        self.assertIn("apply the edge_firewall role before this one", result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertNotIn("forwarding 10.20.1.0/24", result.stdout)

    def test_refuses_when_nft_is_not_installed_and_there_is_no_legacy_rule(self):
        # `nft` missing must read as "no table", not as a crash that `set -e` hides.
        result = self.run_script(drop_nft=True, legacy_masquerade=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no masquerade for 10.20.1.0/24 exists", result.stderr)

    def test_an_nft_table_without_a_masquerade_rule_is_not_a_masquerade(self):
        # The table can be there with the masquerade rule gone (a hand edit, a failed load).
        # Presence of the table is not the fact the estate's egress needs.
        env_table = NFT_NAT_TABLE_CAPTURE.replace(
            'ip saddr 10.20.1.0/24 oifname "eth0" masquerade', "counter"
        )
        result = self.run_script(
            nft_table=True, legacy_masquerade=False, nat_table_text=env_table
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no masquerade for 10.20.1.0/24 exists", result.stderr)

    def test_refuses_when_forwarding_is_off(self):
        result = self.run_script(forwarding="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("net.ipv4.ip_forward is not 1", result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertEqual([c for c in self.sysctl_calls() if "-w" in c.split()], [])

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


class NatGatewayHandInstallerTests(unittest.TestCase):
    """nat-gateway.sh used to install this reconciler and its unit by hand. The reconciler no
    longer masquerades, so a host built that way would forward with no masquerade and no outbound
    internet. The script must refuse, on every host, and install nothing."""

    def test_refuses_and_installs_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = os.path.join(tmp, "bin")
            os.makedirs(bin_dir)
            log = os.path.join(tmp, "calls.log")
            for name in ("install", "systemctl", "cmp", "cp", "mv"):
                path = os.path.join(bin_dir, name)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(f'#!/usr/bin/env bash\necho "{name} $*" >> "{log}"\n')
                os.chmod(path, 0o755)
            env = dict(os.environ)
            env["PATH"] = f"{bin_dir}:/usr/bin:/bin"
            result = subprocess.run(
                ["bash", HAND_INSTALLER],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("refusing", result.stderr)
            self.assertIn("edge_firewall", result.stderr)
            self.assertFalse(os.path.exists(log), "the refusing installer ran a command")


class SingleHomeTests(unittest.TestCase):
    """The reconciler's text, not its behaviour: the masquerade and the forwarding sysctl each
    have one home (the edge_firewall role), and the reconciler carries neither. The behaviour
    tests above hold the same fact with fakes; this holds it against a new line that a fake would
    not exercise, such as a branch only a real kernel reaches."""

    def setUp(self):
        with open(SCRIPT, encoding="utf-8") as handle:
            self.code = [
                line for line in handle.read().splitlines() if not line.lstrip().startswith("#")
            ]

    def test_no_line_inserts_or_appends_to_the_nat_table(self):
        for line in self.code:
            with self.subTest(line=line):
                self.assertNotRegex(line, r"ensure_rule\s+nat\b")
                self.assertNotRegex(line, r"iptables\s+-t\s+nat\s+-[IA]\b")

    def test_no_line_writes_the_sysctl_drop_in_or_sets_forwarding(self):
        for line in self.code:
            with self.subTest(line=line):
                self.assertNotIn("99-branchleft-nat.conf", line)
                self.assertNotRegex(line, r"sysctl\s+(-q\s+)?-w")


class UnitFileTests(unittest.TestCase):
    """branchleft-nat.service is installed verbatim by the egress_nat role, so its
    content -- not merely its presence -- is what a later `docker.service`
    restart depends on to reassert the estate's NAT rules."""

    def setUp(self):
        with open(UNIT, encoding="utf-8") as handle:
            self.lines = [line.strip() for line in handle]

    def test_carries_partof_docker_so_a_restart_of_docker_propagates(self):
        self.assertIn("PartOf=docker.service", self.lines)

    def test_does_not_upgrade_to_requires_or_bindsto_docker(self):
        # Either would pull docker.service in as a start dependency, which
        # the existing After (without Requires) deliberately avoids so a
        # Docker-less host still comes up as a gateway.
        joined = "\n".join(self.lines)
        self.assertNotIn("Requires=docker.service", joined)
        self.assertNotIn("BindsTo=docker.service", joined)

    def test_keeps_the_after_ordering_a_docker_less_host_relies_on(self):
        self.assertIn("After=network-online.target docker.service", self.lines)

    def test_runs_after_the_firewall_unit_that_loads_the_masquerade_it_checks_for(self):
        # At boot the reconciler refuses when no masquerade exists, and the masquerade is loaded
        # by branchleft-firewall.service. Without this ordering a boot could race the two and
        # leave the gateway unit failed with a masquerade that arrives a moment later.
        self.assertIn("After=branchleft-firewall.service", self.lines)
        self.assertIn("Wants=branchleft-firewall.service", self.lines)

    def test_does_not_require_the_firewall_unit(self):
        # Requires would stop the reconciler when the firewall load fails, hiding the one message
        # that says what is missing. Wants orders and pulls without making the failure silent.
        self.assertNotIn("Requires=branchleft-firewall.service", self.lines)
        self.assertNotIn("BindsTo=branchleft-firewall.service", self.lines)


def _extract_gateway_check_patterns():
    """Pull the three `grep` invocations out of RUNBOOK-provision-host.md's
    "Confirm the gateway is forwarding" block, so the test below runs the
    exact command an operator pastes rather than a paraphrase of it."""
    section = runbook_section(RUNBOOK, "### 3. Confirm the gateway is forwarding")
    block = section.split("```bash", 1)[1].split("```", 1)[0]
    matches = re.findall(r'grep( -E)? -- "([^"]+)"', block)
    if len(matches) != 3:
        raise AssertionError(
            "expected 3 grep patterns in the runbook's gateway-check block, "
            f"found {len(matches)}"
        )
    return [(flag == " -E", pattern) for flag, pattern in matches]


# The masquerade line is the real capture above (NFT_NAT_TABLE_CAPTURE), taken from the kernel's
# own text. The two DOCKER-USER lines are copied verbatim from a real `iptables -S` capture taken
# against edge1 in its known-correct state; the masquerade is no longer an iptables rule, so
# `iptables -t nat -S POSTROUTING` is not asked about it any more.
DOCKER_USER_SNAPSHOT = (
    "-A DOCKER-USER -d 10.20.1.0/24 -i eth0 -m conntrack "
    "--ctstate RELATED,ESTABLISHED -j ACCEPT\n"
    "-A DOCKER-USER -s 10.20.1.0/24 -o eth0 -j ACCEPT\n"
)
# What `iptables -t nat -S POSTROUTING` shows on a healthy gateway now: Docker's own rule, and no
# masquerade for the estate. The old pattern would have reported the gateway broken.
IPTABLES_POSTROUTING_ON_A_HEALTHY_GATEWAY = "-P POSTROUTING ACCEPT\n-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n"


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

    def test_masquerade_pattern_matches_the_real_nft_capture(self):
        self.assertEqual(
            self._grep(self.masquerade_flag, self.masquerade_pattern, NFT_NAT_TABLE_CAPTURE),
            0,
        )

    def test_masquerade_pattern_is_the_nftables_one_not_the_iptables_one(self):
        # The check moved because `iptables -t nat -S POSTROUTING` cannot see an nftables table.
        # Run against what that command shows on a healthy gateway, the pattern must not match,
        # and the pattern must not be one that could: it names the nft rule's own words.
        self.assertTrue(self.masquerade_flag, "the nft pattern uses extended regular expressions")
        self.assertIn("oifname", self.masquerade_pattern)
        self.assertNotEqual(
            self._grep(
                self.masquerade_flag,
                self.masquerade_pattern,
                IPTABLES_POSTROUTING_ON_A_HEALTHY_GATEWAY,
            ),
            0,
        )

    def test_masquerade_pattern_fails_on_a_table_with_no_masquerade(self):
        # The sabotage the unit test stands for: a capture with no masquerade, red.
        without = NFT_NAT_TABLE_CAPTURE.replace(
            'ip saddr 10.20.1.0/24 oifname "eth0" masquerade\n', ""
        )
        self.assertNotEqual(
            self._grep(self.masquerade_flag, self.masquerade_pattern, without), 0
        )

    def test_masquerade_pattern_fails_on_an_unscoped_masquerade(self):
        # A masquerade for every source launders any packet this host can be made to forward.
        unscoped = NFT_NAT_TABLE_CAPTURE.replace("ip saddr 10.20.1.0/24 ", "")
        self.assertNotEqual(
            self._grep(self.masquerade_flag, self.masquerade_pattern, unscoped), 0
        )

    def test_masquerade_pattern_fails_on_a_masquerade_for_another_subnet(self):
        other = NFT_NAT_TABLE_CAPTURE.replace("10.20.1.0/24", "10.21.1.0/24")
        self.assertNotEqual(
            self._grep(self.masquerade_flag, self.masquerade_pattern, other), 0
        )

    def test_masquerade_pattern_does_not_match_a_dot_that_is_any_character(self):
        # The dots in the subnet are escaped in the pattern: 10x20x1x0/24 is not the estate.
        lookalike = NFT_NAT_TABLE_CAPTURE.replace("10.20.1.0/24", "10x20x1x0/24")
        self.assertNotEqual(
            self._grep(self.masquerade_flag, self.masquerade_pattern, lookalike), 0
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


class RunbookRestartCheckTests(unittest.TestCase):
    """The acceptance bar for the durability fix is a restart proven to
    leave egress working, not merely the three rules proven present once.
    This asserts the operator step that proves it is actually in §3, rather
    than only in this repo's memory of having written it."""

    def setUp(self):
        self.section = runbook_section(RUNBOOK, "### 3. Confirm the gateway is forwarding")

    def test_restarts_docker_before_reverifying(self):
        self.assertIn("systemctl restart docker.service", self.section)

    def test_reverifies_all_three_rules_after_the_restart(self):
        patterns = re.findall(r'grep( -E)? -- "([^"]+)"', self.section)
        # Three in the boot-time block, the same three again after the
        # restart -- a partial re-check would leave exactly the gap the
        # issue names: the masquerade rule surviving while the accepts do not.
        self.assertEqual(len(patterns), 6)

    def test_checks_the_firewall_unit_and_that_nftables_is_masked(self):
        # The boot-time block must assert both halves of the flush-survival design: the role's
        # own unit is what restores the tables at boot, and nftables.service is masked so that
        # neither a restart nor an unattended upgrade can run `nft flush ruleset`.
        first_block = self.section.split("```bash")[1].split("```", 1)[0]
        self.assertIn("systemctl is-enabled branchleft-firewall.service", first_block)
        self.assertRegex(
            first_block, r'test "\$\(systemctl is-enabled nftables\.service\)" = masked'
        )

    def test_no_check_asks_iptables_about_the_masquerade(self):
        # `iptables -t nat -S POSTROUTING` cannot see an nftables table. A check of the
        # masquerade that still asks it would report a healthy gateway broken, or, written
        # loosely, would pass on Docker's own masquerade rule.
        self.assertNotIn("iptables -t nat -S POSTROUTING | grep", self.section)

    def test_compares_the_tables_before_and_after_the_restart(self):
        restart_block = [b for b in self.section.split("```bash")[1:] if "restart docker" in b][0]
        self.assertIn("TABLES_BEFORE", restart_block)
        self.assertIn('test "$TABLES_BEFORE" = "$TABLES_AFTER"', restart_block)


def _extract_restart_check_script():
    """Pull the exact remote command body out of the restart-and-reverify
    block in §3, the same way _extract_gateway_check_patterns does for the
    boot-time block -- so the test below runs the operator's paste, not a
    paraphrase of it."""
    section = runbook_section(RUNBOOK, "### 3. Confirm the gateway is forwarding")
    blocks = section.split("```bash")[1:]
    restart_blocks = [b for b in blocks if "systemctl restart docker.service" in b]
    if len(restart_blocks) != 1:
        raise AssertionError(
            "expected 1 bash block in section 3 that restarts docker, "
            f"found {len(restart_blocks)}"
        )
    restart_block = restart_blocks[0].split("```", 1)[0]
    body = restart_block.split('root@"$EDGE1_IPV4" \'', 1)[1]
    return body.rsplit("'", 1)[0]


FAKE_SYSTEMCTL_RESTART_CHECK = """#!/usr/bin/env bash
case "$*" in
    "show -p ActiveEnterTimestamp --value branchleft-nat.service")
        if [[ -f "$FAKE_SYSTEMCTL_CALLED" ]]; then
            printf '%s
' "$FAKE_SYSTEMCTL_TS_AFTER"
        else
            : > "$FAKE_SYSTEMCTL_CALLED"
            printf '%s
' "$FAKE_SYSTEMCTL_TS_BEFORE"
        fi
        exit 0
        ;;
    "restart docker.service") : > "$FAKE_RESTARTED"; exit 0 ;;
esac
exit 0
"""

FAKE_IPTABLES_SHOW = """#!/usr/bin/env bash
case "$*" in
    "-t filter -S DOCKER-USER") printf '%s' "$DOCKER_USER_SHOW"; exit 0 ;;
esac
exit 1
"""

# The role's two tables as `nft` prints them. After a restart of Docker they must read the same;
# FAKE_NFT_FLUSH_ON_RESTART=1 makes the fake lose them when Docker is restarted, which is what a
# restart of nftables.service (`nft flush ruleset`) would do to a host.
FAKE_NFT_SHOW = """#!/usr/bin/env bash
if [[ "${FAKE_NFT_FLUSH_ON_RESTART:-0}" == "1" && -f "$FAKE_RESTARTED" ]]; then
    echo "Error: No such file or directory" >&2
    exit 1
fi
case "$*" in
    "-s list table inet branchleft_edge") printf '%s' "$NFT_FILTER_TABLE"; exit 0 ;;
    "-s list table ip branchleft_edge_nat"|"list table ip branchleft_edge_nat")
        printf '%s' "$NFT_NAT_TABLE"; exit 0 ;;
esac
exit 1
"""


class RunbookRestartCheckExecutionTests(unittest.TestCase):
    """Runs the pasted restart-and-reverify block for real, against fakes,
    rather than only checking it names the right commands. A block that
    merely mentions `systemctl restart docker.service` would still print
    success on a host where nothing re-ran the reconciler: Docker never
    flushes DOCKER-USER on its own, and the masquerade rule lives in the
    nat table Docker never touches, so the three rule checks alone pass
    whether or not PartOf=docker.service actually fired. Both scenarios are
    exercised here by controlling only what the fake `systemctl show`
    reports for branchleft-nat.service's activation timestamp.
    """

    def setUp(self):
        self.script = _extract_restart_check_script()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "systemctl"), FAKE_SYSTEMCTL_RESTART_CHECK)
        self._write_fake(os.path.join(bin_dir, "iptables"), FAKE_IPTABLES_SHOW)
        self._write_fake(os.path.join(bin_dir, "nft"), FAKE_NFT_SHOW)
        self.bin_dir = bin_dir
        self.called_marker = os.path.join(self.tmp.name, "systemctl-called")
        self.restarted_marker = os.path.join(self.tmp.name, "docker-restarted")

    @staticmethod
    def _write_fake(path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_block(self, ts_before, ts_after, nat_table=NFT_NAT_TABLE_CAPTURE, flush=False):
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_SYSTEMCTL_CALLED": self.called_marker,
                "FAKE_RESTARTED": self.restarted_marker,
                "FAKE_SYSTEMCTL_TS_BEFORE": ts_before,
                "FAKE_SYSTEMCTL_TS_AFTER": ts_after,
                "FAKE_NFT_FLUSH_ON_RESTART": "1" if flush else "0",
                "NFT_FILTER_TABLE": "table inet branchleft_edge {\n}\n",
                "NFT_NAT_TABLE": nat_table,
                "DOCKER_USER_SHOW": DOCKER_USER_SNAPSHOT,
            }
        )
        return subprocess.run(
            ["bash", "-c", self.script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_passes_when_the_reconciler_actually_restarted(self):
        result = self.run_block(
            "Thu 2026-08-20 09:00:00 UTC", "Thu 2026-08-20 13:47:00 UTC"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("gateway survives a docker restart", result.stdout)

    def test_fails_when_the_reconciler_never_restarted(self):
        # The scenario the review round demonstrated: PartOf=docker.service
        # missing or broken, docker restarts, and DOCKER-USER and the
        # masquerade rule survive on their own -- so the three rule checks
        # would still pass. Only the unchanged timestamp catches it, and it
        # has to abort before those checks get a chance to print success.
        same_timestamp = "Thu 2026-08-20 09:00:00 UTC"
        result = self.run_block(same_timestamp, same_timestamp)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("gateway survives a docker restart", result.stdout)

    def test_fails_when_the_restart_took_the_roles_tables_with_it(self):
        # The hazard the role is built around: something on the restart path ran
        # `nft flush ruleset` and the role's tables are gone. The reconciler reran, the
        # timestamp moved, and DOCKER-USER is intact; only the comparison of the tables
        # before and after catches it.
        result = self.run_block(
            "Thu 2026-08-20 09:00:00 UTC", "Thu 2026-08-20 13:47:00 UTC", flush=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("gateway survives a docker restart", result.stdout)

    def test_fails_when_the_nat_table_carries_no_masquerade_after_the_restart(self):
        # The tables are unchanged by the restart, but the masquerade was never there: the
        # pattern, not the comparison, must fail the block.
        result = self.run_block(
            "Thu 2026-08-20 09:00:00 UTC",
            "Thu 2026-08-20 13:47:00 UTC",
            nat_table=NFT_NAT_TABLE_CAPTURE.replace(
                'ip saddr 10.20.1.0/24 oifname "eth0" masquerade\n', ""
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("gateway survives a docker restart", result.stdout)


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
        self.assertEqual(len(commands), 4, commands)
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


PYCACHE_CLEANUP = (
    "find /root/platform-provision -type d -name __pycache__ -prune -exec rm -rf {} +"
)


def _scp_sites_with_following_context():
    """Pair each provisioning `scp` line with the text between it and the
    closing ``` of its code fence -- the same technique
    `rsync_commands_with_following_context` uses in
    test_runbook_rsync_commands.py, reused here because `scp` carries no
    exclude flag either, so a `__pycache__/` this workstation's own test
    runs left under `hetzner/provision/` travels in the same copy."""
    with open(RUNBOOK, encoding="utf-8") as handle:
        lines = handle.readlines()
    sites = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("scp "):
            continue
        following = []
        for later in lines[index + 1 :]:
            if later.strip() == "```":
                break
            following.append(later)
        sites.append((stripped, "".join(following)))
    return sites


class RunbookPycacheCleanupTests(unittest.TestCase):
    """CPython recompiles a `.pyc` on a source size/mtime mismatch rather
    than trusting a foreign one, so a workstation-built `__pycache__/`
    reaching a host is hygiene, not a live defect -- but nothing available
    to CI can observe whether one reaches a host, so the cleanup command's
    presence and position after every `scp -r hetzner/provision/.` site is
    the only thing a test can pin, the same reasoning `RunbookScpCommandTests`
    already applies to the `scp` lines themselves.
    """

    def test_every_scp_site_is_followed_by_the_pycache_cleanup(self):
        sites = _scp_sites_with_following_context()
        self.assertEqual(len(sites), 4, [command for command, _ in sites])
        for command, context in sites:
            with self.subTest(command=command):
                self.assertIn(
                    PYCACHE_CLEANUP,
                    context,
                    f"no __pycache__ cleanup found after: {command}",
                )

    def test_the_cleanup_runs_before_anything_else_touches_the_copy(self):
        for command, context in _scp_sites_with_following_context():
            with self.subTest(command=command):
                cleanup_pos = context.find(PYCACHE_CLEANUP)
                self.assertNotEqual(
                    cleanup_pos, -1, f"no __pycache__ cleanup found after: {command}"
                )
                chmod_pos = context.find("chmod +x")
                if chmod_pos != -1:
                    self.assertLess(
                        cleanup_pos,
                        chmod_pos,
                        f"chmod +x runs before the __pycache__ cleanup after: {command}",
                    )


if __name__ == "__main__":
    unittest.main()
