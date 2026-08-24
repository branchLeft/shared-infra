#!/usr/bin/env python3
"""Unit tests for branchleft_docker_user_policy.sh.

The script bounds what a compromised tenant container can reach on the
private subnet, and getting it wrong is not a smaller version of the same
mistake in either direction: writing the drop before the conntrack accept
takes every tenant site down (DOCKER-USER matches post-DNAT addresses, so an
inbound flow's own reply matches the drop), and running it on the estate's
NAT gateway cuts that host's own forwarding path to every app host and to
db1. Three behaviours are asserted directly rather than smoke-tested by a
real run: the final rule order after every insert has landed, the refusal on
a host with a public interface, and the fail-closed refusal when DOCKER-USER
does not exist.

The script talks to the live network configuration and netfilter, neither of
which a test process may do. Both are replaced by fakes earlier on `PATH`,
the same shape test_branchleft_nat.py uses for the same reason.
"""

import os
import stat
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "branchleft_docker_user_policy.sh")
UNIT = os.path.join(os.path.dirname(__file__), "branchleft-docker-user-policy.service")
RUNBOOK = os.path.join(os.path.dirname(__file__), "..", "RUNBOOK-provision-host.md")

FAKE_IP = """#!/usr/bin/env bash
for arg in "$@"; do
    case "$arg" in
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

# An app host: one private address, no public interface at all -- every app
# host is created with publicNetworking: false.
APP_HOST_ADDRESSES = (
    "3: enp7s0    inet 10.20.1.100/32 brd 10.20.1.100 scope global dynamic enp7s0"
)

# edge1's own addresses, the same fixture test_branchleft_nat.py uses for it:
# the one host in the estate that terminates public traffic.
GATEWAY_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
    ]
)


class DockerUserPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "ip"), FAKE_IP)
        self._write_fake(os.path.join(bin_dir, "iptables"), FAKE_IPTABLES)
        self.bin_dir = bin_dir

        self.iptables_log = os.path.join(self.tmp.name, "iptables.log")

    @staticmethod
    def _write_fake(path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_script(
        self,
        addresses=APP_HOST_ADDRESSES,
        docker_user=True,
        rule_present=False,
        subnet=None,
        db_host=None,
        db_port=None,
        drop_iptables=False,
        insert_exit="0",
    ):
        if drop_iptables:
            os.remove(os.path.join(self.bin_dir, "iptables"))
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ADDR": addresses,
                "FAKE_IPTABLES_LOG": self.iptables_log,
                "FAKE_IPTABLES_DOCKER_USER_EXIT": "0" if docker_user else "1",
                "FAKE_IPTABLES_CHECK_EXIT": "0" if rule_present else "1",
                "FAKE_IPTABLES_INSERT_EXIT": insert_exit,
            }
        )
        if subnet is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_SUBNET"] = subnet
        if db_host is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST"] = db_host
        if db_port is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_DB_PORT"] = db_port
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

    def final_chain_order(self):
        # Every insert lands at position 1, so the call made *last* ends up
        # matched *first* -- the final top-to-bottom order is the reverse of
        # the order the script issued the inserts in.
        return list(reversed(self.inserted()))

    # -- Trap 1: rule order is load-bearing -----------------------------

    def test_installs_the_three_rules_in_the_decided_order(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.final_chain_order(),
            [
                "-t filter -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                "-t filter -I DOCKER-USER 1 -d 10.20.1.20 -p tcp --dport 3306 -j ACCEPT",
                "-t filter -I DOCKER-USER 1 -d 10.20.1.0/24 -j DROP",
                "-t filter -I DOCKER-USER 1 -d 169.254.169.254 -j DROP",
            ],
        )

    def test_conntrack_established_is_evaluated_before_either_drop(self):
        # This is the outage the naive form of this policy causes: a
        # published port is a DNAT, so an inbound flow's reply leaves the
        # container with dst inside the subnet -- exactly what the drop
        # matches -- and only conntrack state tells that reply apart from a
        # tenant-initiated connection to a co-tenant.
        self.run_script()
        order = self.final_chain_order()
        established_index = next(
            i for i, call in enumerate(order) if "ESTABLISHED,RELATED" in call
        )
        subnet_drop_index = next(
            i for i, call in enumerate(order) if "-d 10.20.1.0/24 -j DROP" in call
        )
        metadata_drop_index = next(
            i for i, call in enumerate(order) if "169.254.169.254" in call
        )
        self.assertLess(established_index, subnet_drop_index)
        self.assertLess(established_index, metadata_drop_index)

    def test_db1_accept_is_evaluated_before_either_drop(self):
        self.run_script()
        order = self.final_chain_order()
        db_index = next(i for i, call in enumerate(order) if "--dport 3306" in call)
        subnet_drop_index = next(
            i for i, call in enumerate(order) if "-d 10.20.1.0/24 -j DROP" in call
        )
        metadata_drop_index = next(
            i for i, call in enumerate(order) if "169.254.169.254" in call
        )
        self.assertLess(db_index, subnet_drop_index)
        self.assertLess(db_index, metadata_drop_index)

    def test_db1_accept_is_scoped_to_tcp_3306_not_the_whole_host(self):
        # db1 also carries an exporter and administrative sockets over the
        # same address; the allow-list is this one rule, not the host.
        self.run_script()
        db_rule = next(call for call in self.inserted() if "10.20.1.20" in call)
        self.assertIn("-p tcp", db_rule)
        self.assertIn("--dport 3306", db_rule)

    def test_drop_names_the_subnet_and_the_metadata_address_only(self):
        # A blanket deny of everything that isn't db1 would also catch a
        # tenant's own outbound traffic to the public internet -- the
        # outbound-egress rule this programme has ruled out on cost grounds.
        self.run_script()
        drops = [call for call in self.inserted() if call.endswith("-j DROP")]
        self.assertEqual(len(drops), 2)
        self.assertTrue(any("10.20.1.0/24" in call for call in drops))
        self.assertTrue(any("169.254.169.254" in call for call in drops))

    def test_db_host_and_port_are_overridable_for_testing(self):
        result = self.run_script(db_host="10.20.1.99", db_port="3307")
        self.assertEqual(result.returncode, 0, result.stderr)
        db_rule = next(call for call in self.inserted() if "10.20.1.99" in call)
        self.assertIn("--dport 3307", db_rule)

    def test_subnet_is_overridable_for_testing(self):
        result = self.run_script(subnet="10.30.1.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.30.1.0/24" in call for call in self.inserted()))

    def test_adds_nothing_when_the_rules_are_already_present(self):
        result = self.run_script(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertEqual(len([c for c in self.iptables_calls() if " -C " in c]), 4)

    def test_fails_when_a_rule_cannot_be_inserted(self):
        # `set -e` is what carries this: a host that half-applied its rules
        # has to exit non-zero rather than print its closing summary and let
        # the unit go active with an incomplete policy.
        result = self.run_script(insert_exit="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("app-host isolation applied", result.stdout)

    # -- Trap 2: this policy is for app hosts only -----------------------

    def test_refuses_a_host_with_a_public_interface(self):
        result = self.run_script(addresses=GATEWAY_ADDRESSES)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estate's NAT gateway", result.stderr)
        self.assertIn("scoped to app hosts only", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_a_private_only_host_is_not_treated_as_the_gateway(self):
        # The discriminating case for the guard: an app host's own private
        # address must not itself trip the public-interface check.
        result = self.run_script(addresses=APP_HOST_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)

    # -- Trap 3: DOCKER-USER's existence is conditional, fail closed ----

    def test_fails_closed_when_docker_user_chain_is_absent(self):
        # Unlike branchleft_nat.sh there is no FORWARD fallback: a policy
        # that bounds container traffic has nothing to bound on a host where
        # Docker is not enforcing through iptables, and writing it into
        # FORWARD would filter forwarded traffic that has nothing to do with
        # any container.
        result = self.run_script(docker_user=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no DOCKER-USER chain", result.stderr)
        self.assertIn("no safe substitute", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_reports_a_missing_iptables_rather_than_failing_as_a_broken_unit(self):
        result = self.run_script(drop_iptables=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iptables is not installed", result.stderr)

    # -- Scope limit stated in the code, not only in prose ---------------

    def test_never_targets_the_app_hosts_own_private_address(self):
        # DOCKER-USER only sees forwarded traffic; a container reaching the
        # app host's own address is delivered locally via INPUT, which this
        # chain never sees. Nothing this script installs should reference an
        # app-host address as a destination -- doing so would look like a
        # control that bounds that path when it cannot.
        self.run_script()
        for call in self.inserted():
            self.assertNotIn("10.20.1.100", call)


class UnitFileTests(unittest.TestCase):
    """branchleft-docker-user-policy.service is installed verbatim by
    app-host-isolation.sh, so its content -- not merely its presence -- is
    what a later `docker.service` restart depends on to reassert the
    policy."""

    def setUp(self):
        with open(UNIT, encoding="utf-8") as handle:
            self.lines = [line.strip() for line in handle]

    def test_carries_partof_docker_so_a_restart_of_docker_propagates(self):
        self.assertIn("PartOf=docker.service", self.lines)

    def test_does_not_upgrade_to_requires_or_bindsto_docker(self):
        joined = "\n".join(self.lines)
        self.assertNotIn("Requires=docker.service", joined)
        self.assertNotIn("BindsTo=docker.service", joined)

    def test_is_a_remain_after_exit_oneshot(self):
        self.assertIn("Type=oneshot", self.lines)
        self.assertIn("RemainAfterExit=yes", self.lines)


class RunbookAppHostIsolationTests(unittest.TestCase):
    """The runbook is where an operator learns this exists and which hosts
    it applies to -- this asserts the section is there rather than only in
    this repo's memory of having written it."""

    def setUp(self):
        with open(RUNBOOK, encoding="utf-8") as handle:
            self.text = handle.read()

    def test_lists_app_host_isolation_in_the_script_table(self):
        self.assertIn("app-host-isolation.sh", self.text)

    def test_states_it_is_scoped_to_app_hosts_only(self):
        self.assertIn("App hosts only", self.text)

    def test_states_the_input_scope_limit(self):
        # The control this policy does not provide: bounding a container's
        # reach to the app host's own address goes via INPUT, which
        # DOCKER-USER never sees.
        self.assertIn("INPUT", self.text)

    def test_is_not_part_of_run_all(self):
        # Deliberately outside run-all.sh, the same way nat-gateway.sh is.
        with open(
            os.path.join(os.path.dirname(__file__), "run-all.sh"), encoding="utf-8"
        ) as handle:
            run_all = handle.read()
        self.assertNotIn("app-host-isolation.sh", run_all)


if __name__ == "__main__":
    unittest.main()
