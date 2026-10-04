#!/usr/bin/env python3
"""Unit tests for branchleft_docker_user_policy.sh.

The script talks to the live network configuration and netfilter, so both are
replaced by fakes earlier on PATH. Rule order is asserted by replaying every
insert into a model of the chain. What each rule is for, and why the order
matters: the ghost-platform-docs runbooks.
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
    *" -C "*)
        case "$args" in *"${FAKE_ABSENT:-@@none@@}"*) exit 1 ;; esac
        exit "${FAKE_IPTABLES_CHECK_EXIT:-1}" ;;
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
# the estate's NAT gateway, identified by holding 10.20.1.10.
GATEWAY_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
    ]
)

# app1's real shape: publicNetworking: true is deliberate for it too
# (ghost-platform/infra/hosts/index.ts, for CI SSH deploy access), so it
# holds a public address exactly like edge1 does. This is the fixture that
# would have tripped a "holds any public interface" guard -- the bug this
# script does not ship because the guard checks the gateway's specific
# address instead.
APP_HOST_WITH_PUBLIC_IP_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.50/32 brd 203.0.113.50 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.100/32 brd 10.20.1.100 scope global dynamic enp7s0",
    ]
)

# ops1's real shape: private-only, like db1 -- no public interface at
# all (publicNetworking: false). The one host self-identification is
# expected to recognise as not a Ghost tenant by default.
OPS1_ADDRESSES = (
    "3: enp7s0    inet 10.20.1.50/32 brd 10.20.1.50 scope global dynamic enp7s0"
)


class DockerUserPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "ip"), FAKE_IP)
        self._write_fake(os.path.join(bin_dir, "iptables"), FAKE_IPTABLES)
        self._write_fake(
            os.path.join(bin_dir, "ip6tables"),
            FAKE_IPTABLES.replace("FAKE_IPTABLES_LOG", "FAKE_IP6TABLES_LOG").replace(
                "FAKE_IPTABLES_DOCKER_USER_EXIT", "FAKE_IP6TABLES_DOCKER_USER_EXIT"
            ),
        )
        self.bin_dir = bin_dir

        self.iptables_log = os.path.join(self.tmp.name, "iptables.log")
        self.ip6tables_log = os.path.join(self.tmp.name, "ip6tables.log")

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
        gateway_ip=None,
        no_db_exception_addresses=None,
        drop_iptables=False,
        insert_exit="0",
        spool_bridge=None,
        ip6_present=True,
        ip6_docker_user=True,
        absent=None,
    ):
        if drop_iptables:
            os.remove(os.path.join(self.bin_dir, "iptables"))
        if not ip6_present:
            os.remove(os.path.join(self.bin_dir, "ip6tables"))
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ADDR": addresses,
                "FAKE_IPTABLES_LOG": self.iptables_log,
                "FAKE_IP6TABLES_LOG": self.ip6tables_log,
                "FAKE_IP6TABLES_DOCKER_USER_EXIT": "0" if ip6_docker_user else "1",
                "FAKE_IPTABLES_DOCKER_USER_EXIT": "0" if docker_user else "1",
                "FAKE_IPTABLES_CHECK_EXIT": "0" if rule_present else "1",
                "FAKE_IPTABLES_INSERT_EXIT": insert_exit,
            }
        )
        # BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST must be genuinely absent from
        # the child environment for the "never told anything" case -- popping
        # it here guards against it leaking in from this test process's own
        # environment, which os.environ was just copied from above.
        env.pop("BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST", None)
        if absent is not None:
            env["FAKE_ABSENT"] = absent
        if subnet is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_SUBNET"] = subnet
        if db_host is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST"] = db_host
        if db_port is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_DB_PORT"] = db_port
        if spool_bridge is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_MAIL_SPOOL_BRIDGE"] = spool_bridge
        if gateway_ip is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_GATEWAY_IP"] = gateway_ip
        if no_db_exception_addresses is not None:
            env["BRANCHLEFT_DOCKER_USER_POLICY_NO_DB_EXCEPTION_ADDRESSES"] = (
                no_db_exception_addresses
            )
        return subprocess.run(
            ["bash", SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def _calls(self, path):
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def iptables_calls(self):
        return self._calls(self.iptables_log)

    def ip6tables_calls(self):
        return self._calls(self.ip6tables_log)

    def inserted(self):
        return [call for call in self.iptables_calls() if " -I " in call]

    def inserted6(self):
        return [call for call in self.ip6tables_calls() if " -I " in call]

    def inserted_into(self, chain):
        return [call for call in self.inserted() if f" -I {chain} " in call]

    @staticmethod
    def replay(calls, chain, start=None):
        """The chain's final top-to-bottom order after every insert lands."""
        rules = list(start or [])
        for call in calls:
            parts = call.split()
            if " -I " in call and parts[3] == chain:
                rules.insert(int(parts[4]) - 1, " ".join(parts[5:]))
        return rules

    def final_chain_order(self, chain="DOCKER-USER", calls=None):
        return self.replay(self.inserted() if calls is None else calls, chain)

    # -- Trap 1: rule order is load-bearing -----------------------------

    EXISTING_POLICY = [
        "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-d 10.20.1.20 -p tcp --dport 3306 -j ACCEPT",
        "-d 10.20.1.0/24 -j DROP",
        "-d 169.254.169.254 -j DROP",
    ]
    SPOOL_RULES = [
        "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-i br-mailspool ! -o br-mailspool -j DROP",
        "-d 10.20.1.20 -p tcp --dport 3306 -j ACCEPT",
        "-d 10.20.1.0/24 -j DROP",
        "-d 169.254.169.254 -j DROP",
    ]
    INPUT_RULES = [
        "-i br-mailspool -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-i br-mailspool -j DROP",
    ]

    def test_installs_the_rules_in_the_decided_order(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.final_chain_order(), self.SPOOL_RULES)
        self.assertEqual(self.final_chain_order("INPUT"), self.INPUT_RULES)

    def test_a_rerun_on_a_host_with_the_policy_gives_the_same_order_as_a_boot(self):
        # Only the spool rules are missing: the forward drop must land at
        # position 2, directly under the conntrack accept, not above it.
        result = self.run_script(rule_present=True, absent="mailspool")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.replay(self.inserted(), "DOCKER-USER", self.EXISTING_POLICY),
            self.SPOOL_RULES,
        )

    def test_the_spool_rules_are_written_after_the_conntrack_accept(self):
        # A failure in the new calls must never leave the drops without the
        # reply accept ahead of them.
        self.run_script()
        calls = self.inserted()
        conntrack = next(
            i for i, c in enumerate(calls) if "DOCKER-USER 1 -m conntrack" in c
        )
        first_spool = next(i for i, c in enumerate(calls) if "br-mailspool" in c)
        self.assertLess(conntrack, first_spool)

    def test_a_failing_spool_insert_leaves_the_conntrack_accept_in_place(self):
        result = self.run_script(rule_present=True, absent="mailspool", insert_exit="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.replay(self.inserted(), "DOCKER-USER", self.EXISTING_POLICY)[0],
            self.EXISTING_POLICY[0],
        )

    # -- IPv6: app1 holds a public IPv6 address --------------------------

    FORWARD_DROP = "-i br-mailspool ! -o br-mailspool -j DROP"

    def test_ipv6_forward_drop_sits_above_dockers_own_return(self):
        # On Docker 27 the chain's only rule is its RETURN; a drop inserted
        # beneath it is never reached, so it must land at position 1.
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.replay(self.inserted6(), "DOCKER-USER", ["-j RETURN"]),
            [self.FORWARD_DROP, "-j RETURN"],
        )

    def test_ipv6_forward_drop_works_on_an_empty_chain(self):
        self.run_script()
        self.assertEqual(
            self.replay(self.inserted6(), "DOCKER-USER", []), [self.FORWARD_DROP]
        )

    def test_ipv6_input_pair_is_replies_then_drop(self):
        self.run_script()
        self.assertEqual(self.replay(self.inserted6(), "INPUT"), self.INPUT_RULES)

    def test_ipv4_forward_drop_stays_under_the_conntrack_accept(self):
        self.run_script(rule_present=True, absent="mailspool")
        self.assertEqual(
            self.replay(self.inserted(), "DOCKER-USER", self.EXISTING_POLICY)[:2],
            [self.EXISTING_POLICY[0], self.FORWARD_DROP],
        )

    def test_ipv6_rules_name_the_spool_bridge_alone(self):
        self.run_script()
        self.assertEqual(len(self.inserted6()), 3)
        for call in self.inserted6():
            self.assertIn(" -i br-mailspool", call)

    def test_ipv6_adds_nothing_when_already_present(self):
        result = self.run_script(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted6(), [])

    def test_ipv6_without_a_docker_user_chain_still_gets_the_input_rules(self):
        result = self.run_script(ip6_docker_user=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.replay(self.inserted6(), "INPUT"), self.INPUT_RULES)
        self.assertFalse(any("DOCKER-USER" in c for c in self.inserted6()))
        self.assertIn("forward drop skipped", result.stdout)

    def test_a_missing_ip6tables_fails_after_the_ipv4_policy_is_in_place(self):
        result = self.run_script(ip6_present=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ip6tables is not installed", result.stderr)
        self.assertEqual(self.final_chain_order(), self.SPOOL_RULES)

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
        drops = [
            call
            for call in self.inserted_into("DOCKER-USER")
            if call.endswith("-j DROP") and "-i " not in call
        ]
        self.assertEqual(len(drops), 2)
        self.assertTrue(any("10.20.1.0/24" in call for call in drops))
        self.assertTrue(any("169.254.169.254" in call for call in drops))

    def test_db_host_and_port_are_overridable_for_testing(self):
        result = self.run_script(db_host="10.20.1.99", db_port="3307")
        self.assertEqual(result.returncode, 0, result.stderr)
        db_rule = next(call for call in self.inserted() if "10.20.1.99" in call)
        self.assertIn("--dport 3307", db_rule)

    def test_db_host_unset_still_defaults_to_db1(self):
        # Regression guard for the app1 case: not passing the variable at all
        # must keep carving out the db1 exception, exactly as before this
        # script could be told to skip it.
        result = self.run_script(db_host=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.20.1.20" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 7)

    def test_db_host_explicitly_empty_skips_the_db_accept_rule_entirely(self):
        # The fix for a real reachability defect: an app host with no
        # legitimate reason to reach db1 (ops1 is not a Ghost tenant)
        # must get a deny-all-to-the-subnet policy with no exception, not a
        # copy of app1's allow-list pointed at nothing.
        result = self.run_script(db_host="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("--dport" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 6)
        # The two drops and the conntrack accept still land -- this host
        # still needs its own reply traffic to work, just no forward exception.
        self.assertTrue(any("10.20.1.0/24" in call for call in self.inserted()))
        self.assertTrue(any("169.254.169.254" in call for call in self.inserted()))
        self.assertTrue(any("ESTABLISHED,RELATED" in call for call in self.inserted()))

    # -- The mail spool's drain bridge ------------------------------------

    SPOOL_FORWARD_DROP = "-i br-mailspool ! -o br-mailspool -j DROP"

    def test_spool_bridge_forward_drop_is_between_conntrack_and_db1_accept(self):
        # Above the db1 accept so the spool cannot borrow Ghost's exception,
        # below conntrack so the drain reply on the published port still flows.
        self.run_script()
        order = self.final_chain_order()
        spool = next(i for i, c in enumerate(order) if self.SPOOL_FORWARD_DROP in c)
        established = next(i for i, c in enumerate(order) if "ESTABLISHED" in c)
        db = next(i for i, c in enumerate(order) if "--dport 3306" in c)
        subnet = next(i for i, c in enumerate(order) if "-d 10.20.1.0/24 -j DROP" in c)
        self.assertLess(established, spool)
        self.assertLess(spool, db)
        self.assertLess(spool, subnet)

    def test_spool_bridge_forward_drop_exists_even_with_no_db_exception(self):
        result = self.run_script(db_host="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(self.SPOOL_FORWARD_DROP in c for c in self.inserted()))

    def test_spool_bridge_input_returns_replies_before_dropping_the_rest(self):
        # INPUT sees a connection to the host itself. The reply to the drain
        # request must be accepted ahead of the blanket drop for the bridge.
        self.run_script()
        order = self.final_chain_order("INPUT")
        self.assertEqual(len(order), 2)
        self.assertIn("--ctstate ESTABLISHED,RELATED -j ACCEPT", order[0])
        self.assertEqual(order[1], "-i br-mailspool -j DROP")

    def test_every_spool_rule_matches_the_spool_bridge_interface_alone(self):
        # The rules reach into INPUT, so each must name the one interface: an
        # unscoped INPUT drop would cut the host off, and this guards it.
        self.run_script()
        for call in self.inserted_into("INPUT"):
            self.assertIn("-i br-mailspool", call)
        for call in self.inserted():
            if "br-mailspool" in call:
                self.assertTrue(" -i br-mailspool" in call, call)

    def test_spool_bridge_name_is_overridable_for_testing(self):
        result = self.run_script(spool_bridge="br-other")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("-i br-other ! -o br-other -j DROP" in c for c in self.inserted()))
        self.assertFalse(any("br-mailspool" in c for c in self.inserted()))

    def test_spool_bridge_is_the_name_the_spool_renderer_gives_it(self):
        # The fixed name is a contract with ghost-platform's render-core
        # (MAIL_SPOOL_DRAIN_BRIDGE); a rename on either side must be loud.
        with open(SCRIPT, encoding="utf-8") as handle:
            self.assertIn(":-br-mailspool}", handle.read())

    # -- Trap 4: self-identification, not a one-off env var, must decide it -

    def test_self_identified_non_tenant_host_skips_the_db_accept_by_default(self):
        # The actual fix for the reachability defect: ops1 gets this
        # for free, from its own address, with nothing set in its
        # environment at all -- the shape every real boot is in, since
        # branchleft-docker-user-policy.service carries no Environment=.
        result = self.run_script(addresses=OPS1_ADDRESSES, db_host=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("--dport" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 6)

    def test_explicit_db_host_override_wins_over_self_identification(self):
        # An explicit caller value, even on a self-identifying host, is
        # still honoured -- self-identification is a default, not a lock.
        result = self.run_script(addresses=OPS1_ADDRESSES, db_host="10.20.1.20")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.20.1.20" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 7)

    def test_ordinary_app_host_is_not_self_identified_as_non_tenant(self):
        # The discriminating case: app1's own address must not trip the
        # default meant for ops1 -- otherwise every Ghost tenant host
        # silently loses its db1 route the moment this ships.
        result = self.run_script(addresses=APP_HOST_ADDRESSES, db_host=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.20.1.20" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 7)

    def test_no_db_exception_addresses_is_overridable_for_testing(self):
        result = self.run_script(
            addresses=APP_HOST_ADDRESSES,
            db_host=None,
            no_db_exception_addresses="10.20.1.100",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("--dport" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 6)

    def test_subnet_is_overridable_for_testing(self):
        result = self.run_script(subnet="10.30.1.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.30.1.0/24" in call for call in self.inserted()))

    def test_adds_nothing_when_the_rules_are_already_present(self):
        result = self.run_script(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertEqual(len([c for c in self.iptables_calls() if " -C " in c]), 7)

    def test_fails_when_a_rule_cannot_be_inserted(self):
        # `set -e` is what carries this: a host that half-applied its rules
        # has to exit non-zero rather than print its closing summary and let
        # the unit go active with an incomplete policy.
        result = self.run_script(insert_exit="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("app-host isolation applied", result.stdout)

    # -- Trap 2: this policy is for app hosts only -----------------------

    def test_refuses_the_host_holding_the_gateway_address(self):
        result = self.run_script(addresses=GATEWAY_ADDRESSES)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estate's gateway address", result.stderr)
        self.assertIn("scoped to app hosts only", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_a_private_only_host_is_not_treated_as_the_gateway(self):
        # The discriminating case for the guard: an app host's own private
        # address must not itself trip it.
        result = self.run_script(addresses=APP_HOST_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_public_app_host_is_not_treated_as_the_gateway(self):
        # The regression this guards: app1 is also created with
        # publicNetworking: true, deliberately, for CI's SSH deploy path
        # (ghost-platform/infra/hosts/index.ts) -- so "does this host hold
        # any public address" is not a valid test for "is this the gateway".
        # A guard built on that premise would refuse to run on the one host
        # this policy exists to protect, while reporting a role-scope error
        # that looks like it is working as designed.
        result = self.run_script(addresses=APP_HOST_WITH_PUBLIC_IP_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.inserted(), [])

    def test_the_guards_own_gateway_address_is_overridable_for_testing(self):
        result = self.run_script(
            addresses=APP_HOST_ADDRESSES, gateway_ip="10.20.1.100"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estate's gateway address", result.stderr)

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

    def test_states_not_every_app_host_is_a_ghost_tenant(self):
        # ops1 runs this same step unchanged, but must not silently
        # get app1's db1 exception -- the runbook has to say so, not just
        # the script, or an operator reading only this file has no way to
        # know the two hosts end up with different rules.
        self.assertIn("Not every app host is a Ghost tenant", self.text)
        self.assertIn("ops1", self.text)

    def test_is_not_part_of_run_all(self):
        # Deliberately outside run-all.sh, the same way nat-gateway.sh is.
        with open(
            os.path.join(os.path.dirname(__file__), "run-all.sh"), encoding="utf-8"
        ) as handle:
            run_all = handle.read()
        self.assertNotIn("app-host-isolation.sh", run_all)


if __name__ == "__main__":
    unittest.main()
