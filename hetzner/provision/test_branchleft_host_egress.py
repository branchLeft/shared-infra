#!/usr/bin/env python3
"""Unit tests for branchleft_host_egress.sh.

The script is the host half of the estate's egress path: without it, a
private-only host has no default route and no resolver, and every apt
mirror is unreachable for the host's whole life. Its two highest-risk
behaviours are asserted directly rather than smoke-tested by a real run:
that it derives the gateway from the host's own routing table instead of a
hardcoded address, and that it is a clean no-op on any host that already has
a public interface.

The script talks to the live routing table and `resolvconf`, neither of
which a test process may do. Both are replaced by fakes earlier on `PATH`,
and the resolver head path is redirected with the environment variable the
script reads as an override.
"""

import os
import stat
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "branchleft_host_egress.sh")
RUNBOOK = os.path.join(os.path.dirname(__file__), "..", "RUNBOOK-provision-host.md")

FAKE_IP = """#!/usr/bin/env bash
args="$*"
case "$args" in
    *"route replace"*)
        printf '%s\\n' "$args" >> "$FAKE_IP_LOG"
        exit 0
        ;;
    *"route show default"*)
        printf '%s\\n' "$FAKE_IP_ROUTE_DEFAULT"
        exit 0
        ;;
    *"route show"*)
        printf '%s\\n' "$FAKE_IP_ROUTE_TABLE"
        exit 0
        ;;
    *"addr show"*)
        printf '%s\\n' "$FAKE_IP_ADDR"
        exit 0
        ;;
esac
exit 0
"""

FAKE_RESOLVCONF = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_RESOLVCONF_LOG"
exit 0
"""

# A host with a public interface: the same fixture shape as
# test_branchleft_nat.py's EDGE_ADDRESSES (`ip -4 -o addr show scope global`
# on edge1), which carries a public address alongside a private one.
PUBLIC_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
    ]
)

# A private-only host: one address, and it is private.
PRIVATE_ONLY_ADDRESSES = (
    "3: enp7s0    inet 10.20.1.20/32 brd 10.20.1.20 scope global dynamic enp7s0"
)

# What Hetzner's DHCP actually delivers to a private-only host: the subnet
# route and the metadata route, both `via` the same gateway -- and no
# default. `169.254.169.254` is the metadata service, hardcoded because it
# is Hetzner's, not the estate's.
SUBNET_ROUTE_TABLE = "\n".join(
    [
        "10.20.0.0/16 via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
        "169.254.169.254 via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
    ]
)

NO_DEFAULT_ROUTE = ""


class HostEgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "ip"), FAKE_IP)
        self._write_fake(os.path.join(bin_dir, "resolvconf"), FAKE_RESOLVCONF)
        self.bin_dir = bin_dir

        self.ip_log = os.path.join(self.tmp.name, "ip.log")
        self.resolvconf_log = os.path.join(self.tmp.name, "resolvconf.log")
        # Nested and not yet created, so a passing test also proves the
        # write creates its parent directories rather than assuming they
        # already exist -- `/etc/resolvconf/resolv.conf.d/` is not
        # guaranteed present before `resolvconf` is installed.
        self.resolver_head = os.path.join(
            self.tmp.name, "resolvconf.d", "resolv.conf.d", "head"
        )

    @staticmethod
    def _write_fake(path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_script(
        self,
        addresses,
        route_table="",
        route_default=NO_DEFAULT_ROUTE,
        nameserver_1=None,
        nameserver_2=None,
    ):
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ADDR": addresses,
                "FAKE_IP_ROUTE_TABLE": route_table,
                "FAKE_IP_ROUTE_DEFAULT": route_default,
                "FAKE_IP_LOG": self.ip_log,
                "FAKE_RESOLVCONF_LOG": self.resolvconf_log,
                "BRANCHLEFT_EGRESS_RESOLVER_HEAD": self.resolver_head,
            }
        )
        if nameserver_1 is not None:
            env["BRANCHLEFT_EGRESS_NAMESERVER_1"] = nameserver_1
        if nameserver_2 is not None:
            env["BRANCHLEFT_EGRESS_NAMESERVER_2"] = nameserver_2
        return subprocess.run(
            ["bash", SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def ip_calls(self):
        if not os.path.exists(self.ip_log):
            return []
        with open(self.ip_log, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def resolvconf_calls(self):
        if not os.path.exists(self.resolvconf_log):
            return []
        with open(self.resolvconf_log, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def test_is_a_clean_noop_on_a_host_with_a_public_interface(self):
        result = self.run_script(PUBLIC_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no-op", result.stdout)
        self.assertEqual(self.ip_calls(), [])
        self.assertEqual(self.resolvconf_calls(), [])
        self.assertFalse(os.path.exists(self.resolver_head))

    def test_sets_the_default_route_and_resolver_on_a_fresh_private_only_host(self):
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default=NO_DEFAULT_ROUTE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.ip_calls(), ["route replace default via 10.20.0.1 dev enp7s0"]
        )
        with open(self.resolver_head, encoding="utf-8") as handle:
            self.assertEqual(
                handle.read(), "nameserver 185.12.64.1\nnameserver 185.12.64.2\n"
            )
        self.assertEqual(self.resolvconf_calls(), ["-u"])

    def test_derives_the_gateway_from_the_routing_table_rather_than_hardcoding_it(self):
        # The regression this guards: an earlier hand-repair used
        # 10.20.0.1 because that happened to be live when it was written.
        # A different gateway here has to produce a different route.
        route_table = "\n".join(
            [
                "10.20.0.0/16 via 10.30.0.9 dev enp7s0 proto dhcp metric 1024",
                "169.254.169.254 via 10.30.0.9 dev enp7s0 proto dhcp metric 1024",
            ]
        )
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES, route_table=route_table, route_default=NO_DEFAULT_ROUTE
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.ip_calls(), ["route replace default via 10.30.0.9 dev enp7s0"]
        )

    def test_excludes_the_metadata_route_from_the_gateway_candidates(self):
        # A metadata route with a *different* via-address than the subnet
        # route proves it is excluded rather than merely deduplicated: if it
        # were not, this would either pick the wrong gateway or trip the
        # ambiguous-candidates guard below.
        route_table = "\n".join(
            [
                "10.20.0.0/16 via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
                "169.254.169.254 via 10.20.0.9 dev enp7s0 proto dhcp metric 1024",
            ]
        )
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES, route_table=route_table, route_default=NO_DEFAULT_ROUTE
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.ip_calls(), ["route replace default via 10.20.0.1 dev enp7s0"]
        )

    def test_is_idempotent_when_the_route_and_resolver_are_already_correct(self):
        os.makedirs(os.path.dirname(self.resolver_head))
        with open(self.resolver_head, "w", encoding="utf-8") as handle:
            handle.write("nameserver 185.12.64.1\nnameserver 185.12.64.2\n")

        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default="default via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already up to date", result.stdout)
        self.assertEqual(self.ip_calls(), [])
        self.assertEqual(self.resolvconf_calls(), [])

    def test_replaces_a_stale_default_route_pointing_at_the_wrong_gateway(self):
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default="default via 10.99.0.1 dev enp7s0 proto static metric 50",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.ip_calls(), ["route replace default via 10.20.0.1 dev enp7s0"]
        )

    def test_fails_when_no_subnet_route_can_be_found(self):
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES, route_table="", route_default=NO_DEFAULT_ROUTE
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no private subnet route", result.stderr)

    def test_fails_rather_than_guesses_when_two_candidate_routes_exist(self):
        route_table = "\n".join(
            [
                "10.20.0.0/16 via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
                "10.21.0.0/16 via 10.21.0.1 dev enp7s0 proto dhcp metric 1024",
            ]
        )
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES, route_table=route_table, route_default=NO_DEFAULT_ROUTE
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("more than one candidate", result.stderr)
        self.assertEqual(self.ip_calls(), [])

    def test_uses_the_overridable_nameservers_for_testing(self):
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default=NO_DEFAULT_ROUTE,
            nameserver_1="192.0.2.1",
            nameserver_2="192.0.2.2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.resolver_head, encoding="utf-8") as handle:
            self.assertEqual(
                handle.read(), "nameserver 192.0.2.1\nnameserver 192.0.2.2\n"
            )


class RunbookHostEgressPreconditionTests(unittest.TestCase):
    """The host half is a precondition the runbook has to state as clearly as
    the network and gateway halves it already documented -- this asserts the
    section exists rather than only living in this repo's memory of having
    written it."""

    def setUp(self):
        with open(RUNBOOK, encoding="utf-8") as handle:
            self.text = handle.read()

    def test_states_the_host_half_precondition(self):
        self.assertIn("05-configure-host-egress.sh", self.text)
        self.assertIn("third precondition", self.text)

    def test_carries_a_verification_command(self):
        self.assertIn("branchleft-host-egress.service", self.text)
        self.assertIn("ip route show default", self.text)

    def test_carries_a_one_line_reboot_repair(self):
        self.assertIn("ip route replace default via", self.text)
        # The repair derives the gateway rather than restating a specific
        # host's address, which is the exact hardcoding the fix retires.
        self.assertNotIn("via 10.20.0.1 dev", self.text)

    def test_never_uses_a_platform_owner_gated_phrasing_that_docs_lint_rejects(self):
        self.assertNotIn("Rob-gated", self.text)


if __name__ == "__main__":
    unittest.main()
