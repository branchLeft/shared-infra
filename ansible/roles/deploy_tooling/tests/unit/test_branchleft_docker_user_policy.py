"""Unit tests for branchleft_docker_user_policy.py, the program the role installs.

The program talks to the live network configuration and to netfilter, so both are replaced by
fake programs earlier on PATH. Rule order is asserted by replaying every insert into a model of
the chain. What each rule is for, and why the order matters, is in the program's docstring and
the role's README.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

import branchleft_docker_user_policy as policy

ROLE = Path(__file__).resolve().parents[2]
REPOSITORY = ROLE.parents[2]
PROGRAM = ROLE / "files" / "branchleft_docker_user_policy.py"
UNIT = ROLE / "files" / "branchleft-docker-user-policy.service"
HAND_UNIT = REPOSITORY / "hetzner" / "provision" / "branchleft-docker-user-policy.service"
CONTROL_PLANE_COMPOSE = REPOSITORY / "hetzner" / "control-plane" / "stack" / "compose.yml"

FAKE_IP = """#!@PY@
import os
import sys

if "addr" in sys.argv[1:]:
    sys.stdout.write(os.environ["FAKE_IP_ADDR"] + "\\n")
sys.exit(int(os.environ.get("FAKE_IP_EXIT", "0")))
"""

# Without FAKE_STATE the fake answers from the environment: a check succeeds for every
# rule or fails for every rule (except those that contain FAKE_ABSENT), an insert succeeds or
# fails as told. With FAKE_STATE it keeps the chains in a file and answers like the real
# tool, so a second run sees what the first inserted.
FAKE_IPTABLES = """#!@PY@
import json
import os
import sys

args = " ".join(sys.argv[1:])
with open(os.environ["@LOG@"], "a", encoding="utf-8") as handle:
    handle.write(args + "\\n")
if os.environ.get("FAKE_HANG") and os.environ["FAKE_HANG"] in args:
    os.execvp("sleep", ["sleep", "60"])
if "-S DOCKER-USER" in args:
    sys.exit(int(os.environ.get("@DOCKER_USER_EXIT@", "1")))
state_path = os.environ.get("FAKE_STATE")
words = sys.argv[1:]
if state_path:
    try:
        with open(state_path, encoding="utf-8") as handle:
            state = json.load(handle)
    except FileNotFoundError:
        state = {}
    key = os.path.basename(sys.argv[0]) + " " + words[3]
    rule = " ".join(words[5:] if " -I " in args else words[4:])
    rules = state.setdefault(key, [])
    if " -C " in args:
        sys.exit(0 if rule in rules else 1)
    if " -I " in args:
        rules.insert(int(words[4]) - 1, " ".join(words[5:]))
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
    sys.exit(0)
if " -C " in args:
    if os.environ.get("FAKE_ABSENT", "@@none@@") in args:
        sys.exit(1)
    sys.exit(int(os.environ.get("FAKE_IPTABLES_CHECK_EXIT", "1")))
if " -I " in args:
    sys.exit(int(os.environ.get("FAKE_IPTABLES_INSERT_EXIT", "0")))
"""

# An app host: one private address, no public interface at all.
APP_HOST_ADDRESSES = "3: enp7s0    inet 10.20.1.100/32 brd 10.20.1.100 scope global dynamic enp7s0"

# edge1's own addresses: the estate's NAT gateway, identified by holding 10.20.1.10.
GATEWAY_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.10/32 brd 203.0.113.10 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.10/32 brd 10.20.1.10 scope global dynamic enp7s0",
    ]
)

# app1's real shape: it holds a public address exactly like edge1 does, so a guard that
# asked "does this host hold any public interface" would refuse to run on the one host the
# policy exists to protect. The guard checks the gateway's specific address instead.
APP_HOST_WITH_PUBLIC_IP_ADDRESSES = "\n".join(
    [
        "2: eth0    inet 203.0.113.50/32 brd 203.0.113.50 scope global dynamic eth0",
        "3: enp7s0    inet 10.20.1.100/32 brd 10.20.1.100 scope global dynamic enp7s0",
    ]
)

# ops1's real shape: private-only, and the one host that recognises itself as not a Ghost
# tenant host by default.
OPS1_ADDRESSES = "3: enp7s0    inet 10.20.1.50/32 brd 10.20.1.50 scope global dynamic enp7s0"

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
FORWARD_DROP = "-i br-mailspool ! -o br-mailspool -j DROP"
PORT_8300 = (
    "-p tcp -m conntrack --ctorigdst 10.20.1.50 --ctorigdstport 8300 ! -s 10.20.1.10 -j DROP"
)
PORT_8301 = PORT_8300.replace("8300", "8301")
PORT_8302 = PORT_8300.replace("8300", "8302")
PORT_8303 = PORT_8300.replace("8300", "8303")
PROTECTED_PORT_RULES = [PORT_8300, PORT_8301, PORT_8302, PORT_8303]
# The whole DOCKER-USER chain of ops1, top to bottom: the established accept, the spool's
# forward drop, the four port drops (the last inserted is the first evaluated), the subnet
# drop and the metadata drop, and no database exception.
OPS1_CHAIN = [
    "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    FORWARD_DROP,
    PORT_8303,
    PORT_8302,
    PORT_8301,
    PORT_8300,
    "-d 10.20.1.0/24 -j DROP",
    "-d 169.254.169.254 -j DROP",
]


def replay(calls: Sequence[str], chain: str, start: Sequence[str] = ()) -> list[str]:
    """Return the chain's final top-to-bottom order after every insert lands."""
    rules = list(start)
    for call in calls:
        parts = call.split()
        if " -I " in call and parts[3] == chain:
            rules.insert(int(parts[4]) - 1, " ".join(parts[5:]))
    return rules


class PolicyCase(unittest.TestCase):
    """A scratch directory with fake ip, iptables and ip6tables, and a way to run the program."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin_dir = Path(self.tmp.name) / "bin"
        self.bin_dir.mkdir()
        self.write_fake("ip", FAKE_IP)
        self.write_fake(
            "iptables",
            FAKE_IPTABLES.replace("@LOG@", "FAKE_IPTABLES_LOG").replace(
                "@DOCKER_USER_EXIT@", "FAKE_IPTABLES_DOCKER_USER_EXIT"
            ),
        )
        self.write_fake(
            "ip6tables",
            FAKE_IPTABLES.replace("@LOG@", "FAKE_IP6TABLES_LOG").replace(
                "@DOCKER_USER_EXIT@", "FAKE_IP6TABLES_DOCKER_USER_EXIT"
            ),
        )
        self.iptables_log = Path(self.tmp.name) / "iptables.log"
        self.ip6tables_log = Path(self.tmp.name) / "ip6tables.log"
        self.state_path = Path(self.tmp.name) / "state.json"

    def write_fake(self, name: str, content: str) -> None:
        """Write one fake program, run by the interpreter that runs the tests."""
        path = self.bin_dir / name
        path.write_text(content.replace("@PY@", sys.executable), encoding="utf-8")
        path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def environment(
        self,
        addresses: str = APP_HOST_ADDRESSES,
        *,
        docker_user: bool = True,
        rule_present: bool = False,
        insert_exit: str = "0",
        ip6_docker_user: bool = True,
        ip6_docker_user_exit: str | None = None,
        ip_exit: str = "0",
        extra: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        """Return the child's environment: PATH with the fakes, and what the fakes are told."""
        ip6_exit = ip6_docker_user_exit or ("0" if ip6_docker_user else "1")
        env = dict(os.environ)
        for name in [key for key in env if key.startswith(policy.ENVIRONMENT_PREFIX)]:
            del env[name]
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ADDR": addresses,
                "FAKE_IPTABLES_LOG": str(self.iptables_log),
                "FAKE_IP6TABLES_LOG": str(self.ip6tables_log),
                "FAKE_IP_EXIT": ip_exit,
                "FAKE_IP6TABLES_DOCKER_USER_EXIT": ip6_exit,
                "FAKE_IPTABLES_DOCKER_USER_EXIT": "0" if docker_user else "1",
                "FAKE_IPTABLES_CHECK_EXIT": "0" if rule_present else "1",
                "FAKE_IPTABLES_INSERT_EXIT": insert_exit,
            }
        )
        env.update(extra or {})
        return env

    def run_program(
        self,
        addresses: str = APP_HOST_ADDRESSES,
        *,
        policy_env: Mapping[str, str] | None = None,
        absent: str | None = None,
        drop_iptables: bool = False,
        ip6_present: bool = True,
        stateful: bool = False,
        arguments: Sequence[str] = (),
        docker_user: bool = True,
        rule_present: bool = False,
        insert_exit: str = "0",
        ip6_docker_user: bool = True,
        ip6_docker_user_exit: str | None = None,
        ip_exit: str = "0",
    ) -> subprocess.CompletedProcess[str]:
        """Run the program as a host would, as a separate process."""
        if drop_iptables:
            (self.bin_dir / "iptables").unlink()
        if not ip6_present:
            (self.bin_dir / "ip6tables").unlink()
        extra = {
            f"{policy.ENVIRONMENT_PREFIX}{name}": value
            for name, value in (policy_env or {}).items()
        }
        if absent is not None:
            extra["FAKE_ABSENT"] = absent
        if stateful:
            extra["FAKE_STATE"] = str(self.state_path)
        env = self.environment(
            addresses,
            docker_user=docker_user,
            rule_present=rule_present,
            insert_exit=insert_exit,
            ip6_docker_user=ip6_docker_user,
            ip6_docker_user_exit=ip6_docker_user_exit,
            ip_exit=ip_exit,
            extra=extra,
        )
        return subprocess.run(  # noqa: S603 -- the interpreter and the program are fixed paths
            [sys.executable, "-I", str(PROGRAM), *arguments],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def calls(path: Path) -> list[str]:
        """Return the lines a fake logged."""
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8").splitlines()

    def iptables_calls(self) -> list[str]:
        """Return every call the fake iptables saw."""
        return self.calls(self.iptables_log)

    def ip6tables_calls(self) -> list[str]:
        """Return every call the fake ip6tables saw."""
        return self.calls(self.ip6tables_log)

    def inserted(self) -> list[str]:
        """Return the IPv4 inserts."""
        return [call for call in self.iptables_calls() if " -I " in call]

    def inserted6(self) -> list[str]:
        """Return the IPv6 inserts."""
        return [call for call in self.ip6tables_calls() if " -I " in call]

    def inserted_into(self, chain: str) -> list[str]:
        """Return the IPv4 inserts into one chain."""
        return [call for call in self.inserted() if f" -I {chain} " in call]

    def final_chain_order(self, chain: str = "DOCKER-USER") -> list[str]:
        """Return the IPv4 chain's order after the inserts."""
        return replay(self.inserted(), chain)


class OrderTests(PolicyCase):
    """The rules are inserted in the decided order, so the chain ends in it."""

    def test_installs_the_rules_in_the_decided_order(self) -> None:
        result = self.run_program()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.final_chain_order(), SPOOL_RULES)
        self.assertEqual(self.final_chain_order("INPUT"), INPUT_RULES)

    def test_a_rerun_on_a_host_with_the_policy_gives_the_same_order_as_a_boot(self) -> None:
        # Only the spool rules are missing: the forward drop must land at position 2,
        # directly under the conntrack accept, not above it.
        result = self.run_program(rule_present=True, absent="mailspool")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(replay(self.inserted(), "DOCKER-USER", EXISTING_POLICY), SPOOL_RULES)

    def test_the_spool_rules_are_written_after_the_conntrack_accept(self) -> None:
        # A failure in the spool calls must never leave the drops without the reply accept
        # ahead of them.
        self.run_program()
        calls = self.inserted()
        conntrack = next(i for i, c in enumerate(calls) if "DOCKER-USER 1 -m conntrack" in c)
        first_spool = next(i for i, c in enumerate(calls) if "br-mailspool" in c)
        self.assertLess(conntrack, first_spool)

    def test_a_failing_spool_insert_leaves_the_conntrack_accept_in_place(self) -> None:
        result = self.run_program(rule_present=True, absent="mailspool", insert_exit="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            replay(self.inserted(), "DOCKER-USER", EXISTING_POLICY)[0], EXISTING_POLICY[0]
        )

    def test_conntrack_established_is_evaluated_before_either_drop(self) -> None:
        # The outage the naive form of this policy causes: a published port is a DNAT, so an
        # inbound flow's reply leaves the container with a destination inside the subnet,
        # which the drop matches, and only conntrack state tells that reply apart from a
        # tenant-initiated connection to a co-tenant.
        self.run_program()
        order = self.final_chain_order()
        established = next(i for i, call in enumerate(order) if "ESTABLISHED,RELATED" in call)
        subnet_drop = next(i for i, call in enumerate(order) if "-d 10.20.1.0/24 -j DROP" in call)
        metadata_drop = next(i for i, call in enumerate(order) if "169.254.169.254" in call)
        self.assertLess(established, subnet_drop)
        self.assertLess(established, metadata_drop)

    def test_db1_accept_is_evaluated_before_either_drop(self) -> None:
        self.run_program()
        order = self.final_chain_order()
        database = next(i for i, call in enumerate(order) if "--dport 3306" in call)
        subnet_drop = next(i for i, call in enumerate(order) if "-d 10.20.1.0/24 -j DROP" in call)
        metadata_drop = next(i for i, call in enumerate(order) if "169.254.169.254" in call)
        self.assertLess(database, subnet_drop)
        self.assertLess(database, metadata_drop)

    def test_db1_accept_is_scoped_to_tcp_3306_not_the_whole_host(self) -> None:
        # db1 also carries an exporter and administrative sockets over the same address; the
        # allow-list is this one rule, not the host.
        self.run_program()
        rule = next(call for call in self.inserted() if "10.20.1.20" in call)
        self.assertIn("-p tcp", rule)
        self.assertIn("--dport 3306", rule)

    def test_drop_names_the_subnet_and_the_metadata_address_only(self) -> None:
        # A blanket deny of everything that is not db1 would also catch a tenant's own
        # outbound traffic to the public internet.
        self.run_program()
        drops = [
            call
            for call in self.inserted_into("DOCKER-USER")
            if call.endswith("-j DROP") and "-i " not in call
        ]
        self.assertEqual(len(drops), 2)
        self.assertTrue(any("10.20.1.0/24" in call for call in drops))
        self.assertTrue(any("169.254.169.254" in call for call in drops))


class IpSixTests(PolicyCase):
    """app1 holds a public IPv6 address, so the spool rules are written for both families."""

    def test_ipv6_forward_drop_sits_above_dockers_own_return(self) -> None:
        # On Docker 27 the chain's only rule is its RETURN; a drop inserted beneath it is
        # never reached, so it must land at position 1.
        result = self.run_program()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            replay(self.inserted6(), "DOCKER-USER", ["-j RETURN"]), [FORWARD_DROP, "-j RETURN"]
        )

    def test_ipv6_forward_drop_works_on_an_empty_chain(self) -> None:
        self.run_program()
        self.assertEqual(replay(self.inserted6(), "DOCKER-USER"), [FORWARD_DROP])

    def test_ipv6_input_pair_is_replies_then_drop(self) -> None:
        self.run_program()
        self.assertEqual(replay(self.inserted6(), "INPUT"), INPUT_RULES)

    def test_ipv4_forward_drop_stays_under_the_conntrack_accept(self) -> None:
        self.run_program(rule_present=True, absent="mailspool")
        self.assertEqual(
            replay(self.inserted(), "DOCKER-USER", EXISTING_POLICY)[:2],
            [EXISTING_POLICY[0], FORWARD_DROP],
        )

    def test_ipv6_rules_name_the_spool_bridge_alone(self) -> None:
        self.run_program()
        self.assertEqual(len(self.inserted6()), 3)
        for call in self.inserted6():
            self.assertIn(" -i br-mailspool", call)

    def test_ipv6_adds_nothing_when_already_present(self) -> None:
        result = self.run_program(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted6(), [])

    def test_ipv6_without_a_docker_user_chain_still_gets_the_input_rules(self) -> None:
        result = self.run_program(ip6_docker_user=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(replay(self.inserted6(), "INPUT"), INPUT_RULES)
        self.assertFalse(any("DOCKER-USER" in c for c in self.inserted6()))
        self.assertIn("forward drop skipped", result.stdout)

    def test_a_missing_ip6tables_fails_after_the_ipv4_policy_is_in_place(self) -> None:
        result = self.run_program(ip6_present=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ip6tables is not installed", result.stderr)
        self.assertEqual(self.final_chain_order(), SPOOL_RULES)


class SpoolBridgeTests(PolicyCase):
    """The mail spool's drain bridge may open nothing, forwarded or to the host itself."""

    def test_spool_bridge_forward_drop_is_between_conntrack_and_db1_accept(self) -> None:
        # Above the db1 accept so the spool cannot borrow Ghost's exception, below
        # conntrack so the drain reply on the published port still flows.
        self.run_program()
        order = self.final_chain_order()
        spool = next(i for i, c in enumerate(order) if FORWARD_DROP in c)
        established = next(i for i, c in enumerate(order) if "ESTABLISHED" in c)
        database = next(i for i, c in enumerate(order) if "--dport 3306" in c)
        subnet = next(i for i, c in enumerate(order) if "-d 10.20.1.0/24 -j DROP" in c)
        self.assertLess(established, spool)
        self.assertLess(spool, database)
        self.assertLess(spool, subnet)

    def test_spool_bridge_forward_drop_exists_even_with_no_db_exception(self) -> None:
        result = self.run_program(policy_env={"DB_HOST": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(FORWARD_DROP in c for c in self.inserted()))

    def test_spool_bridge_input_returns_replies_before_dropping_the_rest(self) -> None:
        # INPUT sees a connection to the host itself. The reply to the drain request must be
        # accepted ahead of the blanket drop for the bridge.
        self.run_program()
        order = self.final_chain_order("INPUT")
        self.assertEqual(len(order), 2)
        self.assertIn("--ctstate ESTABLISHED,RELATED -j ACCEPT", order[0])
        self.assertEqual(order[1], "-i br-mailspool -j DROP")

    def test_every_spool_rule_matches_the_spool_bridge_interface_alone(self) -> None:
        # The rules reach into INPUT, so each must name the one interface: an unscoped INPUT
        # drop would cut the host off.
        self.run_program()
        for call in self.inserted_into("INPUT"):
            self.assertIn("-i br-mailspool", call)
        for call in self.inserted():
            if "br-mailspool" in call:
                self.assertIn(" -i br-mailspool", call)

    def test_spool_bridge_name_is_overridable_for_testing(self) -> None:
        result = self.run_program(policy_env={"MAIL_SPOOL_BRIDGE": "br-other"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("-i br-other ! -o br-other -j DROP" in c for c in self.inserted()))
        self.assertFalse(any("br-mailspool" in c for c in self.inserted()))

    def test_spool_bridge_is_the_name_the_spool_renderer_gives_it(self) -> None:
        # The fixed name is a contract with the spool renderer's MAIL_SPOOL_DRAIN_BRIDGE; a
        # rename on either side must be loud.
        self.assertEqual(policy.DEFAULT_MAIL_SPOOL_BRIDGE, "br-mailspool")


class ProtectedPortTests(PolicyCase):
    """ops1's published control-plane ports are reachable from the gateway alone."""

    def test_ops1_refuses_every_source_but_the_gateway_on_8300_to_8303(self) -> None:
        result = self.run_program(OPS1_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        order = self.final_chain_order()
        for rule in PROTECTED_PORT_RULES:
            self.assertIn(rule, order)

    def test_ops1_ends_with_exactly_this_chain(self) -> None:
        result = self.run_program(OPS1_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.final_chain_order(), OPS1_CHAIN)

    def test_the_status_page_port_is_one_of_the_protected_ports(self) -> None:
        self.assertEqual(policy.DEFAULT_PROTECTED_PORTS.split(), ["8300", "8301", "8302", "8303"])

    def test_the_port_drops_sit_under_the_conntrack_accept_on_a_boot(self) -> None:
        # Above the accept they would drop the replies of the gateway's own allowed
        # connections: the outage, not the tightening.
        self.run_program(OPS1_ADDRESSES)
        order = self.final_chain_order()
        established = next(i for i, c in enumerate(order) if "ESTABLISHED" in c)
        for rule in PROTECTED_PORT_RULES:
            self.assertLess(established, order.index(rule))
        self.assertEqual(established, 0)

    def test_a_rerun_with_only_the_port_drops_missing_keeps_the_accept_first(self) -> None:
        result = self.run_program(OPS1_ADDRESSES, rule_present=True, absent="ctorigdstport")
        self.assertEqual(result.returncode, 0, result.stderr)
        order = replay(self.inserted(), "DOCKER-USER", EXISTING_POLICY)
        self.assertEqual(order[0], EXISTING_POLICY[0])
        for rule in PROTECTED_PORT_RULES:
            self.assertIn(rule, order[:5])

    def test_the_port_drops_name_tcp_and_one_original_port_each_not_the_host(self) -> None:
        # Nextcloud's published port (and every other) must match nothing.
        self.run_program(OPS1_ADDRESSES)
        drops = [c for c in self.inserted() if "ctorigdstport" in c]
        self.assertEqual(len(drops), 4)
        for call in drops:
            self.assertIn("-p tcp", call)
            self.assertIn("--ctorigdst 10.20.1.50", call)
            self.assertNotIn("11000", call)
        for port in ("8300", "8301", "8302", "8303"):
            self.assertEqual(len([c for c in drops if f"--ctorigdstport {port} " in c]), 1, port)

    def test_an_ordinary_app_host_gets_no_port_drops(self) -> None:
        # The discriminating case: app1 must not lose anything to ops1's rule.
        for addresses in (APP_HOST_ADDRESSES, APP_HOST_WITH_PUBLIC_IP_ADDRESSES):
            with self.subTest(addresses=addresses):
                self.iptables_log.unlink(missing_ok=True)
                result = self.run_program(addresses)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any("ctorigdst" in c for c in self.iptables_calls()))

    def test_the_port_drops_are_idempotent(self) -> None:
        result = self.run_program(OPS1_ADDRESSES, rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_the_gateway_source_exempt_is_the_gateway_address(self) -> None:
        self.run_program(OPS1_ADDRESSES, policy_env={"GATEWAY_IP": "10.20.1.11"})
        self.assertTrue(any("! -s 10.20.1.11 -j DROP" in c for c in self.inserted()))

    def test_protected_address_and_ports_are_overridable_for_testing(self) -> None:
        self.run_program(
            policy_env={"PROTECTED_ADDRESS": "10.20.1.100", "PROTECTED_PORTS": "9001"},
        )
        self.assertTrue(
            any("--ctorigdst 10.20.1.100 --ctorigdstport 9001" in c for c in self.inserted())
        )
        self.assertFalse(any("8301" in c for c in self.inserted()))

    def test_the_protected_address_default_is_ops1s(self) -> None:
        self.assertEqual(policy.DEFAULT_PROTECTED_ADDRESS, "10.20.1.50")
        self.assertEqual(policy.DEFAULT_PROTECTED_PORTS, "8300 8301 8302 8303")

    def test_the_ports_match_the_compose_publishes(self) -> None:
        compose = CONTROL_PLANE_COMPOSE.read_text(encoding="utf-8")
        # The sign-in service listens on 8080 inside its container.
        self.assertIn("'10.20.1.50:8300:8080'", compose)
        for port in ("8301", "8302"):
            self.assertIn(f"'10.20.1.50:{port}:{port}'", compose)


class VariantTests(PolicyCase):
    """Self-identification, not a one-off environment variable, decides the variant."""

    def test_self_identified_non_tenant_host_skips_the_db_accept_by_default(self) -> None:
        # ops1 gets this from its own address, with nothing set in its environment at all:
        # the shape every real boot is in, since the unit carries no Environment=.
        result = self.run_program(OPS1_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("--dport" in call for call in self.inserted()))
        # 6 as for any host with no db1 exception, plus the four port drops.
        self.assertEqual(len(self.inserted()), 10)

    def test_explicit_db_host_override_wins_over_self_identification(self) -> None:
        # Self-identification is a default, not a lock.
        result = self.run_program(OPS1_ADDRESSES, policy_env={"DB_HOST": "10.20.1.20"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.20.1.20" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 11)

    def test_ordinary_app_host_is_not_self_identified_as_non_tenant(self) -> None:
        # app1's own address must not trip the default meant for ops1, or every Ghost tenant
        # host silently loses its db1 route.
        result = self.run_program(APP_HOST_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.20.1.20" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 7)

    def test_db_host_and_port_are_overridable_for_testing(self) -> None:
        result = self.run_program(policy_env={"DB_HOST": "10.20.1.99", "DB_PORT": "3307"})
        self.assertEqual(result.returncode, 0, result.stderr)
        rule = next(call for call in self.inserted() if "10.20.1.99" in call)
        self.assertIn("--dport 3307", rule)

    def test_db_host_explicitly_empty_skips_the_db_accept_rule_entirely(self) -> None:
        # An app host with no reason to reach db1 gets a deny-all-to-the-subnet policy with
        # no exception, not a copy of app1's allow-list pointed at nothing.
        result = self.run_program(policy_env={"DB_HOST": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("--dport" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 6)
        # The two drops and the conntrack accept still land: the host still needs its own
        # reply traffic to work.
        self.assertTrue(any("10.20.1.0/24" in call for call in self.inserted()))
        self.assertTrue(any("169.254.169.254" in call for call in self.inserted()))
        self.assertTrue(any("ESTABLISHED,RELATED" in call for call in self.inserted()))

    def test_no_db_exception_addresses_is_overridable_for_testing(self) -> None:
        result = self.run_program(policy_env={"NO_DB_EXCEPTION_ADDRESSES": "10.20.1.100"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("--dport" in call for call in self.inserted()))
        self.assertEqual(len(self.inserted()), 6)

    def test_subnet_is_overridable_for_testing(self) -> None:
        result = self.run_program(policy_env={"SUBNET": "10.30.1.0/24"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("10.30.1.0/24" in call for call in self.inserted()))

    def test_adds_nothing_when_the_rules_are_already_present(self) -> None:
        result = self.run_program(rule_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inserted(), [])
        self.assertEqual(len([c for c in self.iptables_calls() if " -C " in c]), 7)

    def test_fails_when_a_rule_cannot_be_inserted(self) -> None:
        # A host that half-applied its rules has to exit non-zero rather than print its
        # closing summary and let the unit go active with an incomplete policy.
        result = self.run_program(insert_exit="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("app-host isolation applied", result.stdout)

    def test_a_failed_insert_passes_on_the_tools_own_status(self) -> None:
        result = self.run_program(insert_exit="4")
        self.assertEqual(result.returncode, 4)


class IdempotenceTests(PolicyCase):
    """A second run against the chain the first one built changes nothing."""

    def test_a_second_run_inserts_nothing_and_leaves_the_chain_as_it_was(self) -> None:
        for addresses, chain in (
            (OPS1_ADDRESSES, OPS1_CHAIN),
            (APP_HOST_ADDRESSES, SPOOL_RULES),
        ):
            with self.subTest(addresses=addresses):
                self.state_path.unlink(missing_ok=True)
                self.iptables_log.unlink(missing_ok=True)
                self.ip6tables_log.unlink(missing_ok=True)
                first = self.run_program(addresses, stateful=True)
                self.assertEqual(first.returncode, 0, first.stderr)
                state = json.loads(self.state_path.read_text(encoding="utf-8"))
                self.assertEqual(state["iptables DOCKER-USER"], chain)
                self.assertEqual(state["iptables INPUT"], INPUT_RULES)
                self.assertEqual(state["ip6tables DOCKER-USER"], [FORWARD_DROP])
                self.iptables_log.unlink()
                self.ip6tables_log.unlink()
                second = self.run_program(addresses, stateful=True)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(self.inserted(), [])
                self.assertEqual(self.inserted6(), [])
                self.assertEqual(json.loads(self.state_path.read_text(encoding="utf-8")), state)


class RefusalTests(PolicyCase):
    """The program stops, and inserts nothing, where the policy does not apply."""

    def test_refuses_the_host_holding_the_gateway_address(self) -> None:
        result = self.run_program(GATEWAY_ADDRESSES)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estate's gateway address", result.stderr)
        self.assertIn("scoped to app hosts only", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_a_private_only_host_is_not_treated_as_the_gateway(self) -> None:
        result = self.run_program(APP_HOST_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_public_app_host_is_not_treated_as_the_gateway(self) -> None:
        # app1 is created with a public address for CI's SSH deploy path, so "does this host
        # hold any public address" is not a valid test for "is this the gateway".
        result = self.run_program(APP_HOST_WITH_PUBLIC_IP_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.inserted(), [])

    def test_the_guards_own_gateway_address_is_overridable_for_testing(self) -> None:
        result = self.run_program(policy_env={"GATEWAY_IP": "10.20.1.100"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("estate's gateway address", result.stderr)

    def test_fails_closed_when_docker_user_chain_is_absent(self) -> None:
        # There is no FORWARD fallback: a policy that bounds container traffic has nothing to
        # bound where Docker is not enforcing through iptables.
        result = self.run_program(docker_user=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no DOCKER-USER chain", result.stderr)
        self.assertIn("no safe substitute", result.stderr)
        self.assertEqual(self.inserted(), [])

    def test_reports_a_missing_iptables_rather_than_failing_as_a_broken_unit(self) -> None:
        result = self.run_program(drop_iptables=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            result.stderr.strip(),
            "branchleft-docker-user-policy: iptables is not installed: "
            "apply the host_baseline role first",
        )

    def test_never_targets_the_app_hosts_own_private_address(self) -> None:
        # DOCKER-USER only sees forwarded traffic; a container reaching the app host's own
        # address is delivered locally via INPUT, which this chain never sees. Nothing
        # inserted should name an app-host address as a destination: it would look like a
        # control that bounds a path it cannot.
        self.run_program()
        for call in self.inserted():
            self.assertNotIn("10.20.1.100", call)

    def test_refuses_an_argument(self) -> None:
        result = self.run_program(arguments=["--flush"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.iptables_calls(), [])

    def test_refuses_a_value_that_is_not_the_shape_its_name_needs(self) -> None:
        unusable = {
            "SUBNET": "10.20.1.0",
            "DB_PORT": "3306; reboot",
            "GATEWAY_IP": "gateway",
            "PROTECTED_ADDRESS": "10.20.1.50/32",
            "PROTECTED_PORTS": "8300 http",
            "MAIL_SPOOL_BRIDGE": "br mailspool",
            "NO_DB_EXCEPTION_ADDRESSES": "10.20.1.50 nowhere",
            "DB_HOST": "db1",
        }
        for name, value in unusable.items():
            with self.subTest(name=name):
                self.iptables_log.unlink(missing_ok=True)
                result = self.run_program(policy_env={name: value})
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"{policy.ENVIRONMENT_PREFIX}{name}", result.stderr)
                self.assertEqual(self.iptables_calls(), [])


class NoAnswerTests(PolicyCase):
    """A probe that does not finish is no answer: the program stops and inserts nothing."""

    def run_in_process(self, hang: str, addresses: str = APP_HOST_ADDRESSES) -> tuple[int, str]:
        """Run main() with the fakes on PATH, one command hanging, and a one second timeout."""
        env = self.environment(addresses, extra={"FAKE_HANG": hang})
        err = io.StringIO()
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(policy, "COMMAND_TIMEOUT_SECONDS", 1),
            mock.patch.object(sys, "argv", ["policy"]),
            contextlib.redirect_stderr(err),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            policy.main()
        return int(str(stopped.exception.code)), err.getvalue()

    def test_a_check_that_hangs_refuses_and_inserts_nothing_more(self) -> None:
        status, err = self.run_in_process("-C DOCKER-USER -d 169.254.169.254")
        self.assertEqual(status, 1)
        self.assertIn("could not learn", err)
        self.assertEqual(self.inserted(), [])

    def test_the_chain_probe_that_hangs_refuses_and_inserts_nothing(self) -> None:
        status, err = self.run_in_process("-S DOCKER-USER")
        self.assertEqual(status, 1)
        self.assertIn("could not learn whether DOCKER-USER exists", err)
        self.assertEqual(self.inserted(), [])

    def test_the_address_list_that_hangs_refuses_and_inserts_nothing(self) -> None:
        self.write_fake("ip", "#!@PY@\nimport time\n\ntime.sleep(60)\n")
        status, err = self.run_in_process("@@never@@")
        self.assertEqual(status, 1)
        self.assertIn("could not learn which addresses it holds", err)
        self.assertEqual(self.iptables_calls(), [])


class FailedProbeTests(PolicyCase):
    """A probe that runs and fails is no answer either: the program stops, not guesses."""

    def test_an_address_probe_that_exits_non_zero_refuses_and_issues_no_rule(self) -> None:
        # ops1's addresses are what ip would print, but it failed: reading that as "no
        # addresses" would make ops1 look like an app host and skip its port drops.
        result = self.run_program(OPS1_ADDRESSES, ip_exit="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not learn which addresses it holds", result.stderr)
        self.assertIn("refusing rather than guess", result.stderr)
        self.assertEqual(self.iptables_calls(), [])
        self.assertEqual(self.ip6tables_calls(), [])

    def test_an_address_probe_that_exits_non_zero_with_no_output_refuses(self) -> None:
        for status in ("1", "2", "255"):
            with self.subTest(status=status):
                result = self.run_program("", ip_exit=status)
                self.assertEqual(result.returncode, 1)
                self.assertIn("exited", result.stderr)
                self.assertEqual(self.iptables_calls(), [])
                self.assertEqual(self.ip6tables_calls(), [])

    def test_an_address_probe_that_succeeds_behaves_as_before(self) -> None:
        result = self.run_program(OPS1_ADDRESSES, ip_exit="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.final_chain_order(), OPS1_CHAIN)

    def test_an_ip6tables_chain_probe_that_fails_for_another_reason_refuses(self) -> None:
        # Only exit 1, "no such chain", means the chain is absent. Anything else is a probe
        # that failed, and skipping the forward drop on it would leave IPv6 open.
        result = self.run_program(ip6_docker_user_exit="4")
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not learn whether ip6tables has a chain", result.stderr)
        self.assertNotIn("forward drop skipped", result.stdout)
        self.assertEqual(self.inserted6(), [])

    def test_an_iptables_spool_chain_probe_that_fails_for_another_reason_refuses(self) -> None:
        # The spool step probes the chain again after the main step found it: a failure
        # now must not skip the IPv4 forward drop.
        calls: list[list[str]] = []

        def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 4, "", "")

        err = io.StringIO()
        with (
            mock.patch.object(policy, "run", fake_run),
            mock.patch("shutil.which", return_value="/usr/sbin/iptables"),
            contextlib.redirect_stderr(err),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as stopped,
        ):
            policy.ensure_spool_rules("iptables", 2, "br-mailspool")
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(len(calls), 1)
        self.assertIn("could not learn whether iptables has a chain", err.getvalue())


class ProgramFileTests(unittest.TestCase):
    """The file is the program the role pins: its interpreter line, its mode and its values."""

    def test_is_the_program_with_the_shebang_and_mode_the_role_pins(self) -> None:
        first = PROGRAM.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first, "#!/usr/bin/python3 -I")
        self.assertEqual(stat.S_IMODE(PROGRAM.stat().st_mode), 0o755)

    def test_the_estate_values_are_the_ones_the_address_plan_gives(self) -> None:
        self.assertEqual(policy.DEFAULT_SUBNET, "10.20.1.0/24")
        self.assertEqual(policy.DEFAULT_GATEWAY_PRIVATE_IP, "10.20.1.10")
        self.assertEqual(policy.DEFAULT_DB_HOST, "10.20.1.20")
        self.assertEqual(policy.DEFAULT_DB_PORT, "3306")
        self.assertEqual(policy.METADATA_ADDRESS, "169.254.169.254")

    def test_no_environment_leaves_every_value_at_the_estates_own(self) -> None:
        settings = policy.read_settings({})
        self.assertEqual(settings.subnet, "10.20.1.0/24")
        self.assertEqual(settings.protected_ports, ("8300", "8301", "8302", "8303"))
        self.assertIsNone(settings.db_host_override)

    def test_every_default_passes_its_own_check(self) -> None:
        for name, default, check in (
            ("SUBNET", policy.DEFAULT_SUBNET, policy.is_subnet),
            ("GATEWAY_IP", policy.DEFAULT_GATEWAY_PRIVATE_IP, policy.is_address),
            ("DB_HOST", policy.DEFAULT_DB_HOST, policy.is_address),
            ("DB_PORT", policy.DEFAULT_DB_PORT, policy.is_port),
            ("MAIL_SPOOL_BRIDGE", policy.DEFAULT_MAIL_SPOOL_BRIDGE, policy.BRIDGE_NAME.fullmatch),
        ):
            with self.subTest(name=name):
                self.assertTrue(check(default))


class UnitFileTests(unittest.TestCase):
    """The unit is what a later docker.service restart depends on to reassert the policy."""

    def setUp(self) -> None:
        self.lines = [line.strip() for line in UNIT.read_text(encoding="utf-8").splitlines()]

    def test_carries_partof_docker_so_a_restart_of_docker_propagates(self) -> None:
        self.assertIn("PartOf=docker.service", self.lines)

    def test_does_not_upgrade_to_requires_or_bindsto_docker(self) -> None:
        joined = "\n".join(self.lines)
        self.assertNotIn("Requires=docker.service", joined)
        self.assertNotIn("BindsTo=docker.service", joined)

    def test_is_a_remain_after_exit_oneshot(self) -> None:
        self.assertIn("Type=oneshot", self.lines)
        self.assertIn("RemainAfterExit=yes", self.lines)

    def test_runs_the_installed_program_with_no_arguments_and_no_environment(self) -> None:
        self.assertIn("ExecStart=/usr/local/sbin/branchleft-docker-user-policy", self.lines)
        self.assertFalse(any(line.startswith("Environment") for line in self.lines))

    def test_is_the_same_bytes_as_the_copy_the_hand_installer_still_installs(self) -> None:
        # Until that installer is removed, two writers install this unit.
        self.assertEqual(UNIT.read_bytes(), HAND_UNIT.read_bytes())


class SourceTests(unittest.TestCase):
    """The program names no shell and no script due for removal."""

    def test_runs_no_shell(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"shell\s*=\s*True|os\.system|os\.popen", text))


if __name__ == "__main__":
    unittest.main()
