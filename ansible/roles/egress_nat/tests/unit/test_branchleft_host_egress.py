"""Unit tests for branchleft_host_egress.py, the host half of the estate's egress path.

Without the program, a private-only host has no default route and no resolver, and every apt
mirror is unreachable for the host's whole life. Its two highest-risk behaviours are asserted
directly: that it derives the gateway from the host's own routing table instead of a hardcoded
address, and that it is a clean no-op on any host that already has a public interface.

The program is run as a subprocess, as the shell program it replaces was, with the live routing
table and resolvconf replaced by fakes earlier on PATH. The resolver head is redirected with the
environment variable the program reads as an override. Every case of the shell suite that
exercised that program is carried over here with the same fixtures and expectations.
"""

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

ROLE = Path(__file__).resolve().parents[2]
SCRIPT = ROLE / "files" / "branchleft_host_egress.py"

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

# Like FAKE_IP, but the subnet route is absent from the first FAKE_IP_EMPTY_LOOKS lookups and
# present from the next one on: the state a boot leaves behind when the network brings the route
# up after the unit has already looked. Lookups are counted in a file, since each `ip` call is a
# new process.
FAKE_IP_LATE = """#!/usr/bin/env bash
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
        n=$(cat "$FAKE_IP_COUNT" 2>/dev/null || echo 0)
        n=$((n + 1))
        printf '%s\\n' "$n" > "$FAKE_IP_COUNT"
        if [ "$n" -le "$FAKE_IP_EMPTY_LOOKS" ]; then
            exit 0
        fi
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

# A host with a public interface, as `ip -4 -o addr show scope global` reports one: a public
# address alongside a private one.
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

# What Hetzner's DHCP delivers to a private-only host: the subnet route and the metadata route,
# both `via` the same gateway, and no default. 169.254.169.254 is the metadata service.
SUBNET_ROUTE_TABLE = "\n".join(
    [
        "10.20.0.0/16 via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
        "169.254.169.254 via 10.20.0.1 dev enp7s0 proto dhcp metric 1024",
    ]
)

NO_DEFAULT_ROUTE = ""
PRESENT_DEFAULT = "default via 10.20.0.1 dev enp7s0 proto dhcp metric 1024"


def write_fake(path: str, content: str) -> None:
    """Write an executable fake command."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)  # noqa: S103 -- a fake must run


def load_module() -> ModuleType:
    """Import the program as a module, for the constants and the classification it exposes."""
    spec = importlib.util.spec_from_file_location("branchleft_host_egress", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_lines(path: str) -> list[str]:
    """The lines a fake command logged, or none if it never ran."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line.rstrip("\n") for line in handle]


class HostEgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        write_fake(os.path.join(bin_dir, "ip"), FAKE_IP)
        write_fake(os.path.join(bin_dir, "resolvconf"), FAKE_RESOLVCONF)
        self.bin_dir = bin_dir

        self.ip_log = os.path.join(self.tmp.name, "ip.log")
        self.resolvconf_log = os.path.join(self.tmp.name, "resolvconf.log")
        # Nested and not yet created, so a passing test also proves the write creates its parent
        # directories: the resolv.conf.d directory is not guaranteed before resolvconf is installed.
        self.resolver_head = os.path.join(self.tmp.name, "resolvconf.d", "resolv.conf.d", "head")

    def run_script(
        self,
        addresses: str,
        route_table: str = "",
        route_default: str = NO_DEFAULT_ROUTE,
        nameserver_1: str | None = None,
        nameserver_2: str | None = None,
        drop_resolvconf: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if drop_resolvconf:
            os.remove(os.path.join(self.bin_dir, "resolvconf"))
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
                # No wait here: a test with no subnet route must fail at once, not sit through
                # the production bound. The wait itself is tested in SubnetRouteArrivesLateTests.
                "BRANCHLEFT_EGRESS_ROUTE_WAIT_SECONDS": "0",
            }
        )
        if nameserver_1 is not None:
            env["BRANCHLEFT_EGRESS_NAMESERVER_1"] = nameserver_1
        if nameserver_2 is not None:
            env["BRANCHLEFT_EGRESS_NAMESERVER_2"] = nameserver_2
        return subprocess.run(  # noqa: S603 -- argv is a fixed list, and no shell is involved
            [sys.executable, "-I", str(SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def ip_calls(self) -> list[str]:
        return read_lines(self.ip_log)

    def resolvconf_calls(self) -> list[str]:
        return read_lines(self.resolvconf_log)

    def test_is_a_clean_noop_on_a_host_with_a_public_interface(self) -> None:
        result = self.run_script(PUBLIC_ADDRESSES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no-op", result.stdout)
        self.assertEqual(self.ip_calls(), [])
        self.assertEqual(self.resolvconf_calls(), [])
        self.assertFalse(os.path.exists(self.resolver_head))

    def test_sets_the_default_route_and_resolver_on_a_fresh_private_only_host(self) -> None:
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default=NO_DEFAULT_ROUTE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ip_calls(), ["route replace default via 10.20.0.1 dev enp7s0"])
        with open(self.resolver_head, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "nameserver 185.12.64.1\nnameserver 185.12.64.2\n")
        self.assertEqual(self.resolvconf_calls(), ["-u"])

    def test_derives_the_gateway_from_the_routing_table_rather_than_hardcoding_it(self) -> None:
        # The regression this guards: an earlier hand-repair used 10.20.0.1 because that happened
        # to be live when it was written. A different gateway here has to produce a different route.
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
        self.assertEqual(self.ip_calls(), ["route replace default via 10.30.0.9 dev enp7s0"])

    def test_excludes_the_metadata_route_from_the_gateway_candidates(self) -> None:
        # A metadata route with a different via-address than the subnet route proves it is
        # excluded rather than merely deduplicated: otherwise this would pick the wrong gateway
        # or trip the ambiguous-candidates refusal.
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
        self.assertEqual(self.ip_calls(), ["route replace default via 10.20.0.1 dev enp7s0"])

    def test_is_idempotent_when_the_route_and_resolver_are_already_correct(self) -> None:
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

    def test_replaces_a_stale_default_route_pointing_at_the_wrong_gateway(self) -> None:
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default="default via 10.99.0.1 dev enp7s0 proto static metric 50",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ip_calls(), ["route replace default via 10.20.0.1 dev enp7s0"])

    def test_fails_closed_rather_than_exit_127_when_resolvconf_is_missing(self) -> None:
        # A bare "command not found" (exit 127) names no missing package and reads as this program
        # being broken. Checked before the route is touched, so a host without resolvconf is left
        # exactly as found rather than half-repaired.
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default=NO_DEFAULT_ROUTE,
            drop_resolvconf=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 127)
        self.assertIn("resolvconf is not installed", result.stderr)
        self.assertEqual(self.ip_calls(), [])

    def test_fails_when_no_subnet_route_can_be_found(self) -> None:
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES, route_table="", route_default=NO_DEFAULT_ROUTE
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no private subnet route", result.stderr)

    def test_fails_rather_than_guesses_when_two_candidate_routes_exist(self) -> None:
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
        self.assertIn("  10.21.0.0/16 via 10.21.0.1 dev enp7s0", result.stderr)
        self.assertEqual(self.ip_calls(), [])

    def test_fails_when_the_candidate_route_carries_no_gateway(self) -> None:
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            # Ends in " via " with nothing after it: the candidate matches, the gateway does not.
            route_table="10.20.0.0/16 dev enp7s0 via ",
            route_default=NO_DEFAULT_ROUTE,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("carries no gateway or device", result.stderr)
        self.assertEqual(self.ip_calls(), [])

    def test_uses_the_overridable_nameservers_for_testing(self) -> None:
        result = self.run_script(
            PRIVATE_ONLY_ADDRESSES,
            route_table=SUBNET_ROUTE_TABLE,
            route_default=NO_DEFAULT_ROUTE,
            nameserver_1="192.0.2.1",
            nameserver_2="192.0.2.2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.resolver_head, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "nameserver 192.0.2.1\nnameserver 192.0.2.2\n")

    def test_running_twice_with_the_route_present_changes_nothing(self) -> None:
        # The timer re-runs the program every minute, so a run with the route and resolver
        # already correct must change nothing and exit 0.
        os.makedirs(os.path.dirname(self.resolver_head))
        with open(self.resolver_head, "w", encoding="utf-8") as handle:
            handle.write("nameserver 185.12.64.1\nnameserver 185.12.64.2\n")
        for run in (1, 2):
            with self.subTest(run=run):
                result = self.run_script(
                    PRIVATE_ONLY_ADDRESSES,
                    route_table=SUBNET_ROUTE_TABLE,
                    route_default=PRESENT_DEFAULT,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("no-op", result.stdout)
        self.assertEqual(self.ip_calls(), [], "a re-run with the route present touched routing")
        self.assertEqual(
            self.resolvconf_calls(), [], "a re-run with the resolver present rewrote it"
        )


class SubnetRouteArrivesLateTests(unittest.TestCase):
    """The private route is not in the table yet when the unit runs.

    A program that looks once finds nothing and exits 1, which leaves a private-only host with no
    default route until someone intervenes. This one polls for a bounded time before giving up.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        write_fake(os.path.join(bin_dir, "ip"), FAKE_IP_LATE)
        write_fake(os.path.join(bin_dir, "resolvconf"), FAKE_RESOLVCONF)
        self.bin_dir = bin_dir
        self.ip_log = os.path.join(self.tmp.name, "ip.log")
        self.count_file = os.path.join(self.tmp.name, "lookups")
        self.resolvconf_log = os.path.join(self.tmp.name, "resolvconf.log")
        self.resolver_head = os.path.join(self.tmp.name, "resolv.conf.d", "head")

    def run_late(
        self, empty_looks: int, wait_seconds: int, poll_seconds: int
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ADDR": PRIVATE_ONLY_ADDRESSES,
                "FAKE_IP_ROUTE_TABLE": SUBNET_ROUTE_TABLE,
                "FAKE_IP_ROUTE_DEFAULT": NO_DEFAULT_ROUTE,
                "FAKE_IP_LOG": self.ip_log,
                "FAKE_IP_COUNT": self.count_file,
                "FAKE_IP_EMPTY_LOOKS": str(empty_looks),
                "FAKE_RESOLVCONF_LOG": self.resolvconf_log,
                "BRANCHLEFT_EGRESS_RESOLVER_HEAD": self.resolver_head,
                "BRANCHLEFT_EGRESS_ROUTE_WAIT_SECONDS": str(wait_seconds),
                "BRANCHLEFT_EGRESS_ROUTE_POLL_SECONDS": str(poll_seconds),
            }
        )
        return subprocess.run(  # noqa: S603 -- argv is a fixed list, and no shell is involved
            [sys.executable, "-I", str(SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def lookups(self) -> int:
        if not os.path.exists(self.count_file):
            return 0
        with open(self.count_file, encoding="utf-8") as handle:
            return int(handle.read().strip())

    def ip_calls(self) -> list[str]:
        return read_lines(self.ip_log)

    def test_waits_for_a_subnet_route_that_arrives_after_the_first_look(self) -> None:
        # Route absent on lookups 1 and 2, present from 3. A program that looks once gives up
        # here with exit 1 and no default route is set.
        result = self.run_late(empty_looks=2, wait_seconds=5, poll_seconds=1)
        self.assertEqual(
            result.returncode,
            0,
            f"the program gave up before the subnet route arrived: {result.stderr.strip()}",
        )
        self.assertEqual(
            self.ip_calls(),
            ["route replace default via 10.20.0.1 dev enp7s0"],
            "the default route was not set once the subnet route appeared",
        )

    def test_gives_up_only_after_the_bounded_total_wait(self) -> None:
        # Route never arrives. The wait is 2 s polled every 1 s: one look, then two polls, then the
        # same error. Unbounded or immediate are both wrong.
        result = self.run_late(empty_looks=999, wait_seconds=2, poll_seconds=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no private subnet route", result.stderr)
        self.assertEqual(
            self.lookups(),
            3,
            "the program did not poll for the bounded total: expected 1 look plus 2 polls, "
            f"saw {self.lookups()} lookups",
        )
        self.assertEqual(self.ip_calls(), [])


class ModuleContractTests(unittest.TestCase):
    """Constants and the public-address classification, asserted on the module itself."""

    module: ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_production_defaults_are_a_bounded_120_second_wait_polled_every_5_seconds(self) -> None:
        self.assertEqual(self.module.DEFAULT_ROUTE_WAIT_SECONDS, 120)
        self.assertEqual(self.module.DEFAULT_ROUTE_POLL_SECONDS, 5)

    def test_production_resolver_is_hetzners_recursive_pair_at_the_standard_head(self) -> None:
        self.assertEqual(self.module.DEFAULT_NAMESERVER_1, "185.12.64.1")
        self.assertEqual(self.module.DEFAULT_NAMESERVER_2, "185.12.64.2")
        self.assertEqual(self.module.DEFAULT_RESOLVER_HEAD, "/etc/resolvconf/resolv.conf.d/head")

    def test_classifies_the_rfc1918_boundaries_of_172_16_to_172_31(self) -> None:
        private = ["172.16.0.1", "172.19.9.9", "172.20.0.1", "172.29.0.1", "172.31.255.1"]
        public = ["172.15.0.1", "172.32.0.1", "172.160.0.1", "172.200.1.1"]
        for address in private:
            with self.subTest(address=address):
                self.assertTrue(self.module.is_private_v4(address))
        for address in public:
            with self.subTest(address=address):
                self.assertFalse(self.module.is_private_v4(address))

    def test_classifies_the_other_private_and_link_local_ranges(self) -> None:
        for address in ["10.20.1.10", "192.168.1.1", "127.0.0.1", "169.254.169.254"]:
            with self.subTest(address=address):
                self.assertTrue(self.module.is_private_v4(address))
        self.assertFalse(self.module.is_private_v4("203.0.113.10"))


if __name__ == "__main__":
    unittest.main()
