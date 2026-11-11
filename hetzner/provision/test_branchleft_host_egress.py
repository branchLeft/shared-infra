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
import re
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
        drop_resolvconf=False,
    ):
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
                # No wait here: a test with no subnet route must fail at once,
                # not sit through the production bound. The wait itself is
                # tested in SubnetRouteArrivesLateTests.
                "BRANCHLEFT_EGRESS_ROUTE_WAIT_SECONDS": "0",
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

    def test_fails_closed_rather_than_exit_127_when_resolvconf_is_missing(self):
        # A bare "command not found" (exit 127) is what run-all.sh's
        # `set -euo pipefail` would otherwise abort on, and it names no
        # missing package -- it reads as this script being broken rather
        # than a host missing a dependency. Checked before the route is
        # touched, so a host without resolvconf is left exactly as found
        # rather than half-repaired.
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


def _extract_repair_one_liner():
    with open(RUNBOOK, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"^GW=\$\(ip -4 route show.*$", text, re.MULTILINE)
    if not match:
        raise AssertionError(
            "the manual repair one-liner was not found in RUNBOOK-provision-host.md"
        )
    return match.group(0)


class RunbookRepairOneLinerTests(unittest.TestCase):
    """The manual repair line is pasted directly into a root shell on a live
    host with nothing else reviewing it, so its actual behaviour is asserted
    against synthetic `ip` output here -- not just checked for containing
    the right substrings. It has to fail closed the same way the reconciler
    does: guessing a gateway among more than one candidate risks pointing a
    host's whole egress at the wrong address."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        path = os.path.join(bin_dir, "ip")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(FAKE_IP)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.bin_dir = bin_dir
        self.ip_log = os.path.join(self.tmp.name, "ip.log")
        self.command = _extract_repair_one_liner()

    def run_repair(self, route_table):
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.bin_dir}:/usr/bin:/bin",
                "FAKE_IP_ROUTE_TABLE": route_table,
                "FAKE_IP_LOG": self.ip_log,
            }
        )
        return subprocess.run(
            ["bash", "-c", self.command],
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

    def test_applies_the_single_candidate_gateway(self):
        self.run_repair(SUBNET_ROUTE_TABLE)
        self.assertEqual(self.ip_calls(), ["route replace default via 10.20.0.1"])

    def test_fails_closed_rather_than_guesses_with_two_candidates(self):
        route_table = "\n".join(
            [
                "10.20.0.0/16 via 10.20.0.1 dev enp7s0",
                "10.21.0.0/16 via 10.21.0.1 dev enp7s0",
            ]
        )
        result = self.run_repair(route_table)
        self.assertEqual(self.ip_calls(), [])
        self.assertIn("no single candidate route found", result.stderr)

    def test_fails_closed_rather_than_guesses_with_no_candidates(self):
        result = self.run_repair("")
        self.assertEqual(self.ip_calls(), [])
        self.assertIn("no single candidate route found", result.stderr)


HERE = os.path.dirname(os.path.abspath(__file__))
TIMER_UNIT = os.path.join(HERE, "branchleft-host-egress.timer")
SERVICE_UNIT = os.path.join(HERE, "branchleft-host-egress.service")
INSTALLER = os.path.join(HERE, "05-configure-host-egress.sh")

# Like FAKE_IP, but the subnet route is absent from the first
# FAKE_IP_EMPTY_LOOKS lookups and present from the next one on: the state a
# boot leaves behind when the network brings the route up after the unit has
# already looked. Lookups are counted in a file, since each `ip` call is a new
# process.
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


class SubnetRouteArrivesLateTests(unittest.TestCase):
    """Cause (a): the private route is not in the table yet when the unit runs.

    The unfixed script looks once, finds nothing, and exits 1, which leaves a
    private-only host with no default route until someone intervenes. The
    fixed script polls for a bounded time before giving up.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        path = os.path.join(bin_dir, "ip")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(FAKE_IP_LATE)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        resolvconf = os.path.join(bin_dir, "resolvconf")
        with open(resolvconf, "w", encoding="utf-8") as handle:
            handle.write(FAKE_RESOLVCONF)
        os.chmod(resolvconf, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.bin_dir = bin_dir
        self.ip_log = os.path.join(self.tmp.name, "ip.log")
        self.count_file = os.path.join(self.tmp.name, "lookups")
        self.resolvconf_log = os.path.join(self.tmp.name, "resolvconf.log")
        self.resolver_head = os.path.join(self.tmp.name, "resolv.conf.d", "head")

    def run_late(self, empty_looks, wait_seconds, poll_seconds):
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
        return subprocess.run(
            ["bash", SCRIPT], env=env, capture_output=True, text=True, check=False
        )

    def lookups(self):
        if not os.path.exists(self.count_file):
            return 0
        with open(self.count_file, encoding="utf-8") as handle:
            return int(handle.read().strip())

    def ip_calls(self):
        if not os.path.exists(self.ip_log):
            return []
        with open(self.ip_log, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def test_waits_for_a_subnet_route_that_arrives_after_the_first_look(self):
        # Route absent on lookups 1 and 2, present from 3. A script that looks
        # once gives up here with exit 1 and no default route is set.
        result = self.run_late(empty_looks=2, wait_seconds=5, poll_seconds=1)
        self.assertEqual(
            result.returncode,
            0,
            "the script gave up before the subnet route arrived (it looked once, "
            f"and exited without waiting): {result.stderr.strip()}",
        )
        self.assertEqual(
            self.ip_calls(),
            ["route replace default via 10.20.0.1 dev enp7s0"],
            "the default route was not set once the subnet route appeared",
        )

    def test_production_defaults_are_a_bounded_120_second_wait(self):
        with open(SCRIPT, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("BRANCHLEFT_EGRESS_ROUTE_WAIT_SECONDS:-120}", text,
                      "the production wait is not a bounded 120 s by default")
        self.assertIn("BRANCHLEFT_EGRESS_ROUTE_POLL_SECONDS:-5}", text,
                      "the production poll interval is not 5 s by default")

    def test_gives_up_only_after_the_bounded_total_wait(self):
        # Route never arrives. The wait is 2 s polled every 1 s: one look, then
        # two polls, then the same error. Unbounded or immediate are both wrong.
        result = self.run_late(empty_looks=999, wait_seconds=2, poll_seconds=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no private subnet route", result.stderr)
        self.assertEqual(
            self.lookups(),
            3,
            "the script did not poll for the bounded total: expected 1 look plus "
            f"2 polls, saw {self.lookups()} lookups",
        )
        self.assertEqual(self.ip_calls(), [])


class TimerAndUnitContractTests(unittest.TestCase):
    """Cause (b): the route or the default is removed after the unit succeeded.

    Nothing re-ran the unit in that case. The fix is a timer that re-runs the
    same oneshot service about every minute, and a service that retries on
    failure. These assert the unit files and the installer that lands them.
    """

    @staticmethod
    def read(path):
        if not os.path.exists(path):
            raise AssertionError(
                f"{os.path.basename(path)} does not exist: nothing re-runs the "
                "egress service after boot, so a route removed later is never put back"
            )
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    @staticmethod
    def section(text, name):
        body = re.search(rf"^\[{name}\]\n(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
        if not body:
            raise AssertionError(f"no [{name}] section")
        values = {}
        for line in body.group(1).splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        return values

    def test_timer_exists_and_reruns_the_service_about_every_minute(self):
        timer = self.read(TIMER_UNIT)
        timer_section = self.section(timer, "Timer")
        self.assertEqual(
            timer_section.get("OnBootSec"),
            "30s",
            "the timer does not run shortly after boot",
        )
        self.assertEqual(
            timer_section.get("OnUnitActiveSec"),
            "1min",
            "the timer does not re-run the service about every minute, so a route "
            "removed after a successful run is not put back",
        )
        self.assertEqual(
            timer_section.get("Unit"),
            "branchleft-host-egress.service",
            "the timer does not trigger the egress service",
        )
        self.assertEqual(
            self.section(timer, "Install").get("WantedBy"),
            "timers.target",
            "the timer is not wanted by timers.target, so it never starts at boot",
        )

    def test_service_retries_a_failed_run_after_a_delay(self):
        service = self.read(SERVICE_UNIT)
        service_section = self.section(service, "Service")
        self.assertEqual(
            service_section.get("Restart"),
            "on-failure",
            "the service is not retried on failure, so a run that exits 1 is left until the next timer tick",
        )
        self.assertTrue(
            service_section.get("RestartSec"),
            "the service has no RestartSec delay between retries",
        )

    def test_installer_installs_and_enables_the_timer(self):
        text = self.read(INSTALLER)
        self.assertRegex(
            text,
            r"install -m 0644 -o root -g root \"\$SCRIPT_DIR/branchleft-host-egress\.timer\" \"\$TIMER\"",
            "the installer does not copy the timer into /etc/systemd/system",
        )
        self.assertRegex(
            text,
            r"systemctl enable branchleft-host-egress\.timer",
            "the installer does not enable the timer, so it is not started at boot",
        )
        self.assertRegex(
            text,
            r"systemctl restart branchleft-host-egress\.timer",
            "the installer does not restart the timer, so a changed schedule is not loaded on a live host",
        )


class RerunChangesNothingTests(unittest.TestCase):
    """The timer re-runs the script every minute, so a run with the route and
    resolver already correct must change nothing and exit 0. Reuses the
    harness of HostEgressTests rather than repeating it."""

    setUp = HostEgressTests.setUp
    _write_fake = staticmethod(HostEgressTests._write_fake)
    run_script = HostEgressTests.run_script
    ip_calls = HostEgressTests.ip_calls
    resolvconf_calls = HostEgressTests.resolvconf_calls

    def test_running_twice_with_the_route_present_changes_nothing(self):
        os.makedirs(os.path.dirname(self.resolver_head))
        with open(self.resolver_head, "w", encoding="utf-8") as handle:
            handle.write("nameserver 185.12.64.1\nnameserver 185.12.64.2\n")
        present = "default via 10.20.0.1 dev enp7s0 proto dhcp metric 1024"
        for run in (1, 2):
            with self.subTest(run=run):
                result = self.run_script(
                    PRIVATE_ONLY_ADDRESSES,
                    route_table=SUBNET_ROUTE_TABLE,
                    route_default=present,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("no-op", result.stdout)
        self.assertEqual(
            self.ip_calls(), [], "a re-run with the route present touched the routing table"
        )
        self.assertEqual(
            self.resolvconf_calls(), [], "a re-run with the resolver present rewrote it"
        )


if __name__ == "__main__":
    unittest.main()
