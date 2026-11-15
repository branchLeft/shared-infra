"""Unit tests for the chain watch: it fails when the policy has been reopened, passes when not.

The chains are the captured listings the module's own tests use (see that file), so a
"reopened" case here is a real listing with one thing taken away or added, and the intact
case is the capture itself. The checks themselves are the module's and are tested there;
these tests prove what the watch does with each outcome: the exit status that becomes the
unit's result, that an unchecked host is never read as intact, and that what it prints holds
no rule of the host.
"""

import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import branchleft_docker_user_watch as watcher
import deploy_tooling_chain as chain
from jinja2 import Environment, StrictUndefined
from test_deploy_tooling_chain import (
    PROGRAM,
    PROTECTED,
    STANDARD,
    V4_STANDARD_DELETIONS,
    inserted,
    listing,
    runner_for,
    v6_listing,
    without,
)

ROLE = Path(__file__).resolve().parents[2]
FORWARD_JUMP = "-A FORWARD -j DOCKER-USER"
ESTABLISHED = V4_STANDARD_DELETIONS["established accept"]
RETURN_RULE = "-A DOCKER-USER -j RETURN"
FOREIGN_ADDRESS = "192.0.2.77"


class Outcome:
    """What one run of the watch returned and printed."""

    def __init__(self, status: int, out: str, err: str) -> None:
        self.status = status
        self.out = out
        self.err = err


def run_watch(
    runner: chain.Runner,
    variant: str = STANDARD,
    reconciler: Path = PROGRAM,
    allowlist: tuple[str, ...] = (),
) -> Outcome:
    """Run the watch once against ``runner`` and return its status and both streams."""
    out, err = io.StringIO(), io.StringIO()
    status = watcher.watch(reconciler, variant, allowlist, runner, out, err)
    return Outcome(status, out.getvalue(), err.getvalue())


def v4(edit: Callable[[list[str]], list[str]] | None = None) -> chain.Runner:
    """Return a runner whose IPv4 listing is the standard capture with ``edit`` applied."""
    return runner_for(listing(STANDARD, edit))


class TestIntact(unittest.TestCase):
    """The captured chains carry the policy, so the watch passes."""

    def test_the_standard_capture_is_intact(self) -> None:
        found = run_watch(v4())
        self.assertEqual(found.status, watcher.EXIT_INTACT)
        self.assertIn("intact", found.out)
        self.assertEqual(found.err, "")

    def test_the_protected_capture_is_intact_for_its_variant(self) -> None:
        found = run_watch(runner_for(listing(PROTECTED)), variant=PROTECTED)
        self.assertEqual(found.status, watcher.EXIT_INTACT)

    def test_a_listed_foreign_chain_above_the_policy_is_still_intact(self) -> None:
        edit = inserted("-A DOCKER-USER -j f2b-sshd", before=ESTABLISHED)
        found = run_watch(v4(edit), allowlist=("f2b-sshd",))
        self.assertEqual(found.status, watcher.EXIT_INTACT)


class TestReopened(unittest.TestCase):
    """Each way the policy can be reopened makes the watch exit 1 and say so."""

    def assert_reopened(self, found: Outcome, fragment: str) -> None:
        self.assertEqual(found.status, watcher.EXIT_REOPENED, found.err)
        self.assertIn("REOPENED", found.err)
        self.assertIn(fragment, found.err)
        self.assertEqual(found.out, "")

    def test_a_chain_that_is_absent(self) -> None:
        # The nftables backend: no DOCKER-USER chain at all, nothing to hold the policy.
        found = run_watch(v4(lambda lines: [ln for ln in lines if "DOCKER-USER" not in ln]))
        self.assert_reopened(found, "no DOCKER-USER chain")

    def test_a_chain_flushed_to_dockers_return(self) -> None:
        # What a Docker restart or an operator leaves: the chain exists and holds only the return.
        def flushed(lines: list[str]) -> list[str]:
            return [ln for ln in lines if not ln.startswith("-A DOCKER-USER")] + [RETURN_RULE]

        found = run_watch(v4(flushed))
        self.assert_reopened(found, "is missing")

    def test_each_rule_of_the_policy_missing(self) -> None:
        for label, line in V4_STANDARD_DELETIONS.items():
            with self.subTest(rule=label):
                self.assert_reopened(run_watch(v4(without(line))), "is missing")

    def test_the_right_rules_in_the_wrong_order(self) -> None:
        def moved(lines: list[str]) -> list[str]:
            kept = [ln for ln in lines if ln != ESTABLISHED]
            index = kept.index(RETURN_RULE)
            return [*kept[:index], ESTABLISHED, *kept[index:]]

        self.assert_reopened(run_watch(v4(moved)), "wrong place")

    def test_an_accept_above_the_policy(self) -> None:
        edit = inserted(f"-A DOCKER-USER -s {FOREIGN_ADDRESS}/32 -j ACCEPT", before=ESTABLISHED)
        self.assert_reopened(run_watch(v4(edit)), "can let a packet past")

    def test_an_accept_in_forward_above_the_jump(self) -> None:
        edit = inserted("-A FORWARD -j ACCEPT", before=FORWARD_JUMP)
        self.assert_reopened(run_watch(v4(edit)), "first rule is not the jump")

    def test_an_ipv6_forward_drop_missing(self) -> None:
        drop = V4_STANDARD_DELETIONS["spool bridge forward drop"]
        found = run_watch(runner_for(listing(STANDARD), v6_listing(without(drop))))
        self.assert_reopened(found, "ip6tables")

    def test_a_host_that_must_carry_protected_drops_but_does_not(self) -> None:
        # The standard chain on a host expected to be the protected variant is a reopened one.
        found = run_watch(v4(), variant=PROTECTED)
        self.assert_reopened(found, "is missing")

    def test_what_it_prints_holds_no_rule_of_the_host(self) -> None:
        edit = inserted(f"-A DOCKER-USER -s {FOREIGN_ADDRESS}/32 -j ACCEPT", before=ESTABLISHED)
        found = run_watch(v4(edit))
        self.assertNotIn(FOREIGN_ADDRESS, found.err + found.out)


class TestUnchecked(unittest.TestCase):
    """A check that cannot be made exits 2: it is a failure, never an intact chain."""

    def assert_unchecked(self, found: Outcome) -> None:
        self.assertEqual(found.status, watcher.EXIT_UNCHECKED, found.err)
        self.assertIn("CANNOT CHECK", found.err)
        self.assertEqual(found.out, "")

    def test_a_listing_the_tool_refused(self) -> None:
        found = run_watch(runner_for("", status=4, stderr="Permission denied (you must be root)"))
        self.assert_unchecked(found)

    def test_a_missing_policy_program(self) -> None:
        self.assert_unchecked(run_watch(v4(), reconciler=ROLE / "no-such-program"))

    def test_a_policy_program_that_no_longer_names_its_values(self) -> None:
        empty = ROLE / "tests" / "unit" / "fixtures" / "v6-standard.txt"
        self.assert_unchecked(run_watch(v4(), reconciler=empty))

    def test_a_chain_name_that_is_not_one(self) -> None:
        self.assert_unchecked(run_watch(v4(), allowlist=("not a chain name",)))

    def test_an_exit_zero_listing_of_nothing_is_not_intact(self) -> None:
        found = run_watch(runner_for(""))
        self.assertNotEqual(found.status, watcher.EXIT_INTACT)

    def test_an_unexpected_failure_is_unchecked_and_names_only_its_type(self) -> None:
        def broken(_family: chain.Family) -> chain.Listing:
            message = f"secret {FOREIGN_ADDRESS}"
            raise RuntimeError(message)

        err = io.StringIO()
        with (
            mock.patch.object(watcher, "list_table", broken),
            mock.patch.object(sys, "stderr", err),
        ):
            status = watcher.main(["--variant", STANDARD, "--reconciler", str(PROGRAM)])
        self.assertEqual(status, watcher.EXIT_UNCHECKED)
        self.assertIn("RuntimeError", err.getvalue())
        self.assertNotIn(FOREIGN_ADDRESS, err.getvalue())


class TestTool(unittest.TestCase):
    """The real listing call: what it runs, and what it makes of a tool that cannot run."""

    def test_it_lists_the_filter_table_waiting_for_the_lock_without_a_shell(self) -> None:
        done = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="-P INPUT ACCEPT\n", stderr=""
        )
        with (
            mock.patch.object(watcher, "find_tool", return_value="/usr/sbin/iptables"),
            mock.patch.object(subprocess, "run", return_value=done) as run,
        ):
            result = watcher.list_table("iptables")
        self.assertEqual(result, chain.Listing(0, "-P INPUT ACCEPT\n", ""))
        self.assertEqual(run.call_args.args[0], ["/usr/sbin/iptables", "-w", "-t", "filter", "-S"])
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(run.call_args.kwargs["timeout"], watcher.LIST_TIMEOUT_SECONDS)

    def test_a_tool_that_is_not_installed_is_a_failed_listing(self) -> None:
        with mock.patch.object(watcher, "find_tool", return_value=None):
            result = watcher.list_table("ip6tables")
        self.assertNotEqual(result.status, 0)

    def test_a_tool_that_hangs_is_a_failed_listing(self) -> None:
        timeout = subprocess.TimeoutExpired(cmd="iptables", timeout=1)
        with (
            mock.patch.object(watcher, "find_tool", return_value="/usr/sbin/iptables"),
            mock.patch.object(subprocess, "run", side_effect=timeout),
        ):
            result = watcher.list_table("iptables")
        self.assertNotEqual(result.status, 0)

    def test_a_tool_that_cannot_be_run_is_a_failed_listing(self) -> None:
        with (
            mock.patch.object(watcher, "find_tool", return_value="/usr/sbin/iptables"),
            mock.patch.object(subprocess, "run", side_effect=PermissionError(13, "denied")),
        ):
            result = watcher.list_table("iptables")
        self.assertNotEqual(result.status, 0)

    def test_installed_beside_its_checks_it_runs_isolated_and_loads_them_by_path(self) -> None:
        # As the unit runs it: the interpreter in isolated mode, the program and the checks
        # copied side by side into a directory that is on no path. A missing policy program
        # is refused before any firewall tool is asked, so the status does not depend on the
        # machine the test runs on.
        with tempfile.TemporaryDirectory() as directory:
            for name in ("branchleft_docker_user_watch.py", "deploy_tooling_chain.py"):
                shutil.copy(ROLE / "library" / name, directory)
            done = subprocess.run(  # noqa: S603 - the test interpreter and files it just copied
                [
                    sys.executable,
                    "-I",
                    str(Path(directory) / "branchleft_docker_user_watch.py"),
                    "--variant",
                    STANDARD,
                    "--reconciler",
                    str(Path(directory) / "no-such-program"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(done.returncode, watcher.EXIT_UNCHECKED, done.stderr)
        self.assertIn("cannot read the policy program", done.stderr)

    def test_the_status_of_main_is_the_status_of_the_check(self) -> None:
        arguments = ["--variant", STANDARD, "--reconciler", str(PROGRAM)]
        with mock.patch.object(watcher, "list_table", v4()):
            self.assertEqual(watcher.main(arguments), watcher.EXIT_INTACT)
        reopened = v4(without(ESTABLISHED))
        with mock.patch.object(watcher, "list_table", reopened):
            self.assertEqual(watcher.main(arguments), watcher.EXIT_REOPENED)


class TestUnits(unittest.TestCase):
    """The service and the timer the role installs run the watch and fail the unit with it."""

    def service(self, **values: object) -> str:
        environment = Environment(  # noqa: S701 - a systemd unit, not HTML
            undefined=StrictUndefined,
            keep_trailing_newline=True,
            trim_blocks=True,  # as Ansible renders a template
        )
        environment.filters["quote"] = lambda text: f"'{text}'"
        template = (ROLE / "templates" / "branchleft-docker-user-watch.service.j2").read_text(
            "utf-8"
        )
        context = {
            "deploy_tooling_watch_program_path": "/WATCH/program.py",
            "deploy_tooling_policy_variant": "standard",
            "deploy_tooling_reconciler_path": "/POLICY/program",
            "deploy_tooling_foreign_chain_allowlist": [],
            **values,
        }
        return environment.from_string(template).render(context)

    def exec_start(self, text: str) -> str:
        lines = [ln for ln in text.splitlines() if ln.startswith("ExecStart=")]
        self.assertEqual(len(lines), 1)
        return lines[0]

    def test_the_service_runs_the_watch_isolated_with_the_variant_and_the_program(self) -> None:
        self.assertEqual(
            self.exec_start(self.service()),
            "ExecStart=/usr/bin/python3 -I /WATCH/program.py --variant standard "
            "--reconciler /POLICY/program",
        )

    def test_the_service_names_each_allowed_chain(self) -> None:
        text = self.service(deploy_tooling_foreign_chain_allowlist=["f2b-sshd", "other"])
        self.assertTrue(self.exec_start(text).endswith("--allow 'f2b-sshd' --allow 'other'"))

    def test_the_service_is_a_oneshot_that_stays_inactive_between_ticks(self) -> None:
        text = self.service()
        self.assertIn("Type=oneshot", text)
        self.assertNotIn("RemainAfterExit", text)

    def test_the_service_holds_only_the_capability_it_reads_the_firewall_with(self) -> None:
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", self.service())
        self.assertIn("NoNewPrivileges=yes", self.service())

    def test_the_timer_fires_after_boot_and_again_after_every_run_even_a_failed_one(self) -> None:
        text = (ROLE / "templates" / "branchleft-docker-user-watch.timer.j2").read_text("utf-8")
        self.assertIn("OnBootSec=", text)
        self.assertIn("OnUnitInactiveSec=", text)
        self.assertIn("WantedBy=timers.target", text)

    def test_the_policy_and_the_watch_are_the_files_the_role_installs(self) -> None:
        # The program the service runs and the checks it imports are the role's own library
        # files: one copy in the repository, installed side by side.
        self.assertTrue((ROLE / "library" / "branchleft_docker_user_watch.py").is_file())
        self.assertTrue((ROLE / "library" / "deploy_tooling_chain.py").is_file())


if __name__ == "__main__":
    unittest.main()
