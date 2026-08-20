#!/usr/bin/env python3
"""Unit tests for check-address-plan-drift.

Every fault this checker looks for is silent in production -- a stale literal
looks like a passing NAT script or a passing runbook check, never like an
error -- so the tests are written the other way round from the usual: each
one builds the drifted layout and asserts the checker *notices*, because a
checker that has stopped noticing is indistinguishable from a clean tree.

The one that matters most is not a drift case at all: a missing or malformed
`addressPlan.ts` has to fail loudly. A checker that finds nothing to compare
and exits 0 is worse than no checker, because it reports health for exactly
the tree it could not actually examine.

No network. No subprocess.
"""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


def _load_module():
    path = pathlib.Path(__file__).resolve().parent / "check-address-plan-drift.py"
    spec = importlib.util.spec_from_file_location("check_address_plan_drift", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capd = _load_module()

SUBNET_CIDR = "10.20.1.0/24"
EDGE1 = "10.20.1.10"


def address_plan(subnet_cidr: str = SUBNET_CIDR, edge1: str = EDGE1) -> str:
    return (
        "export const NETWORK_CIDR = '10.20.0.0/16';\n"
        f"export const SUBNET_CIDR = '{subnet_cidr}';\n"
        "export const HOST_IPS = {\n"
        f"  edge1: '{edge1}',\n"
        "  db1: '10.20.1.20',\n"
        "} as const;\n"
        "export const APP_HOST_IPS = {\n"
        "  app1: '10.20.1.100',\n"
        "} as const;\n"
    )


def nat_script(subnet_cidr: str = SUBNET_CIDR) -> str:
    return f'SUBNET="${{BRANCHLEFT_NAT_SUBNET:-{subnet_cidr}}}"\n'


def runbook(subnet_cidr: str = SUBNET_CIDR, edge1: str = EDGE1, second_cidr: str | None = None) -> str:
    """A runbook with one bare edge1 reference and two verification blocks,
    matching the shape RUNBOOK-provision-host.md actually has: several
    verification steps each grepping the subnet, plus one prose mention of
    the gateway's own address."""
    second_cidr = subnet_cidr if second_cidr is None else second_cidr
    return (
        f"The gateway is `edge1`, at `{edge1}`, which is the address the route names.\n"
        f'  iptables -t nat -S POSTROUTING | grep -- "-s {subnet_cidr} .*-j MASQUERADE"\n'
        f'  iptables -t filter -S DOCKER-USER | grep -- "-s {subnet_cidr} .*-j ACCEPT"\n'
        f'  iptables -t nat -S POSTROUTING | grep -- "-s {second_cidr} .*-j MASQUERADE"\n'
    )


class TreeBuilder:
    """A repository-root-shaped tree in a temporary directory."""

    def __init__(self, root: pathlib.Path):
        self.root = root

    def write(self, relative: str, text: str) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def sound(
        self,
        plan_subnet: str = SUBNET_CIDR,
        plan_edge1: str = EDGE1,
        nat_subnet: str = SUBNET_CIDR,
        runbook_subnet: str = SUBNET_CIDR,
        runbook_second_subnet: str | None = None,
        runbook_edge1: str = EDGE1,
    ) -> "TreeBuilder":
        # Every shell-side value defaults to the *original* literal, not to
        # whatever `plan_*` is this call -- so overriding only `plan_subnet`
        # or `plan_edge1` is what building a drifted tree looks like, without
        # every other parameter having to be restated at every call site.
        runbook_second_subnet = (
            runbook_subnet if runbook_second_subnet is None else runbook_second_subnet
        )
        self.write("hetzner-host/addressPlan.ts", address_plan(plan_subnet, plan_edge1))
        self.write("hetzner/provision/branchleft_nat.sh", nat_script(nat_subnet))
        self.write(
            "hetzner/RUNBOOK-provision-host.md",
            runbook(runbook_subnet, runbook_edge1, runbook_second_subnet),
        )
        return self


class AgreementTests(unittest.TestCase):
    def test_a_consistent_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            self.assertEqual(capd.check(tree.root), [])


class SubnetDriftTests(unittest.TestCase):
    def test_a_widened_subnet_left_stale_in_the_nat_script_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_subnet="10.20.0.0/23")
            failures = capd.check(tree.root)
            joined = " ".join(failures)
            self.assertTrue(
                any("branchleft_nat.sh" in f and "10.20.1.0/24" in f and "10.20.0.0/23" in f for f in failures),
                joined,
            )

    def test_a_widened_subnet_left_stale_in_the_runbook_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(
                plan_subnet="10.20.0.0/23",
                nat_subnet="10.20.0.0/23",  # caught up; only the runbook is stale
            )
            failures = capd.check(tree.root)
            self.assertTrue(
                any(
                    "RUNBOOK-provision-host.md" in f and "10.20.1.0/24" in f and "10.20.0.0/23" in f
                    for f in failures
                ),
                failures,
            )

    def test_the_message_names_the_file_and_both_values(self):
        # The acceptance bar for this gate: an operator reading stderr must
        # see which file disagreed and what the two values were, not only
        # that something, somewhere, did not match.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_subnet="10.20.2.0/24")
            failures = capd.check(tree.root)
            nat_failure = next(f for f in failures if "branchleft_nat.sh" in f)
            self.assertIn(str(tree.root / "hetzner" / "provision" / "branchleft_nat.sh"), nat_failure)
            self.assertIn("10.20.1.0/24", nat_failure)
            self.assertIn("10.20.2.0/24", nat_failure)

    def test_only_one_of_several_runbook_occurrences_going_stale_still_fails(self):
        # RUNBOOK-provision-host.md carries the subnet in several
        # verification blocks. A checker that reads only the first
        # occurrence would call a half-updated runbook clean.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(
                plan_subnet="10.20.2.0/24",
                nat_subnet="10.20.2.0/24",
                runbook_subnet="10.20.2.0/24",
                runbook_second_subnet="10.20.1.0/24",  # this one block was missed
            )
            failures = capd.check(tree.root)
            runbook_failures = [f for f in failures if "RUNBOOK-provision-host.md" in f]
            self.assertEqual(len(runbook_failures), 1)
            self.assertIn("10.20.1.0/24", runbook_failures[0])
            self.assertIn("10.20.2.0/24", runbook_failures[0])

    def test_all_runbook_occurrences_agreeing_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(
                plan_subnet="10.20.2.0/24",
                nat_subnet="10.20.2.0/24",
                runbook_subnet="10.20.2.0/24",
                runbook_second_subnet="10.20.2.0/24",
            )
            self.assertEqual(capd.check(tree.root), [])


class Edge1DriftTests(unittest.TestCase):
    def test_a_moved_edge1_left_stale_in_the_runbook_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_edge1="10.20.1.11")
            failures = capd.check(tree.root)
            edge1_failures = [f for f in failures if "10.20.1.10" in f and "10.20.1.11" in f]
            self.assertEqual(len(edge1_failures), 1)
            self.assertIn("RUNBOOK-provision-host.md", edge1_failures[0])

    def test_edge1_agreeing_while_subnet_drifts_reports_only_the_subnet_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_subnet="10.20.2.0/24")
            failures = capd.check(tree.root)
            self.assertFalse(any("10.20.1.10" in f for f in failures), failures)


class MissingLiteralTests(unittest.TestCase):
    def test_a_runbook_that_stops_mentioning_the_subnet_fails_rather_than_passing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "hetzner/RUNBOOK-provision-host.md",
                f"The gateway is `edge1`, at `{EDGE1}`.\nEverything else moved elsewhere.\n",
            )
            failures = capd.check(tree.root)
            self.assertTrue(
                any(
                    "RUNBOOK-provision-host.md" in f and "found none" in f and "SUBNET_CIDR" in f
                    for f in failures
                ),
                failures,
            )

    def test_a_nat_script_with_no_subnet_literal_fails_rather_than_passing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("hetzner/provision/branchleft_nat.sh", "echo hello\n")
            failures = capd.check(tree.root)
            self.assertTrue(
                any(
                    "branchleft_nat.sh" in f and "found none" in f
                    for f in failures
                ),
                failures,
            )


class MalformedAddressPlanTests(unittest.TestCase):
    """The failure that matters most: a plan the parser cannot read has to
    stop the gate, not let it silently find nothing to compare."""

    def test_a_missing_address_plan_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").unlink()
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("cannot read", failures[0])

    def test_a_plan_with_no_subnet_cidr_constant_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const HOST_IPS = { edge1: '10.20.1.10' } as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("SUBNET_CIDR", failures[0])

    def test_a_plan_with_no_host_ips_block_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("HOST_IPS", failures[0])

    def test_a_host_ips_block_with_no_edge1_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = {\n  db1: '10.20.1.20',\n} as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no `edge1`", failures[0])

    def test_an_empty_address_plan_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text("")
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("SUBNET_CIDR", failures[0])

    def test_a_host_ips_block_does_not_borrow_edge1_from_app_host_ips(self):
        # A regex that searched the whole file for the first `edge1:` rather
        # than scoping to the HOST_IPS block would still pass this tree, and
        # for the wrong reason: it would never have read HOST_IPS at all.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = {\n  db1: '10.20.1.20',\n} as const;\n"
                "export const APP_HOST_IPS = {\n  edge1: '10.20.1.100',\n} as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no `edge1`", failures[0])


class ParsingTests(unittest.TestCase):
    def test_read_address_plan_returns_both_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "addressPlan.ts"
            path.write_text(address_plan())
            self.assertEqual(capd.read_address_plan(path), (SUBNET_CIDR, EDGE1))

    def test_a_bare_ipv4_regex_does_not_match_inside_a_cidr(self):
        self.assertEqual(capd._BARE_IPV4_RE.findall("10.20.1.0/24"), [])

    def test_a_cidr_regex_does_not_match_a_bare_address(self):
        self.assertEqual(capd._CIDR_RE.findall("10.20.1.10"), [])


class ThisRepositoryTests(unittest.TestCase):
    def test_the_real_tree_agrees(self):
        self.assertEqual(capd.check(capd.DEFAULT_ROOT), [])


if __name__ == "__main__":
    unittest.main()
