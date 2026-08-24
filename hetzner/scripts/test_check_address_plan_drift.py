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
import sys
import tempfile
import unittest


def _load_module():
    path = pathlib.Path(__file__).resolve().parent / "check-address-plan-drift.py"
    spec = importlib.util.spec_from_file_location("check_address_plan_drift", path)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves its owning module through sys.modules at class
    # creation time, so the module has to be registered there before exec --
    # a module built by spec_from_file_location alone never is.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


capd = _load_module()

SUBNET_CIDR = "10.20.1.0/24"
EDGE1 = "10.20.1.10"
DB1 = "10.20.1.20"


def address_plan(subnet_cidr: str = SUBNET_CIDR, edge1: str = EDGE1, db1: str = DB1) -> str:
    return (
        "export const NETWORK_CIDR = '10.20.0.0/16';\n"
        f"export const SUBNET_CIDR = '{subnet_cidr}';\n"
        "export const HOST_IPS = {\n"
        f"  edge1: '{edge1}',\n"
        f"  db1: '{db1}',\n"
        "} as const;\n"
        "export const APP_HOST_IPS = {\n"
        "  app1: '10.20.1.100',\n"
        "} as const;\n"
    )


def nat_script(subnet_cidr: str = SUBNET_CIDR) -> str:
    return f'SUBNET="${{BRANCHLEFT_NAT_SUBNET:-{subnet_cidr}}}"\n'


def docker_user_policy_script(db1: str = DB1) -> str:
    return f'DB_HOST="${{BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST:-{db1}}}"\n'


def runbook(
    subnet_cidr: str = SUBNET_CIDR,
    edge1: str = EDGE1,
    second_cidr: str | None = None,
    db1: str = DB1,
) -> str:
    """A runbook with one bare edge1 reference and two verification blocks,
    matching the shape RUNBOOK-provision-host.md actually has: several
    verification steps each grepping the subnet, one prose mention of the
    gateway's own address, and one verification line naming db1 as the single
    host a DOCKER-USER accept rule renders back with a `/32`."""
    second_cidr = subnet_cidr if second_cidr is None else second_cidr
    return (
        f"The gateway is `edge1`, at `{edge1}`, which is the address the route names.\n"
        f'  iptables -t nat -S POSTROUTING | grep -- "-s {subnet_cidr} .*-j MASQUERADE"\n'
        f'  iptables -t filter -S DOCKER-USER | grep -- "-s {subnet_cidr} .*-j ACCEPT"\n'
        f'  iptables -t nat -S POSTROUTING | grep -- "-s {second_cidr} .*-j MASQUERADE"\n'
        f'  iptables -t filter -S DOCKER-USER | grep -- "-d {db1}/32 -p tcp --dport 3306 -j ACCEPT"\n'
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
        plan_db1: str = DB1,
        nat_subnet: str = SUBNET_CIDR,
        docker_user_policy_db1: str = DB1,
        runbook_subnet: str = SUBNET_CIDR,
        runbook_second_subnet: str | None = None,
        runbook_edge1: str = EDGE1,
        runbook_db1: str = DB1,
    ) -> "TreeBuilder":
        # Every shell-side value defaults to the *original* literal, not to
        # whatever `plan_*` is this call -- so overriding only `plan_subnet`,
        # `plan_edge1` or `plan_db1` is what building a drifted tree looks
        # like, without every other parameter having to be restated at every
        # call site.
        runbook_second_subnet = (
            runbook_subnet if runbook_second_subnet is None else runbook_second_subnet
        )
        self.write(
            "hetzner-host/addressPlan.ts", address_plan(plan_subnet, plan_edge1, plan_db1)
        )
        self.write("hetzner/provision/branchleft_nat.sh", nat_script(nat_subnet))
        self.write(
            "hetzner/provision/branchleft_docker_user_policy.sh",
            docker_user_policy_script(docker_user_policy_db1),
        )
        self.write(
            "hetzner/RUNBOOK-provision-host.md",
            runbook(runbook_subnet, runbook_edge1, runbook_second_subnet, runbook_db1),
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


class Db1DriftTests(unittest.TestCase):
    """db1's address is checked in two places this PR adds: the bare literal
    branchleft_docker_user_policy.sh hardcodes as its DB_HOST default (no
    repository checkout on the host to derive it from, same constraint
    branchleft_nat.sh's SUBNET literal already has), and the `/32` form the
    runbook's own verification block greps for against real `iptables -S`
    output."""

    def test_a_moved_db1_left_stale_in_the_docker_user_policy_script_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_db1="10.20.1.25")
            failures = capd.check(tree.root)
            script_failures = [
                f
                for f in failures
                if "branchleft_docker_user_policy.sh" in f and "10.20.1.20" in f and "10.20.1.25" in f
            ]
            self.assertEqual(len(script_failures), 1, failures)

    def test_a_moved_db1_left_stale_in_the_runbook_slash_32_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(
                plan_db1="10.20.1.25",
                docker_user_policy_db1="10.20.1.25",  # caught up; only the runbook is stale
            )
            failures = capd.check(tree.root)
            runbook_failures = [
                f
                for f in failures
                if "RUNBOOK-provision-host.md" in f
                and "10.20.1.20/32" in f
                and "10.20.1.25/32" in f
            ]
            self.assertEqual(len(runbook_failures), 1, failures)

    def test_db1_agreeing_while_subnet_drifts_reports_only_the_subnet_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_subnet="10.20.2.0/24")
            failures = capd.check(tree.root)
            self.assertFalse(any("10.20.1.20" in f for f in failures), failures)

    def test_db1_and_edge1_and_subnet_all_agreeing_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            self.assertEqual(capd.check(tree.root), [])


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

    def test_a_docker_user_policy_script_with_no_db1_literal_fails_rather_than_passing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("hetzner/provision/branchleft_docker_user_policy.sh", "echo hello\n")
            failures = capd.check(tree.root)
            self.assertTrue(
                any(
                    "branchleft_docker_user_policy.sh" in f and "found none" in f
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

    def test_a_plan_with_no_network_cidr_constant_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = { edge1: '10.20.1.10' } as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("NETWORK_CIDR", failures[0])

    def test_a_plan_with_no_subnet_cidr_constant_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const NETWORK_CIDR = '10.20.0.0/16';\n"
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
                "export const NETWORK_CIDR = '10.20.0.0/16';\n"
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
                "export const NETWORK_CIDR = '10.20.0.0/16';\n"
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = {\n  db1: '10.20.1.20',\n} as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no `edge1`", failures[0])

    def test_a_host_ips_block_with_no_db1_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const NETWORK_CIDR = '10.20.0.0/16';\n"
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = {\n  edge1: '10.20.1.10',\n} as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no `db1`", failures[0])

    def test_an_empty_address_plan_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text("")
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("NETWORK_CIDR", failures[0])

    def test_a_host_ips_block_does_not_borrow_edge1_from_app_host_ips(self):
        # A regex that searched the whole file for the first `edge1:` rather
        # than scoping to the HOST_IPS block would still pass this tree, and
        # for the wrong reason: it would never have read HOST_IPS at all.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).sound()
            (root / "hetzner-host" / "addressPlan.ts").write_text(
                "export const NETWORK_CIDR = '10.20.0.0/16';\n"
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = {\n  db1: '10.20.1.20',\n} as const;\n"
                "export const APP_HOST_IPS = {\n  edge1: '10.20.1.100',\n} as const;\n"
            )
            failures = capd.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no `edge1`", failures[0])

    def test_a_value_that_exists_only_inside_a_comment_is_not_the_export(self):
        # This module's house style narrates reasoning in prose at length,
        # including earlier decisions -- a stale value ahead of the real
        # `export const` in a comment is a realistic accident, not a
        # contrived one, and reading it as canonical points an operator at
        # the wrong file entirely.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            tree = TreeBuilder(root).sound()
            decoy = (
                "// deprecated: export const SUBNET_CIDR = '10.20.2.0/24'; -- do not use\n"
                "/* an old plan once used SUBNET_CIDR = '10.20.3.0/24' here */\n"
            ) + address_plan()
            tree.write("hetzner-host/addressPlan.ts", decoy)
            plan = capd.read_address_plan(root / "hetzner-host" / "addressPlan.ts")
            self.assertEqual(plan.subnet_cidr, SUBNET_CIDR)
            self.assertEqual(capd.check(root), [])


class FalsePositiveExemptionTests(unittest.TestCase):
    """A literal that shares the shape of `SUBNET_CIDR` or `HOST_IPS.edge1`
    is not automatically a stale copy of either -- these are the legitimate
    mentions a gate that matched on shape alone would wrongly flag."""

    def test_the_default_route_and_the_docker_bridge_default_are_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            text = tree.root.joinpath("hetzner/RUNBOOK-provision-host.md").read_text()
            text += (
                "\nA default route (`0.0.0.0/0`) is required, alongside the "
                "docker bridge default `172.17.0.0/16`.\n"
            )
            tree.write("hetzner/RUNBOOK-provision-host.md", text)
            self.assertEqual(capd.check(tree.root), [])

    def test_mentioning_the_estate_s_own_network_cidr_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            text = tree.root.joinpath("hetzner/RUNBOOK-provision-host.md").read_text()
            text += "\nThe whole estate sits inside `10.20.0.0/16`.\n"
            tree.write("hetzner/RUNBOOK-provision-host.md", text)
            self.assertEqual(capd.check(tree.root), [])

    def test_mentioning_another_hosts_real_address_is_not_flagged(self):
        # db1's address is a bare IPv4 literal in the shape the edge1 check
        # scans for, and it is genuinely correct -- it just isn't edge1's.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            text = tree.root.joinpath("hetzner/RUNBOOK-provision-host.md").read_text()
            text += "\n`db1` is reachable at `10.20.1.20`.\n"
            tree.write("hetzner/RUNBOOK-provision-host.md", text)
            self.assertEqual(capd.check(tree.root), [])

    def test_a_genuinely_stale_value_inside_network_cidr_still_fails(self):
        # The exemption above must not swallow the real failure this gate
        # exists for: a stale subnet is inside NETWORK_CIDR too, and matches
        # no *current* plan value, which is exactly what makes it stale.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound(plan_subnet="10.20.2.0/24")
            failures = capd.check(tree.root)
            self.assertTrue(any("branchleft_nat.sh" in f for f in failures), failures)

    def test_a_hosts_own_address_as_a_slash_32_is_not_flagged_as_a_subnet(self):
        # The regression this guards: a DOCKER-USER accept rule naming one
        # host renders back as `<addr>/32` from `iptables -S`, which is
        # CIDR-shaped and falls inside NETWORK_CIDR -- exactly what the
        # SUBNET_CIDR check's own literal scan would otherwise flag as a
        # stale copy of the subnet, on no stronger basis than sharing its
        # shape with one.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            text = tree.root.joinpath("hetzner/RUNBOOK-provision-host.md").read_text()
            text += "\n`db1` is reachable at `10.20.1.20/32`.\n"
            tree.write("hetzner/RUNBOOK-provision-host.md", text)
            self.assertEqual(capd.check(tree.root), [])

    def test_a_stale_slash_32_still_fails_despite_the_exemption_above(self):
        # The exemption must not swallow the real failure either: a stale
        # host address written as a /32 is inside NETWORK_CIDR too, and
        # matches no *current* plan value in either form.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            text = tree.root.joinpath("hetzner/RUNBOOK-provision-host.md").read_text()
            text += "\n`db1` used to be reachable at `10.20.1.25/32`.\n"
            tree.write("hetzner/RUNBOOK-provision-host.md", text)
            failures = capd.check(tree.root)
            self.assertTrue(
                any("RUNBOOK-provision-host.md" in f and "10.20.1.25/32" in f for f in failures),
                failures,
            )


class ParsingTests(unittest.TestCase):
    def test_read_address_plan_returns_the_plans_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "addressPlan.ts"
            path.write_text(address_plan())
            plan = capd.read_address_plan(path)
            self.assertEqual(plan.subnet_cidr, SUBNET_CIDR)
            self.assertEqual(plan.edge1, EDGE1)
            self.assertEqual(plan.db1, DB1)
            self.assertEqual(plan.network_cidr, "10.20.0.0/16")
            self.assertEqual(plan.host_ips["db1"], "10.20.1.20")
            self.assertEqual(plan.app_host_ips["app1"], "10.20.1.100")

    def test_app_host_ips_is_optional(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "addressPlan.ts"
            path.write_text(
                "export const NETWORK_CIDR = '10.20.0.0/16';\n"
                "export const SUBNET_CIDR = '10.20.1.0/24';\n"
                "export const HOST_IPS = {\n  edge1: '10.20.1.10',\n  db1: '10.20.1.20',\n} as const;\n"
            )
            plan = capd.read_address_plan(path)
            self.assertEqual(plan.app_host_ips, {})

    def test_known_values_includes_each_hosts_address_as_a_slash_32(self):
        # The form iptables -S renders an unmasked -d <addr> back as. Without
        # this, a correct /32 host literal and a stale one are
        # indistinguishable from a CIDR-shaped literal's point of view.
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "addressPlan.ts"
            path.write_text(address_plan())
            plan = capd.read_address_plan(path)
            known = plan.known_values()
            self.assertIn(f"{EDGE1}/32", known)
            self.assertIn(f"{DB1}/32", known)
            self.assertIn("10.20.1.100/32", known)  # app1
            # The bare forms stay too -- this only adds to the set.
            self.assertIn(EDGE1, known)
            self.assertIn(DB1, known)

    def test_a_bare_ipv4_regex_does_not_match_inside_a_cidr(self):
        self.assertEqual(capd._BARE_IPV4_RE.findall("10.20.1.0/24"), [])

    def test_a_cidr_regex_does_not_match_a_bare_address(self):
        self.assertEqual(capd._CIDR_RE.findall("10.20.1.10"), [])

    def test_host_slash_32_regex_matches_only_the_slash_32_form(self):
        self.assertEqual(capd._HOST_SLASH_32_RE.findall("10.20.1.20/32"), ["10.20.1.20/32"])
        self.assertEqual(capd._HOST_SLASH_32_RE.findall("10.20.1.0/24"), [])
        self.assertEqual(capd._HOST_SLASH_32_RE.findall("10.20.1.20"), [])

    def test_strip_comments_removes_block_and_line_comments(self):
        text = (
            "kept1\n"
            "// dropped line comment\n"
            "kept2 /* dropped inline block */ kept3\n"
            "/* dropped\nmultiline\nblock */\n"
            "kept4\n"
        )
        stripped = capd._strip_comments(text)
        self.assertIn("kept1", stripped)
        self.assertIn("kept2", stripped)
        self.assertIn("kept3", stripped)
        self.assertIn("kept4", stripped)
        self.assertNotIn("dropped", stripped)


class ThisRepositoryTests(unittest.TestCase):
    def test_the_real_tree_agrees(self):
        self.assertEqual(capd.check(capd.DEFAULT_ROOT), [])


if __name__ == "__main__":
    unittest.main()
