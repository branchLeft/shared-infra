"""Check that the estate's masquerade and its forwarding sysctl each have one home on a host, and
that edge1 alone applies the role that holds them there.

The masquerade used to be an iptables rule inserted by the NAT reconciler. On edge1 it is now a
rule in the `ip branchleft_edge_nat` table that the `edge_firewall` role loads, and the reconciler
(`egress_nat`'s `branchleft_nat.py`) reads that table: when it holds a masquerade the reconciler
inserts none and writes no sysctl drop-in. On every host without the role's table (the edget
gateway) the reconciler keeps doing both, as it always did. Two homes on one host would be two
masquerades for the same traffic, or one that a later change removes while the other keeps the
checks green. The forwarding sysctl is the same: the role writes the drop-in and sets the running
value, and the reconciler writes it only where the role's table is not loaded.

The role's variables are edge1's alone: `HOST_PLAY_VARS` in the owner-only checks pins them, so
the enforce flip is an owner-merged change and no other host can carry the role's input filter.

Red then green: make the reconciler masquerade whether or not the role's table is loaded, or write
`/etc/sysctl.d/99-branchleft-nat.conf` from another role, or set `edge_firewall_enforce` in
another playbook, and a test below fails.
"""

from __future__ import annotations

import ast
import re
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from check_enrolment import HOST_PLAY_VARS, ROOT

ANSIBLE = ROOT / "ansible"
HETZNER = ROOT / "hetzner"
ROLE = "edge_firewall"
ROLE_DIR = ANSIBLE / "roles" / ROLE
GATEWAY_HOST = "edge1"
OTHER_HOSTS = ("ops1", "app1", "db1", "demo1", "dbt1", "appt1", "edget", "mx1")
PINNED = {"edge_firewall_nat_source": "10.20.1.0/24", "edge_firewall_enforce": False}
DROP_IN = "99-branchleft-nat.conf"

# What a source file looks like when it adds a masquerade: an nftables rule ending in the verb, or
# an iptables insert or append (or the reconciler's ensure_rule helper) naming MASQUERADE.
NFT_MASQUERADE = re.compile(
    r"^\s*(?:ip\s+saddr\b.*)?\boifname\b.*\bmasquerade\s*$|^\s*masquerade\s*$"
)
IPTABLES_MASQUERADE_ADD = re.compile(
    r"(?:\s-[IA]\s|ensure_rule\s+nat\b|ensure_rule\(\s*[\"']nat[\"']).*MASQUERADE"
    r"|MASQUERADE.*(?:\s-[IA]\s)"
)

# Directories whose files are tests, fixtures, documentation or a recipe for a consumer to copy,
# not code a host runs: they may show a masquerade without being a second home for it.
SKIPPED_PARTS = frozenset(("molecule", "tests", "patterns", "node_modules", ".venv", "__pycache__"))
SKIPPED_SUFFIXES = (".md",)

# The program that may insert the iptables masquerade: the reconciler the egress_nat role delivers.
# On a host where this role has loaded its table it inserts none (see the AST test below).
RECONCILER = "ansible/roles/egress_nat/files/branchleft_nat.py"
HAND_INSTALLERS = ANSIBLE / "checks" / "hand_installers.yml"


def pending_role_scripts() -> frozenset[str]:
    """The hand-installed scripts due for removal, as the register lists them.

    They are read from the register and not named here, so a script added to it later is
    covered with no edit, and this file names none of them.
    """
    register = _mapping(yaml.safe_load(HAND_INSTALLERS.read_text(encoding="utf-8")))
    return frozenset(
        path for path, row in register.items() if _mapping(row).get("reason") == "pending-role"
    )


def code_in_the_tree() -> list[Path]:
    """Every file a host runs under ansible/ and hetzner/, but for the hand installers."""
    pending = pending_role_scripts()
    return [
        path
        for path in _files(ANSIBLE) + _files(HETZNER)
        if str(path.relative_to(ROOT)) not in pending
    ]


def _mapping(value: object) -> dict[str, object]:
    """Return the mapping with string keys.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"expected a mapping, found {type(value).__name__}"
        raise TypeError(message)
    return {str(key): item for key, item in value.items()}


def _sequence(value: object) -> list[object]:
    """Return the list.

    Raises:
        TypeError: the value is not a list.
    """
    if not isinstance(value, list):
        message = f"expected a list, found {type(value).__name__}"
        raise TypeError(message)
    return list(value)


def _is_code(path: Path) -> bool:
    name = path.name
    if name.startswith("test_") or name.endswith((".test.ts", "_test.py")):
        return False
    if name.endswith(SKIPPED_SUFFIXES):
        return False
    return not SKIPPED_PARTS.intersection(path.parts)


def _files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*") if path.is_file() and _is_code(path.relative_to(ROOT))
    )


def code_lines(path: Path) -> list[str]:
    """The non-comment lines of a file, or none if it is not text."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def masquerade_adders(paths: list[Path]) -> list[str]:
    """The files that add a masquerade, as repository-relative paths."""
    found: list[str] = []
    for path in paths:
        for line in code_lines(path):
            if NFT_MASQUERADE.search(line) or IPTABLES_MASQUERADE_ADD.search(line):
                found.append(str(path.relative_to(ROOT)))
                break
    return found


def play(host: str) -> dict[str, object]:
    """The one play of a host's playbook."""
    plays = _sequence(
        yaml.safe_load((ANSIBLE / "playbooks" / f"{host}.yml").read_text(encoding="utf-8"))
    )
    return _mapping(plays[0])


def play_vars(host: str) -> dict[str, object]:
    """The play vars of a host's playbook."""
    return _mapping(play(host).get("vars", {}))


def role_names(host: str) -> list[str]:
    """The roles a host's playbook applies, by directory name."""
    return [Path(str(_mapping(entry)["role"])).name for entry in _sequence(play(host)["roles"])]


def _called_in_the_else_of(path: Path, callee: str, first_argument: str | None) -> bool:
    """Whether every call of `callee` in the file sits in the `else` of `if role_owns_nat:`.

    A call that sat anywhere else would run on a host where the role's table is the home, and
    the reconciler would then be a second home. At least one such call must exist, so a rename
    that made the scan find nothing is a failure and not a pass.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == callee
        and (
            first_argument is None
            or (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == first_argument
            )
        )
    ]
    if not calls:
        return False
    for call in calls:
        node: ast.AST = call
        inside_else = False
        while node in parents:
            parent = parents[node]
            if (
                isinstance(parent, ast.If)
                and isinstance(parent.test, ast.Name)
                and parent.test.id == "role_owns_nat"
                and node in parent.orelse
            ):
                inside_else = True
                break
            node = parent
        if not inside_else:
            return False
    return True


class MasqueradeHasOneHomePerHost(unittest.TestCase):
    """Only the role's template adds the nftables masquerade; only the reconciler, and only where
    the role's table is not the home, adds the iptables one."""

    def test_the_scan_finds_the_template_it_is_meant_to_find(self) -> None:
        # A control: a scan that found nothing anywhere would make the next test pass.
        found = masquerade_adders([ROLE_DIR / "templates" / "rules.nft.j2"])
        self.assertEqual(["ansible/roles/edge_firewall/templates/rules.nft.j2"], found)

    def test_the_scan_finds_a_reconciler_that_inserts_one(self) -> None:
        sabotaged = [
            'ensure_rule nat POSTROUTING -s "$SUBNET" -o "$uplink" -j MASQUERADE',
            "iptables -t nat -I POSTROUTING 1 -s 10.20.1.0/24 -o eth0 -j MASQUERADE",
            'ensure_rule("nat", "POSTROUTING", "-s", subnet, "-o", uplink, "-j", "MASQUERADE")',
        ]
        for line in sabotaged:
            with self.subTest(line=line):
                self.assertTrue(IPTABLES_MASQUERADE_ADD.search(line))
        self.assertIsNone(
            IPTABLES_MASQUERADE_ADD.search("iptables -t nat -C POSTROUTING -j MASQUERADE")
        )
        self.assertIsNone(
            IPTABLES_MASQUERADE_ADD.search("iptables -t nat -D POSTROUTING -j MASQUERADE")
        )

    def test_the_register_of_hand_installers_is_read_and_not_empty(self) -> None:
        # A control: an empty read would make the scans below cover every file, hand
        # installers included, and the next test would then fail for the wrong reason.
        self.assertGreater(len(pending_role_scripts()), 5)

    def test_only_the_roles_template_and_the_reconciler_add_a_masquerade(self) -> None:
        self.assertEqual(
            sorted(["ansible/roles/edge_firewall/templates/rules.nft.j2", RECONCILER]),
            sorted(masquerade_adders(code_in_the_tree())),
        )

    def test_the_reconciler_masquerades_only_where_the_roles_table_is_not_the_home(self) -> None:
        reconciler = ROOT / RECONCILER
        self.assertTrue(_called_in_the_else_of(reconciler, "ensure_rule", "nat"))

    def test_the_reconciler_sets_forwarding_only_where_the_role_does_not(self) -> None:
        reconciler = ROOT / RECONCILER
        self.assertTrue(_called_in_the_else_of(reconciler, "write_forwarding_drop_in", None))
        self.assertTrue(_called_in_the_else_of(reconciler, "turn_forwarding_on", None))

    def test_the_scan_of_the_branch_notices_a_call_outside_it(self) -> None:
        # Sabotage on a copy: the masquerade call moved out of the else.
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "branchleft_nat.py"
            copy.write_text(
                "def main():\n"
                "    if role_owns_nat:\n"
                "        pass\n"
                "    else:\n"
                "        ensure_rule('nat', 'POSTROUTING')\n"
                "    ensure_rule('nat', 'POSTROUTING')\n",
                encoding="utf-8",
            )
            self.assertFalse(_called_in_the_else_of(copy, "ensure_rule", "nat"))
            copy.write_text("def main():\n    pass\n", encoding="utf-8")
            self.assertFalse(_called_in_the_else_of(copy, "ensure_rule", "nat"))

    def test_the_roles_only_other_use_of_the_iptables_masquerade_is_to_read_and_remove_it(
        self,
    ) -> None:
        tasks = (ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8")
        flags = re.findall(r"- -([A-Za-z])\n      - POSTROUTING", tasks)
        self.assertEqual(["C", "D"], flags)


class ForwardingSysctlHasOneWriterPerHost(unittest.TestCase):
    """The role writes the drop-in and sets the running value; the reconciler writes it only
    where the role's table is not loaded."""

    HOMES = sorted(["ansible/roles/edge_firewall/vars/main.yml", RECONCILER])

    def test_the_drop_in_is_named_in_the_role_and_the_reconciler_and_no_other_code(
        self,
    ) -> None:
        named = [
            str(path.relative_to(ROOT))
            for path in code_in_the_tree()
            if any(DROP_IN in line for line in code_lines(path))
        ]
        self.assertEqual(self.HOMES, sorted(named))

    def test_no_code_but_the_role_and_the_reconciler_sets_forwarding(self) -> None:
        setters = re.compile(
            r"sysctl\s+(?:-q\s+)?-w\s+net\.ipv4\.ip_forward"
            r"|name:\s*net\.ipv4\.ip_forward"
            r"|[\"']sysctl[\"'],\s*[\"']-q[\"'],\s*[\"']-w[\"'],\s*[\"']net\.ipv4\.ip_forward"
        )
        found = [
            str(path.relative_to(ROOT))
            for path in code_in_the_tree()
            if any(setters.search(line) for line in code_lines(path))
        ]
        self.assertEqual(
            sorted(["ansible/roles/edge_firewall/tasks/main.yml", RECONCILER]),
            sorted(found),
        )


class TheRoleIsEdge1Alone(unittest.TestCase):
    """The role's two variables are edge1's, pinned by the owner-only checks."""

    def test_the_table_pins_edge1_to_the_two_values(self) -> None:
        row = HOST_PLAY_VARS[GATEWAY_HOST]
        self.assertEqual(PINNED, {key: row[key] for key in PINNED})

    def test_edge1s_whole_row_is_the_class_the_switch_and_the_two_firewall_values(self) -> None:
        self.assertEqual(
            {
                "deploy_tooling_host_class": "gateway",
                "egress_nat_gateway_enabled": True,
                **PINNED,
            },
            HOST_PLAY_VARS[GATEWAY_HOST],
        )

    def test_edge1s_playbook_carries_exactly_the_pinned_values(self) -> None:
        carried = play_vars(GATEWAY_HOST)
        self.assertEqual(PINNED, {key: carried[key] for key in PINNED})

    def test_enforce_is_off_until_the_owner_merges_the_flip(self) -> None:
        # Stage A is monitor mode. The flip to enforce is one line in two files, merged by the
        # owner (ansible/checks/ is an owner path). This holds the playbook at monitor mode so the
        # flip cannot arrive by any other file.
        self.assertIs(play_vars(GATEWAY_HOST)["edge_firewall_enforce"], False)
        self.assertIs(HOST_PLAY_VARS[GATEWAY_HOST]["edge_firewall_enforce"], False)

    def test_no_other_host_is_pinned_to_either_value(self) -> None:
        for host, pinned in HOST_PLAY_VARS.items():
            if host != GATEWAY_HOST:
                with self.subTest(host=host):
                    self.assertFalse(set(PINNED) & set(pinned))

    def test_no_other_playbook_sets_either_value_or_applies_the_role(self) -> None:
        for host in OTHER_HOSTS:
            with self.subTest(host=host):
                self.assertFalse(set(PINNED) & set(play_vars(host)))
                self.assertNotIn(ROLE, role_names(host))

    def test_the_role_is_on_edge1s_list_alone(self) -> None:
        holders = [
            path.stem
            for path in sorted((ANSIBLE / "checks" / "host_roles").glob("*.yml"))
            if ROLE in _sequence(yaml.safe_load(path.read_text(encoding="utf-8")))
        ]
        self.assertEqual([GATEWAY_HOST], holders)

    def test_the_role_is_applied_once_on_edge1_after_the_baseline_and_before_the_reconciler(
        self,
    ) -> None:
        names = role_names(GATEWAY_HOST)
        self.assertEqual(1, names.count(ROLE))
        self.assertLess(names.index("host_baseline"), names.index(ROLE))
        self.assertLess(names.index(ROLE), names.index("egress_nat"))

    def test_no_file_outside_the_role_the_checks_and_edge1s_playbook_names_either_variable(
        self,
    ) -> None:
        homes = (ROLE_DIR, ANSIBLE / "checks", ANSIBLE / "playbooks" / f"{GATEWAY_HOST}.yml")
        names = ("edge_firewall_nat_source", "edge_firewall_enforce")
        stray = [
            str(path.relative_to(ROOT))
            for path in _files(ANSIBLE)
            if not any(path == home or home in path.parents for home in homes)
            and any(name in line for line in code_lines(path) for name in names)
        ]
        self.assertEqual([], stray)


# The address plan's one home for the estate subnet. The drift gate (hetzner/scripts/
# check-address-plan-drift.py) ties the playbook and the nat script to it; this ties the two
# pins the owner-only checks hold for edge1, which the drift gate does not read.
ADDRESS_PLAN = ROOT / "hetzner-host" / "addressPlan.ts"
SUBNET_CIDR_EXPORT = re.compile(r"^export const SUBNET_CIDR = '([^']+)'", re.MULTILINE)
SOURCE = "edge_firewall_nat_source"


def _subnet_tie_findings(plan: Path) -> list[str]:
    """Name each way the two pins disagree with the plan's SUBNET_CIDR.

    An empty plan read is a finding, not a pass: a parse that found nothing would agree with
    nothing it was meant to check.
    """
    found = SUBNET_CIDR_EXPORT.findall(plan.read_text(encoding="utf-8"))
    if len(found) != 1:
        return [f"{plan.name}: expected exactly one SUBNET_CIDR export, found {len(found)}"]
    subnet = found[0]
    findings = []
    if PINNED[SOURCE] != subnet:
        findings.append(
            f"PINNED[{SOURCE!r}] is {PINNED[SOURCE]!r}, the plan's SUBNET_CIDR is {subnet!r}"
        )
    if HOST_PLAY_VARS[GATEWAY_HOST][SOURCE] != subnet:
        findings.append(
            f"HOST_PLAY_VARS[{GATEWAY_HOST!r}][{SOURCE!r}] is "
            f"{HOST_PLAY_VARS[GATEWAY_HOST][SOURCE]!r}, the plan's SUBNET_CIDR is {subnet!r}"
        )
    return findings


class TheSourcePinIsThePlansSubnet(unittest.TestCase):
    """edge1's masquerade source is the one estate subnet the address plan names."""

    def test_the_real_pins_agree_with_the_address_plan(self) -> None:
        self.assertEqual([], _subnet_tie_findings(ADDRESS_PLAN))

    def test_a_plan_with_another_subnet_fails_by_name(self) -> None:
        # Sabotage on a copy: the plan with its subnet changed, the pins left as they are.
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "addressPlan.ts"
            text = ADDRESS_PLAN.read_text(encoding="utf-8")
            sabotaged = text.replace(
                "export const SUBNET_CIDR = '10.20.1.0/24'",
                "export const SUBNET_CIDR = '10.20.9.0/24'",
                1,
            )
            self.assertNotEqual(text, sabotaged, "the sabotage matched nothing in the plan")
            copy.write_text(sabotaged, encoding="utf-8")
            findings = _subnet_tie_findings(copy)
        self.assertTrue(any(SOURCE in finding for finding in findings), findings)

    def test_an_unreadable_subnet_is_a_finding_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "addressPlan.ts"
            copy.write_text("export const NETWORK_CIDR = '10.20.0.0/16';\n", encoding="utf-8")
            findings = _subnet_tie_findings(copy)
        self.assertEqual(1, len(findings), findings)


if __name__ == "__main__":
    unittest.main()
