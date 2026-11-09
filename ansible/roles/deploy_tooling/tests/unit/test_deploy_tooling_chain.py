"""Unit tests for deploy_tooling_chain: the policy it expects, and each way a chain can fail it.

The fixtures under ``fixtures/`` are what ``iptables -S`` printed in a Debian 13 test
container for the policy program, captured from a real run (the module's docstring says
how they print). The container has no Docker, so its test puts the jump from FORWARD to
DOCKER-USER in place the way Docker does, and the captured listings carry that one line.
The program tested is the one the role installs, read from its one home in
``hetzner/provision``. The pattern README gives the command, with the library directory
on PYTHONPATH.
"""

import dataclasses
import json
import re
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast
from unittest import mock

import deploy_tooling_chain as chain
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
FIXTURES = ROLE / "tests" / "unit" / "fixtures"
PROGRAMS = ROLE.parents[2] / "hetzner" / "provision"
PROGRAM = PROGRAMS / "branchleft_docker_user_policy.sh"

STANDARD: chain.Variant = "standard"
PROTECTED: chain.Variant = "protected_no_db"

# The lines each variant's captured chain holds, written out so that a case deletes one by
# its text. They restate the capture on purpose: the table has to be independent of the
# module's own expectation, or removing a row from the module would remove the case too.
V4_STANDARD_DELETIONS: Mapping[str, str] = {
    "established accept": "-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "spool bridge forward drop": "-A DOCKER-USER -i br-mailspool ! -o br-mailspool -j DROP",
    "database accept": "-A DOCKER-USER -d 10.20.1.20/32 -p tcp -m tcp --dport 3306 -j ACCEPT",
    "subnet drop": "-A DOCKER-USER -d 10.20.1.0/24 -j DROP",
    "metadata drop": "-A DOCKER-USER -d 169.254.169.254/32 -j DROP",
}
V4_PROTECTED_DELETIONS: Mapping[str, str] = {
    "established accept": V4_STANDARD_DELETIONS["established accept"],
    "spool bridge forward drop": V4_STANDARD_DELETIONS["spool bridge forward drop"],
    "protected-port drop 8302": (
        "-A DOCKER-USER ! -s 10.20.1.10/32 -p tcp -m conntrack --ctorigdst 10.20.1.50 "
        "--ctorigdstport 8302 -j DROP"
    ),
    "protected-port drop 8301": (
        "-A DOCKER-USER ! -s 10.20.1.10/32 -p tcp -m conntrack --ctorigdst 10.20.1.50 "
        "--ctorigdstport 8301 -j DROP"
    ),
    "protected-port drop 8300": (
        "-A DOCKER-USER ! -s 10.20.1.10/32 -p tcp -m conntrack --ctorigdst 10.20.1.50 "
        "--ctorigdstport 8300 -j DROP"
    ),
    "subnet drop": V4_STANDARD_DELETIONS["subnet drop"],
    "metadata drop": V4_STANDARD_DELETIONS["metadata drop"],
}
INPUT_DELETIONS: Mapping[str, str] = {
    "spool bridge established accept": (
        "-A INPUT -i br-mailspool -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    ),
    "spool bridge input drop": "-A INPUT -i br-mailspool -j DROP",
}
V6_DOCKER_USER_DELETIONS: Mapping[str, str] = {
    "spool bridge forward drop": "-A DOCKER-USER -i br-mailspool ! -o br-mailspool -j DROP",
}


def fixture(name: str) -> str:
    """Return one captured listing."""
    return (FIXTURES / name).read_text(encoding="utf-8")


def listing(variant: str, edit: Callable[[list[str]], list[str]] | None = None) -> str:
    """Return the IPv4 listing of a variant, with ``edit`` applied to its lines."""
    lines = fixture(f"v4-{variant}.txt").splitlines()
    return "\n".join(edit(lines) if edit else lines) + "\n"


def v6_listing(edit: Callable[[list[str]], list[str]] | None = None) -> str:
    """Return the IPv6 listing, with ``edit`` applied to its lines."""
    lines = fixture("v6-standard.txt").splitlines()
    return "\n".join(edit(lines) if edit else lines) + "\n"


def without(*unwanted: str) -> Callable[[list[str]], list[str]]:
    """Return an edit that drops the lines equal to ``unwanted``, and fails if one is absent."""

    def edit(lines: list[str]) -> list[str]:
        for line in unwanted:
            if line not in lines:
                message = f"fixture has no line {line!r}"
                raise AssertionError(message)
        return [line for line in lines if line not in unwanted]

    return edit


def inserted(line: str, before: str) -> Callable[[list[str]], list[str]]:
    """Return an edit that puts ``line`` immediately above the line ``before``."""

    def edit(lines: list[str]) -> list[str]:
        index = lines.index(before)
        return [*lines[:index], line, *lines[index:]]

    return edit


def runner_for(
    v4: str, v6: str | None = None, *, status: int = 0, stderr: str = ""
) -> chain.Runner:
    """Return a runner that lists ``v4`` for iptables and ``v6`` (or the capture) for ip6tables."""
    texts = {"iptables": v4, "ip6tables": v6 if v6 is not None else v6_listing()}

    def run(family: chain.Family) -> chain.Listing:
        return chain.Listing(status, texts[family], stderr)

    return run


def check(
    variant: chain.Variant,
    v4: str | None = None,
    v6: str | None = None,
    allowed: frozenset[str] = frozenset(),
    program: Path = PROGRAM,
) -> chain.Result:
    """Run the whole check against listings, defaulting to the captured ones."""
    params = chain.Params(program, variant, allowed)
    return chain.check_all(params, runner_for(v4 or listing(variant), v6))


class ArgumentSpecTests(unittest.TestCase):
    """The argument_spec matches the documentation, and the module supports check mode."""

    def test_documentation_options_match_the_argument_spec(self) -> None:
        documented = cast(
            "Mapping[str, Mapping[str, Mapping[str, object]]]",
            YAML(typ="safe").load(chain.DOCUMENTATION),
        )["options"]
        self.assertEqual(set(documented), set(chain.ARGUMENT_SPEC))
        for name, option in chain.ARGUMENT_SPEC.items():
            with self.subTest(option=name):
                doc = documented[name]
                self.assertEqual(doc["type"], option["type"])
                self.assertEqual(doc.get("required", False), option.get("required", False))
                self.assertEqual(doc.get("choices"), option.get("choices"))
                self.assertEqual(doc.get("default"), option.get("default"))

    def test_the_module_declares_check_mode_and_changes_nothing(self) -> None:
        fake = mock.MagicMock()
        fake.params = {
            "reconciler_path": str(PROGRAM),
            "variant": STANDARD,
            "foreign_chain_allowlist": [],
        }
        fake.get_bin_path.side_effect = lambda name, required=False: name  # noqa: ARG005
        fake.run_command.side_effect = lambda argv, check_rc=False: (  # noqa: ARG005
            (0, listing(STANDARD), "") if argv[0] == "iptables" else (0, v6_listing(), "")
        )
        with mock.patch.object(chain, "AnsibleModule", return_value=fake) as constructor:
            chain.main()
        self.assertTrue(constructor.call_args.kwargs["supports_check_mode"])
        fake.fail_json.assert_not_called()
        self.assertFalse(fake.exit_json.call_args.kwargs["changed"])
        for call in fake.run_command.call_args_list:
            self.assertEqual(call.args[0][1:], ["-w", "-t", "filter", "-S"])

    def test_a_failing_chain_fails_the_module_with_the_message(self) -> None:
        fake = mock.MagicMock()
        fake.params = {
            "reconciler_path": str(PROGRAM),
            "variant": STANDARD,
            "foreign_chain_allowlist": [],
        }
        fake.get_bin_path.side_effect = lambda name, required=False: name  # noqa: ARG005
        broken = listing(STANDARD, without(V4_STANDARD_DELETIONS["metadata drop"]))
        fake.run_command.side_effect = lambda argv, check_rc=False: (  # noqa: ARG005
            (0, broken, "") if argv[0] == "iptables" else (0, v6_listing(), "")
        )
        fake.fail_json.side_effect = SystemExit
        with (
            mock.patch.object(chain, "AnsibleModule", return_value=fake),
            self.assertRaises(SystemExit),
        ):
            chain.main()
        self.assertIn("metadata drop", fake.fail_json.call_args.kwargs["msg"])


class LiteralTests(unittest.TestCase):
    """The rules' literals come from the policy program, the single home of each."""

    def test_every_literal_is_read_from_the_program_the_role_installs(self) -> None:
        literals = chain.read_literals(PROGRAM.read_text(encoding="utf-8"))
        self.assertEqual(len(dataclasses.asdict(literals)), len(chain.LITERAL_NAMES))
        self.assertTrue(literals.protected_ports)
        self.assertTrue(all(value for value in dataclasses.astuple(literals)))

    def test_a_program_that_no_longer_assigns_a_literal_is_refused_naming_it(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        for name in chain.LITERAL_NAMES:
            with self.subTest(literal=name):
                renamed = text.replace(f"{name}=", f"RENAMED_{name}=")
                self.assertNotEqual(renamed, text)
                with self.assertRaises(chain.LiteralMissingError) as caught:
                    chain.read_literals(renamed)
                self.assertIn(name, str(caught.exception))

    def test_a_program_that_assigns_a_literal_twice_is_refused(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8") + '\nMETADATA_ADDRESS="169.254.169.253"\n'
        with self.assertRaises(chain.LiteralMissingError) as caught:
            chain.read_literals(text)
        self.assertIn("METADATA_ADDRESS", str(caught.exception))

    def test_a_value_that_is_not_an_address_a_port_or_a_name_is_refused(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        bad = text.replace(
            'METADATA_ADDRESS="169.254.169.254"', 'METADATA_ADDRESS="not-an-address"'
        )
        with self.assertRaises(chain.LiteralInvalidError) as caught:
            chain.read_literals(bad)
        self.assertIn("METADATA_ADDRESS", str(caught.exception))

    def test_a_missing_program_is_reported_as_unreadable(self) -> None:
        with self.assertRaises(chain.ReconcilerUnreadableError):
            check(STANDARD, program=PROGRAMS / "does-not-exist")


class ParserTests(unittest.TestCase):
    """The parser reads what iptables prints, and never calls an unknown option an owned rule."""

    def test_an_address_prints_with_a_host_mask_and_is_read_without_it(self) -> None:
        _, rule = chain.parse_rule("-A DOCKER-USER -d 169.254.169.254/32 -j DROP")
        self.assertEqual(rule.dst, "169.254.169.254")

    def test_a_negated_source_and_interface_are_kept_as_negations(self) -> None:
        _, rule = chain.parse_rule(V4_PROTECTED_DELETIONS["protected-port drop 8302"])
        self.assertTrue(rule.src_negated)
        self.assertEqual(rule.src, "10.20.1.10")
        _, forward = chain.parse_rule(V4_STANDARD_DELETIONS["spool bridge forward drop"])
        self.assertTrue(forward.out_negated)
        self.assertEqual(forward.out_iface, "br-mailspool")

    def test_a_negation_the_parser_cannot_keep_makes_the_rule_foreign(self) -> None:
        _, rule = chain.parse_rule("-A DOCKER-USER ! -d 10.20.1.0/24 -j DROP")
        self.assertIn("!", rule.extra)
        self.assertNotEqual(rule, chain.Rule(target="DROP", dst="10.20.1.0/24"))

    def test_an_unknown_option_is_kept_and_counts_as_a_match(self) -> None:
        _, rule = chain.parse_rule('-A DOCKER-USER -m comment --comment "a b" -j DROP')
        self.assertTrue(rule.extra)
        self.assertTrue(rule.has_match)

    def test_a_line_with_an_unbalanced_quote_is_foreign(self) -> None:
        _, rule = chain.parse_rule('-A DOCKER-USER -m comment --comment "open -j ACCEPT')
        self.assertEqual(rule.extra, ("unparsed",))

    def test_a_rule_for_every_packet_has_no_match(self) -> None:
        _, rule = chain.parse_rule("-A DOCKER-USER -j DROP")
        self.assertFalse(rule.has_match)


class PassingTests(unittest.TestCase):
    """The chains the program builds, as captured, pass."""

    def test_the_standard_chain_passes(self) -> None:
        found = check(STANDARD)
        # Five owned rules in IPv4 DOCKER-USER, two in each INPUT, one in IPv6 DOCKER-USER; the
        # two foreign rules are Docker's own RETURN in each DOCKER-USER chain.
        self.assertEqual((found.owned_rules, found.foreign_rules), (5 + 2 + 2 + 1, 2))

    def test_the_protected_chain_without_a_database_passes(self) -> None:
        found = check(PROTECTED)
        self.assertEqual((found.owned_rules, found.foreign_rules), (7 + 2 + 2 + 1, 2))

    def test_a_host_with_no_ipv6_docker_user_chain_passes(self) -> None:
        no_chain = v6_listing(lambda lines: [line for line in lines if "DOCKER-USER" not in line])
        found = check(STANDARD, v6=no_chain)
        self.assertEqual((found.owned_rules, found.foreign_rules), (5 + 2 + 2, 1))


class MissingRuleTests(unittest.TestCase):
    """Deleting any one rule the program adds fails the read-back, naming the rule."""

    def assert_red(self, label: str, message: str) -> None:
        self.assertIn(label, message)
        self.assertIn("missing", message)

    def test_each_ipv4_docker_user_rule_of_a_standard_host(self) -> None:
        for label, line in V4_STANDARD_DELETIONS.items():
            with self.subTest(rule=label), self.assertRaises(chain.RuleMissingError) as caught:
                check(STANDARD, v4=listing(STANDARD, without(line)))
            self.assert_red(label, str(caught.exception))

    def test_each_ipv4_docker_user_rule_of_a_protected_host(self) -> None:
        for label, line in V4_PROTECTED_DELETIONS.items():
            with self.subTest(rule=label), self.assertRaises(chain.RuleMissingError) as caught:
                check(PROTECTED, v4=listing(PROTECTED, without(line)))
            self.assert_red(label, str(caught.exception))

    def test_each_ipv4_input_rule(self) -> None:
        for label, line in INPUT_DELETIONS.items():
            with self.subTest(rule=label), self.assertRaises(chain.RuleMissingError) as caught:
                check(STANDARD, v4=listing(STANDARD, without(line)))
            self.assert_red(label, str(caught.exception))

    def test_each_ipv6_input_rule(self) -> None:
        for label, line in INPUT_DELETIONS.items():
            with self.subTest(rule=label), self.assertRaises(chain.RuleMissingError) as caught:
                check(STANDARD, v6=v6_listing(without(line)))
            self.assert_red(label, str(caught.exception))

    def test_the_ipv6_forward_drop_when_the_chain_exists(self) -> None:
        for label, line in V6_DOCKER_USER_DELETIONS.items():
            with self.subTest(rule=label), self.assertRaises(chain.RuleMissingError) as caught:
                check(STANDARD, v6=v6_listing(without(line)))
            self.assert_red(label, str(caught.exception))

    def test_a_missing_ipv4_docker_user_chain(self) -> None:
        gone = listing(STANDARD, lambda lines: [ln for ln in lines if "DOCKER-USER" not in ln])
        with self.assertRaises(chain.ChainAbsentError):
            check(STANDARD, v4=gone)

    def test_the_message_names_the_expected_rule_and_counts_nothing_else_out(self) -> None:
        with self.assertRaises(chain.RuleMissingError) as caught:
            check(STANDARD, v4=listing(STANDARD, without(V4_STANDARD_DELETIONS["metadata drop"])))
        message = str(caught.exception)
        self.assertIn("-d 169.254.169.254 -j DROP", message)
        self.assertNotIn("RETURN", message)


class OrderTests(unittest.TestCase):
    """The rules have to run in the order the program builds them."""

    def test_the_established_accept_below_the_drops_fails(self) -> None:
        accept = V4_STANDARD_DELETIONS["established accept"]

        def reorder(lines: list[str]) -> list[str]:
            kept = [line for line in lines if line != accept]
            index = kept.index(V4_STANDARD_DELETIONS["metadata drop"])
            return [*kept[: index + 1], accept, *kept[index + 1 :]]

        with self.assertRaises(chain.RuleMisplacedError) as caught:
            check(STANDARD, v4=listing(STANDARD, reorder))
        self.assertTrue(
            str(caught.exception).startswith(
                "iptables DOCKER-USER: the established accept is in the wrong place;"
            ),
            str(caught.exception),
        )

    def test_the_rule_named_is_the_one_that_moved_not_the_one_after_it(self) -> None:
        drop = V4_STANDARD_DELETIONS["spool bridge forward drop"]

        def reorder(lines: list[str]) -> list[str]:
            kept = [line for line in lines if line != drop]
            index = kept.index(V4_STANDARD_DELETIONS["metadata drop"])
            return [*kept[: index + 1], drop, *kept[index + 1 :]]

        with self.assertRaises(chain.RuleMisplacedError) as caught:
            check(STANDARD, v4=listing(STANDARD, reorder))
        self.assertTrue(
            str(caught.exception).startswith(
                "iptables DOCKER-USER: the spool bridge forward drop is in the wrong place;"
            ),
            str(caught.exception),
        )

    def test_protected_ports_in_the_wrong_order_fail(self) -> None:
        first = V4_PROTECTED_DELETIONS["protected-port drop 8302"]
        second = V4_PROTECTED_DELETIONS["protected-port drop 8301"]

        def swap(lines: list[str]) -> list[str]:
            return [second if ln == first else first if ln == second else ln for ln in lines]

        with self.assertRaises(chain.RuleMisplacedError):
            check(PROTECTED, v4=listing(PROTECTED, swap))

    def test_the_two_lowest_protected_ports_in_the_wrong_order_fail(self) -> None:
        first = V4_PROTECTED_DELETIONS["protected-port drop 8301"]
        second = V4_PROTECTED_DELETIONS["protected-port drop 8300"]

        def swap(lines: list[str]) -> list[str]:
            return [second if ln == first else first if ln == second else ln for ln in lines]

        with self.assertRaises(chain.RuleMisplacedError):
            check(PROTECTED, v4=listing(PROTECTED, swap))


class VariantTests(unittest.TestCase):
    """A host is expected to carry exactly its variant's rules."""

    def test_a_standard_host_that_carries_the_protected_drops_fails(self) -> None:
        extra = V4_PROTECTED_DELETIONS["protected-port drop 8302"]
        with self.assertRaises(chain.RuleForbiddenError) as caught:
            check(
                STANDARD,
                v4=listing(
                    STANDARD, inserted(extra, before=V4_STANDARD_DELETIONS["database accept"])
                ),
            )
        self.assertIn("protected-port drop 8302", str(caught.exception))

    def test_a_protected_host_that_carries_the_database_accept_fails(self) -> None:
        extra = V4_STANDARD_DELETIONS["database accept"]
        with self.assertRaises(chain.RuleForbiddenError) as caught:
            check(
                PROTECTED,
                v4=listing(PROTECTED, inserted(extra, before=V4_STANDARD_DELETIONS["subnet drop"])),
            )
        self.assertIn("database accept", str(caught.exception))

    def test_a_protected_chain_read_as_standard_fails_for_the_database_accept(self) -> None:
        with self.assertRaises(chain.RuleMissingError) as caught:
            check(STANDARD, v4=listing(PROTECTED))
        self.assertIn("database accept", str(caught.exception))

    def test_a_standard_chain_read_as_protected_fails_for_the_protected_drops(self) -> None:
        with self.assertRaises(chain.RuleMissingError) as caught:
            check(PROTECTED, v4=listing(STANDARD))
        self.assertIn("protected-port drop", str(caught.exception))


class ForeignRuleTests(unittest.TestCase):
    """A foreign rule above the policy's last drop must not be able to let a packet past it."""

    ABOVE = V4_STANDARD_DELETIONS["established accept"]

    def put_above(self, rule: str, allowed: frozenset[str] = frozenset()) -> chain.Result:
        return check(
            STANDARD, v4=listing(STANDARD, inserted(rule, before=self.ABOVE)), allowed=allowed
        )

    def test_a_matched_accept_above_the_policy_fails(self) -> None:
        with self.assertRaises(chain.RuleBypassError) as caught:
            self.put_above("-A DOCKER-USER -s 172.17.0.0/16 -j ACCEPT")
        self.assertIn(
            "iptables DOCKER-USER: rule 1 of the chain (target: ACCEPT)", str(caught.exception)
        )

    def test_a_failure_prints_no_text_of_the_foreign_rule_only_its_place_and_target(self) -> None:
        rule = (
            "-A DOCKER-USER -s 172.17.0.0/16 -p tcp -m tcp --dport 2222"
            " -m comment --comment admin-ssh -j ACCEPT"
        )
        with self.assertRaises(chain.RuleBypassError) as caught:
            self.put_above(rule)
        message = str(caught.exception)
        for leaked in ("172.17.0.0/16", "2222", "admin-ssh", "comment", "--dport", rule):
            with self.subTest(leaked=leaked):
                self.assertNotIn(leaked, message)
        self.assertEqual(
            message,
            "iptables DOCKER-USER: rule 1 of the chain (target: ACCEPT) is above the policy's last "
            "drop and can let a packet past it; the chain holds 2 other rules",
        )

    def test_a_target_that_is_not_a_chain_name_is_not_printed(self) -> None:
        with self.assertRaises(chain.RuleBypassError) as caught:
            self.put_above("-A DOCKER-USER -j ACCEPT;secret")
        self.assertNotIn("secret", str(caught.exception))
        self.assertIn("target: none or unreadable", str(caught.exception))

    def test_every_failure_of_a_chain_says_how_many_other_rules_it_holds(self) -> None:
        missing = V4_STANDARD_DELETIONS["metadata drop"]
        with self.assertRaises(chain.RuleMissingError) as gone:
            check(STANDARD, v4=listing(STANDARD, without(missing)))
        self.assertTrue(str(gone.exception).endswith("the chain holds 1 other rule"))
        extra = V4_PROTECTED_DELETIONS["protected-port drop 8302"]
        with self.assertRaises(chain.RuleForbiddenError) as forbidden:
            check(
                STANDARD,
                v4=listing(
                    STANDARD, inserted(extra, before=V4_STANDARD_DELETIONS["database accept"])
                ),
            )
        self.assertTrue(str(forbidden.exception).endswith("the chain holds 1 other rule"))

        def reorder(lines: list[str]) -> list[str]:
            accept = V4_STANDARD_DELETIONS["established accept"]
            kept = [line for line in lines if line != accept]
            index = kept.index(V4_STANDARD_DELETIONS["metadata drop"])
            return [*kept[: index + 1], accept, *kept[index + 1 :]]

        with self.assertRaises(chain.RuleMisplacedError) as moved:
            check(STANDARD, v4=listing(STANDARD, reorder))
        self.assertTrue(str(moved.exception).endswith("the chain holds 1 other rule"))

    def test_a_matched_return_above_the_policy_fails(self) -> None:
        with self.assertRaises(chain.RuleBypassError):
            self.put_above("-A DOCKER-USER -s 172.17.0.0/16 -j RETURN")

    def test_a_jump_to_a_chain_nobody_listed_fails(self) -> None:
        with self.assertRaises(chain.RuleBypassError):
            self.put_above("-A DOCKER-USER -j f2b-ssh")

    def test_a_goto_to_a_listed_chain_fails(self) -> None:
        with self.assertRaises(chain.RuleBypassError):
            self.put_above("-A DOCKER-USER -g f2b-ssh", allowed=frozenset({"f2b-ssh"}))

    def test_an_unmatched_drop_above_the_policy_fails(self) -> None:
        with self.assertRaises(chain.RuleBypassError):
            self.put_above("-A DOCKER-USER -j DROP")

    def test_a_jump_to_a_listed_chain_passes(self) -> None:
        found = self.put_above("-A DOCKER-USER -j f2b-ssh", allowed=frozenset({"f2b-ssh"}))
        self.assertEqual(found.foreign_rules, 3)

    def test_a_matched_drop_above_the_policy_passes(self) -> None:
        self.assertEqual(self.put_above("-A DOCKER-USER -s 192.0.2.7/32 -j DROP").foreign_rules, 3)

    def test_a_foreign_accept_in_input_above_the_spool_drop_fails(self) -> None:
        with self.assertRaises(chain.RuleBypassError):
            check(
                STANDARD,
                v4=listing(
                    STANDARD,
                    inserted(
                        "-A INPUT -i eth0 -j ACCEPT",
                        before=INPUT_DELETIONS["spool bridge input drop"],
                    ),
                ),
            )

    def test_a_rule_below_the_last_drop_is_not_checked(self) -> None:
        lines = listing(STANDARD).splitlines()
        lines.append("-A DOCKER-USER -j ACCEPT")
        self.assertEqual(check(STANDARD, v4="\n".join(lines) + "\n").foreign_rules, 3)


class ForwardChainTests(unittest.TestCase):
    """DOCKER-USER is only worth checking if a forwarded packet reaches it first.

    Docker puts the jump to DOCKER-USER first in FORWARD. The captured listings carry that
    jump (the container test puts it there, as Docker does). A rule put above it is evaluated
    before every rule of the policy.
    """

    JUMP = "-A FORWARD -j DOCKER-USER"

    def v4_with(self, edit: Callable[[list[str]], list[str]]) -> chain.Result:
        return check(STANDARD, v4=listing(STANDARD, edit))

    def test_the_captured_listings_carry_the_jump_first(self) -> None:
        for name in ("v4-standard.txt", "v4-protected_no_db.txt", "v6-standard.txt"):
            with self.subTest(listing=name):
                forward = [ln for ln in fixture(name).splitlines() if ln.startswith("-A FORWARD")]
                self.assertEqual(forward, [self.JUMP])

    def test_an_accept_above_the_jump_fails(self) -> None:
        with self.assertRaises(chain.ForwardBypassError) as caught:
            self.v4_with(inserted("-A FORWARD -j ACCEPT", before=self.JUMP))
        self.assertEqual(
            str(caught.exception),
            "iptables FORWARD: its first rule is not the jump to DOCKER-USER, so a forwarded "
            "packet can be accepted before the policy sees it; the chain holds 2 rules",
        )

    def test_a_matched_accept_above_the_jump_fails_without_printing_it(self) -> None:
        with self.assertRaises(chain.ForwardBypassError) as caught:
            self.v4_with(inserted("-A FORWARD -s 192.0.2.7/32 -j ACCEPT", before=self.JUMP))
        self.assertNotIn("192.0.2.7", str(caught.exception))

    def test_a_forward_chain_with_no_jump_fails(self) -> None:
        with self.assertRaises(chain.ForwardBypassError) as caught:
            self.v4_with(without(self.JUMP))
        self.assertIn("the chain holds 0 rules", str(caught.exception))

    def test_a_jump_that_only_some_packets_take_fails(self) -> None:
        with self.assertRaises(chain.ForwardBypassError):
            self.v4_with(
                lambda lines: [
                    "-A FORWARD -i eth0 -j DOCKER-USER" if ln == self.JUMP else ln for ln in lines
                ]
            )

    def test_the_jump_below_other_rules_fails(self) -> None:
        def moved(lines: list[str]) -> list[str]:
            kept = [ln for ln in lines if ln != self.JUMP]
            return [*kept, "-A FORWARD -j DROP", self.JUMP]

        with self.assertRaises(chain.ForwardBypassError):
            self.v4_with(moved)

    def test_the_ipv6_forward_chain_is_read_where_the_chain_exists(self) -> None:
        edit = inserted("-A FORWARD -j ACCEPT", before=self.JUMP)
        with self.assertRaises(chain.ForwardBypassError) as caught:
            check(STANDARD, v6=v6_listing(edit))
        self.assertTrue(str(caught.exception).startswith("ip6tables FORWARD:"))

    def test_the_ipv6_forward_chain_is_not_read_where_docker_made_no_chain(self) -> None:
        no_chain = v6_listing(lambda lines: [ln for ln in lines if "DOCKER-USER" not in ln])
        accept = no_chain.replace(
            "-A INPUT -i br-mailspool -j DROP\n",
            "-A INPUT -i br-mailspool -j DROP\n-A FORWARD -j ACCEPT\n",
        )
        self.assertIn("-A FORWARD -j ACCEPT", accept)
        found = check(STANDARD, v6=accept)
        self.assertEqual(found.owned_rules, 5 + 2 + 2)


class ToolFailureTests(unittest.TestCase):
    """A firewall tool that cannot list its table fails the check, whichever family."""

    def test_either_tool_failing_is_a_failure(self) -> None:
        params = chain.Params(PROGRAM, STANDARD, frozenset())
        with self.assertRaises(chain.ListingError) as caught:
            chain.check_all(params, runner_for("", status=4, stderr="Permission denied\nmore"))
        self.assertIn("exit 4", str(caught.exception))
        self.assertIn("Permission denied", str(caught.exception))

    def test_only_the_first_line_of_the_tools_complaint_is_kept(self) -> None:
        params = chain.Params(PROGRAM, STANDARD, frozenset())
        with self.assertRaises(chain.ListingError) as caught:
            chain.check_all(params, runner_for("", status=4, stderr="first\nsecond"))
        self.assertNotIn("second", str(caught.exception))


class ParameterTests(unittest.TestCase):
    """The typed parameters refuse what the argument_spec lets through."""

    VALID: Mapping[str, object] = {
        "reconciler_path": "/x",
        "variant": STANDARD,
        "foreign_chain_allowlist": ["f2b-ssh"],
    }

    def test_valid_values_are_typed(self) -> None:
        params = chain.params_from_mapping(self.VALID)
        self.assertEqual(params.variant, STANDARD)
        self.assertEqual(params.foreign_chain_allowlist, frozenset({"f2b-ssh"}))

    def test_an_unknown_variant_is_refused(self) -> None:
        with self.assertRaises(chain.ParameterError):
            chain.params_from_mapping({**self.VALID, "variant": "not_applicable"})

    def test_a_chain_name_with_a_space_or_an_option_is_refused(self) -> None:
        for name in ("f2b ssh", "-j", "", "a" * 40):
            with self.subTest(name=name), self.assertRaises(chain.ParameterError):
                chain.params_from_mapping({**self.VALID, "foreign_chain_allowlist": [name]})


def summarise(
    variant: chain.Variant = STANDARD,
    v4: str | None = None,
    v6: str | None = None,
    allowed: frozenset[str] = frozenset(),
    runner: chain.Runner | None = None,
) -> chain.Summary:
    """Run the summary against listings, defaulting to the captured ones and the real program."""
    params = chain.SummaryParams(PROGRAM.read_text(encoding="utf-8"), variant, allowed)
    return chain.summarise(params, runner or runner_for(v4 or listing(variant), v6))


def fresh(lines: list[str]) -> list[str]:
    """Return a listing as a host has it before the policy: no rule of the policy in it."""
    owned = {*V4_STANDARD_DELETIONS.values(), *INPUT_DELETIONS.values()}
    return [line for line in lines if line not in owned]


def refused_position(error: chain.PolicyError) -> int:
    """Return the place in its chain that a RuleBypassError names."""
    found = re.search(r"rule (\d+) of the chain", str(error))
    assert found is not None, str(error)  # noqa: S101
    return int(found[1])


def verdicts(found: chain.Summary, family: chain.Family, name: str) -> list[tuple[int, str]]:
    """Return (place, verdict) for every other rule of one chain."""
    (one,) = [c for c in found.chains if (c.family, c.chain) == (family, name)]
    return [(row.position, row.verdict) for row in one.rows]


# Text a foreign rule carries that a public log must never show: an address, a port, an
# interface, a comment, a negation. Each marker is unique, so a leak is found by the marker.
MARKER_RULES = (
    "-A INPUT -s 198.51.100.77/32 -p tcp -m tcp --dport 2299"
    " -m comment --comment marker-note -j ACCEPT",
    "-A INPUT -i eth9 ! -s 203.0.113.9/32 -j f2b-sshd",
    "-A DOCKER-USER -s 192.0.2.44/32 -i wg-marker0 -j ACCEPT",
    "-A FORWARD -o marker-out0 -j ACCEPT",
)
MARKERS = (
    "198.51.100.77",
    "2299",
    "marker-note",
    "comment",
    "eth9",
    "203.0.113.9",
    "192.0.2.44",
    "wg-marker0",
    "marker-out0",
    "--dport",
    "-A ",
    " ! ",
)


class SummaryTests(unittest.TestCase):
    """Mode summary says what the read-back would refuse, and prints no rule's text."""

    def marked(self) -> str:
        """Return a standard listing whose foreign rules carry the markers, above the policy."""

        def edit(lines: list[str]) -> list[str]:
            out = inserted(
                MARKER_RULES[0], before=INPUT_DELETIONS["spool bridge established accept"]
            )(lines)
            out = inserted(
                MARKER_RULES[1], before=INPUT_DELETIONS["spool bridge established accept"]
            )(out)
            out = inserted(MARKER_RULES[2], before=V4_STANDARD_DELETIONS["established accept"])(out)
            return inserted(MARKER_RULES[3], before="-A FORWARD -j DOCKER-USER")(out)

        return listing(STANDARD, edit)

    def test_the_summary_prints_names_positions_and_counts_never_rule_text(self) -> None:
        found = summarise(v4=self.marked())
        everything = json.dumps(chain.summary_result(found)) + "\n".join(found.lines())
        for marker in MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, everything)
        # The names that may be shown are shown: that is what the capture needs.
        self.assertIn("f2b-sshd", everything)
        self.assertIn("target: ACCEPT", everything)

    def test_a_listing_error_prints_the_exit_status_and_nothing_the_tool_said(self) -> None:
        runner = runner_for("", status=4, stderr="Permission denied 198.51.100.77 marker-note")
        found = summarise(runner=runner)
        everything = json.dumps(chain.summary_result(found)) + "\n".join(found.lines())
        self.assertNotIn("198.51.100.77", everything)
        self.assertNotIn("marker-note", everything)
        self.assertIn("exited 4", everything)

    def test_a_listing_error_is_an_unreadable_row_not_a_failure(self) -> None:
        found = summarise(runner=runner_for("", status=4, stderr="boom"))
        self.assertEqual(found.would_refuse, 0)
        self.assertEqual(found.unreadable, 6)  # four chains and two FORWARD checks
        self.assertTrue(all(c.state == "unreadable" for c in found.chains))

    def test_a_policy_text_that_is_not_usable_still_fails_as_the_apply_would(self) -> None:
        params = chain.SummaryParams("not a program\n", STANDARD, frozenset())
        with self.assertRaises(chain.LiteralMissingError):
            chain.summarise(params, runner_for(listing(STANDARD)))

    def test_the_result_is_counts_flags_and_names_only(self) -> None:
        found = summarise(v4=self.marked())
        result = chain.summary_result(found)
        self.assertEqual(
            set(result),
            {"msg", "summary_lines", "chains", "forward", "would_refuse", "at_risk", "unreadable"},
        )
        # Every word in the structured part is a chain, a family, a state, a verdict or a
        # target name: none of them can be the text of a rule.
        name = re.compile(f"{chain.CHAIN_NAME.pattern}|{re.escape(chain.UNREADABLE_TARGET)}")

        def walk(value: object) -> None:
            if isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    walk(item)
            elif isinstance(value, str):
                self.assertRegex(value, name)
                self.assertIsNotNone(name.fullmatch(value), value)
            else:
                self.assertIsInstance(value, (int, bool))

        walk([result["chains"], result["forward"]])
        for key in ("would_refuse", "at_risk", "unreadable"):
            self.assertIsInstance(result[key], int)

    def test_the_summary_marks_exactly_the_rules_the_apply_would_refuse(self) -> None:
        above = V4_STANDARD_DELETIONS["established accept"]
        cases = {
            "an accept": ("-A DOCKER-USER -s 172.17.0.0/16 -j ACCEPT", frozenset[str]()),
            "a return": ("-A DOCKER-USER -s 172.17.0.0/16 -j RETURN", frozenset[str]()),
            "a jump to an unlisted chain": ("-A DOCKER-USER -j f2b-ssh", frozenset[str]()),
            "a goto to a listed chain": ("-A DOCKER-USER -g f2b-ssh", frozenset({"f2b-ssh"})),
            "an unmatched drop": ("-A DOCKER-USER -j DROP", frozenset[str]()),
        }
        for name, (rule, allowed) in cases.items():
            with self.subTest(case=name):
                text = listing(STANDARD, inserted(rule, before=above))
                with self.assertRaises(chain.RuleBypassError) as caught:
                    check(STANDARD, v4=text, allowed=allowed)
                found = summarise(v4=text, allowed=allowed)
                refused = [
                    p for p, v in verdicts(found, "iptables", "DOCKER-USER") if v == "would-refuse"
                ]
                self.assertEqual(refused[0], refused_position(caught.exception))
                self.assertEqual(found.would_refuse, 1)

    def test_the_same_rules_pass_when_the_apply_would_pass_them(self) -> None:
        above = V4_STANDARD_DELETIONS["established accept"]
        cases = {
            "a jump to a listed chain": ("-A DOCKER-USER -j f2b-ssh", frozenset({"f2b-ssh"})),
            "a matched drop": ("-A DOCKER-USER -s 192.0.2.7/32 -j DROP", frozenset[str]()),
        }
        for name, (rule, allowed) in cases.items():
            with self.subTest(case=name):
                text = listing(STANDARD, inserted(rule, before=above))
                check(STANDARD, v4=text, allowed=allowed)
                found = summarise(v4=text, allowed=allowed)
                self.assertEqual(found.would_refuse, 0)
                self.assertEqual(verdicts(found, "iptables", "DOCKER-USER")[0], (1, "ok"))

    def test_an_allowlisted_target_flips_the_verdict(self) -> None:
        text = listing(
            STANDARD,
            inserted(
                "-A DOCKER-USER -j f2b-ssh", before=V4_STANDARD_DELETIONS["established accept"]
            ),
        )
        self.assertEqual(summarise(v4=text).would_refuse, 1)
        self.assertEqual(summarise(v4=text, allowed=frozenset({"f2b-ssh"})).would_refuse, 0)

    def test_a_rule_below_the_last_drop_is_below_policy(self) -> None:
        text = "\n".join([*listing(STANDARD).splitlines(), "-A DOCKER-USER -j ACCEPT"]) + "\n"
        found = summarise(v4=text)
        self.assertEqual(verdicts(found, "iptables", "DOCKER-USER")[-1], (7, "below-policy"))
        self.assertEqual(found.would_refuse, 0)

    def test_the_captured_chains_have_nothing_the_apply_would_refuse(self) -> None:
        for variant in (STANDARD, PROTECTED):
            with self.subTest(variant=variant):
                found = summarise(variant)
                self.assertEqual((found.would_refuse, found.at_risk, found.unreadable), (0, 0, 0))
                self.assertEqual(
                    verdicts(found, "iptables", "DOCKER-USER"),
                    [(6 if variant == STANDARD else 8, "below-policy")],
                )

    def test_forward_rule_one_other_than_the_docker_user_jump_is_reported(self) -> None:
        jump = "-A FORWARD -j DOCKER-USER"
        cases = {
            "other": inserted("-A FORWARD -j ACCEPT", before=jump),
            "empty": without(jump),
        }
        for first, edit in cases.items():
            with self.subTest(first=first):
                text = listing(STANDARD, edit)
                with self.assertRaises(chain.ForwardBypassError):
                    check(STANDARD, v4=text)
                found = summarise(v4=text)
                (forward,) = [f for f in found.forwards if f.family == "iptables"]
                self.assertEqual(forward.first, first)
                self.assertEqual(found.would_refuse, 1)
                self.assertIn(f"iptables FORWARD: first rule is {first}", " ".join(found.lines()))

    def test_forward_is_reported_as_the_jump_when_it_is_and_not_checked_without_the_chain(
        self,
    ) -> None:
        no_chain = v6_listing(lambda lines: [ln for ln in lines if "DOCKER-USER" not in ln])
        found = summarise(v6=no_chain)
        self.assertEqual(
            {f.family: f.first for f in found.forwards},
            {"iptables": "jump-to-DOCKER-USER", "ip6tables": "not-checked"},
        )

    def test_a_fresh_chain_reports_policy_absent_and_at_risk_not_would_refuse(self) -> None:
        def edit(lines: list[str]) -> list[str]:
            kept = fresh(lines)
            kept = inserted("-A DOCKER-USER -j f2b-ssh", before="-A DOCKER-USER -j RETURN")(kept)
            kept = inserted(
                "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", before="-A FORWARD -j DOCKER-USER"
            )(kept)
            return [*kept, "-A INPUT -s 192.0.2.7/32 -j DROP"]

        text = listing(STANDARD, edit)
        with self.assertRaises(chain.RuleMissingError):
            check(STANDARD, v4=text)
        found = summarise(v4=text)
        (docker_user,) = [
            c for c in found.chains if (c.family, c.chain) == ("iptables", "DOCKER-USER")
        ]
        self.assertEqual((docker_user.policy_present, docker_user.policy_total), (0, 5))
        self.assertEqual(
            verdicts(found, "iptables", "DOCKER-USER"), [(1, "at-risk"), (2, "below-policy")]
        )
        self.assertEqual(verdicts(found, "iptables", "INPUT"), [(1, "at-risk"), (2, "ok")])
        self.assertEqual((found.would_refuse, found.at_risk), (0, 2))

    def test_a_chain_the_policy_needs_that_is_absent_would_be_refused(self) -> None:
        gone = listing(STANDARD, lambda lines: [ln for ln in lines if "DOCKER-USER" not in ln])
        with self.assertRaises(chain.ChainAbsentError):
            check(STANDARD, v4=gone)
        self.assertEqual(summarise(v4=gone).would_refuse, 1)

    def test_a_lookalike_of_an_owned_rule_is_foreign_as_it_is_for_the_read_back(self) -> None:
        lookalike = V4_STANDARD_DELETIONS["subnet drop"].replace("DROP", "ACCEPT")
        text = listing(
            STANDARD, inserted(lookalike, before=V4_STANDARD_DELETIONS["established accept"])
        )
        with self.assertRaises(chain.RuleBypassError):
            check(STANDARD, v4=text)
        self.assertEqual(summarise(v4=text).would_refuse, 1)

    def test_main_in_summary_mode_only_lists_and_never_fails_on_a_listing_error(self) -> None:
        for status in (0, 4):
            with self.subTest(status=status):
                fake = mock.MagicMock()
                fake.params = {
                    "mode": "summary",
                    "reconciler_path": None,
                    "reconciler_text": PROGRAM.read_text(encoding="utf-8"),
                    "variant": STANDARD,
                    "foreign_chain_allowlist": [],
                }
                fake.get_bin_path.side_effect = lambda name, required=False: name  # noqa: ARG005
                fake.run_command.side_effect = lambda argv, check_rc=False, code=status: (  # noqa: ARG005
                    (code, listing(STANDARD) if code == 0 else "", "denied")
                )
                with mock.patch.object(chain, "AnsibleModule", return_value=fake) as constructor:
                    chain.main()
                self.assertEqual(constructor.call_args.kwargs["required_if"], chain.REQUIRED_IF)
                fake.fail_json.assert_not_called()
                self.assertFalse(fake.exit_json.call_args.kwargs["changed"])
                self.assertIn("summary_lines", fake.exit_json.call_args.kwargs)
                for call in fake.run_command.call_args_list:
                    self.assertEqual(call.args[0][1:], ["-w", "-t", "filter", "-S"])

    def test_mode_check_is_the_default_and_keeps_its_result(self) -> None:
        values = {
            "reconciler_path": str(PROGRAM),
            "variant": STANDARD,
            "foreign_chain_allowlist": [],
        }
        runner = runner_for(listing(STANDARD))
        expected = {
            "msg": "the firewall chains carry the policy",
            "owned_rules": 5 + 2 + 2 + 1,
            "foreign_rules": 2,
        }
        self.assertEqual(chain.run(values, runner), expected)
        self.assertEqual(chain.run({**values, "mode": "check"}, runner), expected)

    def test_each_mode_requires_its_own_program_input(self) -> None:
        documented = cast(
            "Mapping[str, Mapping[str, Mapping[str, object]]]",
            YAML(typ="safe").load(chain.DOCUMENTATION),
        )["options"]
        self.assertEqual(
            {(mode, name) for _, mode, names in chain.REQUIRED_IF for name in names},
            {("check", "reconciler_path"), ("summary", "reconciler_text")},
        )
        self.assertEqual(documented["mode"]["choices"], ["check", "summary"])
        self.assertEqual(documented["mode"]["default"], "check")
        for _, _, names in chain.REQUIRED_IF:
            for name in names:
                self.assertFalse(chain.ARGUMENT_SPEC[name].get("required", False))


if __name__ == "__main__":
    unittest.main()
