#!/usr/bin/env python3
"""Pins who may reach the mailgun-shim's bulk-mail port in mail/firewall.ts.

Port 8443 is the shim's TLS endpoint. Its one caller is the blog's Ghost on
app1. app1 has its own public interface (ghost-platform `infra/hosts` creates
it with public networking), so it reaches mx1 from its own public IPv4, not
from the estate NAT's. The rule must name that address and nothing wider, and
must read it from the hosts stack's `app1PublicIpv4` output rather than any
other host's: edge1's address, which an earlier draft used, would refuse every
send. The address is never typed into this repository. Stdlib only, like the
port parity test beside this file, whose rule parsing this one does not reuse
so that neither test depends on the other's parser.

Each check has a negative case that feeds the same parser a deliberately
widened rule and expects the failure, so a parser that matched nothing, or a
check that could not fail, shows red here instead of passing for it.
"""

from __future__ import annotations

import pathlib
import re
import unittest

FIREWALL = pathlib.Path(__file__).resolve().parent.parent / "firewall.ts"

BULK_MAIL_PORT = "8443"
HOSTS_STACK = "organization/branchleft-ghost-platform-hosts/production"
APP1_OUTPUT = "app1PublicIpv4"
WRONG_HOST_OUTPUT = "edge1PublicIpv4"
SOURCE_BINDING = "app1EgressSource"

RULE_OBJECT = re.compile(r"\{[^{}]*\}")
RULE_PORT = re.compile(r"\bport:\s*'([^']*)'")
RULE_SOURCES = re.compile(r"\bsourceIps:\s*\[([^\]]*)\]")
STACK_REFERENCE = re.compile(r"const (\w+) = new pulumi\.StackReference\(\s*'([^']*)'\s*\);")
WILDCARD_SOURCES = ("0.0.0.0/0", "::/0")
DOTTED_QUAD = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def code_lines(text: str) -> str:
    """The text without whole-line `//` comments, so a comment that mentions a
    wildcard or an address is never read as a rule."""
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))


def rules_for_port(text: str, port: str) -> list[list[str]]:
    """The `sourceIps` entries of every rule object whose port is `port`.

    Raises:
        AssertionError: a rule for the port has no `sourceIps: [...]` list,
            which would be a rule this parser cannot judge."""
    found: list[list[str]] = []
    for rule in RULE_OBJECT.findall(code_lines(text)):
        port_match = RULE_PORT.search(rule)
        if port_match is None or port_match.group(1) != port:
            continue
        sources = RULE_SOURCES.search(rule)
        if sources is None:
            raise AssertionError(f"a rule for port {port} has no sourceIps list: {rule!r}")
        found.append([entry.strip() for entry in sources.group(1).split(",") if entry.strip()])
    return found


def binding_origin(text: str, binding: str) -> tuple[str, str]:
    """The (stack, output) a `const <binding> = <ref>.requireOutput('<out>')...;`
    reads, following the reference variable to the stack it names.

    Raises:
        AssertionError: the binding, its reference variable or its stack
            reference is absent, so the origin cannot be judged."""
    code = code_lines(text)
    stacks = dict(STACK_REFERENCE.findall(code))
    declared = re.search(rf"const {binding} = (\w+)\s*\.requireOutput\('([^']*)'\)", code)
    if declared is None:
        raise AssertionError(f"no `const {binding} = <stack>.requireOutput('<output>')` in firewall.ts")
    variable, output = declared.groups()
    if variable not in stacks:
        raise AssertionError(f"{binding} reads from {variable}, which is not a StackReference constant")
    return stacks[variable], output


def firewall_text() -> str:
    """The text of mail/firewall.ts."""
    return FIREWALL.read_text(encoding="utf-8")


def _rule(port: str, sources: str) -> str:
    return (
        "      {\n"
        "        direction: 'in',\n"
        "        protocol: 'tcp',\n"
        f"        port: '{port}',\n"
        f"        sourceIps: [{sources}],\n"
        "      },\n"
    )


class BulkMailSourceTests(unittest.TestCase):
    def test_the_bulk_mail_port_has_exactly_one_rule(self):
        """One rule for 8443. Two would let a second, wider one hide beside the
        narrow one."""
        rules = rules_for_port(firewall_text(), BULK_MAIL_PORT)
        self.assertEqual(len(rules), 1, f"expected one rule for {BULK_MAIL_PORT}, found {rules}")

    def test_the_bulk_mail_rule_names_the_app1_binding_alone(self):
        """The rule's only source is the binding read from the hosts stack."""
        (sources,) = rules_for_port(firewall_text(), BULK_MAIL_PORT)
        self.assertEqual(sources, [SOURCE_BINDING])

    def test_no_wildcard_source_reaches_the_bulk_mail_port(self):
        """Neither the IPv4 nor the IPv6 wildcard appears in the rule: the port
        is not open to the internet."""
        for sources in rules_for_port(firewall_text(), BULK_MAIL_PORT):
            for wildcard in WILDCARD_SOURCES:
                self.assertNotIn(wildcard, " ".join(sources))

    def test_the_source_is_app1s_own_address_from_the_hosts_stack(self):
        """The binding reads app1PublicIpv4 from the stack that creates app1. Any
        other host's address, or another stack's output of the same name, is the
        wrong host and would refuse every send."""
        self.assertEqual(binding_origin(firewall_text(), SOURCE_BINDING), (HOSTS_STACK, APP1_OUTPUT))

    def test_the_source_goes_through_the_validator_and_is_never_typed(self):
        """The binding passes the output through bulkMailSourceCidr, and the rule
        holds no dotted-quad literal."""
        text = code_lines(firewall_text())
        binding = re.search(rf"const {SOURCE_BINDING} = ([^;]*);", text)
        self.assertIsNotNone(binding, f"no `const {SOURCE_BINDING} = ...;` in firewall.ts")
        assert binding is not None
        self.assertIn("bulkMailSourceCidr(", binding.group(1))
        (sources,) = rules_for_port(text, BULK_MAIL_PORT)
        for source in sources:
            self.assertIsNone(DOTTED_QUAD.search(source), f"a literal address in the rule: {source}")

    def test_no_other_hosts_address_is_read_by_the_program(self):
        """The edge1 output is not read anywhere in the file: it is the address of
        a host that does not carry app1's traffic."""
        self.assertNotIn(WRONG_HOST_OUTPUT, code_lines(firewall_text()))

    def test_the_comment_no_longer_claims_a_serverless_caller(self):
        """Ghost no longer runs on a serverless platform, so the old reason for
        leaving the port open must not survive in the file."""
        self.assertNotIn("serverless", firewall_text().lower())


class ParserCanFailTests(unittest.TestCase):
    """The same parser, fed the rule as it would look if the narrowing were
    undone, so each assertion above is shown able to fail."""

    def test_a_reopened_rule_is_read_as_wildcard(self):
        """Both wildcards back in the rule: the sources are not the binding."""
        (sources,) = rules_for_port(_rule("8443", "'0.0.0.0/0', '::/0'"), BULK_MAIL_PORT)
        self.assertNotEqual(sources, [SOURCE_BINDING])
        self.assertEqual(sources, ["'0.0.0.0/0'", "'::/0'"])

    def test_a_second_wider_rule_is_counted(self):
        """A wide rule added beside the narrow one is seen as a second rule."""
        text = _rule("8443", SOURCE_BINDING) + _rule("8443", "'0.0.0.0/0'")
        self.assertEqual(len(rules_for_port(text, BULK_MAIL_PORT)), 2)

    def test_an_added_ipv6_wildcard_is_seen_beside_the_binding(self):
        """IPv6 left open while IPv4 is narrowed is not the binding alone."""
        (sources,) = rules_for_port(_rule("8443", f"{SOURCE_BINDING}, '::/0'"), BULK_MAIL_PORT)
        self.assertNotEqual(sources, [SOURCE_BINDING])

    def test_a_typed_address_is_not_the_binding(self):
        """A literal address in place of the binding is a different source."""
        (sources,) = rules_for_port(_rule("8443", "'203.0.113.9/32'"), BULK_MAIL_PORT)
        self.assertNotEqual(sources, [SOURCE_BINDING])
        self.assertTrue(DOTTED_QUAD.search(sources[0]))

    def test_the_estate_nat_address_is_read_as_the_wrong_host(self):
        """The earlier draft's source, edge1's address from the estate stack, reads
        as a different origin from the one the rule must have."""
        wrong = (
            "const estateStack = new pulumi.StackReference('organization/branchleft-hetzner-estate/production');\n"
            f"const {SOURCE_BINDING} = estateStack.requireOutput('{WRONG_HOST_OUTPUT}').apply(String);\n"
        )
        origin = binding_origin(wrong, SOURCE_BINDING)
        self.assertEqual(origin, ("organization/branchleft-hetzner-estate/production", WRONG_HOST_OUTPUT))
        self.assertNotEqual(origin, (HOSTS_STACK, APP1_OUTPUT))

    def test_the_right_output_from_the_wrong_stack_is_caught(self):
        """The output's name alone does not pass: the stack must be the hosts stack."""
        wrong = (
            "const estateStack = new pulumi.StackReference('organization/branchleft-hetzner-estate/production');\n"
            f"const {SOURCE_BINDING} = estateStack.requireOutput('{APP1_OUTPUT}');\n"
        )
        self.assertNotEqual(binding_origin(wrong, SOURCE_BINDING), (HOSTS_STACK, APP1_OUTPUT))

    def test_the_wrong_output_from_the_right_stack_is_caught(self):
        """The stack alone does not pass either: the output must be app1's."""
        wrong = (
            f"const hostsStack = new pulumi.StackReference('{HOSTS_STACK}');\n"
            f"const {SOURCE_BINDING} = hostsStack.requireOutput('db1PrivateIp');\n"
        )
        self.assertNotEqual(binding_origin(wrong, SOURCE_BINDING), (HOSTS_STACK, APP1_OUTPUT))

    def test_a_binding_through_the_other_of_two_references_is_followed(self):
        """With both references present, the variable the binding reads decides the
        origin, not the order they are declared in."""
        text = (
            f"const hostsStack = new pulumi.StackReference('{HOSTS_STACK}');\n"
            "const estateStack = new pulumi.StackReference('organization/branchleft-hetzner-estate/production');\n"
            f"const {SOURCE_BINDING} = estateStack.requireOutput('{WRONG_HOST_OUTPUT}');\n"
        )
        self.assertEqual(
            binding_origin(text, SOURCE_BINDING),
            ("organization/branchleft-hetzner-estate/production", WRONG_HOST_OUTPUT),
        )

    def test_a_binding_with_no_reference_raises(self):
        """A source that is not read from a stack reference is refused, not guessed."""
        with self.assertRaises(AssertionError):
            binding_origin(f"const {SOURCE_BINDING} = someOutput.requireOutput('x');\n", SOURCE_BINDING)

    def test_other_ports_are_not_read_as_the_bulk_mail_rule(self):
        """A wildcard on another port, such as 587, is not this rule."""
        self.assertEqual(rules_for_port(_rule("587", "'0.0.0.0/0', '::/0'"), BULK_MAIL_PORT), [])

    def test_a_commented_out_rule_is_ignored(self):
        """A rule on `//` comment lines is not a rule."""
        commented = "".join(f"      // {line}\n" for line in _rule("8443", "'0.0.0.0/0'").splitlines())
        self.assertEqual(rules_for_port(commented, BULK_MAIL_PORT), [])

    def test_a_rule_without_a_source_list_raises(self):
        """A rule this parser cannot judge is refused, not skipped."""
        rule = "      {\n        direction: 'in',\n        protocol: 'tcp',\n        port: '8443',\n      },\n"
        with self.assertRaises(AssertionError):
            rules_for_port(rule, BULK_MAIL_PORT)

    def test_the_parser_finds_the_rules_the_file_declares(self):
        """A parser that matched nothing would pass every check above vacuously."""
        text = firewall_text()
        for port in ("22", "25", "587", "8443"):
            self.assertTrue(rules_for_port(text, port), f"no rule parsed for port {port}")


if __name__ == "__main__":
    unittest.main()
