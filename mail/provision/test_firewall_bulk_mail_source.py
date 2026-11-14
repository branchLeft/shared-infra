#!/usr/bin/env python3
"""Pins who may reach the mailgun-shim's bulk-mail port in mail/firewall.ts.

Port 8443 is the shim's TLS endpoint. Its one caller is the blog on a
private-only estate host, which arrives from the estate's NAT address, so the
rule must name that address and nothing wider. The address is read from the
estate stack's `edge1PublicIpv4` output and never typed into this repository:
a rebuilt edge1 comes back on a different one. Stdlib only, like the port
parity test beside this file, whose rule parsing this one does not reuse so
that neither test depends on the other's parser.

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
ESTATE_STACK = "organization/branchleft-hetzner-estate/production"
ESTATE_OUTPUT = "edge1PublicIpv4"
SOURCE_BINDING = "estateEgressSource"

RULE_OBJECT = re.compile(r"\{[^{}]*\}")
RULE_PORT = re.compile(r"\bport:\s*'([^']*)'")
RULE_SOURCES = re.compile(r"\bsourceIps:\s*\[([^\]]*)\]")
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

    def test_the_bulk_mail_rule_names_the_estate_address_alone(self):
        """The rule's only source is the binding read from the estate stack."""
        (sources,) = rules_for_port(firewall_text(), BULK_MAIL_PORT)
        self.assertEqual(sources, [SOURCE_BINDING])

    def test_no_wildcard_source_reaches_the_bulk_mail_port(self):
        """Neither the IPv4 nor the IPv6 wildcard appears in the rule: the port
        is not open to the internet."""
        for sources in rules_for_port(firewall_text(), BULK_MAIL_PORT):
            for wildcard in WILDCARD_SOURCES:
                self.assertNotIn(wildcard, " ".join(sources))

    def test_the_source_is_read_from_the_estate_stack_not_typed(self):
        """The binding comes from the estate stack's edge1PublicIpv4 output,
        through the validator, and the rule holds no dotted-quad literal."""
        text = code_lines(firewall_text())
        self.assertIn(f"new pulumi.StackReference('{ESTATE_STACK}')", text)
        binding = re.search(rf"const {SOURCE_BINDING} = ([^;]*);", text)
        self.assertIsNotNone(binding, f"no `const {SOURCE_BINDING} = ...;` in firewall.ts")
        assert binding is not None
        self.assertIn(f".requireOutput('{ESTATE_OUTPUT}')", binding.group(1))
        self.assertIn("bulkMailSourceCidr(", binding.group(1))
        (sources,) = rules_for_port(text, BULK_MAIL_PORT)
        for source in sources:
            self.assertIsNone(DOTTED_QUAD.search(source), f"a literal address in the rule: {source}")

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
