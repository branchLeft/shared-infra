#!/usr/bin/env python3
"""Pins who may reach the mailgun-shim's bulk-mail port in mail/firewall.ts.

Port 8443 is the shim's TLS endpoint. Exactly two sources may reach it, each
read from the stack that names it and never typed into this repository:

- app1's own public IPv4, from the application hosts stack's `app1PublicIpv4`.
  The blog's Ghost on app1 is the caller; app1 has its own public interface, so
  it reaches mx1 from its own address, not through edge1's NAT.
- edge1's public IPv4, from the estate stack's `edge1PublicIpv4`. edge1 runs
  the blackbox probe of this port and certificate, and is the NAT of the
  estate's private-only hosts (the ops1 collector).

Anything else, a wildcard, an IPv6 source, a third address, or either binding
read from the other host's stack, is refused. IPv6 is not allowed at all.
Stdlib only, like the port parity test beside this file, whose rule parsing
this one does not reuse so that neither test depends on the other's parser.
"""

from __future__ import annotations

import pathlib
import re
import unittest

FIREWALL = pathlib.Path(__file__).resolve().parent.parent / "firewall.ts"

BULK_MAIL_PORT = "8443"
HOSTS_STACK = "organization/branchleft-ghost-platform-hosts/production"
ESTATE_STACK = "organization/branchleft-hetzner-estate/production"
APP1_BINDING = "app1EgressSource"
EDGE1_BINDING = "edge1ProbeSource"
APP1_OUTPUT = "app1PublicIpv4"
EDGE1_OUTPUT = "edge1PublicIpv4"
# binding name -> the (stack, output) it must read
ALLOWED = {
    APP1_BINDING: (HOSTS_STACK, APP1_OUTPUT),
    EDGE1_BINDING: (ESTATE_STACK, EDGE1_OUTPUT),
}

RULE_OBJECT = re.compile(r"\{[^{}]*\}")
RULE_PORT = re.compile(r"\bport:\s*'([^']*)'")
RULE_SOURCES = re.compile(r"\bsourceIps:\s*\[([^\]]*)\]")
STACK_REFERENCE = re.compile(r"const (\w+) = new pulumi\.StackReference\(\s*'([^']*)'\s*\);")
WILDCARD_SOURCES = ("0.0.0.0/0", "::/0")
DOTTED_QUAD = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
REQUIRED_OUTPUT = re.compile(r"\.requireOutput\('([^']*)'\)")


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


def refused_sources(sources: list[str]) -> list[str]:
    """The entries of a rule's source list that are not one of the two allowed
    bindings: wildcards, IPv6, typed addresses and any other name."""
    return [entry for entry in sources if entry not in ALLOWED]


def missing_sources(sources: list[str]) -> list[str]:
    """The allowed bindings a rule's source list leaves out."""
    return [binding for binding in ALLOWED if binding not in sources]


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

    def test_the_rule_names_exactly_the_two_allowed_sources(self):
        """app1's and edge1's bindings, each once, and nothing else."""
        (sources,) = rules_for_port(firewall_text(), BULK_MAIL_PORT)
        self.assertEqual(refused_sources(sources), [], f"sources outside the allowed two: {sources}")
        self.assertEqual(missing_sources(sources), [], f"allowed sources left out: {sources}")
        self.assertEqual(len(sources), len(ALLOWED), f"a source is repeated: {sources}")

    def test_no_wildcard_source_reaches_the_bulk_mail_port(self):
        """Neither the IPv4 nor the IPv6 wildcard appears in the rule: the port
        is not open to the internet."""
        for sources in rules_for_port(firewall_text(), BULK_MAIL_PORT):
            for wildcard in WILDCARD_SOURCES:
                self.assertNotIn(wildcard, " ".join(sources))

    def test_each_source_is_read_from_the_stack_that_names_that_host(self):
        """app1's binding reads app1PublicIpv4 from the stack that creates app1;
        edge1's reads edge1PublicIpv4 from the estate stack. Either read from the
        other host's stack or output is the wrong host: app1's sends would be
        refused, or the monitoring probe would be."""
        text = firewall_text()
        for binding, expected in ALLOWED.items():
            with self.subTest(binding=binding):
                self.assertEqual(binding_origin(text, binding), expected)

    def test_the_program_reads_no_other_output(self):
        """Only the two outputs are read from any stack."""
        outputs = REQUIRED_OUTPUT.findall(code_lines(firewall_text()))
        self.assertEqual(sorted(outputs), sorted(output for _, output in ALLOWED.values()))

    def test_each_source_goes_through_the_validator_and_is_never_typed(self):
        """Each binding passes its output through bulkMailSourceCidr, and the rule
        holds no dotted-quad literal."""
        text = code_lines(firewall_text())
        for binding in ALLOWED:
            with self.subTest(binding=binding):
                declared = re.search(rf"const {binding} = ([^;]*);", text)
                self.assertIsNotNone(declared, f"no `const {binding} = ...;` in firewall.ts")
                assert declared is not None
                self.assertIn("bulkMailSourceCidr(", declared.group(1))
        (sources,) = rules_for_port(text, BULK_MAIL_PORT)
        for source in sources:
            self.assertIsNone(DOTTED_QUAD.search(source), f"a literal address in the rule: {source}")

    def test_the_comment_no_longer_claims_a_serverless_caller(self):
        """Ghost no longer runs on a serverless platform, so the old reason for
        leaving the port open must not survive in the file."""
        self.assertNotIn("serverless", firewall_text().lower())


class ParserCanFailTests(unittest.TestCase):
    """The same parsers, fed the rule as it would look if the narrowing were
    undone or pointed at the wrong host, so each assertion above is shown able
    to fail."""

    def test_a_reopened_rule_is_refused(self):
        """Both wildcards back in the rule: neither is an allowed source."""
        (sources,) = rules_for_port(_rule("8443", "'0.0.0.0/0', '::/0'"), BULK_MAIL_PORT)
        self.assertEqual(refused_sources(sources), ["'0.0.0.0/0'", "'::/0'"])
        self.assertEqual(missing_sources(sources), list(ALLOWED))

    def test_app1_alone_is_missing_edge1(self):
        """The earlier head's rule, app1 only, leaves the monitoring probe out."""
        (sources,) = rules_for_port(_rule("8443", APP1_BINDING), BULK_MAIL_PORT)
        self.assertEqual(refused_sources(sources), [])
        self.assertEqual(missing_sources(sources), [EDGE1_BINDING])

    def test_edge1_alone_is_missing_app1(self):
        """The first draft's rule, edge1 only, would refuse every send from app1."""
        (sources,) = rules_for_port(_rule("8443", EDGE1_BINDING), BULK_MAIL_PORT)
        self.assertEqual(refused_sources(sources), [])
        self.assertEqual(missing_sources(sources), [APP1_BINDING])

    def test_a_third_source_is_refused(self):
        """A typed address or another binding beside the two is not allowed."""
        for extra in ("'203.0.113.9/32'", "ops1Source", "'2001:db8::/64'", "'::/0'"):
            with self.subTest(extra=extra):
                (sources,) = rules_for_port(
                    _rule("8443", f"{APP1_BINDING}, {EDGE1_BINDING}, {extra}"), BULK_MAIL_PORT
                )
                self.assertEqual(refused_sources(sources), [extra])

    def test_a_second_wider_rule_is_counted(self):
        """A wide rule added beside the narrow one is seen as a second rule."""
        text = _rule("8443", f"{APP1_BINDING}, {EDGE1_BINDING}") + _rule("8443", "'0.0.0.0/0'")
        self.assertEqual(len(rules_for_port(text, BULK_MAIL_PORT)), 2)

    def test_the_app1_binding_reading_edge1_is_the_wrong_host(self):
        """app1's binding fed edge1's output from the estate stack reads as a
        different origin from the one it must have."""
        wrong = (
            f"const estateStack = new pulumi.StackReference('{ESTATE_STACK}');\n"
            f"const {APP1_BINDING} = estateStack.requireOutput('{EDGE1_OUTPUT}').apply(String);\n"
        )
        origin = binding_origin(wrong, APP1_BINDING)
        self.assertEqual(origin, (ESTATE_STACK, EDGE1_OUTPUT))
        self.assertNotEqual(origin, ALLOWED[APP1_BINDING])

    def test_the_edge1_binding_reading_app1_is_the_wrong_host(self):
        """The swap the other way: edge1's binding fed app1's output."""
        wrong = (
            f"const hostsStack = new pulumi.StackReference('{HOSTS_STACK}');\n"
            f"const {EDGE1_BINDING} = hostsStack.requireOutput('{APP1_OUTPUT}');\n"
        )
        self.assertNotEqual(binding_origin(wrong, EDGE1_BINDING), ALLOWED[EDGE1_BINDING])

    def test_the_right_output_from_the_wrong_stack_is_caught(self):
        """The output's name alone does not pass: the stack must be the right one."""
        wrong = (
            f"const estateStack = new pulumi.StackReference('{ESTATE_STACK}');\n"
            f"const {APP1_BINDING} = estateStack.requireOutput('{APP1_OUTPUT}');\n"
        )
        self.assertNotEqual(binding_origin(wrong, APP1_BINDING), ALLOWED[APP1_BINDING])

    def test_the_wrong_output_from_the_right_stack_is_caught(self):
        """The stack alone does not pass either: the output must be the host's."""
        wrong = (
            f"const hostsStack = new pulumi.StackReference('{HOSTS_STACK}');\n"
            f"const {APP1_BINDING} = hostsStack.requireOutput('db1PrivateIp');\n"
        )
        self.assertNotEqual(binding_origin(wrong, APP1_BINDING), ALLOWED[APP1_BINDING])

    def test_a_binding_through_the_other_of_two_references_is_followed(self):
        """With both references present, the variable the binding reads decides the
        origin, not the order they are declared in."""
        text = (
            f"const hostsStack = new pulumi.StackReference('{HOSTS_STACK}');\n"
            f"const estateStack = new pulumi.StackReference('{ESTATE_STACK}');\n"
            f"const {APP1_BINDING} = estateStack.requireOutput('{EDGE1_OUTPUT}');\n"
        )
        self.assertEqual(binding_origin(text, APP1_BINDING), (ESTATE_STACK, EDGE1_OUTPUT))

    def test_a_binding_with_no_reference_raises(self):
        """A source that is not read from a stack reference is refused, not guessed."""
        with self.assertRaises(AssertionError):
            binding_origin(f"const {APP1_BINDING} = someOutput.requireOutput('x');\n", APP1_BINDING)

    def test_a_third_output_read_is_seen(self):
        """An extra requireOutput in the program shows in the list the test compares."""
        text = f"a.requireOutput('{APP1_OUTPUT}');\nb.requireOutput('{EDGE1_OUTPUT}');\nc.requireOutput('db1PrivateIp');\n"
        self.assertEqual(len(REQUIRED_OUTPUT.findall(code_lines(text))), 3)

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
        self.assertEqual(len(REQUIRED_OUTPUT.findall(code_lines(text))), len(ALLOWED))


if __name__ == "__main__":
    unittest.main()
