#!/usr/bin/env python3
"""Port parity between the mail host's compose files and mail/firewall.ts.

Every non-loopback port a container publishes must be opened by the Hetzner
firewall, and every TCP port the firewall opens must be published by a
container, except the host's own SSH port. Stdlib only: this directory has no
YAML parser, so the compose parser reads just the `ports:` lists it needs.
"""

from __future__ import annotations

import ipaddress
import pathlib
import re
import unittest

PROVISION_DIR = pathlib.Path(__file__).resolve().parent
COMPOSE_FILES = [PROVISION_DIR / "docker-compose.yml", PROVISION_DIR / "shim-compose.yml"]
FIREWALL = PROVISION_DIR.parent / "firewall.ts"

# Host sshd listens on 22 directly; no container publishes it.
FIREWALL_ONLY_TCP_PORTS = {22}

PORTS_KEY = "ports:"
LIST_ITEM_SCALAR = re.compile(r"""-\s+(?:'([^']*)'|"([^"]*)"|([^\s'"#\[\]{}]+))\s*(?:#.*)?$""")
PORT_MAPPING = re.compile(
    r"(?:(\[[0-9A-Fa-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3}):)?(\d+):(\d+)(?:/(tcp|udp))?"
)
RULES_OPEN = "rules: ["
RULES_CLOSE = "],"
RULE_OBJECT = re.compile(r"\{[^{}]*\}")
RULE_DIRECTION = re.compile(r"\bdirection:\s*'([^']*)'")
RULE_PROTOCOL = re.compile(r"\bprotocol:\s*'([^']*)'")
RULE_PORT = re.compile(r"\bport:\s*([^,}\n]+)")
PLAIN_PORT_VALUE = re.compile(r"'(\d+)'")


def _indent(line: str) -> int:
    """Number of leading spaces on a line."""
    return len(line) - len(line.lstrip(" "))


def _parse_mapping(item_text: str) -> tuple[str | None, int, str]:
    """Split one `ports:` scalar into (host_ip_or_None, host_port, protocol).

    Raises AssertionError for anything that is not a single HOST:CONTAINER or
    IP:HOST:CONTAINER mapping, optionally with /tcp or /udp.
    """
    match = LIST_ITEM_SCALAR.match(item_text.strip())
    if match is None:
        raise AssertionError(f"unsupported ports entry (not a single scalar): {item_text!r}")
    scalar = next(group for group in match.groups() if group is not None)
    mapping = PORT_MAPPING.fullmatch(scalar)
    if mapping is None:
        raise AssertionError(
            f"unsupported ports entry {scalar!r}: only HOST:CONTAINER or IP:HOST:CONTAINER, "
            "optionally /tcp or /udp, is parsed (no bare container ports, ranges or long syntax)"
        )
    host_ip, host_port, _container_port, protocol = mapping.groups()
    return host_ip, int(host_port), protocol or "tcp"


def _is_loopback(host_ip: str | None) -> bool:
    """True for a bind address on the loopback interface (127.x.x.x or [::1])."""
    if host_ip is None:
        return False
    return ipaddress.ip_address(host_ip.strip("[]")).is_loopback


def published_ports(text: str) -> set[tuple[int, str]]:
    """(host_port, protocol) for every non-loopback published port in a compose file.

    Reads only the list items under a `ports:` key. Anything else in the file,
    including `- ` items under other keys, is never parsed.
    """
    published: set[tuple[int, str]] = set()
    block_indent: int | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if block_indent is not None:
            if not stripped or stripped.startswith("#"):
                continue
            if _indent(line) <= block_indent:
                block_indent = None
            else:
                host_ip, host_port, protocol = _parse_mapping(stripped)
                if not _is_loopback(host_ip):
                    published.add((host_port, protocol))
                continue
        if stripped == PORTS_KEY:
            block_indent = _indent(line)
        elif stripped.startswith(PORTS_KEY):
            raise AssertionError(f"inline ports value is not parsed: {stripped!r}")
    return published


def firewall_inbound_tcp_ports(text: str) -> set[int]:
    """The port of every inbound TCP rule in mail/firewall.ts's `rules: [` array.

    Commented-out lines are ignored, and nothing after the array's closing
    `],` (such as the applyTos object) is read.
    """
    lines = [line for line in text.splitlines() if not line.strip().startswith("//")]
    stripped = [line.strip() for line in lines]
    if RULES_OPEN not in stripped:
        raise AssertionError("no `rules: [` opening in firewall.ts; the parser has drifted")
    start = stripped.index(RULES_OPEN)
    if RULES_CLOSE not in stripped[start + 1 :]:
        raise AssertionError("no `],` closing the rules array in firewall.ts; the parser has drifted")
    end = start + 1 + stripped[start + 1 :].index(RULES_CLOSE)
    array_body = "\n".join(lines[start + 1 : end])

    ports: set[int] = set()
    for rule in RULE_OBJECT.findall(array_body):
        direction = RULE_DIRECTION.search(rule)
        protocol = RULE_PROTOCOL.search(rule)
        if direction is None or protocol is None:
            continue
        if direction.group(1) != "in" or protocol.group(1) != "tcp":
            continue
        port = RULE_PORT.search(rule)
        value = port.group(1).strip() if port is not None else ""
        plain = PLAIN_PORT_VALUE.fullmatch(value)
        if plain is None:
            raise AssertionError(f"inbound tcp rule has a port that is not a plain digit string: {rule!r}")
        ports.add(int(plain.group(1)))
    return ports


def compose_published_tcp_ports() -> set[int]:
    """Non-loopback published TCP host ports across both compose files."""
    return {
        port
        for compose in COMPOSE_FILES
        for port, protocol in published_ports(compose.read_text(encoding="utf-8"))
        if protocol == "tcp"
    }


def firewall_text() -> str:
    """The text of mail/firewall.ts."""
    return FIREWALL.read_text(encoding="utf-8")


class PortParityTests(unittest.TestCase):
    def test_every_port_a_container_publishes_to_the_network_is_opened_by_the_firewall(self):
        """Each non-loopback published TCP host port in docker-compose.yml and
        shim-compose.yml has an inbound TCP rule in firewall.ts. A port with no
        rule would be published but unreachable, or reachable only by accident.
        """
        opened = firewall_inbound_tcp_ports(firewall_text())
        missing = sorted(compose_published_tcp_ports() - opened)
        self.assertEqual(
            missing,
            [],
            f"published on the network but no inbound tcp rule in mail/firewall.ts: {missing}",
        )

    def test_every_tcp_port_the_firewall_opens_is_published_by_a_container_except_ssh(self):
        """Each inbound TCP port in firewall.ts is published by a container,
        apart from FIREWALL_ONLY_TCP_PORTS (the host's sshd). A rule with nothing
        behind it is an opening that serves nothing.
        """
        opened = firewall_inbound_tcp_ports(firewall_text())
        unpublished = sorted(opened - compose_published_tcp_ports() - FIREWALL_ONLY_TCP_PORTS)
        self.assertEqual(
            unpublished,
            [],
            f"inbound tcp rule in mail/firewall.ts with no container publishing it: {unpublished}",
        )


class ParserNotVacuousTests(unittest.TestCase):
    def test_the_parsers_find_the_ports_the_files_declare(self):
        """A parser that matched nothing would pass the parity tests vacuously."""
        published_count = sum(
            len(published_ports(compose.read_text(encoding="utf-8"))) for compose in COMPOSE_FILES
        )
        self.assertGreaterEqual(published_count, 5, f"only {published_count} published ports parsed")
        inbound_count = len(firewall_inbound_tcp_ports(firewall_text()))
        self.assertGreaterEqual(inbound_count, 8, f"only {inbound_count} inbound tcp rules parsed")


def _compose(ports_lines: str, extra: str = "") -> str:
    """A minimal compose document with one service whose `ports:` block holds
    the given lines (each already indented to 6 spaces).
    """
    return f"services:\n  svc:\n{extra}    ports:\n{ports_lines}"


class ComposeParserTests(unittest.TestCase):
    def test_a_plain_host_container_pair_is_a_tcp_port(self):
        """'25:25' publishes host port 25 over tcp."""
        self.assertEqual(published_ports(_compose("      - '25:25'\n")), {(25, "tcp")})

    def test_a_loopback_bind_is_excluded_for_ipv4_and_ipv6(self):
        """127.0.0.1 and [::1] binds are not network-reachable and are excluded."""
        self.assertEqual(published_ports(_compose("      - '127.0.0.1:8080:8080'\n")), set())
        self.assertEqual(published_ports(_compose("      - '[::1]:8080:8080'\n")), set())

    def test_a_non_loopback_ip_bind_keeps_the_host_port(self):
        """0.0.0.0:2525:25 publishes host port 2525, not the container port 25."""
        self.assertEqual(published_ports(_compose("      - '0.0.0.0:2525:25'\n")), {(2525, "tcp")})

    def test_an_explicit_tcp_suffix_is_tcp(self):
        """'25:25/tcp' is the same as '25:25'."""
        self.assertEqual(published_ports(_compose("      - '25:25/tcp'\n")), {(25, "tcp")})

    def test_a_udp_mapping_is_reported_as_udp(self):
        """'53:53/udp' is udp, so the tests' tcp filter excludes it."""
        self.assertEqual(published_ports(_compose("      - '53:53/udp'\n")), {(53, "udp")})

    def test_a_healthcheck_test_list_beside_ports_is_not_read(self):
        """List items under healthcheck `test:` are not ports and do not raise."""
        healthcheck = (
            "    healthcheck:\n"
            "      test:\n"
            "        - CMD\n"
            "        - node\n"
        )
        document = _compose("      - '25:25'\n", extra=healthcheck)
        self.assertEqual(published_ports(document), {(25, "tcp")})

    def test_a_bare_container_port_raises(self):
        """'8080' alone is a container port with no host mapping, so it is refused."""
        with self.assertRaises(AssertionError):
            published_ports(_compose("      - '8080'\n"))

    def test_a_port_range_raises(self):
        """A range such as '8000-8010:8000-8010' is refused, not silently skipped."""
        with self.assertRaises(AssertionError):
            published_ports(_compose("      - '8000-8010:8000-8010'\n"))

    def test_the_long_syntax_raises(self):
        """The long `target:`/`published:` form is refused."""
        with self.assertRaises(AssertionError):
            published_ports(_compose("      - target: 80\n        published: 80\n"))

    def test_an_inline_ports_value_raises(self):
        """`ports: ['25:25']` on one line is refused, since it is not parsed."""
        with self.assertRaises(AssertionError):
            published_ports("services:\n  svc:\n    ports: ['25:25']\n")


def _firewall(rules: str, after: str = "") -> str:
    """A minimal firewall.ts-shaped document with the given rule objects."""
    return (
        "export const mailFirewall = new hcloud.Firewall('mail-firewall', {\n"
        "    rules: [\n"
        f"{rules}"
        "    ],\n"
        f"{after}"
        "}, {});\n"
    )


TCP_RULE_22 = (
    "      {\n"
    "        direction: 'in',\n"
    "        protocol: 'tcp',\n"
    "        port: '22',\n"
    "        sourceIps: ['0.0.0.0/0', '::/0'],\n"
    "      },\n"
)


class FirewallParserTests(unittest.TestCase):
    def test_a_plain_inbound_tcp_rule_is_read(self):
        """A tcp inbound rule with a digit-string port contributes that port."""
        self.assertEqual(firewall_inbound_tcp_ports(_firewall(TCP_RULE_22)), {22})

    def test_a_commented_out_rule_is_ignored(self):
        """A rule on `//` comment lines is not a rule."""
        commented = "".join(f"      // {line}\n" for line in TCP_RULE_22.splitlines())
        self.assertEqual(firewall_inbound_tcp_ports(_firewall(commented)), set())

    def test_a_tcp_rule_with_a_port_range_raises(self):
        """port: '80-90' is not a plain integer string, so the rule is refused."""
        rule = TCP_RULE_22.replace("port: '22'", "port: '80-90'")
        with self.assertRaises(AssertionError):
            firewall_inbound_tcp_ports(_firewall(rule))

    def test_a_tcp_rule_with_a_numeric_port_raises(self):
        """port: 80 (a number, not a string) is refused."""
        rule = TCP_RULE_22.replace("port: '22'", "port: 80")
        with self.assertRaises(AssertionError):
            firewall_inbound_tcp_ports(_firewall(rule))

    def test_an_icmp_rule_is_ignored(self):
        """An icmp rule has no port and is not an inbound TCP rule."""
        icmp = (
            "      {\n"
            "        direction: 'in',\n"
            "        protocol: 'icmp',\n"
            "        sourceIps: ['0.0.0.0/0', '::/0'],\n"
            "      },\n"
        )
        self.assertEqual(firewall_inbound_tcp_ports(_firewall(icmp + TCP_RULE_22)), {22})

    def test_an_outbound_tcp_rule_is_ignored(self):
        """A direction 'out' tcp rule does not open an inbound port."""
        outbound = TCP_RULE_22.replace("direction: 'in'", "direction: 'out'").replace("port: '22'", "port: '9000'")
        self.assertEqual(firewall_inbound_tcp_ports(_firewall(outbound + TCP_RULE_22)), {22})

    def test_an_object_after_the_rules_array_is_never_read(self):
        """An applyTos-style object after the closing `],` is not a rule."""
        after = (
            "    applyTos: [\n"
            "      {\n"
            "        direction: 'in',\n"
            "        protocol: 'tcp',\n"
            "        port: '9999',\n"
            "      },\n"
            "    ],\n"
        )
        self.assertEqual(firewall_inbound_tcp_ports(_firewall(TCP_RULE_22, after=after)), {22})


if __name__ == "__main__":
    unittest.main()
