"""Check that the edge_firewall role's port lists agree with what edge1 publishes and serves.

The role accepts a short list of TCP ports on edge1: the control port, the public ports, and four
ports published on edge1's private address that reach containers through Docker. Each is a
claim about the rest of the repository, so each is held to its source here:

- the Compose files (`hetzner/edge/stack/compose.yml`, `hetzner/monitoring/stack/compose.yml`):
  every port published on a host address is accepted by a rule, or named as reaching its
  container by DNAT alone, and every rule has a publication behind it;
- the Hetzner firewall (`hetzner-host/firewalls.ts`, EDGE_RULES): the control port and the public
  ports are the ones it opens;
- the monitoring renderer (`hetzner/monitoring/render.ts`) and the Caddyfile: the scrape and
  upstream ports on edge1's private address are among the accepted ones.

A published port with no rule is a flow that default-drop would shut; a rule with no publication
is an opening for nothing. Both fail by name. Red then green: delete the 2586 rule from the
role's vars, or add a published port to a Compose file, and a test below fails.
"""

from __future__ import annotations

import re
import unittest

import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT
from jinja2 import Environment, StrictUndefined

ROLE = ROOT / "ansible" / "roles" / "edge_firewall"
COMPOSE_FILES = (
    ROOT / "hetzner" / "edge" / "stack" / "compose.yml",
    ROOT / "hetzner" / "monitoring" / "stack" / "compose.yml",
)
FIREWALLS_TS = ROOT / "hetzner-host" / "firewalls.ts"
RENDER_TS = ROOT / "hetzner" / "monitoring" / "render.ts"
CADDYFILE = ROOT / "hetzner" / "edge" / "stack" / "Caddyfile"
EDGE1_PRIVATE_ADDRESS = "10.20.1.10"

# host address (None for "every address"), host port, protocol
Publication = tuple[str | None, int, str]


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


def role_vars() -> dict[str, object]:
    """The role's constants, as the role loads them."""
    return _mapping(yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8")))


def port_list(name: str) -> list[int]:
    """One of the role's port lists."""
    return [int(str(port)) for port in _sequence(role_vars()[name])]


def parse_publication(entry: object) -> Publication:
    """Read one `ports:` entry of a Compose service: the short string form or the long mapping.

    Raises:
        ValueError: the entry has a shape the test does not read, so it cannot be judged.
    """
    if isinstance(entry, dict):
        fields = _mapping(entry)
        address = fields.get("host_ip")
        return (
            str(address) if address else None,
            int(str(fields["published"])),
            str(fields.get("protocol", "tcp")),
        )
    text = str(entry)
    protocol = "tcp"
    if "/" in text:
        text, protocol = text.rsplit("/", 1)
    parts = text.split(":")
    if len(parts) == 2:
        return (None, int(parts[0]), protocol)
    if len(parts) == 3:
        return (parts[0], int(parts[1]), protocol)
    message = f"cannot read the published port {entry!r}"
    raise ValueError(message)


def publications(compose_text: str) -> list[Publication]:
    """Every published port of every service in a Compose file."""
    services = _mapping(_mapping(yaml.safe_load(compose_text))["services"])
    found: list[Publication] = []
    for service in services.values():
        for entry in _sequence(_mapping(service).get("ports", [])):
            found.append(parse_publication(entry))
    return found


def all_publications(texts: list[str]) -> list[Publication]:
    """The publications of several Compose files together."""
    found: list[Publication] = []
    for text in texts:
        found.extend(publications(text))
    return found


def private_tcp_ports(published: list[Publication]) -> set[int]:
    """TCP ports published on a private, non-loopback address."""
    return {
        port
        for address, port, protocol in published
        if protocol == "tcp" and address is not None and not address.startswith("127.")
    }


def public_tcp_ports(published: list[Publication]) -> set[int]:
    """TCP ports published on every address."""
    return {port for address, port, protocol in published if protocol == "tcp" and address is None}


def disagreements(
    published: list[Publication],
    *,
    bridge_ports: list[int],
    dnat_only_ports: list[int],
    public_ports: list[int],
) -> list[str]:
    """What a set of publications and a set of rules do not agree on, one sentence each."""
    problems: list[str] = []
    private = private_tcp_ports(published)
    accounted = set(bridge_ports) | set(dnat_only_ports)
    for port in sorted(private - accounted):
        problems.append(
            f"tcp/{port} is published on a private address and has neither an input rule nor "
            "an entry in the DNAT-only list"
        )
    for port in sorted(set(bridge_ports) - private):
        problems.append(f"tcp/{port} has an input rule and no Compose file publishes it")
    for port in sorted(set(dnat_only_ports) - private):
        problems.append(f"tcp/{port} is listed as DNAT-only and no Compose file publishes it")
    for port in sorted(set(dnat_only_ports) & set(bridge_ports)):
        problems.append(f"tcp/{port} is both DNAT-only and given an input rule")
    for port in sorted(public_tcp_ports(published) - set(public_ports)):
        problems.append(f"tcp/{port} is published on every address and is not a public port")
    for port in sorted(set(public_ports) - public_tcp_ports(published)):
        problems.append(f"tcp/{port} is a public port and no Compose file publishes it")
    return problems


def firewall_ports(source: str) -> set[int]:
    """The TCP ports EDGE_RULES opens, read from hetzner-host/firewalls.ts, with SSH.

    Raises:
        AssertionError: the file has no SSH rule this can read, so it cannot be judged.
    """
    rules = source[source.index("export const EDGE_RULES") :]
    rules = rules[: rules.index("];")]
    ports = {int(port) for port in re.findall(r"protocol: 'tcp', port: '(\d+)'", rules)}
    ssh = re.search(r"const SSH[^=]*=\s*\{[^}]*port: '(\d+)'", source)
    if ssh is None:
        message = "hetzner-host/firewalls.ts has no SSH rule the test can read"
        raise AssertionError(message)
    return ports | {int(ssh.group(1))}


def rendered_enforce_rules() -> list[str]:
    """The role's input chain in enforce mode, one rule per entry."""
    env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)  # noqa: S701
    env.filters["bool"] = bool
    template = env.from_string((ROLE / "templates" / "rules.nft.j2").read_text(encoding="utf-8"))
    text = template.render(
        **role_vars(),
        edge_firewall_enforce=True,
        edge_firewall_nat_source="10.20.1.0/24",
        edge_firewall_uplink="eth0",
    )
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


class PortsAgreeWithCompose(unittest.TestCase):
    """Every published port is accounted for, and every rule has a publication."""

    def setUp(self) -> None:
        self.published = all_publications(
            [path.read_text(encoding="utf-8") for path in COMPOSE_FILES]
        )

    def test_the_scan_finds_the_publications_it_is_meant_to_find(self) -> None:
        # A control: a parse that found nothing would make every test below pass.
        self.assertIn((None, 80, "tcp"), self.published)
        self.assertIn((None, 443, "tcp"), self.published)
        self.assertIn((EDGE1_PRIVATE_ADDRESS, 9091, "tcp"), self.published)
        self.assertIn((EDGE1_PRIVATE_ADDRESS, 2586, "tcp"), self.published)
        self.assertGreaterEqual(len(self.published), 8)

    def test_every_published_port_has_a_rule_or_is_named_dnat_only_and_every_rule_is_published(
        self,
    ) -> None:
        self.assertEqual(
            [],
            disagreements(
                self.published,
                bridge_ports=port_list("edge_firewall_bridge_tcp_ports"),
                dnat_only_ports=port_list("edge_firewall_dnat_only_tcp_ports"),
                public_ports=port_list("edge_firewall_public_tcp_ports"),
            ),
        )

    def test_every_loopback_publication_is_covered_by_the_loopback_rule(self) -> None:
        loopback = {
            port
            for address, port, _ in self.published
            if address is not None and address.startswith("127.")
        }
        self.assertGreaterEqual(
            len(loopback), 3, "the probe, Prometheus and Alertmanager are published on loopback"
        )
        rules = rendered_enforce_rules()
        self.assertIn('iif "lo" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept', rules)

    def test_the_rendered_chain_carries_a_rule_for_every_port_the_lists_name(self) -> None:
        rules = " | ".join(rendered_enforce_rules())
        bridge = ", ".join(str(port) for port in port_list("edge_firewall_bridge_tcp_ports"))
        self.assertIn(f'iifname "br-*" tcp dport {{ {bridge} }} accept', rules)
        self.assertIn(f'iifname "docker0" tcp dport {{ {bridge} }} accept', rules)
        public = ", ".join(str(port) for port in port_list("edge_firewall_public_tcp_ports"))
        self.assertIn(f"tcp dport {{ {public} }} accept", rules)
        for port in port_list("edge_firewall_dnat_only_tcp_ports"):
            self.assertNotRegex(
                rules, rf"\b{port}\b", f"tcp/{port} is DNAT-only and must have no rule"
            )


class DisagreementIsDetected(unittest.TestCase):
    """The comparison is not vacuous: each way the lists can drift from the Compose files is
    named. These are the red cases of the sabotage table, run on synthetic input."""

    PUBLISHED: list[Publication] = [
        (None, 80, "tcp"),
        (None, 443, "tcp"),
        ("127.0.0.1", 8080, "tcp"),
        (EDGE1_PRIVATE_ADDRESS, 2586, "tcp"),
        (EDGE1_PRIVATE_ADDRESS, 9091, "tcp"),
    ]

    def agree(self, **changes: list[int]) -> list[str]:
        lists = {"bridge_ports": [2586, 9091], "dnat_only_ports": [], "public_ports": [80, 443]}
        lists.update(changes)
        return disagreements(self.PUBLISHED, **lists)

    def test_the_synthetic_baseline_agrees(self) -> None:
        self.assertEqual([], self.agree())

    def test_a_deleted_rule_is_found(self) -> None:
        # The 2586 rule deleted: the pager's path would be shut by default-drop.
        self.assertEqual(
            [
                "tcp/2586 is published on a private address and has neither an input rule nor "
                "an entry in the DNAT-only list"
            ],
            self.agree(bridge_ports=[9091]),
        )

    def test_a_published_port_with_no_rule_is_found(self) -> None:
        published = [*self.PUBLISHED, (EDGE1_PRIVATE_ADDRESS, 7777, "tcp")]
        problems = disagreements(
            published, bridge_ports=[2586, 9091], dnat_only_ports=[], public_ports=[80, 443]
        )
        self.assertEqual(1, len(problems))
        self.assertIn("tcp/7777", problems[0])

    def test_a_rule_with_no_publication_is_found(self) -> None:
        self.assertEqual(
            ["tcp/3000 has an input rule and no Compose file publishes it"],
            self.agree(bridge_ports=[2586, 3000, 9091]),
        )

    def test_a_dnat_only_entry_with_a_rule_is_found(self) -> None:
        self.assertIn(
            "tcp/9091 is both DNAT-only and given an input rule",
            self.agree(dnat_only_ports=[9091]),
        )

    def test_a_dnat_only_port_needs_no_rule(self) -> None:
        self.assertEqual([], self.agree(bridge_ports=[2586], dnat_only_ports=[9091]))

    def test_a_new_public_port_is_found(self) -> None:
        published = [*self.PUBLISHED, (None, 8443, "tcp")]
        problems = disagreements(
            published, bridge_ports=[2586, 9091], dnat_only_ports=[], public_ports=[80, 443]
        )
        self.assertEqual(
            ["tcp/8443 is published on every address and is not a public port"], problems
        )

    def test_udp_and_loopback_publications_need_no_rule(self) -> None:
        published = [*self.PUBLISHED, (None, 443, "udp"), ("127.0.0.1", 9090, "tcp")]
        self.assertEqual(
            [],
            disagreements(
                published, bridge_ports=[2586, 9091], dnat_only_ports=[], public_ports=[80, 443]
            ),
        )

    def test_both_publication_forms_are_read(self) -> None:
        self.assertEqual((None, 80, "tcp"), parse_publication("80:80"))
        self.assertEqual(("10.20.1.10", 2586, "tcp"), parse_publication("10.20.1.10:2586:80"))
        self.assertEqual((None, 443, "udp"), parse_publication("443:443/udp"))
        self.assertEqual(
            ("10.20.1.10", 3000, "tcp"),
            parse_publication({"host_ip": "10.20.1.10", "published": 3000, "target": 3000}),
        )


class PortsAgreeWithTheRestOfTheRepository(unittest.TestCase):
    """The control port and the public ports are the Hetzner firewall's, and the scrape and
    upstream ports on edge1's private address are among the accepted ones."""

    def test_the_control_and_public_ports_are_the_ones_the_hetzner_firewall_opens(self) -> None:
        opened = firewall_ports(FIREWALLS_TS.read_text(encoding="utf-8"))
        ours = {int(str(role_vars()["edge_firewall_control_port"]))} | set(
            port_list("edge_firewall_public_tcp_ports")
        )
        self.assertEqual(opened, ours)

    def test_the_prometheus_scrape_ports_on_edge1_are_accepted_ports(self) -> None:
        source = RENDER_TS.read_text(encoding="utf-8")
        scraped = {
            int(match)
            for match in re.findall(
                r"export const (?:CADDY|CROWDSEC)_METRICS_PORT = (\d+);", source
            )
        }
        self.assertEqual({9091, 6060}, scraped)
        self.assertLessEqual(scraped, set(port_list("edge_firewall_bridge_tcp_ports")))

    def test_the_caddy_upstreams_on_edge1_are_accepted_ports(self) -> None:
        upstream = {
            int(port)
            for port in re.findall(
                rf"reverse_proxy {re.escape(EDGE1_PRIVATE_ADDRESS)}:(\d+)",
                CADDYFILE.read_text(encoding="utf-8"),
            )
        }
        self.assertEqual({2586}, upstream)
        self.assertLessEqual(upstream, set(port_list("edge_firewall_bridge_tcp_ports")))


class NativeListenersAreExplicitDrops(unittest.TestCase):
    """A native listener on edge1 is not published by Compose, so the test above cannot see it.
    Its port is read from the role that binds it, and it must be an explicit drop: in no list,
    and in no rule. Nothing scrapes it: the monitoring stack reaches the Compose exporter by
    name."""

    def test_the_native_node_exporter_is_an_explicit_drop(self) -> None:
        exporter_vars = _mapping(
            yaml.safe_load(
                (ROOT / "ansible" / "roles" / "node_exporter" / "vars" / "main.yml").read_text(
                    encoding="utf-8"
                )
            )
        )
        exporter = int(str(exporter_vars["node_exporter_port"]))
        dropped = port_list("edge_firewall_native_dropped_tcp_ports")
        self.assertIn(exporter, dropped)
        for name in (
            "edge_firewall_bridge_tcp_ports",
            "edge_firewall_public_tcp_ports",
            "edge_firewall_dnat_only_tcp_ports",
        ):
            self.assertNotIn(exporter, port_list(name), f"{name} must not name tcp/{exporter}")
        rules = " | ".join(rendered_enforce_rules())
        for port in dropped:
            self.assertNotRegex(
                rules, rf"\b{port}\b", f"tcp/{port} is a native drop and must have no rule"
            )


if __name__ == "__main__":
    unittest.main()
