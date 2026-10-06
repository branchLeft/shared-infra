#!/usr/bin/env python3
"""Pins the control-plane stack's contract with the host it shares.

See test_control_plane_stack.md.
"""

import pathlib
import re
import sys
import unittest

if sys.version_info < (3, 10):
    raise RuntimeError(
        "test_control_plane_stack.py requires Python 3.10 or newer; running under "
        f"{sys.version.split()[0]}. On macOS, `/usr/bin/python3` is the system 3.9."
    )

HETZNER = pathlib.Path(__file__).resolve().parent.parent
REPOSITORY = HETZNER.parent
COMPOSE = HETZNER / "control-plane" / "stack" / "compose.yml"
SITES = REPOSITORY / "sites.ts"

OPS1_PRIVATE_IP = "10.20.1.50"

# The owner's reading of ops1 before this stack existed: `free -m` on the host
# reported 3009 MB available, no swap, with Nextcloud already running. Both
# numbers are measurements, not vendor sizing.
HOST_AVAILABLE_MB = 3009
# The margin the stack's limits must leave unclaimed even if every container
# reached its limit at once. A third of the available memory.
REQUIRED_MARGIN_MB = 1000

SERVICES = {"db", "zitadel", "portal", "console"}
APPLICATION_SERVICES = {"portal", "console"}


def compose_text() -> str:
    return COMPOSE.read_text(encoding="utf-8")


def code_lines(text: str) -> list[str]:
    """Lines with whole-line comments and trailing comments removed."""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(re.sub(r"\s+#.*\Z", "", raw.rstrip()))
    return lines


def service_blocks(text: str) -> dict[str, list[str]]:
    """Each service's lines, from the `services:` section only."""
    blocks: dict[str, list[str]] = {}
    in_services = False
    current: str | None = None
    for line in code_lines(text):
        if re.match(r"\A\S", line):
            in_services = line.rstrip() == "services:"
            current = None
            continue
        if not in_services:
            continue
        header = re.match(r"\A  ([a-z][a-z0-9-]*):\s*\Z", line)
        if header:
            current = header.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    return blocks


def mem_limit_mb(block: list[str]) -> int | None:
    for line in block:
        match = re.match(r"\A    mem_limit:\s*(\d+)([mg])\s*\Z", line)
        if match:
            return int(match.group(1)) * (1024 if match.group(2) == "g" else 1)
    return None


def published_ports(block: list[str]) -> list[str]:
    ports = []
    in_ports = False
    for line in block:
        if re.match(r"\A    ports:\s*\Z", line):
            in_ports = True
        elif in_ports and (match := re.match(r"\A      - '?([^'\s]+)'?\s*\Z", line)):
            ports.append(match.group(1))
        elif in_ports:
            in_ports = False
    return ports


class ControlPlaneStackTests(unittest.TestCase):
    def test_the_parser_finds_exactly_the_four_services(self):
        self.assertEqual(set(service_blocks(compose_text())), SERVICES)

    def test_every_service_declares_a_memory_limit(self):
        for name, block in service_blocks(compose_text()).items():
            with self.subTest(service=name):
                self.assertIsNotNone(mem_limit_mb(block), f"{name} has no mem_limit")

    def test_the_limits_fit_the_measured_available_memory_with_a_margin(self):
        total = sum(mem_limit_mb(block) or 0 for block in service_blocks(compose_text()).values())
        self.assertGreater(total, 0)
        self.assertLessEqual(
            total,
            HOST_AVAILABLE_MB - REQUIRED_MARGIN_MB,
            f"the stack's limits sum to {total} MB; {HOST_AVAILABLE_MB} MB is available "
            f"and {REQUIRED_MARGIN_MB} MB must stay unclaimed. A bigger limit is a "
            "decision about the host, which is the owner's.",
        )

    def test_only_private_and_loopback_addresses_are_published(self):
        for name, block in service_blocks(compose_text()).items():
            for port in published_ports(block):
                with self.subTest(service=name, port=port):
                    self.assertRegex(port, rf"\A({OPS1_PRIVATE_IP}|127\.0\.0\.1):\d+:\d+\Z")

    def test_every_ports_entry_is_short_form_on_a_private_or_loopback_address(self):
        """A long-form mapping or an inline list slips past the address check above."""
        short = re.compile(rf"\A      - '({OPS1_PRIVATE_IP}|127\.0\.0\.1):\d+:\d+'\Z")
        for name, block in service_blocks(compose_text()).items():
            in_ports = False
            for line in block:
                if re.match(r"\A    ports:", line):
                    with self.subTest(service=name, line=line):
                        self.assertEqual(line, "    ports:", "ports must be a block list")
                    in_ports = True
                elif in_ports and re.match(r"\A      ", line):
                    with self.subTest(service=name, line=line):
                        self.assertRegex(line, short)
                elif in_ports:
                    in_ports = False

    def test_no_service_shares_the_host_namespaces_or_runs_privileged(self):
        forbidden = re.compile(
            r"\A    (network_mode|pid|ipc|uts|userns_mode|privileged|cap_add|devices|security_opt):"
        )
        for name, block in service_blocks(compose_text()).items():
            for line in block:
                with self.subTest(service=name, line=line):
                    self.assertIsNone(forbidden.match(line))

    def test_every_service_is_first_in_line_for_an_out_of_memory_kill(self):
        for name, block in service_blocks(compose_text()).items():
            with self.subTest(service=name):
                values = [
                    int(m.group(1))
                    for line in block
                    if (m := re.match(r"\A    oom_score_adj:\s*(\d+)\s*\Z", line))
                ]
                self.assertEqual(len(values), 1, f"{name} has no oom_score_adj")
                self.assertGreaterEqual(values[0], 500)

    def test_the_master_key_is_a_secret_file_and_never_in_any_environment(self):
        text = compose_text()
        blocks = service_blocks(text)
        self.assertIn("--masterkeyFile /run/secrets/zitadel-masterkey", "\n".join(blocks["zitadel"]))
        self.assertNotIn("masterkeyFromEnv", text)
        self.assertIn("      - zitadel-masterkey", blocks["zitadel"])
        for name, block in blocks.items():
            for line in block:
                with self.subTest(service=name, line=line):
                    self.assertNotRegex(line.upper(), r"MASTERKEY\w*:")

    def test_the_database_publishes_nothing(self):
        self.assertEqual(published_ports(service_blocks(compose_text())["db"]), [])

    def test_the_applications_publish_the_ports_the_edge_routes_to(self):
        blocks = service_blocks(compose_text())
        sites = SITES.read_text(encoding="utf-8")
        for name, port in (("portal", 8301), ("console", 8302)):
            with self.subTest(service=name):
                self.assertEqual(published_ports(blocks[name]), [f"{OPS1_PRIVATE_IP}:{port}:{port}"])
                self.assertIn(f"PORT: '{port}'", "\n".join(blocks[name]))
                self.assertIn(f"port: {port}", sites, "sites.ts no longer routes this port")

    def test_third_party_images_are_pinned_by_digest_and_the_applications_use_the_pin(self):
        blocks = service_blocks(compose_text())
        for name in ("db", "zitadel"):
            with self.subTest(service=name):
                image = next(line for line in blocks[name] if line.startswith("    image:"))
                self.assertRegex(image, r"@sha256:[0-9a-f]{64}\Z")
        for name in APPLICATION_SERVICES:
            with self.subTest(service=name):
                self.assertIn("    image: ${IMAGE}", blocks[name])

    def test_the_applications_wait_for_the_reconciler_behind_a_profile(self):
        blocks = service_blocks(compose_text())
        for name in APPLICATION_SERVICES:
            with self.subTest(service=name):
                self.assertIn("    profiles: [apps]", blocks[name])
        for name in ("db", "zitadel"):
            with self.subTest(service=name):
                self.assertFalse(any("profiles:" in line for line in blocks[name]))

    def test_the_two_applications_hold_separate_database_logins_and_entry_points(self):
        blocks = service_blocks(compose_text())
        portal, console = "\n".join(blocks["portal"]), "\n".join(blocks["console"])
        self.assertIn("dist/tenant/main.js", portal)
        self.assertIn("dist/console/main.js", console)
        self.assertIn("portal-database-url", portal)
        self.assertNotIn("console-database-url", portal)
        self.assertIn("console-database-url", console)
        self.assertNotIn("portal-database-url", console)

    def test_the_hostnames_are_the_ruled_ones(self):
        text = compose_text()
        self.assertIn("ZITADEL_EXTERNALDOMAIN: id.publicpress.co.uk", text)
        self.assertIn("PORTAL_PUBLIC_ORIGIN: https://portal.publicpress.co.uk", text)
        self.assertIn("CONSOLE_PUBLIC_ORIGIN: https://console.branchleft.co.uk", text)

    def test_nothing_touches_nextcloud_or_the_docker_socket(self):
        text = "\n".join(code_lines(compose_text())).lower()
        self.assertNotIn("nextcloud", text)
        self.assertNotIn("docker.sock", text)

    def test_every_secret_comes_from_the_env_file_and_is_declared_required(self):
        text = compose_text()
        for variable in re.findall(r"\$\{(CONTROL_PLANE_[A-Z_]+)", text):
            with self.subTest(variable=variable):
                self.assertIn(f"${{{variable}:?", text)
        for line in code_lines(text):
            if re.search(r"(PASSWORD|MASTERKEY):", line):
                with self.subTest(line=line.strip()):
                    self.assertIn("${", line)

    def test_the_first_administrator_never_keeps_a_vendor_default_password(self):
        text = compose_text()
        self.assertIn("ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD: ${", text)
        self.assertIn("ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED: 'true'", text)

    def test_the_service_account_is_created_by_the_first_start(self):
        text = compose_text()
        self.assertIn("ZITADEL_FIRSTINSTANCE_PATPATH: /state/reconciler.pat", text)
        self.assertIn("ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME: reconciler", text)

    def test_the_ready_healthcheck_probes_over_the_same_scheme_the_service_serves(self):
        block = "\n".join(service_blocks(compose_text())["zitadel"])
        self.assertIn("'/app/zitadel', 'ready'", block)
        self.assertIn("ZITADEL_TLS_ENABLED: 'false'", block)

    def test_the_sign_in_service_is_reachable_on_loopback_for_owner_recovery(self):
        ports = published_ports(service_blocks(compose_text())["zitadel"])
        self.assertIn("127.0.0.1:8300:8080", ports)
        self.assertIn(f"{OPS1_PRIVATE_IP}:8300:8080", ports)


if __name__ == "__main__":
    unittest.main()
