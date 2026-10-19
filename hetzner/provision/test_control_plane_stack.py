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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stack_keys_check  # noqa: E402  (needs the path above when run by file)

HETZNER = pathlib.Path(__file__).resolve().parent.parent
REPOSITORY = HETZNER.parent
COMPOSE = HETZNER / "control-plane" / "stack" / "compose.yml"
SITES = REPOSITORY / "sites.ts"
PG_HBA = HETZNER / "control-plane" / "stack" / "pg_hba.conf"
INIT_OVERLAY = HETZNER / "control-plane" / "stack" / "compose.init.yml"
UNIT = HETZNER / "provision" / "branchleft-compose@.service"
FIXTURE = HETZNER / "provision" / "fixtures" / "stack-keys-quoted-env-file.yml"

# Every reference to the database administrator's credential: the Zitadel
# variables that carry it and the env-file variable it is read from.
ADMIN_REFERENCE = re.compile(r"POSTGRES_ADMIN|DB_ADMIN")
ADMIN_PASSWORD_VARIABLE = "CONTROL_PLANE_DB_ADMIN_PASSWORD"

# The names `docker compose` reads from a directory when no -f is given.
COMPOSE_DEFAULT_FILES = frozenset(
    f"{base}{suffix}"
    for base in ("compose", "docker-compose")
    for suffix in (".yaml", ".yml", ".override.yaml", ".override.yml")
)

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


def hba_rules() -> list[list[str]]:
    """Each pg_hba.conf rule as its whitespace-separated fields, comments dropped."""
    rules = []
    for raw in PG_HBA.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            rules.append(line.split())
    return rules


PORTAL_LOGINS = {"portal_tenant_login", "portal_owner_login"}


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

    def test_the_database_mounts_the_hba_file_and_selects_it_at_start(self):
        block = "\n".join(service_blocks(compose_text())["db"])
        self.assertIn("      - ./pg_hba.conf:/etc/postgresql/pg_hba.conf:ro", block)
        self.assertIn("'hba_file=/etc/postgresql/pg_hba.conf'", block)
        self.assertTrue(PG_HBA.is_file())

    def test_the_hba_file_ends_in_a_reject_for_host_and_local(self):
        rules = hba_rules()
        self.assertEqual(rules[-2], ["local", "all", "all", "reject"])
        self.assertEqual(rules[-1], ["host", "all", "all", "all", "reject"])

    def test_the_hba_file_never_uses_trust_and_always_uses_scram(self):
        for rule in hba_rules():
            with self.subTest(rule=rule):
                self.assertIn(rule[-1], {"scram-sha-256", "reject"})
        self.assertNotRegex(PG_HBA.read_text(encoding="utf-8"), r"(?im)^[^#]*\b(trust|peer|md5|password)\b")

    def test_each_login_reaches_only_its_own_database(self):
        allowed: dict[str, set[str]] = {}
        for rule in hba_rules():
            if rule[-1] != "scram-sha-256" or rule[0] != "host":
                continue
            databases, user = rule[1].split(","), rule[2]
            with self.subTest(rule=rule):
                self.assertNotIn("all", databases)
                self.assertNotEqual(user, "all")
                self.assertNotIn(rule[3], {"all", "0.0.0.0/0", "::/0"})
            allowed.setdefault(user, set()).update(databases)
        self.assertEqual(allowed["zitadel"], {"zitadel"})
        for login in PORTAL_LOGINS:
            self.assertEqual(allowed[login], {"portal"})
        self.assertEqual(set(allowed), {"zitadel", "postgres"} | PORTAL_LOGINS)

    def test_the_local_socket_admits_only_the_administrator(self):
        local = [r for r in hba_rules() if r[0] == "local" and r[-1] != "reject"]
        self.assertEqual(local, [["local", "all", "postgres", "scram-sha-256"]])

    def test_the_hba_file_carries_no_secret(self):
        self.assertNotRegex(PG_HBA.read_text(encoding="utf-8"), r"(?i)password\s*[:=]")

    def test_the_runtime_sign_in_service_holds_no_administrator_credential(self):
        block = service_blocks(compose_text())["zitadel"]
        self.assertTrue(block, "the parser found no lines for the sign-in service")
        for line in block:
            with self.subTest(line=line.strip()):
                self.assertNotRegex(line, ADMIN_REFERENCE)
                self.assertNotRegex(line, r"USERNAME:\s*postgres\s*\Z")
        joined = "\n".join(block)
        self.assertIn("ZITADEL_DATABASE_POSTGRES_USER_USERNAME: zitadel", joined)
        self.assertIn("ZITADEL_DATABASE_POSTGRES_USER_PASSWORD: ${CONTROL_PLANE_ZITADEL_DB_PASSWORD:?", joined)

    def test_the_administrator_password_is_given_to_the_database_service_alone(self):
        text = compose_text()
        blocks = service_blocks(text)
        for name, block in blocks.items():
            holders = [line for line in block if ADMIN_PASSWORD_VARIABLE in line]
            with self.subTest(service=name):
                self.assertEqual(len(holders), 1 if name == "db" else 0, holders)
        self.assertEqual(
            sum(ADMIN_PASSWORD_VARIABLE in line for line in code_lines(text)),
            1,
            "the administrator's password variable is read somewhere other than the db service",
        )

    def test_the_stack_files_hold_no_file_pulling_key_and_no_unlisted_service_key(self):
        """Checked on parsed YAML: a quoted, flow, anchored or merged key is the same key to Compose."""
        for path in (COMPOSE, INIT_OVERLAY):
            with self.subTest(file=path.name):
                problems = stack_keys_check.check_file(path)
                self.assertEqual(problems, [], "\n".join(problems))

    def test_the_structural_check_still_rejects_a_quoted_env_file(self):
        """The control case: if the check stopped matching, the test above would pass silently."""
        problems = stack_keys_check.check_file(FIXTURE)
        self.assertTrue(
            any("'env_file' pulls another file in" in problem for problem in problems),
            f"the quoted-key fixture was not rejected: {problems}",
        )

    def test_the_runtime_command_runs_the_setup_phase_and_never_the_init_phase(self):
        block = service_blocks(compose_text())["zitadel"]
        commands = [line for line in block if line.startswith("    command:")]
        self.assertEqual(len(commands), 1, commands)
        self.assertRegex(commands[0], r"\A    command: start-from-setup\s")
        self.assertNotRegex(commands[0], r"start-from-init|command:\s*init\b")

    def test_the_init_overlay_is_init_only_and_the_only_file_with_the_administrator_credential(self):
        text = INIT_OVERLAY.read_text(encoding="utf-8")
        blocks = service_blocks(text)
        self.assertEqual(set(blocks), {"zitadel"})
        block = blocks["zitadel"]
        self.assertEqual([line for line in block if line.startswith("    command:")], ["    command: init"])
        self.assertIn("      ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME: postgres", block)
        self.assertTrue(
            any(
                line.startswith("      ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD: ${CONTROL_PLANE_DB_ADMIN_PASSWORD:?")
                for line in block
            ),
            "the overlay must read the administrator password from the env file, required",
        )
        self.assertIn("    restart: 'no'", block)
        for line in block:
            with self.subTest(line=line.strip()):
                self.assertNotRegex(line, r"\A    (ports|profiles|depends_on|image|secrets):")
        self.assertNotRegex(text, r"(?m)^[^#\n]*\bstart(-from-\w+)?\b")

    def test_nothing_in_the_stack_directory_is_read_by_default_except_compose_yml(self):
        self.assertNotIn(INIT_OVERLAY.name, COMPOSE_DEFAULT_FILES)
        present = {path.name for path in COMPOSE.parent.iterdir()}
        self.assertEqual(present & COMPOSE_DEFAULT_FILES, {COMPOSE.name}, present)

    def test_the_unit_never_reads_the_init_overlay(self):
        unit = UNIT.read_text(encoding="utf-8")
        executed = [
            line for line in unit.splitlines() if line.startswith(("ExecStart", "ExecStartPre", "Environment"))
        ]
        self.assertTrue(executed)
        for line in executed:
            with self.subTest(line=line):
                self.assertNotRegex(line, r"compose\.init|COMPOSE_FILE|\s-f\s|--file")
        self.assertNotIn("COMPOSE_FILE", compose_text())


if __name__ == "__main__":
    unittest.main()
