"""Unit tests for the host_tls_identity role: who makes a key, who sees it, and what a pin must be.

demo1's exporter and edge1's Prometheus authenticate each other with self-signed certificates
that each host makes for itself. The private key must therefore never leave the host that uses
it, and the certificate the host trusts from its peer (the pin) must be refused unless it is
exactly the kind of certificate expected. These tests read the role's files and fail in seconds
if a key could be fetched, copied, logged or committed, if the validity or the renewal window
drifts, or if the pin's checks are weakened. The Molecule scenario proves the same on a host.
"""

import re
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2]

# The one place the two hosts' profiles may name each other's usage: server on demo1, client on edge1.
SERVER_AUTH = "serverAuth"
CLIENT_AUTH = "clientAuth"


def text(relative: str) -> str:
    """One file of the role, as text."""
    return (ROLE / relative).read_text(encoding="utf-8")


def mapping(relative: str) -> dict[str, object]:
    """One YAML mapping of the role."""
    parsed: object = yaml.safe_load(text(relative))
    if not isinstance(parsed, dict):
        raise AssertionError(f"{relative} is not a mapping")
    return {str(key): value for key, value in parsed.items()}


def tasks(relative: str) -> list[dict[str, object]]:
    """The tasks of one file of the role, in order."""
    parsed: object = yaml.safe_load(text(relative))
    if not isinstance(parsed, list):
        raise AssertionError(f"{relative} is not a list of tasks")
    return [{str(key): value for key, value in task.items()} for task in parsed]


def every_task() -> list[dict[str, object]]:
    """Every task of every tasks file, nested blocks included."""
    found: list[dict[str, object]] = []

    def walk(items: list[dict[str, object]]) -> None:
        for item in items:
            if "block" not in item:
                found.append(item)
            for section in ("block", "rescue", "always"):
                nested = item.get(section)
                if isinstance(nested, list):
                    walk([{str(k): v for k, v in entry.items()} for entry in nested])

    for path in sorted((ROLE / "tasks").glob("*.yml")):
        walk(tasks(f"tasks/{path.name}"))
    return found


def module_of(task: dict[str, object]) -> str:
    """The fully qualified module a task calls."""
    keywords = {
        "name", "when", "register", "no_log", "diff", "notify", "loop", "loop_control", "vars",
        "check_mode", "changed_when", "failed_when", "block", "rescue", "always", "tags",
        "delegate_to", "become", "ignore_errors", "until", "retries", "delay", "environment",
    }  # fmt: skip
    names = [key for key in task if key not in keywords]
    if len(names) != 1:
        raise AssertionError(f"task {task.get('name')!r} does not call one module")
    return names[0]


def module_of_or_none(task: dict[str, object]) -> str | None:
    """The module of a task that calls one, or None for a block."""
    return None if "block" in task else module_of(task)


def named(part: str) -> dict[str, object]:
    """The one task, anywhere in the role, whose name contains the text."""
    found = [task for task in every_task() if part in str(task.get("name"))]
    if len(found) != 1:
        raise AssertionError(f"expected one task named like {part!r}, found {len(found)}")
    return found[0]


def arguments(task: dict[str, object]) -> dict[str, object]:
    """The module arguments of a task."""
    value = task[module_of(task)]
    if not isinstance(value, dict):
        raise AssertionError(f"task {task.get('name')!r} has no argument mapping")
    return {str(key): item for key, item in value.items()}


def profiles() -> dict[str, dict[str, object]]:
    """The per-host profile table."""
    table = mapping("vars/main.yml")["host_tls_identity_profiles"]
    if not isinstance(table, dict):
        raise AssertionError("host_tls_identity_profiles is not a mapping")
    return {str(host): {str(k): v for k, v in row.items()} for host, row in table.items()}


class AKeyNeverLeavesItsHostTests(unittest.TestCase):
    """No task moves, shows or commits a private key."""

    def test_no_task_fetches_copies_off_the_host_or_delegates(self) -> None:
        refused = {
            "ansible.builtin.fetch", "ansible.posix.synchronize", "ansible.builtin.uri",
            "ansible.builtin.get_url", "ansible.builtin.slurp", "ansible.builtin.shell",
            "ansible.builtin.command", "ansible.builtin.debug",
        }  # fmt: skip
        for task in every_task():
            module = module_of(task)
            if module == "ansible.builtin.debug":
                # A debug says a fixed sentence, never a variable that could hold a key.
                self.assertNotIn("key", str(task[module]).lower(), task)
                continue
            self.assertNotIn(module, refused, task.get("name"))
            self.assertNotIn("delegate_to", task, task.get("name"))

    def test_nothing_asks_a_module_to_hand_a_private_key_back(self) -> None:
        for path in sorted((ROLE / "tasks").glob("*.yml")):
            body = path.read_text(encoding="utf-8")
            for word in (
                "return_content",
                "privatekey_content",
                "content: '{{ host_tls_identity_key",
            ):
                self.assertNotIn(word, body, f"{path.name} names {word}")

    def test_no_pem_block_is_committed_in_the_role(self) -> None:
        # The molecule fixtures are made in the container; the role ships no key or certificate.
        for path in sorted(ROLE.rglob("*")):
            if path.is_file() and path.suffix in {".yml", ".yaml", ".md", ".py", ".j2", ".toml"}:
                body = path.read_text(encoding="utf-8")
                if path.name == "test_host_tls_identity.py":
                    continue
                # A header followed by base64 is a block; the role's checks name the header in quotes.
                self.assertNotRegex(
                    body, r"-----BEGIN [A-Z ]*-----\s+[A-Za-z0-9+/=]{20,}", str(path)
                )

    def test_the_key_is_made_once_on_the_host_and_hidden_from_logs(self) -> None:
        task = named("Make the private key")
        self.assertEqual(module_of(task), "community.crypto.openssl_privatekey")
        self.assertIs(task.get("no_log"), True)
        self.assertIs(task.get("diff"), False)
        options = arguments(task)
        self.assertEqual(options["regenerate"], "never")
        self.assertEqual(options["owner"], "root")
        self.assertEqual(options["mode"], "0640")

    def test_the_certificate_request_is_made_in_memory(self) -> None:
        task = named("Make the certificate request")
        self.assertEqual(module_of(task), "community.crypto.openssl_csr_pipe")
        self.assertIs(task.get("no_log"), True)
        self.assertIs(task.get("diff"), False)

    def test_the_certificate_is_self_signed(self) -> None:
        task = named("Issue the self-signed certificate")
        options = arguments(task)
        self.assertEqual(options["provider"], "selfsigned")
        self.assertEqual(options["selfsigned_not_after"], "+{{ host_tls_identity_validity_days }}d")
        self.assertNotIn("ownca", str(options))


class TheLifetimeTests(unittest.TestCase):
    """Two years of validity, and the run fails when under sixty days are left."""

    def test_validity_and_renewal_window(self) -> None:
        variables = mapping("vars/main.yml")
        self.assertEqual(variables["host_tls_identity_validity_days"], 730)
        self.assertEqual(variables["host_tls_identity_renew_days"], 60)

    def test_an_own_certificate_inside_the_window_fails_the_run_and_names_the_step(self) -> None:
        task = named("Refuse an own certificate with less than the renewal window left")
        self.assertEqual(module_of(task), "ansible.builtin.assert")
        message = str(arguments(task)["fail_msg"])
        self.assertIn("host_tls_identity[renew]", message)
        self.assertIn("README", message)


class TheProfilesTests(unittest.TestCase):
    """What each host makes, where, and what its peer's certificate must be."""

    def test_the_two_hosts_have_a_row(self) -> None:
        self.assertEqual(sorted(profiles()), ["demo1", "edge1"])

    def test_demo1_serves_and_edge1_is_the_client(self) -> None:
        table = profiles()
        self.assertEqual(table["demo1"]["usage"], SERVER_AUTH)
        self.assertEqual(table["demo1"]["peer_usage"], CLIENT_AUTH)
        self.assertEqual(table["edge1"]["usage"], CLIENT_AUTH)
        self.assertEqual(table["edge1"]["peer_usage"], SERVER_AUTH)

    def test_the_server_name_prometheus_verifies_is_in_the_certificate_and_the_pin_check(
        self,
    ) -> None:
        table = profiles()
        self.assertEqual(table["demo1"]["dns_names"], ["demo1"])
        # edge1 must see the name demo1 in the certificate it pins.
        self.assertEqual(table["edge1"]["peer_dns"], "demo1")

    def test_each_host_uses_the_paths_its_consumer_reads(self) -> None:
        table = profiles()
        self.assertEqual(table["demo1"]["dir"], "/etc/branchleft/node-exporter-tls")
        self.assertEqual(
            [table["demo1"][k] for k in ("key_name", "cert_name", "pin_name")],
            ["server.key", "server.crt", "ca.crt"],
        )
        self.assertEqual(table["edge1"]["dir"], "/etc/branchleft/demo1-metrics-tls")
        self.assertEqual(
            [table["edge1"][k] for k in ("key_name", "cert_name", "pin_name")],
            ["client.key", "client.crt", "ca.crt"],
        )
        # Prometheus runs as nobody (65534), so edge1's group is that gid; demo1's group is the
        # exporter's own, which its role gives, so this role leaves it alone.
        self.assertEqual(table["edge1"]["group"], "65534")
        self.assertEqual(table["demo1"]["group"], "")


class ThePinIsRefusedUnlessItIsRightTests(unittest.TestCase):
    """A certificate that is not exactly the expected one is never written as the trust file."""

    def test_the_checks_come_before_the_file_is_written(self) -> None:
        body = tasks("tasks/_pin.yml")
        names = [str(task.get("name")) for task in body]
        write = next(i for i, name in enumerate(names) if name.startswith("Write the pinned"))
        self.assertEqual(write, len(names) - 1, "the write is the last task")
        refusals = [name for name in names[:write] if name.startswith("Refuse")]
        self.assertGreaterEqual(len(refusals), 6)

    def test_every_refusal_has_a_code(self) -> None:
        body = text("tasks/_pin.yml")
        for code in ("pin-shape", "pin-parse", "pin-self-signed", "pin-usage", "pin-name",
                     "pin-ca", "pin-validity"):  # fmt: skip
            self.assertIn(f"host_tls_identity[{code}]", body)

    def test_each_refusal_tests_what_it_names(self) -> None:
        # The condition of each refusal, not only its message, holds the property its code names.
        # A loosening that keeps the words (`that: [true]`) fails here, and in the Molecule case.
        needles = {
            "pin-self-signed": [
                "host_tls_identity_pin_info.subject == host_tls_identity_pin_info.issuer"
            ],
            "pin-ca": ["'CA:TRUE' not in", "basic_constraints"],
            "pin-usage": ["extended_key_usage ==", "host_tls_identity_profile.peer_usage"],
            "pin-name": ["host_tls_identity_profile.peer_dns", "subject_alt_name"],
            "pin-validity": ["valid_at.now", "valid_at.horizon"],
            "pin-shape": ["BEGIN CERTIFICATE", "END CERTIFICATE", "== 1", "PRIVATE KEY"],
        }
        for task in tasks("tasks/_pin.yml"):
            if module_of_or_none(task) != "ansible.builtin.assert":
                continue
            message = str(arguments(task)["fail_msg"])
            for code, required in needles.items():
                if f"host_tls_identity[{code}]" in message:
                    conditions = " ".join(str(item) for item in arguments(task)["that"])  # type: ignore[attr-defined]
                    for needle in required:
                        self.assertIn(needle, conditions, f"{code} no longer tests {needle!r}")
                    needles.pop(code)
                    break
        self.assertEqual(needles, {}, "a refusal code has no assert")

    def test_the_pin_is_written_with_the_hosts_modes(self) -> None:
        task = named("Write the pinned peer certificate")
        options = arguments(task)
        self.assertEqual(options["mode"], "0640")
        self.assertEqual(options["owner"], "root")
        self.assertEqual(options["dest"], "{{ host_tls_identity_pin_file }}")
        # One real newline at the end. A quoted "\\n" inside the template is two characters, and
        # the file would end in a backslash and an n: a certificate no service can read.
        self.assertEqual(options["content"], "{{ host_tls_identity_peer_cert | trim }}\n")


class TheReadmeCarriesTheRunbookTests(unittest.TestCase):
    """The one hand step left is written down, with the command and what good looks like."""

    def test_the_readme_has_the_renewal_and_first_read_steps(self) -> None:
        body = text("README.md")
        for needle in (
            "openssl x509 -in",
            "-noout -fingerprint -sha256 -enddate",
            "What good looks like",
            "host_tls_identity_peer_cert",
            "owner_vars",
        ):
            self.assertIn(needle, body)

    def test_the_readme_has_no_placeholders(self) -> None:
        self.assertIsNone(re.search(r"\b[A-Z]{3,}_[A-Z_]{3,}\b", text("README.md")))


if __name__ == "__main__":
    unittest.main()
