"""Unit tests for the node_exporter_public role: what it installs, in what order, and what it never does.

A host in a Hetzner project of its own (demo1) shares no private network with the monitoring host,
so its exporter is scraped over its public address. That is safe only if the exporter serves TLS and
refuses every client without a certificate the owner's CA signed, from its very first start. These
tests read the role's files and fail in seconds if the exporter could start in plain HTTP, switch
the certificate check off, be downloaded rather than installed from the Debian archive, or carry
key material. The Molecule scenario proves the same on a running exporter.
"""

import re
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2]


def text(relative: str) -> str:
    """One file of the role, as text."""
    return (ROLE / relative).read_text(encoding="utf-8")


def tasks(relative: str) -> list[dict[str, object]]:
    """The tasks of one file of the role, in order."""
    parsed: object = yaml.safe_load(text(relative))
    if not isinstance(parsed, list):
        raise AssertionError(f"{relative} is not a list of tasks")
    return [{str(key): value for key, value in task.items()} for task in parsed]


def position(relative: str, name_part: str) -> int:
    """The index of the one task of a file whose name contains the text."""
    found = [
        index
        for index, task in enumerate(tasks(relative))
        if name_part in str(task.get("name"))
    ]
    if len(found) != 1:
        raise AssertionError(f"expected one task named like {name_part!r}, found {len(found)}")
    return found[0]


class TheExporterIsTheDebianPackageTests(unittest.TestCase):
    """The exporter comes from the Debian archive, so the role never fetches from the network."""

    def test_the_role_installs_the_archive_package_by_apt(self) -> None:
        install = tasks("tasks/_install.yml")[position("tasks/_install.yml", "Install the Debian")]
        arguments = install["ansible.builtin.apt"]
        self.assertIsInstance(arguments, dict)
        assert isinstance(arguments, dict)  # noqa: S101 - narrows the type
        self.assertEqual(arguments["name"], "{{ node_exporter_public_package }}")
        self.assertEqual(arguments["state"], "present")
        variables: object = yaml.safe_load(text("vars/main.yml"))
        assert isinstance(variables, dict)  # noqa: S101 - narrows the type
        self.assertEqual(variables["node_exporter_public_package"], "prometheus-node-exporter")

    def test_no_file_of_the_role_fetches_from_the_network(self) -> None:
        # The same words demo1's own no-fetch check refuses in any role the host applies.
        for path in sorted((ROLE / "tasks").glob("*.yml")) + sorted((ROLE / "handlers").glob("*.yml")):
            body = path.read_text(encoding="utf-8")
            for word in ("get_url", "ansible.builtin.uri", "ansible.builtin.git", "docker", "github"):
                self.assertNotIn(word, body, f"{path.name} names {word}")


class NeverPlainHttpTests(unittest.TestCase):
    """The web config demands a client certificate, and the exporter is told to read it."""

    def test_the_web_config_requires_and_verifies_a_client_certificate(self) -> None:
        body = text("tasks/_install.yml")
        self.assertEqual(re.findall(r"client_auth_type:\s*(\S+)", body), ["RequireAndVerifyClientCert"])
        for key in ("client_ca_file:", "cert_file:", "key_file:"):
            self.assertIn(key, body)

    def test_the_arguments_name_the_web_config_and_nothing_that_weakens_it(self) -> None:
        body = text("tasks/_install.yml")
        arguments = re.findall(r'ARGS="([^"]*)"', body)
        self.assertEqual(len(arguments), 1)
        # Close up the spaces inside each template expression so the arguments split on spaces only.
        closed = re.sub(r"\{\{\s*(\w+)\s*\}\}", r"{{\1}}", arguments[0])
        words = closed.split()
        self.assertIn("--web.config.file={{node_exporter_public_web_config_path}}", words)
        self.assertEqual(
            [word for word in words if not word.startswith("--web.")],
            [],
            "an argument that is not a web flag",
        )

    def test_the_unit_is_held_masked_until_the_web_config_is_written(self) -> None:
        path = "tasks/_install.yml"
        mask = position(path, "Hold the unit masked")
        arguments = position(path, "Write the arguments")
        install = position(path, "Install the Debian")
        web_config = position(path, "Write the web config")
        release = position(path, "Release the unit")
        start = position(path, "Enable and start")
        self.assertLess(mask, install)
        self.assertLess(arguments, install)
        self.assertLess(install, web_config)
        self.assertLess(web_config, release)
        self.assertLess(release, start)

    def test_only_a_link_to_dev_null_is_released(self) -> None:
        release = tasks("tasks/_install.yml")[position("tasks/_install.yml", "Release the unit")]
        condition = str(release["when"])
        self.assertIn("islnk", condition)
        self.assertIn("/dev/null", condition)

    def test_the_role_installs_nothing_until_the_certificate_files_are_in_place(self) -> None:
        include = tasks("tasks/main.yml")[position("tasks/main.yml", "Install and start")]
        self.assertEqual(include["ansible.builtin.include_tasks"], "_install.yml")
        self.assertEqual(include["when"], "node_exporter_public_ready")
        main = text("tasks/main.yml")
        self.assertIn("selectattr('stat.isreg')", main)
        self.assertIn("length == 3", main)


class NoKeyMaterialTests(unittest.TestCase):
    """The role names the files by path and ships none of them."""

    def test_no_file_of_the_role_carries_a_pem_block(self) -> None:
        for path in ROLE.rglob("*"):
            if path.is_file() and not path.is_symlink() and path.suffix in {".yml", ".md", ".py"}:
                self.assertNotRegex(
                    path.read_text(encoding="utf-8"),
                    r"BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)",
                    str(path),
                )

    def test_the_certificate_files_are_read_from_one_root_only_directory(self) -> None:
        variables: object = yaml.safe_load(text("vars/main.yml"))
        assert isinstance(variables, dict)  # noqa: S101 - narrows the type
        self.assertEqual(variables["node_exporter_public_tls_dir"], "/etc/branchleft/node-exporter-tls")


if __name__ == "__main__":
    unittest.main()
