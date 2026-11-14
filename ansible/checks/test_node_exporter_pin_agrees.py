"""The node_exporter version the role installs agrees with the monitoring stack's image tag.

The monitoring stack runs node_exporter as a container image whose tag is declared in
hetzner/monitoring/stack/compose.yml, the place a dependency bot reads and raises a pull
request against. The role installs the same release by URL from defaults/main.yml, which
no bot reads. This test keeps the two versions equal, and checks that the Dependabot
entry that watches the image is still there. A bump that changes the compose tag alone
fails here until the role's version moves with it.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "hetzner" / "monitoring" / "stack" / "compose.yml"
ROLE_DEFAULTS = ROOT / "ansible" / "roles" / "node_exporter" / "defaults" / "main.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
WATCHED_IMAGE = "prom/node-exporter"
WATCHED_DIRECTORY = "/hetzner/monitoring/stack"
IMAGE_TAG = re.compile(r"image:\s*\S*" + re.escape(WATCHED_IMAGE) + r":v(\d+\.\d+\.\d+)@sha256:")


def compose_version(text: str) -> str | None:
    """Return the node_exporter version in the compose image tag, or None when absent."""
    match = IMAGE_TAG.search(text)
    return match.group(1) if match else None


def role_version(document: object) -> str | None:
    """Return the version the role installs, or None when the key is absent."""
    if not isinstance(document, dict):
        return None
    value = document.get("node_exporter_version")
    return str(value) if value is not None else None


def dependabot_watches_image(document: object) -> bool:
    """Return True when a docker-compose entry for the stack allows the exporter image."""
    if not isinstance(document, dict):
        return False
    for entry in document.get("updates", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("package-ecosystem") != "docker-compose":
            continue
        if entry.get("directory") != WATCHED_DIRECTORY:
            continue
        for allowed in entry.get("allow", []):
            if isinstance(allowed, dict) and allowed.get("dependency-name") == WATCHED_IMAGE:
                return True
    return False


def disagreements() -> list[str]:
    """Return one line per place that disagrees with the others, empty when they agree."""
    problems: list[str] = []
    compose_text = COMPOSE.read_text(encoding="utf-8")
    compose = compose_version(compose_text)
    if compose is None:
        problems.append(f"{COMPOSE}: no {WATCHED_IMAGE} image tag found")
    role_document, role_problem = load_yaml(ROLE_DEFAULTS)
    if role_problem is not None:
        problems.append(role_problem)
    role = role_version(role_document)
    if role is None:
        problems.append(f"{ROLE_DEFAULTS}: node_exporter_version missing")
    if compose is not None and role is not None and compose != role:
        problems.append(f"compose tag {compose} != role node_exporter_version {role}")
    dependabot_document, dependabot_problem = load_yaml(DEPENDABOT)
    if dependabot_problem is not None:
        problems.append(dependabot_problem)
    elif not dependabot_watches_image(dependabot_document):
        problems.append(
            f"{DEPENDABOT}: no docker-compose entry for {WATCHED_DIRECTORY}"
            f" allowing {WATCHED_IMAGE}"
        )
    return problems


class NodeExporterPinAgrees(unittest.TestCase):
    """The compose tag, the role's version and the Dependabot entry agree."""

    def test_places_agree(self) -> None:
        self.assertEqual([], disagreements())

    def test_tag_parser_reads_the_real_compose_file(self) -> None:
        version = compose_version(COMPOSE.read_text(encoding="utf-8"))
        self.assertIsNotNone(version)

    def test_version_parser_refuses_a_missing_tag(self) -> None:
        self.assertIsNone(compose_version("image: docker.io/prom/other:v1.2.3@sha256:abc"))


if __name__ == "__main__":
    unittest.main()
