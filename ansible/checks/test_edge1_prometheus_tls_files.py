"""Every TLS file edge1's Prometheus names is one a role on edge1 puts there.

Prometheus reads each file named in a `tls_config` when it loads its configuration, and a missing
file stops it from starting, and with it every alert on edge1. The monitoring stack names those
files by container path in `hetzner/monitoring/stack/prometheus/prometheus.yml` and mounts a host
directory over them in `hetzner/monitoring/stack/compose.yml`; the files reach the host only
through a role on edge1's list (`checks/host_roles/edge1.yml`). Nothing joined the three, so a
pull request that named a file could be delivered to a host that had none.

This test joins them. It reads the container path of every `ca_file`, `cert_file` and `key_file`
in the config, follows it through the Prometheus service's mounts to a path on the host, and
fails when that path is not one the roles on edge1 write. The only role that writes TLS files
there is `host_tls_identity`, whose profile for edge1 names its key, certificate and pin. The pin
(`ca.crt`) is written only once the owner has set `host_tls_identity_peer_cert` in
`owner_vars/edge1.yml`, so a config that names the pin also fails while that value is empty.

What it does not prove: that a file is on the host (that is the gated apply's second run), that a
certificate is valid or unexpired (the role's own checks), or that Prometheus accepts the files.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
STACK = ROOT / "hetzner" / "monitoring" / "stack"
PROMETHEUS_CONFIG = STACK / "prometheus" / "prometheus.yml"
COMPOSE = STACK / "compose.yml"
HOST = "edge1"
SERVICE = "prometheus"
ROLE = "host_tls_identity"
PIN_KEY = "host_tls_identity_peer_cert"
TLS_FILE_KEYS = frozenset(("ca_file", "cert_file", "key_file"))


def _load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _mapping(value: object, what: str) -> dict[str, object]:
    """Return a YAML mapping as a dict.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"{what} is not a mapping"
        raise TypeError(message)
    return cast("dict[str, object]", value)


def referenced_files(config: object) -> list[str]:
    """Every container path a `ca_file`, `cert_file` or `key_file` names, at any depth."""
    found: list[str] = []
    if isinstance(config, dict):
        for key, value in config.items():
            if key in TLS_FILE_KEYS and isinstance(value, str):
                found.append(value)
            else:
                found.extend(referenced_files(value))
    elif isinstance(config, list):
        for item in config:
            found.extend(referenced_files(item))
    return found


def mounts(compose: object, service: str) -> list[tuple[str, str]]:
    """The (host source, container path) of each bind or volume entry of one service.

    Raises:
        TypeError: the service is missing or one of its volumes is not a short-form string.
    """
    services = _mapping(_mapping(compose, "compose")["services"], "services")
    volumes = _mapping(services[service], service).get("volumes", [])
    if not isinstance(volumes, list):
        message = f"{service} volumes is not a list"
        raise TypeError(message)
    pairs: list[tuple[str, str]] = []
    for entry in volumes:
        if not isinstance(entry, str):
            message = f"{service} has a volume that is not a short-form string: {entry!r}"
            raise TypeError(message)
        parts = entry.split(":")
        if len(parts) < 2:  # noqa: PLR2004 - source:target is the shortest mount
            message = f"{service} volume {entry!r} has no container path"
            raise TypeError(message)
        pairs.append((parts[0], parts[1]))
    return pairs


def host_path(container_path: str, pairs: list[tuple[str, str]]) -> tuple[str | None, str | None]:
    """Follow a container path through the mounts: (the host path or None, a problem or None).

    A source that is not an absolute host path (a path in the checkout, or a named volume) is
    not something a role places, so it gives (None, None). The longest matching mount wins.
    """
    best: tuple[str, str] | None = None
    for source, target in pairs:
        inside = container_path == target or container_path.startswith(target.rstrip("/") + "/")
        if inside and (best is None or len(target) > len(best[1])):
            best = (source, target)
    if best is None:
        return None, f"{container_path} is under no mount of {SERVICE}, so no host file backs it"
    source, target = best
    if not source.startswith("/"):
        return None, None
    return source.rstrip("/") + container_path[len(target.rstrip("/")) :], None


def provided(listed: list[str], role_vars: object, owner: object) -> dict[str, str]:
    """The host paths the roles on a host write, each with a note on when it is written.

    Only host_tls_identity writes TLS files for this host. Its pin is written only when the
    owner's value is set, so an empty one leaves it out.

    Raises:
        TypeError: the role's vars or the owner's file have a shape this test does not read.
    """
    if ROLE not in listed:
        return {}
    profiles = _mapping(
        _mapping(role_vars, "role vars")["host_tls_identity_profiles"], "host_tls_identity_profiles"
    )
    profile = _mapping(profiles[HOST], f"profile {HOST}")
    directory = str(profile["dir"]).rstrip("/")
    files = {
        f"{directory}/{profile['key_name']}": "key",
        f"{directory}/{profile['cert_name']}": "certificate",
    }
    peer = _mapping(owner, f"owner_vars/{HOST}.yml").get(PIN_KEY, "")
    if isinstance(peer, str) and peer.strip():
        files[f"{directory}/{profile['pin_name']}"] = "pin"
    return files


def problems(
    config: object, compose: object, listed: list[str], role_vars: object, owner: object
) -> list[str]:
    """One line per TLS file the config names that no role on edge1 puts on the host."""
    pairs = mounts(compose, SERVICE)
    available = provided(listed, role_vars, owner)
    found: list[str] = []
    for container_path in sorted(set(referenced_files(config))):
        path, problem = host_path(container_path, pairs)
        if problem is not None:
            found.append(problem)
        elif path is not None and path not in available:
            found.append(
                f"{container_path} is {path} on {HOST}, which no role on {HOST} writes"
                f" (written by {ROLE}: {sorted(available) or 'role not on the host list'};"
                f" the pin is written only once {PIN_KEY} is set in owner_vars/{HOST}.yml)"
            )
    return found


def real_problems() -> list[str]:
    """The problems of the files as they stand in this tree.

    Raises:
        TypeError: host_roles/edge1.yml is not a list.
    """
    listed = _load(ANSIBLE / "checks" / "host_roles" / f"{HOST}.yml")
    if not isinstance(listed, list):
        message = f"host_roles/{HOST}.yml is not a list"
        raise TypeError(message)
    return problems(
        _load(PROMETHEUS_CONFIG),
        _load(COMPOSE),
        [str(name) for name in listed],
        _load(ANSIBLE / "roles" / ROLE / "vars" / "main.yml"),
        _load(ANSIBLE / "owner_vars" / f"{HOST}.yml"),
    )


# A fixture of the shape the stack takes once it scrapes demo1: three files, one mounted directory.
CONFIG = """
scrape_configs:
  - job_name: node
    tls_config:
      ca_file: /etc/prometheus/demo1-metrics-tls/ca.crt
      cert_file: /etc/prometheus/demo1-metrics-tls/client.crt
      key_file: /etc/prometheus/demo1-metrics-tls/client.key
      server_name: demo1
"""
COMPOSE_TEXT = """
services:
  prometheus:
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - /etc/branchleft/demo1-metrics-tls:/etc/prometheus/demo1-metrics-tls:ro
      - prometheus-data:/prometheus
"""
ROLE_VARS = """
host_tls_identity_profiles:
  edge1:
    dir: /etc/branchleft/demo1-metrics-tls
    key_name: client.key
    cert_name: client.crt
    pin_name: ca.crt
"""
PINNED = "host_tls_identity_peer_cert: |\n  -----BEGIN CERTIFICATE-----\n"
UNPINNED = "host_tls_identity_peer_cert: ''\n"


def _case(
    config: str = CONFIG, listed: tuple[str, ...] = (ROLE,), owner: str = PINNED
) -> list[str]:
    return problems(
        yaml.safe_load(config),
        yaml.safe_load(COMPOSE_TEXT),
        list(listed),
        yaml.safe_load(ROLE_VARS),
        yaml.safe_load(owner),
    )


class Edge1PrometheusTlsFiles(unittest.TestCase):
    """The files the config names are the files the roles write."""

    def test_the_real_tree_names_only_files_a_role_writes(self) -> None:
        self.assertEqual([], real_problems())

    def test_a_config_whose_three_files_are_all_provided_passes(self) -> None:
        self.assertEqual([], _case())

    # Controls: each case changes one thing and must be refused for that thing.
    def test_the_role_missing_from_the_host_list_is_refused(self) -> None:
        found = _case(listed=("monitoring_stack",))
        self.assertEqual(3, len(found), found)
        self.assertTrue(all("no role on edge1 writes" in line for line in found), found)

    def test_an_empty_pin_leaves_only_the_pin_file_missing(self) -> None:
        found = _case(owner=UNPINNED)
        self.assertEqual(1, len(found), found)
        self.assertIn("/etc/prometheus/demo1-metrics-tls/ca.crt", found[0])

    def test_a_file_in_a_directory_no_role_writes_is_refused(self) -> None:
        moved = CONFIG.replace("client.key", "other.key")
        found = _case(config=moved)
        self.assertEqual(1, len(found), found)
        self.assertIn("other.key", found[0])

    def test_a_file_under_no_mount_is_refused(self) -> None:
        stray = CONFIG.replace("/etc/prometheus/demo1-metrics-tls/ca.crt", "/x/ca.crt")
        found = _case(config=stray)
        self.assertEqual(1, len(found), found)
        self.assertIn("under no mount", found[0])

    def test_a_file_shipped_in_the_checkout_needs_no_role(self) -> None:
        shipped = CONFIG.replace(
            "/etc/prometheus/demo1-metrics-tls/ca.crt", "/etc/prometheus/prometheus.yml"
        )
        self.assertEqual([], _case(config=shipped, listed=(ROLE,)))

    def test_the_reader_finds_a_file_at_any_depth(self) -> None:
        nested = {"a": [{"b": {"tls_config": {"ca_file": "/x"}}}], "key_file": "/y"}
        self.assertEqual(["/x", "/y"], sorted(referenced_files(nested)))


if __name__ == "__main__":
    unittest.main()
