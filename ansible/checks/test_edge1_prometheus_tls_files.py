"""Every TLS file edge1's Prometheus names is one a role on edge1 puts there.

Prometheus reads each file named in a `tls_config` when it loads its configuration, and a missing
file stops it, and with it every alert on edge1. The stack names the files by container path in
`hetzner/monitoring/stack/prometheus/` and mounts a host directory over them in `compose.yml`; the
files reach the host only through a role on edge1's list (`checks/host_roles/edge1.yml`).

This test joins them: it follows every `ca_file`, `cert_file` and `key_file` through the Prometheus
service's mounts to a host path and fails unless `host_tls_identity` writes it on edge1. Its pin
(`ca.crt`) is written only once `host_tls_identity_peer_cert` is set in `owner_vars/edge1.yml`.

Two renderings of the config exist. `prometheus.yml` names no file and is held to the rule as it
stands. `prometheus.demo1.yml` names all three and is delivered as `prometheus.yml` by
`monitoring_stack` only while that same value is set, so it is checked as if the value were set and
`gate_problems` then holds the delivery to that flag. A reference conditional on the flag the writer
is conditional on is met; one conditional on anything else, or nothing, is refused.

Not proven: that a file is on the host (the gated apply's second run), that a certificate is valid,
or that Prometheus accepts the files.
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
DEMO1_CONFIG = STACK / "prometheus" / "prometheus.demo1.yml"
COMPOSE = STACK / "compose.yml"
HOST = "edge1"
SERVICE = "prometheus"
ROLE = "host_tls_identity"
DELIVERY_ROLE = "monitoring_stack"
DELIVERY_TASK = "Deliver the stack's files whose diff is not shown"
PIN_KEY = "host_tls_identity_peer_cert"
PIN_TEST = f"{PIN_KEY} | trim != ''"
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


def provided(
    listed: list[str], role_vars: object, owner: object, *, pin_set: bool | None = None
) -> dict[str, str]:
    """The host paths the roles on a host write, each with a note on when it is written.

    Only host_tls_identity writes TLS files for this host. Its pin is written only when the
    owner's value is set, so an empty one leaves it out. `pin_set` answers that question in place
    of the owner's file: a config delivered only while the value is set is read as if it were.

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
    if pin_set is None:
        pin_set = isinstance(peer, str) and bool(peer.strip())
    if pin_set:
        files[f"{directory}/{profile['pin_name']}"] = "pin"
    return files


def problems(
    config: object,
    compose: object,
    listed: list[str],
    role_vars: object,
    owner: object,
    *,
    pin_set: bool | None = None,
) -> list[str]:
    """One line per TLS file the config names that no role on edge1 puts on the host."""
    pairs = mounts(compose, SERVICE)
    available = provided(listed, role_vars, owner, pin_set=pin_set)
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


def _squash(text: object) -> str:
    return " ".join(str(text).split())


def _task_named(tasks: object, name: str) -> dict[str, object]:
    """The task with that name in a role's tasks file, or an empty mapping."""
    for task in tasks if isinstance(tasks, list) else []:
        if isinstance(task, dict) and task.get("name") == name:
            return cast("dict[str, object]", task)
    return {}


def gate_problems(
    listed: list[str],
    compose_text: str,
    pin_tasks: object,
    delivery_vars: object,
    delivery_tasks: object,
) -> list[str]:
    """One line per way the demo1 config could reach the host without the pin being written.

    The config that names the pin counts as written only if three things hold, each read from the
    roles' own files: host_tls_identity writes the pin under `host_tls_identity_peer_cert | trim !=
    ''`; monitoring_stack's flag is that same test of that same variable; and its delivery takes the
    demo1 config only under that flag, delivering it as `prometheus.yml` and not under a name of its
    own that the container could mount.

    Raises:
        TypeError: the delivery role's vars are not a mapping.
    """
    found: list[str] = []
    if DELIVERY_ROLE not in listed:
        found.append(f"{DELIVERY_ROLE} is not on {HOST}'s list, so no config reaches the host")
    pin_list = pin_tasks if isinstance(pin_tasks, list) else []
    pin_task: dict[str, object] = next(
        (
            cast("dict[str, object]", task)
            for task in pin_list
            if isinstance(task, dict) and task.get("ansible.builtin.include_tasks") == "_pin.yml"
        ),
        {},
    )
    when = pin_task.get("when", [])
    when = when if isinstance(when, list) else [when]
    if PIN_TEST not in [_squash(item) for item in when]:
        found.append(f"{ROLE} no longer writes the pin under `{PIN_TEST}`")
    owner_vars = _mapping(delivery_vars, f"{DELIVERY_ROLE} vars")
    flag = _squash(owner_vars.get("monitoring_stack_demo1_scrape", ""))
    if PIN_KEY not in flag or "| trim" not in flag or "!= ''" not in flag:
        found.append(
            f"{DELIVERY_ROLE}_demo1_scrape is `{flag}`, not the test of {PIN_KEY} that {ROLE} makes"
        )
    task = _task_named(delivery_tasks, DELIVERY_TASK)
    copy = task.get("ansible.builtin.copy")
    src = _squash(cast("dict[str, object]", copy).get("src", "")) if isinstance(copy, dict) else ""
    if "monitoring_stack_prometheus_demo1_variant" not in src or (
        "monitoring_stack_demo1_scrape" not in src
    ):
        found.append(f"the delivery's source `{src}` does not take the demo1 config under the flag")
    dest = (
        _squash(cast("dict[str, object]", copy).get("dest", "")) if isinstance(copy, dict) else ""
    )
    if "{{ item }}" not in dest:
        found.append(
            f"the delivery's destination `{dest}` is not the item, so the config is renamed"
        )
    if DEMO1_CONFIG.name in compose_text:
        found.append(f"compose.yml mounts {DEMO1_CONFIG.name} itself, not as prometheus.yml")
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
    names = [str(name) for name in listed]
    role_vars = _load(ANSIBLE / "roles" / ROLE / "vars" / "main.yml")
    owner = _load(ANSIBLE / "owner_vars" / f"{HOST}.yml")
    compose = _load(COMPOSE)
    found = problems(_load(PROMETHEUS_CONFIG), compose, names, role_vars, owner)
    # Delivered only while the pin is set, so read as if it were, and held to that delivery.
    found += [
        f"{DEMO1_CONFIG.name}: {line}"
        for line in problems(_load(DEMO1_CONFIG), compose, names, role_vars, owner, pin_set=True)
    ]
    found += gate_problems(
        names,
        COMPOSE.read_text(encoding="utf-8"),
        _load(ANSIBLE / "roles" / ROLE / "tasks" / "main.yml"),
        _load(ANSIBLE / "roles" / DELIVERY_ROLE / "vars" / "main.yml"),
        _load(ANSIBLE / "roles" / DELIVERY_ROLE / "tasks" / "main.yml"),
    )
    return found


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
    config: str = CONFIG,
    listed: tuple[str, ...] = (ROLE,),
    owner: str = PINNED,
    pin_set: bool | None = None,
) -> list[str]:
    return problems(
        yaml.safe_load(config),
        yaml.safe_load(COMPOSE_TEXT),
        list(listed),
        yaml.safe_load(ROLE_VARS),
        yaml.safe_load(owner),
        pin_set=pin_set,
    )


# The three files the gate reads, cut to the lines it reads: the pin role's task that includes the
# pin, the delivery role's flag, and the task that chooses the source.
GATE_PIN_TASKS = """
- name: Pin the peer's certificate
  ansible.builtin.include_tasks: _pin.yml
  when:
    - host_tls_identity_peer_cert | trim != ''
    - host_tls_identity_can_run | bool
"""
GATE_VARS = """
monitoring_stack_demo1_scrape: >-
  {{ (host_tls_identity_peer_cert | default('') | string | trim) != '' }}
"""
GATE_TASKS = """
- name: Deliver the stack's files whose diff is not shown
  ansible.builtin.copy:
    src: >-
      stack/{{ monitoring_stack_prometheus_demo1_variant
      if (item == p and monitoring_stack_demo1_scrape)
      else item }}
    dest: '{{ monitoring_stack_project_dir }}/{{ item }}'
"""


def _gate(
    listed: tuple[str, ...] = (DELIVERY_ROLE, ROLE),
    compose_text: str = "- ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
    pin_tasks: str = GATE_PIN_TASKS,
    vars_: str = GATE_VARS,
    tasks: str = GATE_TASKS,
) -> list[str]:
    return gate_problems(
        list(listed),
        compose_text,
        yaml.safe_load(pin_tasks),
        yaml.safe_load(vars_),
        yaml.safe_load(tasks),
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

    # The demo1 config is delivered only while the pin is set, so it is read as if it were set.
    def test_the_demo1_config_passes_as_if_the_pin_were_set_and_fails_without_the_role(
        self,
    ) -> None:
        self.assertEqual([], _case(owner=UNPINNED, pin_set=True))
        found = _case(owner=UNPINNED, listed=("monitoring_stack",), pin_set=True)
        self.assertEqual(3, len(found), found)

    def test_a_gate_that_is_the_pin_flag_passes(self) -> None:
        self.assertEqual([], _gate())

    def test_a_delivery_that_always_takes_the_demo1_config_is_refused(self) -> None:
        found = _gate(
            tasks=GATE_TASKS.replace(
                "if (item == p and monitoring_stack_demo1_scrape)", "if (item == p)"
            )
        )
        self.assertEqual(1, len(found), found)
        self.assertIn("does not take the demo1 config under the flag", found[0])

    def test_a_flag_that_is_not_the_pin_test_is_refused(self) -> None:
        found = _gate(vars_=GATE_VARS.replace(" | trim", ""))
        self.assertEqual(1, len(found), found)
        self.assertIn("not the test of host_tls_identity_peer_cert", found[0])

    def test_a_flag_on_another_variable_is_refused(self) -> None:
        found = _gate(vars_=GATE_VARS.replace(PIN_KEY, "some_other_value"))
        self.assertEqual(1, len(found), found)

    def test_a_pin_the_role_writes_unconditionally_is_refused(self) -> None:
        found = _gate(pin_tasks=GATE_PIN_TASKS.replace(f"{PIN_KEY} | trim != ''", "true"))
        self.assertEqual(1, len(found), found)
        self.assertIn("no longer writes the pin under", found[0])

    def test_a_delivery_that_renames_the_config_is_refused(self) -> None:
        found = _gate(tasks=GATE_TASKS.replace("{{ item }}", "{{ variant }}"))
        self.assertEqual(1, len(found), found)
        self.assertIn("is not the item", found[0])

    def test_a_compose_that_mounts_the_demo1_config_itself_is_refused(self) -> None:
        found = _gate(compose_text="- ./prometheus/prometheus.demo1.yml:/etc/prometheus/p.yml")
        self.assertEqual(1, len(found), found)

    def test_a_delivery_role_off_the_host_list_is_refused(self) -> None:
        found = _gate(listed=(ROLE,))
        self.assertEqual(1, len(found), found)

    def test_the_reader_finds_a_file_at_any_depth(self) -> None:
        nested = {"a": [{"b": {"tls_config": {"ca_file": "/x"}}}], "key_file": "/y"}
        self.assertEqual(["/x", "/y"], sorted(referenced_files(nested)))


if __name__ == "__main__":
    unittest.main()
