"""Contract tests of the publicpress website stack: its port, its health signal and its inputs.

These read the role's own files and the files of the other app1 stacks. They need no host and no
container. What they hold: the app's port is the one the compose file publishes and the role's
smoke test asks, and no other app1 stack, edge site or monitoring target uses it; the deploy
program accepts the stack's name and finds a health signal on every service; and the four SMTP
values are the website role's own (the owner's ruling that the app reuses that login), so no input
of this role needs a key the host's inputs file does not already hold.
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path
from types import ModuleType
from typing import cast

import yaml

ROLE = Path(__file__).resolve().parents[2]
REPO = ROLE.parents[2]
ROLES = REPO / "ansible" / "roles"
DEPLOY_PROGRAM = REPO / "hetzner" / "provision" / "branchleft_deploy.py"

STACK = "publicpress-website"
ADDRESS = "10.20.1.100"
PORT = 8081
SMTP_NAMES = ("host", "port", "user", "password")
ENV_KEYS = [f"PUBLICPRESS_SMTP_{name.upper()}" for name in SMTP_NAMES]
WEBSITE_INPUTS = [f"website_app1_smtp_{name}" for name in SMTP_NAMES]
OWN_INPUTS = [f"publicpress_website_app1_smtp_{name}" for name in SMTP_NAMES]


def load_deploy_program() -> ModuleType:
    """Load the host's deploy program from the repository, by path, as its own tests do."""
    spec = importlib.util.spec_from_file_location("branchleft_deploy_under_test", DEPLOY_PROGRAM)
    if spec is None or spec.loader is None:
        raise AssertionError("the deploy program cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_yaml(path: Path) -> dict[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    return cast(dict[str, object], loaded)


def compose_service() -> dict[str, object]:
    """Return the one service of the role's compose file."""
    compose = read_yaml(ROLE / "files" / "compose.yml")
    services = cast(dict[str, dict[str, object]], compose["services"])
    if list(services) != [STACK]:
        raise AssertionError(f"the stack must hold one service, {STACK}; found {list(services)}")
    return services[STACK]


def edge_site_app1_ports(sites: str, own_site: str) -> set[int]:
    """The app1 ports the edge sites other than `own_site` proxy to.

    An edge entry opens with `name: '<site>'` and states its `privateUpstream` after it, so the
    text is cut at each name and the port is read from that site's own section. The site named
    `own_site` is this stack's own entry, so its port is not another user of it.
    """
    used: set[int] = set()
    for section in re.split(r"(?=\bname: ')", sites):
        named = re.match(r"name: '([^']*)'", section)
        if named is None or named.group(1) == own_site:
            continue
        used.update(int(port) for port in re.findall(r"host: 'app1', port: (\d+)", section))
    return used


def ports_used_on_app1() -> set[int]:
    """Every port another stack, an edge site or a monitoring target has on app1."""
    used: set[int] = set()
    bound = re.compile(rf"{re.escape(ADDRESS)}:(\d+)")
    for compose in ROLES.glob("*/files/compose.yml"):
        if compose.parent.parent == ROLE:
            continue
        used.update(int(port) for port in bound.findall(compose.read_text(encoding="utf-8")))
    prometheus = REPO / "hetzner" / "monitoring" / "stack" / "prometheus" / "prometheus.yml"
    used.update(int(port) for port in bound.findall(prometheus.read_text(encoding="utf-8")))
    sites = (REPO / "sites.ts").read_text(encoding="utf-8")
    used.update(edge_site_app1_ports(sites, STACK))
    return used


class PortTests(unittest.TestCase):
    def test_the_compose_file_publishes_the_port_on_the_private_address_only(self) -> None:
        service = compose_service()
        self.assertEqual([f"{ADDRESS}:{PORT}:{PORT}"], service["ports"])
        environment = cast(dict[str, str], service["environment"])
        self.assertEqual(str(PORT), environment["PORT"])

    def test_the_smoke_test_asks_the_port_the_compose_file_publishes(self) -> None:
        variables = read_yaml(ROLE / "vars" / "main.yml")
        self.assertEqual(PORT, variables["publicpress_website_app1_port"])
        defaults = read_yaml(ROLE / "defaults" / "main.yml")
        self.assertEqual(ADDRESS, defaults["publicpress_website_app1_private_address"])

    def test_the_healthcheck_probes_the_same_port(self) -> None:
        healthcheck = cast(dict[str, object], compose_service()["healthcheck"])
        self.assertIn(f"127.0.0.1:{PORT}", " ".join(cast(list[str], healthcheck["test"])))

    def test_no_other_app1_stack_uses_the_port(self) -> None:
        used = ports_used_on_app1()
        # The scan must see the stacks it is about, or an empty set would pass.
        for known in (8080, 9092, 8101):
            self.assertIn(known, used)
        self.assertNotIn(PORT, used)

    def test_the_stacks_own_edge_entry_is_not_another_user_of_the_port(self) -> None:
        sites = (
            "{ name: 'website', privateUpstream: { host: 'app1', port: 8080 } },\n"
            f"{{ name: '{STACK}', privateUpstream: {{ host: 'app1', port: {PORT} }} }},\n"
        )
        self.assertEqual({8080}, edge_site_app1_ports(sites, STACK))

    def test_a_second_edge_site_on_the_port_is_found(self) -> None:
        for order in (("other", STACK), (STACK, "other")):
            entries = {
                STACK: f"{{ name: '{STACK}', privateUpstream: {{ host: 'app1', port: {PORT} }} }},\n",
                "other": f"{{ name: 'other', privateUpstream: {{ host: 'app1', port: {PORT} }} }},\n",
            }
            sites = "".join(entries[name] for name in order)
            self.assertIn(PORT, edge_site_app1_ports(sites, STACK), order)

    def test_the_real_edge_registry_has_the_stacks_own_entry_and_no_other_on_the_port(self) -> None:
        sites = (REPO / "sites.ts").read_text(encoding="utf-8")
        self.assertIn(f"name: '{STACK}'", sites)
        self.assertNotIn(PORT, edge_site_app1_ports(sites, STACK))


class DeployProgramTests(unittest.TestCase):
    def test_the_deploy_program_accepts_the_stack_name(self) -> None:
        program = load_deploy_program()
        self.assertEqual(STACK, program.validate_stack_name(STACK))

    def test_every_service_declares_a_health_signal(self) -> None:
        program = load_deploy_program()
        text = (ROLE / "files" / "compose.yml").read_text(encoding="utf-8")
        self.assertEqual(([], []), program.health_signal_gaps(STACK, text))

    def test_the_stack_is_pinned_by_the_image_the_deploy_program_writes(self) -> None:
        self.assertEqual("${IMAGE}", compose_service()["image"])


class InputTests(unittest.TestCase):
    def test_the_compose_file_requires_exactly_the_four_values_the_env_file_holds(self) -> None:
        text = (ROLE / "files" / "compose.yml").read_text(encoding="utf-8")
        interpolated = re.findall(r"\$\{(PUBLICPRESS_[A-Z_]+):\?", text)
        self.assertEqual(ENV_KEYS, interpolated)
        template = (ROLE / "templates" / "publicpress-website.env.j2").read_text(encoding="utf-8")
        lines = template.splitlines()
        self.assertEqual(
            [f"{key}={{{{ {source} }}}}" for key, source in zip(ENV_KEYS, OWN_INPUTS, strict=True)],
            lines,
        )

    def test_each_value_is_the_website_roles_and_the_host_already_holds_it(self) -> None:
        variables = read_yaml(ROLE / "vars" / "main.yml")
        for own, website in zip(OWN_INPUTS, WEBSITE_INPUTS, strict=True):
            self.assertEqual(f"{{{{ {website} }}}}", variables[own])
        loader = read_yaml(ROLES / "host_inputs" / "vars" / "main.yml")
        rows = cast(dict[str, list[str]], loader["host_inputs_required_by_host"])
        for name in WEBSITE_INPUTS:
            self.assertIn(name, rows["app1"])
        # No new key: the loader holds nothing under this role's names.
        self.assertEqual([], [name for name in rows["app1"] if "publicpress" in name])

    def test_the_role_asks_for_no_input_the_loader_does_not_set(self) -> None:
        specs = read_yaml(ROLE / "meta" / "argument_specs.yml")
        entry = cast(dict[str, dict[str, object]], specs["argument_specs"])["main"]
        options = cast(dict[str, dict[str, object]], entry["options"])
        required = [name for name, option in options.items() if option.get("required") is True]
        self.assertEqual(OWN_INPUTS, required)
        defaults = read_yaml(ROLE / "defaults" / "main.yml")
        self.assertEqual([], [name for name in OWN_INPUTS if name in defaults])


if __name__ == "__main__":
    unittest.main()
