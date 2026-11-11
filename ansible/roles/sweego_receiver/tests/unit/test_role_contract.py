"""Unit tests for the receiver role's contracts, from its files alone, with no container.

The Molecule scenarios prove what the role does to a host. These prove the parts that must not
change by accident: that the compose file the role renders is hardened and binds the private
address only, that the unit that loads the drain-port rule names the port the compose file
publishes and admits ops1 alone, that the repeated constants agree with the files they repeat,
that the role reads no secret, and that no value of one is in the role. A change to any of them
fails here in seconds and names the control it broke.
"""

import re
import unittest
from pathlib import Path

import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[2]

IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PREVIOUS = "sweego_receiver_previous_signing_secret_file"
PUBLIC_PORT = 18080
DRAIN_PORT = 18081

SHELL_MODULES = ("ansible.builtin.shell", "ansible.builtin.raw", "ansible.builtin.script")
# A long run of base64 or hex characters: the shape of a pasted key, token or digest of a secret.
SECRET_SHAPE = re.compile(r"(?<![A-Za-z0-9+/=_.-])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=_.-])")
# Prefixes a webhook signing secret or a PEM block would carry.
SECRET_PREFIX = re.compile(r"whsec_|-----BEGIN|swg_secret|sk_live|AKIA[0-9A-Z]{12}")


def load_yaml(relative: str) -> dict[str, object]:
    """Parse one YAML mapping of the role."""
    parsed: object = yaml.safe_load((ROLE / relative).read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise AssertionError(f"{relative} is not a mapping")
    return {str(key): value for key, value in parsed.items()}


def render(template: str, **extra: object) -> str:
    """Render one template of the role the way the template module does (trim_blocks on)."""
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(ROLE / "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 -- the output is YAML and systemd text, not HTML
    )
    context: dict[str, object] = {
        **load_yaml("defaults/main.yml"),
        **load_yaml("vars/main.yml"),
        "sweego_receiver_port": PUBLIC_PORT,
        "sweego_receiver_drain_port": DRAIN_PORT,
        **extra,
    }
    return environment.get_template(template).render(context)


def compose(**extra: object) -> dict[str, object]:
    """The rendered compose file, parsed."""
    parsed: object = yaml.safe_load(render("compose.yml.j2", **extra))
    if not isinstance(parsed, dict):
        raise AssertionError("the rendered compose file is not a mapping")
    return {str(key): value for key, value in parsed.items()}


def receiver(**extra: object) -> dict[str, object]:
    """The receiver service of the rendered compose file."""
    services = compose(**extra)["services"]
    if not isinstance(services, dict):
        raise AssertionError("services is not a mapping")
    service: object = services["receiver"]
    if not isinstance(service, dict):
        raise AssertionError("the receiver service is not a mapping")
    return {str(key): value for key, value in service.items()}


def as_list(value: object) -> list[object]:
    """Narrow a parsed value to a list, failing the test if it is not one."""
    if not isinstance(value, list):
        raise AssertionError(f"expected a list, got {type(value).__name__}")
    return list(value)


def as_dict(value: object) -> dict[str, object]:
    """Narrow a parsed value to a mapping, failing the test if it is not one."""
    if not isinstance(value, dict):
        raise AssertionError(f"expected a mapping, got {type(value).__name__}")
    return {str(key): item for key, item in value.items()}


def constant(name: str) -> object:
    """One constant of the role's vars/main.yml."""
    return load_yaml("vars/main.yml")[name]


class ComposeContainerIsHardened(unittest.TestCase):
    """The container runs as a fixed non-root account, read-only, with nothing added."""

    def test_the_account_is_a_fixed_number_and_not_root(self) -> None:
        user = str(receiver()["user"])
        uid, gid = user.split(":")
        self.assertEqual(uid, str(constant("sweego_receiver_uid")))
        self.assertEqual(gid, str(constant("sweego_receiver_gid")))
        self.assertGreater(int(uid), 1000)
        self.assertGreater(int(gid), 1000)

    def test_the_root_filesystem_is_read_only(self) -> None:
        self.assertIs(receiver()["read_only"], True)

    def test_every_capability_is_dropped_and_none_is_added(self) -> None:
        service = receiver()
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertNotIn("cap_add", service)

    def test_new_privileges_are_refused(self) -> None:
        self.assertEqual(receiver()["security_opt"], ["no-new-privileges:true"])

    def test_the_container_is_not_privileged_and_shares_nothing_with_the_host(self) -> None:
        service = receiver()
        for key in (
            "privileged",
            "network_mode",
            "pid",
            "ipc",
            "devices",
            "volumes_from",
            "userns_mode",
        ):
            self.assertNotIn(key, service, key)

    def test_the_docker_socket_is_not_mounted(self) -> None:
        for volume in as_list(receiver()["volumes"]):
            self.assertNotIn("docker.sock", str(volume))
            self.assertNotIn("/var/run", str(volume).split(":")[0])

    def test_the_only_writable_mount_is_the_state_directory(self) -> None:
        writable = [str(v) for v in as_list(receiver()["volumes"]) if not str(v).endswith(":ro")]
        self.assertEqual(writable, [f"{constant('sweego_receiver_state_dir')}:/state"])

    def test_no_tmpfs_and_no_other_writable_place(self) -> None:
        self.assertNotIn("tmpfs", receiver())

    def test_a_healthcheck_a_restart_policy_and_limits_are_set(self) -> None:
        service = receiver()
        self.assertIn("healthcheck", service)
        self.assertEqual(as_dict(service["healthcheck"])["test"][0], "CMD")  # type: ignore[index]
        self.assertTrue(str(service["restart"]).startswith("on-failure"))
        for limit in ("mem_limit", "memswap_limit", "pids_limit", "cpus"):
            self.assertIn(limit, service, limit)

    def test_the_restart_policy_does_not_start_the_container_at_boot_by_itself(self) -> None:
        self.assertNotIn("unless-stopped", str(receiver()["restart"]))
        self.assertNotIn("always", str(receiver()["restart"]))

    def test_the_image_comes_from_the_pin_file_and_names_no_tag(self) -> None:
        image = str(receiver()["image"])
        self.assertTrue(image.startswith("${IMAGE:?"), image)
        self.assertNotIn("latest", image)

    def test_it_is_one_service(self) -> None:
        services = as_dict(compose()["services"])
        self.assertEqual(list(services), ["receiver"])
        self.assertNotIn("include", compose())
        self.assertNotIn("build", receiver())


class ComposeBindsThePrivateAddressOnly(unittest.TestCase):
    """Both published ports are on edge1's private address; the receiver binds a specific one."""

    def test_both_ports_are_on_the_private_address(self) -> None:
        address = str(constant("sweego_receiver_private_address"))
        self.assertEqual(
            receiver()["ports"],
            [f"{address}:{PUBLIC_PORT}:8080", f"{address}:{DRAIN_PORT}:8081"],
        )

    def test_no_port_is_published_on_all_addresses_or_the_public_one(self) -> None:
        for port in as_list(receiver()["ports"]):
            text = str(port)
            self.assertTrue(text.startswith("10.20.1.10:"), text)
            self.assertNotIn("0.0.0.0", text)  # noqa: S104 -- asserting it is absent
            self.assertEqual(text.count(":"), 2, text)

    def test_the_receiver_binds_a_specific_address_not_a_wildcard(self) -> None:
        environment = as_dict(receiver()["environment"])
        for name in ("WEBHOOK_HOST", "WEBHOOK_DRAIN_HOST"):
            self.assertEqual(environment[name], constant("sweego_receiver_container_address"))
            wildcards = ("0.0.0.0", "::", "", "0")  # noqa: S104 -- the values refused
            self.assertNotIn(str(environment[name]), wildcards)

    def test_the_container_address_is_inside_its_own_subnet_and_off_the_estate(self) -> None:
        import ipaddress

        network = ipaddress.ip_network(str(constant("sweego_receiver_network_subnet")))
        self.assertIn(
            ipaddress.ip_address(str(constant("sweego_receiver_container_address"))), network
        )
        self.assertIn(
            ipaddress.ip_address(str(constant("sweego_receiver_network_gateway"))), network
        )
        self.assertFalse(network.overlaps(ipaddress.ip_network("10.20.0.0/16")))
        self.assertFalse(network.overlaps(ipaddress.ip_network("172.17.0.0/16")))

    def test_the_container_listens_on_the_ports_the_receiver_names(self) -> None:
        environment = as_dict(receiver()["environment"])
        self.assertEqual(environment["WEBHOOK_PORT"], "8080")
        self.assertEqual(environment["WEBHOOK_DRAIN_PORT"], "8081")


class ComposeHoldsNoSecret(unittest.TestCase):
    """A secret reaches the container as a file; the environment holds paths and nothing else."""

    def test_the_environment_holds_paths_to_files_and_no_value(self) -> None:
        environment = as_dict(receiver()["environment"])
        self.assertEqual(
            sorted(environment),
            sorted(
                [
                    "WEBHOOK_HOST",
                    "WEBHOOK_PORT",
                    "WEBHOOK_DRAIN_HOST",
                    "WEBHOOK_DRAIN_PORT",
                    "WEBHOOK_STATE_DIR",
                    "WEBHOOK_SECRET_FILE",
                    "WEBHOOK_DRAIN_TOKEN_FILE",
                ]
            ),
        )
        for name in ("WEBHOOK_SECRET_FILE", "WEBHOOK_DRAIN_TOKEN_FILE"):
            self.assertTrue(str(environment[name]).startswith("/run/secrets/"), name)

    def test_the_secret_files_are_mounted_read_only_from_host_paths(self) -> None:
        mounts = [str(v) for v in as_list(receiver()["volumes"])]
        secret = [m for m in mounts if "/run/secrets/" in m]
        self.assertEqual(len(secret), 2)
        for mount in secret:
            self.assertTrue(mount.startswith("/etc/branchleft/"), mount)
            self.assertTrue(mount.endswith(":ro"), mount)

    def test_a_previous_secret_adds_one_mount_and_one_name(self) -> None:
        service = receiver(**{PREVIOUS: "/etc/branchleft/old-secret"})
        environment = as_dict(service["environment"])
        self.assertIn("WEBHOOK_SECRET_FILE_PREVIOUS", environment)
        self.assertEqual(
            len([v for v in as_list(service["volumes"]) if "/run/secrets/" in str(v)]), 3
        )
        self.assertNotIn("WEBHOOK_SECRET_FILE_PREVIOUS", as_dict(receiver()["environment"]))

    def test_no_rendered_file_holds_a_value_that_looks_like_a_secret(self) -> None:
        for text in (
            render("compose.yml.j2"),
            render("compose.yml.j2", **{PREVIOUS: "/etc/branchleft/old"}),
            render("branchleft-sweego-drain-rule.service.j2"),
        ):
            self.assertIsNone(SECRET_SHAPE.search(text))
            self.assertIsNone(SECRET_PREFIX.search(text))


class RuleUnitAdmitsOps1Alone(unittest.TestCase):
    """The unit that loads the drain-port rule names the published drain port and ops1 alone."""

    def exec_start(self) -> list[str]:
        """The words of the unit's ExecStart."""
        lines = [
            line
            for line in render("branchleft-sweego-drain-rule.service.j2").splitlines()
            if line.startswith("ExecStart=")
        ]
        self.assertEqual(len(lines), 1)
        return lines[0].removeprefix("ExecStart=").split()

    def option(self, name: str) -> str:
        """The value that follows one option of the ExecStart."""
        words = self.exec_start()
        return words[words.index(name) + 1]

    def test_the_unit_runs_the_installed_program(self) -> None:
        self.assertEqual(self.exec_start()[0], constant("sweego_receiver_program_dest"))

    def test_the_rule_is_on_the_port_the_compose_file_publishes_as_the_drain_port(self) -> None:
        published = str(as_list(receiver()["ports"])[1])
        self.assertEqual(published, f"{self.option('--address')}:{self.option('--port')}:8081")

    def test_the_rule_is_on_the_address_every_port_is_published_on(self) -> None:
        for port in as_list(receiver()["ports"]):
            self.assertTrue(str(port).startswith(self.option("--address") + ":"))

    def test_the_only_source_admitted_is_ops1(self) -> None:
        self.assertEqual(self.option("--allow-source"), "10.20.1.50")
        self.assertEqual(
            self.option("--allow-source"), constant("sweego_receiver_drain_peer_address")
        )

    def test_the_unit_takes_no_environment_and_no_other_option(self) -> None:
        words = self.exec_start()
        self.assertEqual(
            [w for w in words if w.startswith("--")], ["--address", "--port", "--allow-source"]
        )
        self.assertNotIn("Environment", render("branchleft-sweego-drain-rule.service.j2"))

    def test_the_unit_runs_after_docker_and_at_boot_and_follows_a_docker_restart(self) -> None:
        text = render("branchleft-sweego-drain-rule.service.j2")
        self.assertRegex(text, r"(?m)^After=.*docker\.service")
        self.assertRegex(text, r"(?m)^PartOf=docker\.service$")
        self.assertRegex(text, r"(?m)^WantedBy=multi-user\.target$")

    def test_the_receivers_unit_is_ordered_after_and_bound_to_the_rule_unit(self) -> None:
        content = str(constant("sweego_receiver_dropin_content"))
        unit = str(constant("sweego_receiver_rule_unit_name"))
        self.assertIn("Requires={{ sweego_receiver_rule_unit_name }}", content)
        self.assertIn("After={{ sweego_receiver_rule_unit_name }}", content)
        self.assertEqual(unit, Path(str(constant("sweego_receiver_rule_unit_dest"))).name)


class ConstantsAgreeWithTheirHomes(unittest.TestCase):
    """A constant that repeats a value kept elsewhere is held to that file."""

    def test_the_addresses_are_edge1_and_ops1_of_the_address_plan(self) -> None:
        # Written out, not read from the plan: a file outside the role that a role test reads
        # has to be in the CI path filter, and the plan is not. The values are the plan's.
        self.assertEqual(constant("sweego_receiver_private_address"), "10.20.1.10")
        self.assertEqual(constant("sweego_receiver_drain_peer_address"), "10.20.1.50")

    def test_the_container_account_is_not_the_mail_spools(self) -> None:
        self.assertNotEqual(constant("sweego_receiver_uid"), 31000)

    def test_the_compose_unit_and_project_are_one_name(self) -> None:
        self.assertEqual(
            constant("sweego_receiver_compose_unit"), "branchleft-compose@sweego-receiver.service"
        )
        self.assertEqual(constant("sweego_receiver_project_name"), "sweego-receiver")
        self.assertEqual(constant("sweego_receiver_project_dir"), "/opt/branchleft/sweego-receiver")
        self.assertEqual(
            constant("sweego_receiver_image_env_path"), "/etc/branchleft/sweego-receiver.image.env"
        )
        self.assertEqual(constant("sweego_receiver_container"), "sweego-receiver-receiver-1")

    def test_the_receivers_listeners_are_the_ones_its_dockerfile_exposes(self) -> None:
        self.assertEqual(constant("sweego_receiver_container_public_port"), 8080)
        self.assertEqual(constant("sweego_receiver_container_drain_port"), 8081)

    def test_the_secret_path_pattern_admits_one_name_and_nothing_that_edits_a_mount(self) -> None:
        pattern = re.compile(str(constant("sweego_receiver_secret_path_pattern")))
        self.assertIsNotNone(pattern.match("/etc/branchleft/sweego-receiver-signing-secret"))
        for bad in (
            "/etc/branchleft/",
            "/etc/branchleft/a:b",
            "/etc/branchleft/a b",
            "/etc/branchleft/../shadow",
            "/etc/branchleft/sub/file",
            "/etc/other/file",
            "/etc/branchleft/file\n",
            "relative",
        ):
            self.assertIsNone(pattern.match(bad), bad)

    def test_the_image_pin_pattern_needs_a_digest(self) -> None:
        pattern = re.compile(str(constant("sweego_receiver_image_env_pattern")))
        digest = "a" * 64
        self.assertIsNotNone(
            pattern.match(f"IMAGE=ghcr.io/branchleft/sweego-receiver@sha256:{digest}")
        )
        for bad in (
            "IMAGE=ghcr.io/branchleft/sweego-receiver:latest",
            f"IMAGE=ghcr.io/branchleft/sweego-receiver@sha256:{digest[:-1]}",
            f"IMAGE=ghcr.io/branchleft/sweego-receiver@sha256:{digest}\n",
        ):
            self.assertIsNone(pattern.match(bad), bad)


class RoleReadsNoSecretAndWritesNoSecret(unittest.TestCase):
    """The role looks at the secret files and never opens them, and none is in the role."""

    def tasks(self) -> list[tuple[str, dict[str, object]]]:
        """Every task of the role, with the file it is in."""
        found: list[tuple[str, dict[str, object]]] = []

        def walk(node: object, name: str) -> None:
            if isinstance(node, list):
                for item in node:
                    walk(item, name)
            elif isinstance(node, dict):
                found.append((name, {str(k): v for k, v in node.items()}))
                for value in node.values():
                    if isinstance(value, list):
                        walk(value, name)

        for path in sorted((ROLE / "tasks").glob("*.yml")):
            walk(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
        return found

    def test_no_task_runs_a_shell(self) -> None:
        for name, task in self.tasks():
            for module in SHELL_MODULES:
                self.assertNotIn(module, task, f"{name}: {module}")

    def test_the_secret_files_are_looked_at_with_no_checksum(self) -> None:
        stat = [
            task
            for name, task in self.tasks()
            if name == "_secrets.yml" and "ansible.builtin.stat" in task
        ]
        self.assertEqual(len(stat), 1)
        args = as_dict(stat[0]["ansible.builtin.stat"])
        self.assertIs(args["get_checksum"], False)
        self.assertIs(args["follow"], False)

    def test_no_task_opens_a_secret_file(self) -> None:
        for name, task in self.tasks():
            text = yaml.safe_dump(task)
            for module in ("slurp", "lookup('ansible.builtin.file'", "ansible.builtin.fetch"):
                if module in text:
                    self.assertNotRegex(
                        text,
                        r"signing_secret|drain_token|secret_files",
                        f"{name} opens a secret with {module}",
                    )

    def test_no_task_writes_a_secret_file(self) -> None:
        for name, task in self.tasks():
            for module in (
                "ansible.builtin.copy",
                "ansible.builtin.template",
                "ansible.builtin.lineinfile",
            ):
                if module in task:
                    destination = str(as_dict(task[module]).get("dest", ""))
                    self.assertNotIn("secret", destination, name)
                    self.assertNotIn("token", destination, name)
                    self.assertNotIn("/etc/branchleft/sweego", destination, name)

    def test_the_secret_checks_come_before_the_first_write(self) -> None:
        main = [
            line
            for line in (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8").splitlines()
            if "include_tasks" in line
        ]
        names = [line.split(":", 1)[1].strip() for line in main]
        self.assertEqual(
            names,
            [
                "_inputs.yml",
                "_compose_check.yml",
                "_preconditions.yml",
                "_secrets.yml",
                "_rule.yml",
                "_stack.yml",
                "_readback.yml",
            ],
        )

    def test_the_rule_is_installed_and_read_back_before_the_stack_is_delivered(self) -> None:
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertLess(text.index("_rule.yml"), text.index("_stack.yml"))
        self.assertLess(text.index("_secrets.yml"), text.index("_rule.yml"))

    def test_no_file_of_the_role_holds_a_secret_shaped_value(self) -> None:
        for path in sorted(ROLE.rglob("*")):
            # This file holds the patterns themselves and a planted canary for them.
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path == Path(__file__).resolve()
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            # An image digest is a public name, not a secret: the test pins hold them.
            text = IMAGE_DIGEST.sub("", text)
            self.assertIsNone(
                SECRET_SHAPE.search(text), f"{path.relative_to(ROLE)} holds a long encoded run"
            )
            self.assertIsNone(
                SECRET_PREFIX.search(text), f"{path.relative_to(ROLE)} holds a secret prefix"
            )

    def test_the_scan_can_find_something(self) -> None:
        planted = "key = " + "A1b2C3d4" * 6
        self.assertIsNotNone(SECRET_SHAPE.search(planted))
        self.assertIsNotNone(SECRET_PREFIX.search("whsec_" + "x" * 10))


class ArgumentSpecMatchesTheRole(unittest.TestCase):
    """The specification and the defaults agree, and the ports have no default."""

    def test_the_ports_are_required_and_have_no_default(self) -> None:
        options = as_dict(
            as_dict(as_dict(load_yaml("meta/argument_specs.yml")["argument_specs"])["main"])[
                "options"
            ]
        )
        defaults = load_yaml("defaults/main.yml")
        for name in ("sweego_receiver_port", "sweego_receiver_drain_port"):
            self.assertIs(as_dict(options[name])["required"], True)
            self.assertNotIn(name, defaults)

    def test_each_default_is_the_specified_default(self) -> None:
        options = as_dict(
            as_dict(as_dict(load_yaml("meta/argument_specs.yml")["argument_specs"])["main"])[
                "options"
            ]
        )
        defaults = load_yaml("defaults/main.yml")
        for name, value in defaults.items():
            self.assertEqual(as_dict(options[name])["default"], value, name)


if __name__ == "__main__":
    unittest.main()
