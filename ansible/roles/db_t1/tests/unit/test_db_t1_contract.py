"""Unit tests for the db_t1 role: what its rendered files and its tasks must say.

The role is proven on a host only by the gated apply. These tests hold the properties a
review would otherwise have to find by eye: no listener beyond loopback, no root account
reachable from another host, no call-home agent, the configuration actually mounted, the
deploy only ever on an empty host, and the owner-placed root file never read or written.
Each one fails when the line it guards is removed (the sabotage record is in the pull
request). They need no network and no Docker.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import jinja2
import yaml  # type: ignore[import-untyped]

ROLE = Path(__file__).resolve().parents[2]
ROOT = ROLE.parents[2]
VARS: dict[str, object] = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS: dict[str, object] = yaml.safe_load(
    (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
)
DEPLOY_SOURCE = (ROOT / "hetzner" / "provision" / "branchleft_deploy.py").read_text(
    encoding="utf-8"
)
DIGEST = "a" * 64
GOOD_IMAGE = f"ghcr.io/branchleft/percona-server@sha256:{DIGEST}"
ROOT_KEY = "MYSQL_ROOT_PASSWORD"


def mapping(value: object) -> dict[str, object]:
    """Return a mapping with text keys.

    Raises:
        TypeError: the value is not a mapping.
    """
    if not isinstance(value, dict):
        message = f"expected a mapping, got {type(value).__name__}"
        raise TypeError(message)
    return {str(key): item for key, item in value.items()}


def sequence(value: object) -> list[object]:
    """Return a list.

    Raises:
        TypeError: the value is not a list.
    """
    if not isinstance(value, list):
        message = f"expected a list, got {type(value).__name__}"
        raise TypeError(message)
    return list(value)


def text_var(name: str) -> str:
    """Return a text variable of the role's vars.

    Raises:
        TypeError: the variable is not text.
    """
    value = VARS[name]
    if not isinstance(value, str):
        message = f"{name} is not text"
        raise TypeError(message)
    return value


def render(template: str) -> str:
    """Render one of the role's templates with the role's own fixed values."""
    source = (ROLE / "templates" / template).read_text(encoding="utf-8")
    # Text files, not HTML: escaping would change what is rendered.
    environment = jinja2.Environment(  # noqa: S701
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    return environment.from_string(source).render(**VARS)


def compose() -> dict[str, object]:
    """Return the rendered compose file as data.

    Raises:
        TypeError: the file is not a mapping.
    """
    loaded: object = yaml.safe_load(render("compose.yml.j2"))
    if not isinstance(loaded, dict):
        message = "the compose file is not a mapping"
        raise TypeError(message)
    return {str(key): value for key, value in loaded.items()}


def mysql_service() -> dict[str, object]:
    """Return the one service of the compose file.

    Raises:
        AssertionError: the file holds a service other than mysql.
        TypeError: the service is not a mapping.
    """
    services = compose()["services"]
    if not isinstance(services, dict) or list(services) != ["mysql"]:
        message = "the compose file must hold the mysql service and no other"
        raise AssertionError(message)
    service = services["mysql"]
    if not isinstance(service, dict):
        message = "the mysql service is not a mapping"
        raise TypeError(message)
    return {str(key): value for key, value in service.items()}


def cnf_settings() -> dict[str, str]:
    """Return the key and value of every setting line of the rendered configuration."""
    settings: dict[str, str] = {}
    for line in render("branchleft.cnf.j2").splitlines():
        match = re.fullmatch(r"([a-z_-]+)\s*=\s*(\S+)", line.strip())
        if match:
            settings[match.group(1).replace("-", "_")] = match.group(2)
    return settings


def task_files() -> dict[str, list[dict[str, object]]]:
    """Return the tasks of each task file of the role.

    Raises:
        TypeError: a task file is not a list.
    """
    files: dict[str, list[dict[str, object]]] = {}
    # main.yml first: the order the role runs its files in.
    for path in sorted(
        (ROLE / "tasks").glob("*.yml"), key=lambda p: (p.name != "main.yml", p.name)
    ):
        loaded: object = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            message = f"{path.name} is not a list"
            raise TypeError(message)
        files[path.name] = [
            {str(key): value for key, value in task.items()}
            for task in loaded
            if isinstance(task, dict)
        ]
    return files


def all_tasks() -> list[dict[str, object]]:
    """Return every task of the role, in file order."""
    return [task for tasks in task_files().values() for task in tasks]


def task_named(fragment: str) -> dict[str, object]:
    """Return the one task whose name contains the fragment.

    Raises:
        AssertionError: there is not exactly one such task.
    """
    found = [task for task in all_tasks() if fragment in str(task.get("name"))]
    if len(found) != 1:
        message = f"expected one task named like {fragment!r}, found {len(found)}"
        raise AssertionError(message)
    return found[0]


def arguments_of(task: dict[str, object]) -> dict[str, object]:
    """Return the arguments a task gives its module."""
    return mapping(task[module_of(task)])


def module_of(task: dict[str, object]) -> str:
    """Return the fully qualified module a task calls.

    Raises:
        AssertionError: the task does not call exactly one builtin module.
    """
    names = [key for key in task if str(key).startswith("ansible.builtin.")]
    if len(names) != 1:
        message = f"task {task.get('name')!r} must call exactly one builtin module"
        raise AssertionError(message)
    return str(names[0])


class ComposeContract(unittest.TestCase):
    """The rendered compose file."""

    def test_the_image_comes_from_the_pin_and_is_never_a_literal(self) -> None:
        self.assertEqual(mysql_service()["image"], "${IMAGE}")

    def test_the_project_name_is_the_stack_name_the_deploy_program_looks_up(self) -> None:
        self.assertEqual(compose()["name"], VARS["db_t1_stack"])

    def test_root_is_created_for_localhost_only(self) -> None:
        # The Percona entrypoint creates root for every host when this is unset.
        environment = mapping(mysql_service()["environment"])
        self.assertEqual(environment.get("MYSQL_ROOT_HOST"), "localhost")

    def test_the_call_home_agent_is_switched_off(self) -> None:
        environment = mapping(mysql_service()["environment"])
        self.assertEqual(str(environment.get("PERCONA_TELEMETRY_DISABLE")), "1")

    def test_the_root_value_comes_from_the_unit_environment_and_fails_closed(self) -> None:
        environment = mapping(mysql_service()["environment"])
        value = str(environment[ROOT_KEY])
        self.assertTrue(value.startswith("${MYSQL_ROOT_PASSWORD:?"), value)
        self.assertNotIn("MYSQL_ROOT_PASSWORD_FILE", environment)

    def test_no_port_is_published_and_the_host_network_is_used(self) -> None:
        service = mysql_service()
        self.assertNotIn("ports", service)
        self.assertNotIn("expose", service)
        self.assertEqual(service["network_mode"], "host")

    def test_the_configuration_is_one_file_over_the_image_option_directory(self) -> None:
        volumes = sequence(mysql_service()["volumes"])
        self.assertIn("./conf.d/branchleft.cnf:/etc/my.cnf.d/branchleft.cnf:ro", volumes)
        # A directory mount would hide the image's own option files.
        self.assertNotIn(
            "/etc/my.cnf.d:", " ".join(str(v) for v in volumes).replace("/etc/my.cnf.d/", "")
        )

    def test_the_data_and_the_socket_are_mounted(self) -> None:
        volumes = sequence(mysql_service()["volumes"])
        self.assertIn("mysql-data:/var/lib/mysql", volumes)
        self.assertIn("./run/mysqld:/var/run/mysqld", volumes)
        self.assertIn("mysql-data", mapping(compose()["volumes"]))

    def test_the_database_gets_time_to_shut_down_cleanly(self) -> None:
        self.assertEqual(mysql_service()["stop_grace_period"], "2m")

    def test_the_health_check_is_a_real_query_that_reads_the_settings_back(self) -> None:
        health = mapping(mysql_service()["healthcheck"])
        test = sequence(health["test"])
        self.assertEqual(test[0], "CMD-SHELL")
        command = str(test[1])
        self.assertNotIn("mysqladmin", command)
        self.assertNotIn("ping", command)
        for needle in (
            "skip_networking = 0",
            f"@@version = '{VARS['db_t1_server_version']}'",
            f"@@global.server_id = {VARS['db_t1_server_id']}",
            "@@global.bind_address = '127.0.0.1'",
            "@@global.gtid_mode = 'ON'",
            "@@global.enforce_gtid_consistency = 'ON'",
            "@@global.log_bin = 1",
            "@@global.binlog_format = 'ROW'",
            "@@global.require_secure_transport = 1",
        ):
            self.assertIn(needle, command)

    def test_the_health_check_never_carries_the_root_value_in_the_file(self) -> None:
        health = mapping(mysql_service()["healthcheck"])
        command = str(sequence(health["test"])[1])
        # Compose turns $$ into $, so the shell in the container expands it.
        self.assertIn('MYSQL_PWD="$$MYSQL_ROOT_PASSWORD"', command)
        self.assertNotIn("${MYSQL_ROOT_PASSWORD", command)
        self.assertNotIn("-p", command.replace("--protocol", ""))

    def test_the_health_check_has_a_start_period_for_the_first_initialisation(self) -> None:
        health = mapping(mysql_service()["healthcheck"])
        self.assertEqual(health["start_period"], "120s")


class ConfigurationContract(unittest.TestCase):
    """The rendered MySQL configuration."""

    def test_the_server_listens_on_loopback_only(self) -> None:
        settings = cnf_settings()
        self.assertEqual(settings["bind_address"], "127.0.0.1")
        self.assertNotIn("0.0.0.0", render("branchleft.cnf.j2"))  # noqa: S104

    def test_the_x_protocol_listener_is_off(self) -> None:
        # It listens on every address whatever bind-address says.
        self.assertEqual(cnf_settings()["mysqlx"], "OFF")

    def test_gtid_mode_and_the_binary_log_are_on_from_the_first_start(self) -> None:
        settings = cnf_settings()
        self.assertEqual(settings["gtid_mode"], "ON")
        self.assertEqual(settings["enforce_gtid_consistency"], "ON")
        self.assertEqual(settings["log_bin"], "mysql-bin")
        self.assertEqual(settings["binlog_format"], "ROW")
        self.assertEqual(settings["sync_binlog"], "1")

    def test_the_server_id_is_the_pinned_one(self) -> None:
        self.assertEqual(cnf_settings()["server_id"], str(VARS["db_t1_server_id"]))

    def test_transport_security_and_the_character_set_match_the_proof(self) -> None:
        settings = cnf_settings()
        self.assertEqual(settings["require_secure_transport"], "ON")
        self.assertEqual(settings["character_set_server"], "utf8mb4")
        self.assertEqual(settings["collation_server"], "utf8mb4_unicode_ci")

    def test_the_socket_is_where_the_bind_mount_and_the_health_check_expect(self) -> None:
        self.assertEqual(cnf_settings()["socket"], "/var/run/mysqld/mysqld.sock")
        health = mapping(mysql_service()["healthcheck"])
        command = str(sequence(health["test"])[1])
        self.assertIn("--socket=/var/run/mysqld/mysqld.sock", command)


class PinsAndNames(unittest.TestCase):
    """The values that must agree with the deploy program and with the other checks."""

    def test_the_stack_name_is_one_the_deploy_program_accepts(self) -> None:
        match = re.search(r'^STACK_NAME = re\.compile\(r"([^"]+)"\)', DEPLOY_SOURCE, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertRegex(text_var("db_t1_stack"), match.group(1) if match else "")

    def test_the_paths_are_the_ones_the_deploy_program_builds(self) -> None:
        stack = text_var("db_t1_stack")
        self.assertIn('CONFIG_DIR = "/etc/branchleft"', DEPLOY_SOURCE)
        self.assertIn('STACK_DIR = "/opt/branchleft"', DEPLOY_SOURCE)
        self.assertEqual(VARS["db_t1_image_env_path"], f"/etc/branchleft/{stack}.image.env")
        self.assertEqual(VARS["db_t1_compose_path"], f"/opt/branchleft/{stack}/compose.yml")
        self.assertEqual(VARS["db_t1_secrets_path"], f"/etc/branchleft/{stack}.env")
        self.assertEqual(VARS["db_t1_unit"], f"branchleft-compose@{stack}.service")

    def test_the_pin_line_is_the_one_the_deploy_program_writes(self) -> None:
        self.assertIn('handle.write(f"IMAGE={image}\\n")', DEPLOY_SOURCE)
        self.assertEqual(VARS["db_t1_image_env_prefix"], "IMAGE=")

    def test_the_deploy_program_path_is_the_installed_wrapper(self) -> None:
        self.assertEqual(VARS["db_t1_deploy_program"], "/usr/local/sbin/branchleft-deploy")

    def test_the_version_is_the_one_the_proof_measured(self) -> None:
        self.assertEqual(VARS["db_t1_server_version"], "8.0.46-37")

    def test_the_default_deploys_nothing(self) -> None:
        self.assertEqual(DEFAULTS, {"db_t1_image": ""})

    def test_the_other_compose_names_cover_the_files_compose_also_reads(self) -> None:
        names = sequence(VARS["db_t1_other_compose_names"])
        for name in (
            "compose.yaml",
            "docker-compose.yml",
            "compose.override.yml",
            "docker-compose.override.yaml",
            ".env",
        ):
            self.assertIn(name, names)

    def test_no_path_of_this_role_is_a_path_of_the_other_database_role(self) -> None:
        other = yaml.safe_load(
            (ROLE.parent / "db1_stack" / "vars" / "main.yml").read_text(encoding="utf-8")
        )
        mine = {
            v for k, v in VARS.items() if k.endswith(("_path", "_directory")) and isinstance(v, str)
        }
        theirs = {v for v in other.values() if isinstance(v, str) and v.startswith("/")}
        shared = {"/etc/branchleft", "/opt/branchleft", "/run/systemd/system"}
        self.assertEqual((mine & theirs) - shared, set())


class ImagePattern(unittest.TestCase):
    """The shape of the one input."""

    def accepts(self, image: str) -> bool:
        return re.match(text_var("db_t1_image_pattern"), image) is not None

    def test_a_digest_in_the_organisation_registry_is_accepted(self) -> None:
        self.assertTrue(self.accepts(GOOD_IMAGE))
        self.assertTrue(self.accepts(f"ghcr.io/branchleft/a/b-c.d@sha256:{DIGEST}"))

    def test_everything_else_is_refused(self) -> None:
        for image in (
            "ghcr.io/branchleft/percona-server:8.0",
            f"ghcr.io/branchleft/percona-server:8.0@sha256:{DIGEST}",
            f"percona/percona-server@sha256:{DIGEST}",
            f"docker.io/branchleft/percona-server@sha256:{DIGEST}",
            f"ghcr.io/other/percona-server@sha256:{DIGEST}",
            f"ghcr.io/branchleft/Percona@sha256:{DIGEST}",
            f"ghcr.io/branchleft/percona-server@sha256:{DIGEST[:-1]}",
            f"ghcr.io/branchleft/percona-server@sha256:{DIGEST.upper()}",
            f"ghcr.io/branchleft/percona-server@sha256:{DIGEST}\n",
            f"ghcr.io/branchleft/percona-server@sha256:{DIGEST} x",
            f"ghcr.io/branchleft/../x@sha256:{DIGEST}",
        ):
            with self.subTest(image=image):
                self.assertFalse(self.accepts(image))


class SecretFileShape(unittest.TestCase):
    """The two line patterns, applied to one line at a time the way lineinfile applies them."""

    good = ROOT_KEY + "=" + "A1b2" * 8

    def expected(self, line: str) -> bool:
        return re.search(text_var("db_t1_secret_line_pattern"), line) is not None

    def stray(self, line: str) -> bool:
        return re.search(text_var("db_t1_secret_stray_pattern"), line) is not None

    def test_the_expected_line_is_accepted_and_is_not_stray(self) -> None:
        for line in (self.good, self.good + "\n", ROOT_KEY + "=" + "z" * 128 + "\n"):
            with self.subTest(line=line):
                self.assertTrue(self.expected(line))
                self.assertFalse(self.stray(line))

    def test_a_line_that_would_break_the_first_start_is_not_expected(self) -> None:
        for line in (
            ROOT_KEY + "=" + "a" * 31,
            ROOT_KEY + "=" + "a" * 129,
            ROOT_KEY + "=" + "a" * 31 + "'",
            ROOT_KEY + '="' + "a" * 32 + '"',
            ROOT_KEY + "=" + "a" * 31 + "$",
            ROOT_KEY + "=" + "a" * 31 + " ",
            ROOT_KEY + "=" + "a" * 32 + "\r\n",
            " " + self.good,
            "export " + self.good,
        ):
            with self.subTest(line=line):
                self.assertFalse(self.expected(line))
                self.assertTrue(self.stray(line))

    def test_a_line_that_could_override_the_pin_is_stray(self) -> None:
        for line in (
            f"IMAGE=ghcr.io/branchleft/x@sha256:{DIGEST}\n",
            f"  IMAGE=ghcr.io/branchleft/x@sha256:{DIGEST}\n",
            "COMPOSE_FILE=other.yml\n",
            "# a comment\n",
        ):
            with self.subTest(line=line):
                self.assertTrue(self.stray(line))

    def test_a_blank_line_is_not_stray(self) -> None:
        for line in ("\n", "   \n", ""):
            with self.subTest(line=line):
                self.assertFalse(self.stray(line))


class TaskContract(unittest.TestCase):
    """The tasks: what they may call, in what order, and under what condition."""

    def test_the_role_installs_nothing_and_runs_no_shell_and_no_docker(self) -> None:
        allowed = {
            "ansible.builtin.assert",
            "ansible.builtin.command",
            "ansible.builtin.file",
            "ansible.builtin.include_tasks",
            "ansible.builtin.lineinfile",
            "ansible.builtin.set_fact",
            "ansible.builtin.slurp",
            "ansible.builtin.stat",
            "ansible.builtin.systemd_service",
            "ansible.builtin.template",
        }
        self.assertEqual({module_of(task) for task in all_tasks()} - allowed, set())
        text = yaml.safe_dump(all_tasks())
        for word in ("ansible.builtin.shell", "docker compose", "sudo", "become"):
            self.assertNotIn(word, text)

    def test_the_only_command_is_the_deploy_and_it_reports_a_change_in_check_mode(self) -> None:
        commands = [task for task in all_tasks() if module_of(task) == "ansible.builtin.command"]
        self.assertEqual(len(commands), 1)
        (deploy,) = commands
        self.assertIs(deploy["changed_when"], True)
        self.assertNotIn("check_mode", deploy)
        self.assertEqual(
            deploy["ansible.builtin.command"],
            {
                "argv": [
                    "{{ db_t1_deploy_program }}",
                    "{{ db_t1_stack }}",
                    "{{ db_t1_image }}",
                ]
            },
        )

    def test_the_pin_is_compared_with_a_real_line_break_not_a_backslash_and_n(self) -> None:
        # Inside an Ansible expression a backslash and n are two characters, so a pin that
        # was written correctly would never match and the role would refuse its own pin.
        for path in sorted((ROLE / "tasks").glob("*.yml")):
            self.assertNotIn("\\n", path.read_text(encoding="utf-8"), path.name)
        self.assertEqual(VARS["db_t1_line_end"], "\n")
        fact = task_named("Work out what the pin and the data directory say")
        self.assertIn("db_t1_image_env_prefix ~ db_t1_image ~ db_t1_line_end", str(fact))

    def test_the_deploy_runs_only_when_an_image_is_given_and_no_pin_exists(self) -> None:
        deploy = task_named("Pin the image to the stack and start it")
        self.assertEqual(deploy["when"], "db_t1_deploy_needed | bool")
        fact = task_named("Work out whether the image is to be deployed")
        text = str(fact["ansible.builtin.set_fact"])
        self.assertIn('db_t1_image != ""', text)
        self.assertIn("not (db_t1_pin_present | bool)", text)

    def test_the_refusals_come_before_the_deploy(self) -> None:
        names = [str(task.get("name")) for task in task_files()["_pin.yml"]]
        deploy = next(i for i, n in enumerate(names) if n.startswith("Pin the image to the stack"))
        for fragment in (
            "Refuse to replace the image of a database that was already deployed",
            "Refuse to deploy over a data directory that has no pin",
            "Refuse a root file that is absent",
            "Refuse a root file whose lines are not the one expected line",
        ):
            index = next(i for i, n in enumerate(names) if n.startswith(fragment))
            self.assertLess(index, deploy, fragment)

    def test_a_pin_that_differs_is_refused_not_replaced(self) -> None:
        refusal = task_named("Refuse to replace the image of a database that was already deployed")
        self.assertEqual(
            arguments_of(refusal)["that"],
            ["db_t1_image == '' or not (db_t1_pin_present | bool) or (db_t1_pin_matches | bool)"],
        )

    def test_initialised_data_without_a_pin_is_refused(self) -> None:
        refusal = task_named("Refuse to deploy over a data directory that has no pin")
        expected = (
            "db_t1_image == '' or (db_t1_pin_present | bool) or not (db_t1_data_initialised | bool)"
        )
        self.assertEqual(arguments_of(refusal)["that"], [expected])

    def test_the_role_never_writes_the_pin_or_the_root_file(self) -> None:
        protected = {VARS["db_t1_image_env_path"], VARS["db_t1_secrets_path"]}
        variables = {"{{ db_t1_image_env_path }}", "{{ db_t1_secrets_path }}"}
        for task in all_tasks():
            module = module_of(task)
            arguments = task[module]
            if not isinstance(arguments, dict):
                continue
            target = arguments.get("dest", arguments.get("path"))
            if module in {"ansible.builtin.template", "ansible.builtin.file"}:
                self.assertNotIn(target, protected | variables, task["name"])
            if module == "ansible.builtin.lineinfile":
                self.assertEqual(arguments["state"], "absent", task["name"])
                self.assertIs(task["check_mode"], True, task["name"])

    def test_every_task_that_looks_into_the_root_file_hides_its_output_and_diff(self) -> None:
        for task in all_tasks():
            if module_of(task) != "ansible.builtin.lineinfile":
                continue
            self.assertIs(task["no_log"], True, task["name"])
            self.assertIs(task["diff"], False, task["name"])

    def test_the_root_file_is_only_looked_at_when_a_deploy_is_due(self) -> None:
        for task in all_tasks():
            text = str(task)
            if "db_t1_secrets_" in text and "set_fact" not in text:
                self.assertEqual(task.get("when"), "db_t1_deploy_needed | bool", task["name"])

    def test_the_stat_of_the_root_file_does_not_follow_a_link(self) -> None:
        task = task_named("Look at the root file the unit reads")
        self.assertIs(arguments_of(task)["follow"], False)
        self.assertIs(arguments_of(task)["get_checksum"], False)

    def test_the_root_file_must_be_closed_and_owned_by_root(self) -> None:
        task = task_named("Refuse a root file that is absent")
        that = sequence(arguments_of(task)["that"])
        for condition in (
            "db_t1_secrets_stat.stat.isreg",
            "db_t1_secrets_stat.stat.uid == 0",
            "db_t1_secrets_stat.stat.gid == 0",
            "db_t1_secrets_stat.stat.mode == db_t1_secret_file_mode",
        ):
            self.assertIn(condition, that)
        self.assertEqual(VARS["db_t1_secret_file_mode"], "0600")

    def test_the_compose_file_is_rendered_with_its_diff_hidden(self) -> None:
        task = task_named("Render the compose file the deploy program reads")
        self.assertIs(task["diff"], False)

    def test_a_second_compose_file_is_refused(self) -> None:
        task = task_named("Refuse a second compose file or a compose environment file")
        self.assertEqual(
            arguments_of(task)["that"],
            ["db_t1_other_compose_files.results | selectattr('stat.exists') | list | length == 0"],
        )

    def test_the_socket_directory_belongs_to_the_container_user(self) -> None:
        task = task_named("Create the socket directory")
        arguments = arguments_of(task)
        self.assertEqual(arguments["owner"], "{{ db_t1_container_uid }}")
        self.assertEqual(arguments["mode"], "0755")
        self.assertEqual(VARS["db_t1_container_uid"], 1001)

    def test_the_unit_is_enabled_and_not_started(self) -> None:
        task = task_named("Enable the stack's unit")
        arguments = arguments_of(task)
        self.assertEqual(set(arguments), {"name", "enabled"})
        self.assertIs(arguments["enabled"], True)

    def test_the_image_input_is_checked_before_anything_changes(self) -> None:
        first = all_tasks()[0]
        self.assertIn("db_t1_image_pattern", str(first))


if __name__ == "__main__":
    unittest.main()
