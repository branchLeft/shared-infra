"""The role's contract: the one key line, the one sudoers rule, the inputs, and the pins.

The program's own behaviour is `test_tenant_db_entry.py`, and the forced command as a real sshd
serves it is the Molecule scenario's. This file holds what joins them: that the line a client's
key is installed with, the rule sudo reads and the path the program is installed at name the same
program and nothing else, and that the values the program copies from other places still match
them. The naming test fetches ghost-platform's naming.py at the commit the database roles pin and
needs the network, as `db1_grants`' tests do.
"""

from __future__ import annotations

import hashlib
import http.client
import importlib
import re
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from types import ModuleType

import jinja2
import tenant_db_entry as entry
import yaml

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
REPOSITORY = ROLES.parents[1]


def as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError(f"not a mapping: {value!r}")
    return {str(key): item for key, item in value.items()}


def as_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AssertionError(f"not a list: {value!r}")
    return value


def as_str(value: object) -> str:
    if not isinstance(value, str):
        raise AssertionError(f"not a string: {value!r}")
    return value


def load(path: Path) -> object:
    parsed: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parsed


VARS = as_dict(load(ROLE / "vars" / "main.yml"))
TASKS = [as_dict(item) for item in as_list(load(ROLE / "tasks" / "main.yml"))]
INPUT_TASKS = [as_dict(item) for item in as_list(load(ROLE / "tasks" / "_inputs.yml"))]
SPECS = as_dict(load(ROLE / "meta" / "argument_specs.yml"))
META = as_dict(load(ROLE / "meta" / "main.yml"))


def var(name: str) -> str:
    return as_str(VARS[name])


# A real-shaped ed25519 public key, made for this test and never used anywhere.
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "EXAMPLE" * 6 + "0"
ADDRESS = "192.0.2.10"


def render(name: str, **context: str) -> str:
    environment = jinja2.Environment(  # noqa: S701 - plain text files, not HTML
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    source = (ROLE / "templates" / name).read_text(encoding="utf-8")
    values: dict[str, object] = {
        **VARS,
        "db_t1_tenant_entry_controller_key": KEY,
        "db_t1_tenant_entry_controller_address": ADDRESS,
        **context,
    }
    return environment.from_string(source).render(**values)


def task(name_part: str) -> dict[str, object]:
    found = [item for item in TASKS if name_part in str(item.get("name", ""))]
    if len(found) != 1:
        raise AssertionError(f"{len(found)} tasks name {name_part!r}")
    return found[0]


class KeyLineTests(unittest.TestCase):
    def line(self) -> str:
        return render("authorized_keys.j2")

    def test_the_file_is_one_line_with_one_key_and_a_line_break(self) -> None:
        text = self.line()
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(len(text.splitlines()), 1)

    def test_the_line_is_exactly_the_options_the_key_may_have(self) -> None:
        self.assertEqual(
            self.line(),
            'restrict,from="192.0.2.10",'
            'command="/usr/bin/sudo -n /usr/local/sbin/branchleft-tenant-db-entry" '
            f"{KEY}\n",
        )

    def test_it_adds_back_nothing_restrict_takes_away(self) -> None:
        options = self.line().split(" ssh-ed25519 ")[0]
        for forbidden in [
            "pty",
            "port-forwarding",
            "permitopen",
            "permitlisten",
            "agent",
            "X11",
            "user-rc",
            "environment",
            "tunnel",
            "no-",
            "cert-authority",
        ]:
            self.assertNotIn(forbidden, options, forbidden)

    def test_the_command_option_names_the_program_the_role_installs_and_the_rule_allows(
        self,
    ) -> None:
        program = var("db_t1_tenant_entry_program_path")
        self.assertIn(f"{var('db_t1_tenant_entry_sudo_path')} -n {program}", self.line())
        copied = as_dict(task("Install the forced-command program")["ansible.builtin.copy"])
        self.assertEqual(copied["dest"], "{{ db_t1_tenant_entry_program_path }}")
        self.assertIn(f'NOPASSWD: {program} ""', render("sudoers.j2"))

    def test_the_key_is_the_last_thing_the_role_installs(self) -> None:
        self.assertIn("Install the controller's key", as_str(TASKS[-1]["name"]))

    def test_the_key_file_is_root_owned_and_not_writable_by_the_account(self) -> None:
        template = as_dict(TASKS[-1]["ansible.builtin.template"])
        self.assertEqual(template["owner"], "root")
        self.assertEqual(template["mode"], "0640")
        self.assertEqual(template["dest"], "{{ db_t1_tenant_entry_authorized_keys_path }}")

    def test_the_key_task_hides_its_result_and_its_diff(self) -> None:
        self.assertIs(TASKS[-1]["no_log"], True)
        self.assertIs(TASKS[-1]["diff"], False)


class SudoersTests(unittest.TestCase):
    def rules(self) -> list[str]:
        return [
            line
            for line in render("sudoers.j2").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def test_two_lines_and_no_more(self) -> None:
        self.assertEqual(
            self.rules(),
            [
                'Defaults:tenantdb env_keep += "SSH_ORIGINAL_COMMAND"',
                'tenantdb ALL=(root) NOPASSWD: /usr/local/sbin/branchleft-tenant-db-entry ""',
            ],
        )

    def test_the_rule_names_one_path_with_no_argument_and_no_wildcard(self) -> None:
        rule = self.rules()[1]
        self.assertTrue(rule.endswith(' ""'))
        for forbidden in ["*", "ALL,", ", ", "SETENV", "ALL=(ALL", "NOPASSWD: ALL", "!"]:
            self.assertNotIn(forbidden, rule)

    def test_only_the_request_variable_is_kept_through_sudo(self) -> None:
        kept = [line for line in self.rules() if line.startswith("Defaults")]
        self.assertEqual(len(kept), 1)
        self.assertEqual(re.findall(r'"([^"]+)"', kept[0]), ["SSH_ORIGINAL_COMMAND"])

    def test_the_file_is_checked_with_visudo_and_is_root_only(self) -> None:
        item = as_dict(task("Let the account run the program as root")["ansible.builtin.template"])
        self.assertEqual(item["validate"], "/usr/sbin/visudo -csf %s")
        self.assertEqual((item["owner"], item["group"], item["mode"]), ("root", "root", "0440"))
        self.assertNotIn(".", Path(var("db_t1_tenant_entry_sudoers_path")).name)


class AccountAndFilesTests(unittest.TestCase):
    def test_the_account_has_no_home_made_for_it_and_no_usable_password(self) -> None:
        user = as_dict(
            task("Make the account the controller's key logs in as")["ansible.builtin.user"]
        )
        self.assertIs(user["create_home"], False)
        self.assertEqual(user["password"], "*")
        self.assertIs(user["system"], True)

    def test_the_home_and_ssh_directory_are_root_s_and_not_the_account_s(self) -> None:
        directories = as_dict(
            task("Make the account's home and .ssh directory")["ansible.builtin.file"]
        )
        self.assertEqual((directories["owner"], directories["group"]), ("root", "root"))
        self.assertEqual(directories["mode"], "0755")

    def test_the_program_is_root_s_and_is_not_writable_by_anyone_else(self) -> None:
        program = as_dict(task("Install the forced-command program")["ansible.builtin.copy"])
        self.assertEqual(
            (program["owner"], program["group"], program["mode"]), ("root", "root", "0755")
        )
        self.assertTrue((ROLE / "files" / var("db_t1_tenant_entry_program_source")).is_file())

    def test_the_order_is_inputs_account_directories_program_rule_key(self) -> None:
        names = [str(item["name"]) for item in TASKS]
        order = [
            "Refuse an input",
            "Make the account",
            "Make the account's home",
            "Install the forced-command program",
            "Let the account run",
            "Install the controller's key",
        ]
        positions = [
            next(i for i, name in enumerate(names) if name.startswith(part)) for part in order
        ]
        self.assertEqual(positions, sorted(positions))

    def test_no_task_runs_a_command_or_a_shell_or_a_module_beyond_builtin(self) -> None:
        for item in [*TASKS, *INPUT_TASKS]:
            modules = [key for key in item if key.startswith(("ansible.", "community."))]
            self.assertEqual(len(modules), 1, item["name"])
            self.assertTrue(modules[0].startswith("ansible.builtin."), modules[0])
            self.assertNotIn(
                modules[0],
                {"ansible.builtin.command", "ansible.builtin.shell", "ansible.builtin.raw"},
            )

    def test_the_role_reads_no_root_credential_and_names_no_secret_file(self) -> None:
        text = "".join(
            path.read_text(encoding="utf-8")
            for path in ROLE.rglob("*.yml")
            if "molecule" not in path.parts
        )
        for needle in ["dbt1.env", "MYSQL_ROOT_PASSWORD", "db.env", "lookup("]:
            self.assertNotIn(needle, text)

    def test_the_role_imports_no_other_role(self) -> None:
        self.assertNotIn("dependencies", META)
        text = "".join(path.read_text(encoding="utf-8") for path in (ROLE / "tasks").glob("*.yml"))
        self.assertNotIn("include_role", text)
        self.assertNotIn("import_role", text)

    def test_the_account_name_is_one_value_in_every_file(self) -> None:
        account = var("db_t1_tenant_entry_account")
        self.assertEqual(Path(var("db_t1_tenant_entry_home")).name, account)
        self.assertTrue(
            var("db_t1_tenant_entry_authorized_keys_path").startswith(
                var("db_t1_tenant_entry_home")
            )
        )
        self.assertIn(f"Defaults:{account} ", render("sudoers.j2"))


class InputTests(unittest.TestCase):
    key = re.compile(var("db_t1_tenant_entry_key_pattern"))
    address = re.compile(var("db_t1_tenant_entry_address_pattern"))

    def test_the_two_inputs_are_required_and_have_no_default(self) -> None:
        options = as_dict(as_dict(as_dict(SPECS["argument_specs"])["main"])["options"])
        self.assertEqual(
            set(options),
            {"db_t1_tenant_entry_controller_key", "db_t1_tenant_entry_controller_address"},
        )
        for name, raw in options.items():
            option = as_dict(raw)
            self.assertIs(option["required"], True, name)
            self.assertNotIn("default", option, name)
        self.assertEqual(
            (ROLE / "defaults" / "main.yml")
            .read_text(encoding="utf-8")
            .count("db_t1_tenant_entry_"),
            0,
        )
        self.assertIs(as_dict(options["db_t1_tenant_entry_controller_key"])["no_log"], True)

    def test_one_plain_ed25519_key_is_accepted(self) -> None:
        self.assertIsNotNone(self.key.match(KEY))

    def test_a_key_with_a_comment_an_option_a_second_line_or_another_type_is_refused(self) -> None:
        body = KEY.split(" ")[1]
        for bad in [
            f"{KEY} root@example",
            f"{KEY}\n",
            f"{KEY}\n{KEY}",
            f"restrict {KEY}",
            f'command="id" {KEY}',
            f" {KEY}",
            f"ssh-rsa {body}",
            f"ssh-ed25519 {body[:-1]}",
            f"ssh-ed25519 {body}A",
            f"ssh-ed25519 {body} ",
            f"ssh-ed25519\t{body}",
            "",
            "ssh-ed25519",
        ]:
            with self.subTest(key=bad[:60]):
                self.assertIsNone(self.key.match(bad))

    def test_one_ipv4_address_is_accepted(self) -> None:
        for good in ["192.0.2.10", "10.20.1.201", "255.255.255.255", "1.2.3.4"]:
            with self.subTest(address=good):
                self.assertIsNotNone(self.address.match(good))

    def test_a_wildcard_a_mask_a_list_a_name_or_a_padded_octet_is_refused(self) -> None:
        for bad in [
            "10.20.1.%",
            "10.20.1.*",
            "10.20.1.0/24",
            "10.20.1.1,10.20.1.2",
            "10.20.1.1 10.20.1.2",
            "10.20.1",
            "10.20.1.1.1",
            "010.20.1.1",
            "10.20.1.256",
            "10.20.1.1\n",
            " 10.20.1.1",
            "example.org",
            "::1",
            "!10.20.1.1",
            '10.20.1.1",command="id',
            "",
        ]:
            with self.subTest(address=bad):
                self.assertIsNone(self.address.match(bad))

    def test_the_checks_name_the_input_and_print_no_value(self) -> None:
        for item in INPUT_TASKS:
            message = as_str(as_dict(item["ansible.builtin.assert"])["fail_msg"])
            self.assertRegex(message, r"db_t1_tenant_entry_controller_(key|address)")
            self.assertNotIn("{{", message)


class PinTests(unittest.TestCase):
    def test_the_account_host_is_the_application_host_s_address_in_the_address_plan(self) -> None:
        plan = (REPOSITORY / "hetzner-host" / "addressPlan.ts").read_text(encoding="utf-8")
        block = re.search(r"TENANTS_HOST_IPS = \{(.*?)\}", plan, re.DOTALL)
        assert block is not None
        addresses = dict(re.findall(r"(\w+): '([0-9.]+)'", block.group(1)))
        self.assertEqual(entry.TENANT_USER_HOST, addresses["appT1"])

    def test_the_container_is_the_one_the_db_t1_role_renders(self) -> None:
        stack = yaml.safe_load((ROLES / "db_t1" / "vars" / "main.yml").read_text(encoding="utf-8"))[
            "db_t1_stack"
        ]
        self.assertEqual(entry.COMPOSE_PROJECT, stack)
        compose = (ROLES / "db_t1" / "templates" / "compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn(f"\n  {entry.COMPOSE_SERVICE}:\n    image: ${{IMAGE}}", compose)
        self.assertIn("MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD", compose)
        self.assertIn("./run/mysqld:/var/run/mysqld", compose)
        self.assertIn("--socket=/var/run/mysqld/mysqld.sock", entry.CLIENT_SCRIPT)
        self.assertIn("$MYSQL_ROOT_PASSWORD", entry.CLIENT_SCRIPT)

    def test_docker_is_at_the_path_the_deploy_tooling_and_the_baseline_install_it(self) -> None:
        self.assertEqual(entry.DOCKER, "/usr/bin/docker")

    def test_the_program_runs_under_the_interpreter_debian_13_ships(self) -> None:
        first = (
            (ROLE / "files" / var("db_t1_tenant_entry_program_source"))
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        self.assertEqual(first, "#!/usr/bin/python3")


FETCH_ATTEMPTS = 3
FETCH_BACKOFF_SECONDS = 2


def fetch(url: str) -> bytes:
    """The bytes at a fixed URL; a transport error is retried, a digest mismatch never is."""
    for attempt in range(1, FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - a fixed https URL
                body: bytes = response.read()
                return body
        except (OSError, http.client.HTTPException):
            time.sleep(FETCH_BACKOFF_SECONDS * attempt)
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - a fixed https URL
        final: bytes = response.read()
        return final


def pinned_programs() -> tuple[ModuleType, ModuleType]:
    """naming.py and provision_tenant_db.py at the pinned commit, held to their digests."""
    pins = yaml.safe_load(
        (ROLES / "db1_backup_timers" / "vars" / "main.yml").read_text(encoding="utf-8")
    )
    commit = pins["db1_backup_timers_ghost_commit"]
    scratch = Path(tempfile.mkdtemp(prefix="tenant-entry-pinned-"))
    for name in ("naming.py", "provision_tenant_db.py"):
        digest = pins["db1_backup_timers_program_sha256"][name]
        body = fetch(
            f"https://raw.githubusercontent.com/branchLeft/ghost-platform/{commit}/db/provision/{name}"
        )
        if hashlib.sha256(body).hexdigest() != digest:
            raise AssertionError(f"{name} fetched at the pinned commit is not the pinned bytes")
        (scratch / name).write_bytes(body)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(scratch))
    return importlib.import_module("naming"), importlib.import_module("provision_tenant_db")


class NamingTests(unittest.TestCase):
    """The tenant-name rule and the grant escape are copied here and held to ghost-platform's."""

    naming: ModuleType
    provision: ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        cls.naming, cls.provision = pinned_programs()

    def test_the_constants_are_the_same(self) -> None:
        self.assertEqual(entry.TENANT_NAME_PATTERN.pattern, self.naming.TENANT_NAME_PATTERN.pattern)
        self.assertEqual(entry.TENANT_DB_PREFIX, self.naming.TENANT_DB_PREFIX)
        self.assertEqual(entry.MAX_TENANT_NAME_LENGTH, self.naming.MAX_TENANT_NAME_LENGTH)
        self.assertEqual(
            entry.MAX_MYSQL_ACCOUNT_NAME_LENGTH, self.naming.MAX_MYSQL_ACCOUNT_NAME_LENGTH
        )

    def test_the_same_names_are_valid_and_each_gets_the_same_database_name(self) -> None:
        candidates = [
            "a",
            "blog",
            "my-blog",
            "a1",
            "a-1",
            "a--b",
            "a" * 26,
            "a" * 27,
            "Blog",
            "1a",
            "-a",
            "a-",
            "a_b",
            "",
            "a b",
            "\u00e9",
            "a\n",
        ]
        for name in candidates:
            with self.subTest(name=name):
                try:
                    self.naming.validate_tenant_name(name)
                except self.naming.InvalidTenantName:
                    with self.assertRaises(entry.RefusalError):
                        entry.parse_request(f"create-tenant-db {name}")
                    continue
                self.assertEqual(entry.parse_request(f"create-tenant-db {name}"), name)
                expected = self.naming.database_and_user_name(self.naming.sql_identifier(name))
                self.assertEqual(entry.database_name(name), expected)

    def test_the_grant_escape_is_the_same(self) -> None:
        for database in ["ghost_a_b", "ghost_a", "ghost_a%b", "ghost_a\\b", "ghost_a__b"]:
            with self.subTest(database=database):
                self.assertEqual(
                    entry.grant_pattern(database), self.provision.grant_database_pattern(database)
                )


if __name__ == "__main__":
    unittest.main()
