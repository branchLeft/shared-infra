"""Unit tests for the db1_grants role's pins, its derived names and its secret handling.

The role runs a pinned program from another repository and derives, in Jinja, the
names and the escaped grant target that program uses. These tests hold the role to
that program: the pins are the digests of the fixtures byte for byte, the derived
account and grant target are the program's own functions' answers over a table that
includes the characters the escape exists for, and the slug rule is the program's
pattern. They also read the role's tasks and fail when a task that handles a secret
does not hide its log and its diff, and when a work-item reference or an absolute
home path crept into a shipped file.

Run with the Python of the virtual environment that holds the pinned tools (it
brings Jinja2 and PyYAML), from the repository root:

    .venv/bin/python -m unittest discover -b -s ansible/roles/db1_grants/tests/unit -p "test_*.py"

One test reads the vars of the role that delivers the dump programs and fails while
that role is not in the tree: the digests of the two files both roles pin must be
equal, and a test that skipped when the other role was missing would pass on the
day it proved nothing.
"""

import ast
import hashlib
import importlib
import json
import re
import sys
import unittest
from pathlib import Path

import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
FIXTURES = ROLE / "molecule" / "default" / "files" / "fixtures"
TASKS = ROLE / "tasks"
VARS = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
SIBLING_VARS = ROLES / "db1_backup_timers" / "vars" / "main.yml"

sys.path.insert(0, str(FIXTURES))
naming = importlib.import_module("naming")
provision = importlib.import_module("provision_tenant_db")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(expression: str, **context: object) -> str:
    return jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(expression).render(**context)


def main_tasks() -> list[dict]:
    return yaml.safe_load((TASKS / "main.yml").read_text(encoding="utf-8"))


def walk(tasks: list[dict]):
    """Yield every task, descending into block, rescue and always."""
    for task in tasks:
        yield task
        for key in ("block", "rescue", "always"):
            if key in task:
                yield from walk(task[key])


def all_tasks() -> list[tuple[str, dict]]:
    found = []
    for path in sorted(TASKS.glob("*.yml")):
        for task in walk(yaml.safe_load(path.read_text(encoding="utf-8"))):
            found.append((path.name, task))
    return found


class PinTests(unittest.TestCase):
    def test_every_fixture_is_the_pinned_program_byte_for_byte(self) -> None:
        for name, digest in VARS["db1_grants_program_sha256"].items():
            self.assertEqual(sha256(FIXTURES / name), digest, name)

    def test_the_pins_are_full_digests_and_a_full_commit(self) -> None:
        for name, digest in VARS["db1_grants_program_sha256"].items():
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)
        self.assertRegex(VARS["db1_grants_source_commit"], r"^[0-9a-f]{40}$")

    def test_the_staged_files_are_the_program_and_the_module_it_imports(self) -> None:
        self.assertEqual(sorted(VARS["db1_grants_staged_files"]), ["naming.py", "provision_tenant_db.py"])
        imports = re.findall(r"^from (\w+) import", (FIXTURES / "provision_tenant_db.py").read_text(), re.MULTILINE)
        local = [name for name in imports if (FIXTURES / f"{name}.py").exists()]
        self.assertEqual(local, ["naming"])

    def test_the_fixtures_hold_no_other_python_file(self) -> None:
        self.assertEqual(sorted(p.name for p in FIXTURES.glob("*.py")), ["dump_nightly.py", "naming.py", "provision_tenant_db.py"])

    def test_the_role_that_delivers_the_dump_programs_pins_the_same_bytes(self) -> None:
        self.assertTrue(
            SIBLING_VARS.is_file(),
            "ansible/roles/db1_backup_timers is not in the tree: this role is applied after it, and its digests are "
            "what this test compares with. Merge that role first.",
        )
        theirs = yaml.safe_load(SIBLING_VARS.read_text(encoding="utf-8"))["db1_backup_timers_program_sha256"]
        ours = VARS["db1_grants_program_sha256"]
        for name in ("naming.py", "dump_nightly.py"):
            self.assertEqual(ours[name], theirs[name], name)
        # provision_tenant_db.py has one home here; if the other role ever pins it too, the two must agree.
        if "provision_tenant_db.py" in theirs:
            self.assertEqual(ours["provision_tenant_db.py"], theirs["provision_tenant_db.py"])
        self.assertEqual(VARS["db1_grants_source_commit"], yaml.safe_load(SIBLING_VARS.read_text())["db1_backup_timers_ghost_commit"])


class ProgramRuleTests(unittest.TestCase):
    """The role's fixed values are the pinned program's own."""

    def test_the_tenant_host_is_the_programs(self) -> None:
        self.assertEqual(VARS["db1_grants_tenant_host"], naming.TENANT_USER_HOST)

    def test_the_prefix_and_the_length_limit_are_the_programs(self) -> None:
        self.assertEqual(VARS["db1_grants_tenant_prefix"], naming.TENANT_DB_PREFIX)
        self.assertEqual(VARS["db1_grants_slug_max_length"], naming.MAX_TENANT_NAME_LENGTH)

    def test_the_slug_pattern_is_the_programs(self) -> None:
        self.assertEqual(VARS["db1_grants_slug_pattern"], naming.TENANT_NAME_PATTERN.pattern)

    def test_the_connection_limit_is_the_programs_default(self) -> None:
        self.assertEqual(VARS["db1_grants_max_user_connections"], provision.DEFAULT_MAX_USER_CONNECTIONS)

    def test_the_slug_rule_agrees_with_the_program_over_a_table(self) -> None:
        pattern = re.compile(VARS["db1_grants_slug_pattern"])
        limit = VARS["db1_grants_slug_max_length"]
        table = [
            "blog", "second-site", "a", "ab", "a-b", "a1", "a-1", "x" * 26, "x" * 27, "-a", "a-", "1a", "A", "a_b", "a b",
            "a'b", "a`b", "a%b", "a\\b", "", "blog\n", "blog ", "a--b", "é",
        ]  # fmt: skip
        for slug in table:
            try:
                naming.validate_tenant_name(slug)
                program_accepts = True
            except naming.InvalidTenantName:
                program_accepts = False
            role_accepts = pattern.match(slug) is not None and len(slug) <= limit
            self.assertEqual(role_accepts, program_accepts, repr(slug))

    def test_the_ipv4_pattern_accepts_an_address_and_nothing_wider(self) -> None:
        pattern = re.compile(VARS["db1_grants_ipv4_pattern"])
        for good in ("192.0.2.50", "10.20.1.50", "0.0.0.0", "255.255.255.255"):
            self.assertIsNotNone(pattern.match(good), good)
        for bad in ("192.0.2.%", "192.0.2.", "192.0.2", "192.0.2.256", "192.0.2.50\n", " 192.0.2.50", "ops1.example.invalid", "%", "", "192.0.2.50/24", "01.0.2.50"):
            self.assertIsNone(pattern.match(bad), repr(bad))

    def test_the_password_pattern_is_closed_to_what_ends_a_literal(self) -> None:
        pattern = re.compile(VARS["db1_grants_password_pattern"])
        good = "A" * 20
        self.assertIsNotNone(pattern.match(good))
        self.assertIsNotNone(pattern.match("aZ09._~-" * 3))
        for bad in (good + "\n", good[:19], good + "'", good + "\\", good + " ", good + ";", "'" + good, good + "\r", good + "$"):
            self.assertIsNone(pattern.match(bad), repr(bad))


class GrantSetTests(unittest.TestCase):
    """The two backup accounts hold exactly the approved global privileges."""

    def test_the_dump_account_holds_exactly_the_approved_set(self) -> None:
        self.assertEqual(
            sorted(VARS["db1_grants_backup_privileges"]),
            sorted(["SELECT", "PROCESS", "LOCK TABLES", "REPLICATION CLIENT", "SHOW VIEW", "EVENT", "TRIGGER", "BACKUP_ADMIN"]),
        )

    def test_the_ops1_account_holds_exactly_the_approved_set(self) -> None:
        self.assertEqual(
            sorted(VARS["db1_grants_ops1_privileges"]),
            sorted(["SELECT", "SHOW VIEW", "TRIGGER", "LOCK TABLES", "BACKUP_ADMIN"]),
        )

    def test_neither_set_holds_a_privilege_that_would_widen_the_account(self) -> None:
        for name in ("db1_grants_backup_privileges", "db1_grants_ops1_privileges"):
            held = VARS[name]
            self.assertEqual(len(held), len(set(held)), name)
            for widening in ("ALL PRIVILEGES", "ALL", "GRANT OPTION", "RELOAD", "SUPER", "FILE", "CREATE USER", "SYSTEM_USER"):
                self.assertNotIn(widening, held, name)


class DerivedNameTests(unittest.TestCase):
    """The Jinja that derives an account, a database and an escaped grant target is the program's."""

    @staticmethod
    def tenant_task() -> dict:
        for task in main_tasks():
            if task.get("name") == "Derive each tenant's account and its grant target":
                return task
        raise AssertionError("the task that derives the tenant accounts is not in tasks/main.yml")

    def derive(self, slug: str, user: str | None = None) -> dict:
        """Render the role's own expression; `user` stands in for the derived account, to try characters a slug cannot hold."""
        task = self.tenant_task()
        context: dict = {
            "db1_grants_tenant_base": [],
            "db1_grants_tenant_prefix": VARS["db1_grants_tenant_prefix"],
            "db1_grants_tenant_host": VARS["db1_grants_tenant_host"],
            "item": slug,
        }
        context["db1_grants_bs"] = render(task["vars"]["db1_grants_bs"], **context)
        context["db1_grants_user"] = user if user is not None else render(task["vars"]["db1_grants_user"], **context)
        rendered = render(task["ansible.builtin.set_fact"]["db1_grants_tenant_base"], **context)
        return ast.literal_eval(rendered)[0]

    def test_the_derivation_types_no_backslash(self) -> None:
        # A backslash typed in a template literal is read one way by plain Jinja and another by the
        # templating engine of Ansible; the role makes the character from its code so no reader matters.
        task = self.tenant_task()
        self.assertNotIn("\\", task["ansible.builtin.set_fact"]["db1_grants_tenant_base"])
        self.assertNotIn("\\", task["vars"]["db1_grants_bs"] + task["vars"]["db1_grants_user"])

    def test_the_account_and_the_escaped_target_are_the_programs_over_a_table(self) -> None:
        for slug in ("blog", "second-site", "a", "a-b-c", "x1-y2", "ab", "a-1", "z" * 26):
            name = naming.database_and_user_name(naming.sql_identifier(slug))
            derived = self.derive(slug)
            self.assertEqual(derived["user"], name, slug)
            self.assertEqual(derived["escaped"], provision.grant_database_pattern(name), slug)
            self.assertEqual(derived["key"], f"tenant-{slug}")
            self.assertEqual(derived["host"], naming.TENANT_USER_HOST)

    def test_the_escape_is_the_programs_over_a_table_of_the_characters_it_exists_for(self) -> None:
        table = [
            "ghost_blog", "ghost_a_b", "ghost_a%b", "a\\b", "\\", "_", "%", "_%\\_", "plain", "a__b", "%%", "\\_", "\\\\",
            "ghost_second_site", "a\\_b", "\\%",
        ]  # fmt: skip
        for value in table:
            self.assertEqual(self.derive("x", user=value)["escaped"], provision.grant_database_pattern(value), repr(value))

    def test_the_table_includes_the_backslash_that_the_first_step_exists_for(self) -> None:
        self.assertEqual(self.derive("x", user="a\\_b")["escaped"], "a\\\\\\_b")


class SecretHandlingTests(unittest.TestCase):
    """Every task that reads, derives, passes or checks a password hides its log and its diff."""

    SECRET = re.compile(
        r"\bdb1_grants_(admin_password|ops1_password|admin_matches|db_env_slurp|ops1_slurp|ops1_sql)\b"
        r"|\bdb1_grants_program_result\.(stdout|stderr)\b"
    )

    def test_a_task_that_handles_a_secret_sets_no_log_and_diff_false(self) -> None:
        seen = 0
        for file, task in all_tasks():
            own = {key: value for key, value in task.items() if key not in ("block", "rescue", "always")}
            if self.SECRET.search(json.dumps(own)):
                seen += 1
                self.assertIs(task.get("no_log"), True, f"{file}: {task.get('name')} lacks no_log: true")
                if "ansible.builtin.include_tasks" not in task:  # an include has no diff of its own
                    self.assertIs(task.get("diff"), False, f"{file}: {task.get('name')} lacks diff: false")
        self.assertGreater(seen, 8, "the scan found too few secret-handling tasks to prove anything")

    def test_no_message_names_a_secret(self) -> None:
        for file, task in all_tasks():
            for module in ("ansible.builtin.assert", "ansible.builtin.fail"):
                if module in task:
                    message = json.dumps(task[module].get("fail_msg", task[module].get("msg", "")))
                    self.assertNotRegex(message, r"db1_grants_(admin|ops1)_password\b|_slurp|_matches", f"{file}: {task.get('name')}")

    def test_the_only_client_calls_keep_the_password_off_every_command_line(self) -> None:
        # Ansible writes a task's environment in front of the command it runs, where
        # every local account can read it and the controller's log shows it, so no
        # task of the role has an environment at all. The password is the first line
        # of the standard input, behind the fixed wrapper.
        calls = 0
        for file, task in all_tasks():
            self.assertNotIn("environment", task, f"{file}: {task.get('name')} sets an environment")
            command = task.get("ansible.builtin.command")
            if command is None or "argv" not in command:
                continue
            argv = command["argv"]
            if argv[0] == "date":  # the clock reads no secret and holds none
                continue
            calls += 1
            self.assertTrue(
                isinstance(argv, str) and argv.startswith("{{ db1_grants_secret_wrapper + "),
                f"{file}: {task.get('name')} does not run behind the wrapper",
            )
            self.assertTrue(command["stdin"].startswith("{{ db1_grants_admin_password "), f"{file}: {task.get('name')}")
        self.assertEqual(calls, 3, "the role's client calls are the read, the write and the program run")

    def test_the_wrapper_is_one_fixed_text_that_holds_no_value(self) -> None:
        wrapper = VARS["db1_grants_secret_wrapper"]
        self.assertEqual(wrapper[:2], ["/bin/sh", "-c"])
        self.assertEqual(wrapper[2], 'IFS= read -r MYSQL_PWD && export MYSQL_PWD && exec "$@"')
        self.assertNotIn("{{", json.dumps(wrapper))
        self.assertNotIn("-e", VARS["db1_grants_mysql_argv"], "a statement on the command line")

    def test_no_secret_is_a_default_or_an_input(self) -> None:
        self.assertEqual(
            [line for line in (ROLE / "defaults" / "main.yml").read_text().splitlines() if line and not line.startswith("#") and line != "---"],
            [],
        )
        spec = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"]["main"]["options"]
        self.assertEqual(sorted(spec), ["db1_grants_ops1_host", "db1_grants_tenants"])
        for name, option in spec.items():
            self.assertNotIn("default", option, name)
            self.assertTrue(option["required"], name)

    def test_the_role_uses_no_shell_raw_or_script_task(self) -> None:
        for file, task in all_tasks():
            for forbidden in ("ansible.builtin.shell", "ansible.builtin.raw", "ansible.builtin.script"):
                self.assertNotIn(forbidden, task, f"{file}: {task.get('name')}")


class ControlCoverageTests(unittest.TestCase):
    """Every refusal the role can make has a case that requires it."""

    def test_every_refusal_code_has_a_case_and_every_case_names_a_refusal(self) -> None:
        in_tasks = set()
        for path in TASKS.glob("*.yml"):
            in_tasks |= set(re.findall(r"db1_grants\[([a-z0-9]+(?:-[a-z0-9]+)+)\]", path.read_text(encoding="utf-8")))
        cases = yaml.safe_load((ROLE / "molecule" / "default" / "vars" / "cases.yml").read_text(encoding="utf-8"))
        in_cases = {case["code"] for case in cases["db1_grants_verify_cases"]}
        self.assertEqual(sorted(in_tasks - in_cases), [], "a refusal no case requires")
        self.assertEqual(sorted(in_cases - in_tasks), [], "a case that names a refusal the role does not make")


class HygieneTests(unittest.TestCase):
    """What must not be in a shipped file."""

    @staticmethod
    def shipped() -> list[Path]:
        # This file holds the patterns it looks for, so it does not scan itself; the fixtures are another repository's bytes.
        mine = Path(__file__).resolve()
        return [p for p in ROLE.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.parent != FIXTURES and p.resolve() != mine]

    def test_no_work_item_reference(self) -> None:
        for path in self.shipped():
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?<![\w/])[\w-]*#\d{2,}\b", str(path))
            self.assertNotIn("/issues/", text, str(path))
            self.assertNotRegex(text, r"github\.com/[\w.-]+/[\w.-]+/(pull|issues)/\d+", str(path))

    def test_no_absolute_home_path(self) -> None:
        for path in self.shipped():
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"/Users/|/home/\w", str(path))

    def test_no_task_types_a_backslash_escape_in_a_template(self) -> None:
        # The templating engine does not read an escape in a template literal: a typed backslash-n stays two
        # characters, which splits and joins nothing. The role makes such characters in vars/main.yml, where
        # YAML reads them. A backslash in a regular expression (backslash, then a symbol) is not an escape,
        # and the one carriage-return test is a regular expression, which reads the backslash itself.
        escape = re.compile(r"\\[ntr\\]")
        for path in sorted(TASKS.glob("*.yml")) + sorted((ROLE / "molecule" / "default" / "tasks").glob("*.yml")):
            text = path.read_text(encoding="utf-8").replace('is search("\\r")', "")
            self.assertIsNone(escape.search(text), str(path))

    def test_no_placeholder_left_from_the_skeleton(self) -> None:
        for path in self.shipped():
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"AUTHOR_NAME|LICENSE_ID|REPLACE_WITH_ONE_SENTENCE|EXAMPLE_FILES", str(path))


if __name__ == "__main__":
    unittest.main()
