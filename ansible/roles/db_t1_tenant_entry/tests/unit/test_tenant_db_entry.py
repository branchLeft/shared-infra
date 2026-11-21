"""The forced command's request parsing and its one action, against a stand-in container runtime.

The stand-in is a small database: it keeps the accounts and databases that exist, answers the
existence query, and applies the create statements the way the real server would, refusing a
second account or database of the same name. It records every argument list and every standard
input the program sent, so a test can say what reached the container and what did not. The real
server, the real docker and the real sshd are the Molecule scenario's.
"""

from __future__ import annotations

import fcntl
import io
import os
import re
import subprocess
import syslog
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

import tenant_db_entry as entry
from tenant_db_entry import RefusalError

CONTAINER = "a1" * 32
PASSWORD = "PASSWORD_FROM_THE_TEST_FACTORY_0123456789"  # noqa: S105 - a stand-in, not a secret
SERVER_TEXT = "SERVER_ERROR_TEXT_THAT_MUST_NOT_BE_RELAYED"


def _process(
    stdout: str = "", returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeRuntime:
    """Stands in for docker and the database client inside the container."""

    def __init__(self) -> None:
        self.users: set[str] = set()
        self.databases: set[str] = set()
        self.calls: list[tuple[list[str], str]] = []
        self.containers: list[str] = [CONTAINER]
        self.ps_returncode = 0
        self.fail_sql = False

    def __call__(self, argv: Sequence[str], stdin: str) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(argv), stdin))
        if argv[:2] == [entry.DOCKER, "ps"]:
            return _process(
                "".join(f"{identifier}\n" for identifier in self.containers), self.ps_returncode
            )
        if argv[:2] == [entry.DOCKER, "exec"]:
            return self._exec(stdin)
        raise AssertionError(f"the program ran something it should not: {argv}")

    def _exec(self, statements: str) -> subprocess.CompletedProcess[str]:
        if self.fail_sql:
            return _process(returncode=1, stderr=SERVER_TEXT)
        query = re.search(
            r"WHERE User = '([a-z0-9_]+)'.*SCHEMA_NAME = '([a-z0-9_]+)'", statements, re.DOTALL
        )
        if query is not None:
            users = int(query.group(1) in self.users)
            databases = int(query.group(2) in self.databases)
            return _process(f"{users}\t{databases}\n")
        database = re.search(r"CREATE DATABASE `([a-z0-9_]+)`", statements)
        account = re.search(r"CREATE USER '([a-z0-9_]+)'@", statements)
        if database is None or account is None:
            raise AssertionError(f"statements the stand-in does not know: {statements}")
        if database.group(1) in self.databases or account.group(1) in self.users:
            return _process(returncode=1, stderr=SERVER_TEXT)
        self.databases.add(database.group(1))
        self.users.add(account.group(1))
        return _process()

    def sql_sent(self) -> list[str]:
        return [stdin for argv, stdin in self.calls if argv[:2] == [entry.DOCKER, "exec"]]

    def creates(self) -> list[str]:
        return [sql for sql in self.sql_sent() if "CREATE" in sql]


class Result:
    def __init__(self, status: int, stdout: str, stderr: str, log: list[str]) -> None:
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.log = log


def serve(
    request: str | None,
    runtime: FakeRuntime,
    *,
    argv: Sequence[str] = (),
    lock_path: str | None = None,
) -> Result:
    """Run main() the way sshd's forced command does: the request is in the environment."""
    environ = {} if request is None else {"SSH_ORIGINAL_COMMAND": request}
    stdout, stderr = io.StringIO(), io.StringIO()
    log: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        status = entry.main(
            argv,
            environ,
            stdout,
            stderr,
            run=runtime,
            lock_path=lock_path or str(Path(scratch) / "lock"),
            log=log.append,
            password_factory=lambda: PASSWORD,
        )
    return Result(status, stdout.getvalue(), stderr.getvalue(), log)


# What a client can ask for in place of the one command: a shell, a second command in every shape,
# a name with a quote, a name that is too long, and nothing.
SHELL_REQUESTS = [
    "/bin/sh",
    "sh",
    "id",
    "bash -i",
    "sudo -n /bin/true",
    "; id",
    "&& id",
    "$(id)",
    "`id`",
    "create-tenant-db blog; id",
    "create-tenant-db blog && id",
    "create-tenant-db blog | id",
    "create-tenant-db blog > /tmp/EXAMPLE_MARKER",
    "create-tenant-db $(id)",
    "create-tenant-db `id`",
    "create-tenant-db blog\nid",
    "create-tenant-db blog\n",
    "create-tenant-db blog\r",
    "create-tenant-db blog\x00",
    "create-tenant-db blog ",
    " create-tenant-db blog",
    "create-tenant-db  blog",
    "create-tenant-db\tblog",
    "create-tenant-db blog extra",
    "create-tenant-db blog blog",
    "create-tenant-db",
    "create-tenant-db ",
    "CREATE-TENANT-DB blog",
    "create_tenant_db blog",
    "drop-tenant-db blog",
    "list-tenant-db",
    "scp -t /tmp",
    "internal-sftp",
    "",
    " ",
    "x" * 5000,
]

QUOTE_REQUESTS = [
    "create-tenant-db blog'",
    'create-tenant-db blog"',
    "create-tenant-db blog' OR '1'='1",
    "create-tenant-db blog`",
    "create-tenant-db blog\\",
    "create-tenant-db 'blog'",
    "create-tenant-db blog;",
    "create-tenant-db blog%",
    "create-tenant-db blog_one",
    "create-tenant-db blog.one",
    "create-tenant-db blog/one",
    "create-tenant-db ../blog",
    "create-tenant-db *",
    "create-tenant-db é",
    "create-tenant-db blogé",
    "create-tenant-db ٣",
    "create-tenant-db ａ",
]

BAD_NAME_REQUESTS = [
    "create-tenant-db 1blog",
    "create-tenant-db -blog",
    "create-tenant-db blog-",
    "create-tenant-db 0",
    "create-tenant-db " + "a" * (entry.MAX_TENANT_NAME_LENGTH + 1),
    "create-tenant-db " + "a" * 100,
]

VALID_NAMES = [
    "a",
    "ab",
    "blog",
    "my-blog",
    "a1",
    "a-1",
    "blog-2",
    "a--b",
    "a" * entry.MAX_TENANT_NAME_LENGTH,
]


class ParseTests(unittest.TestCase):
    def reason(self, request: str | None) -> str:
        with self.assertRaises(RefusalError) as context:
            entry.parse_request(request)
        self.assertEqual(context.exception.status, entry.EXIT_REFUSED)
        return context.exception.reason

    def test_every_valid_name_is_accepted_and_returned_as_it_was_given(self) -> None:
        for name in VALID_NAMES:
            with self.subTest(name=name):
                self.assertEqual(entry.parse_request(f"create-tenant-db {name}"), name)

    def test_no_request_is_refused_as_no_command(self) -> None:
        self.assertEqual(self.reason(None), "no-command")

    def test_a_request_that_is_not_the_one_command_is_refused(self) -> None:
        for request in SHELL_REQUESTS:
            with self.subTest(request=request[:40]):
                self.assertIn(self.reason(request), {"bad-command", "request-too-long"})

    def test_a_request_longer_than_the_limit_is_refused_before_it_is_matched(self) -> None:
        self.assertEqual(self.reason("create-tenant-db " + "a" * 200), "request-too-long")
        self.assertEqual(self.reason("x" * (entry.MAX_REQUEST_LENGTH + 1)), "request-too-long")

    def test_a_name_with_a_quote_or_a_character_outside_the_alphabet_is_refused(self) -> None:
        for request in QUOTE_REQUESTS:
            with self.subTest(request=request):
                self.assertEqual(self.reason(request), "bad-command")

    def test_a_name_the_tenant_rule_refuses_is_refused_as_a_bad_name(self) -> None:
        for request in BAD_NAME_REQUESTS:
            with self.subTest(request=request[:40]):
                self.assertEqual(self.reason(request), "bad-name")

    def test_the_longest_name_is_26_characters_so_the_database_name_fits_32(self) -> None:
        self.assertEqual(entry.MAX_TENANT_NAME_LENGTH, 26)
        longest = "a" * 26
        self.assertEqual(len(entry.database_name(longest)), 32)
        self.assertEqual(self.reason("create-tenant-db " + "a" * 27), "bad-name")

    def test_a_line_break_after_a_valid_request_is_refused(self) -> None:
        # $ would match before the trailing line break; the patterns end in \Z.
        self.assertEqual(self.reason("create-tenant-db blog\n"), "bad-command")

    def test_every_refusal_is_a_refusal_and_never_a_name(self) -> None:
        for request in [*SHELL_REQUESTS, *QUOTE_REQUESTS, *BAD_NAME_REQUESTS]:
            with self.subTest(request=request[:40]):
                self.reason(request)


class NameTests(unittest.TestCase):
    def test_hyphens_become_underscores_under_the_fixed_prefix(self) -> None:
        self.assertEqual(entry.database_name("my-blog"), "ghost_my_blog")
        self.assertEqual(entry.database_name("blog"), "ghost_blog")

    def test_the_grant_target_escapes_the_underscore_and_the_percent_sign(self) -> None:
        self.assertEqual(entry.grant_pattern("ghost_my_blog"), "ghost\\_my\\_blog")
        self.assertEqual(entry.grant_pattern("a%b"), "a\\%b")
        self.assertEqual(entry.grant_pattern("a\\b"), "a\\\\b")

    def test_two_tenant_names_never_share_a_database_name(self) -> None:
        names = {entry.database_name(name) for name in VALID_NAMES}
        self.assertEqual(len(names), len(VALID_NAMES))


class StatementTests(unittest.TestCase):
    def test_the_create_statements_are_exactly_these(self) -> None:
        self.assertEqual(
            entry.create_statements("ghost_my_blog", "PW"),
            "CREATE DATABASE `ghost_my_blog` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
            "CREATE USER 'ghost_my_blog'@'10.20.1.201' IDENTIFIED BY 'PW' "
            "WITH MAX_USER_CONNECTIONS 10;\n"
            "GRANT ALL PRIVILEGES ON `ghost\\_my\\_blog`.* TO 'ghost_my_blog'@'10.20.1.201';\n"
            "FLUSH PRIVILEGES;\n",
        )

    def test_neither_create_statement_says_if_not_exists(self) -> None:
        sql = entry.create_statements("ghost_blog", "PW")
        self.assertNotIn("IF NOT EXISTS", sql.upper())

    def test_the_account_connects_from_one_address_only(self) -> None:
        sql = entry.create_statements("ghost_blog", "PW")
        self.assertEqual(set(re.findall(r"@'([^']+)'", sql)), {entry.TENANT_USER_HOST})
        self.assertNotIn("%", entry.TENANT_USER_HOST)

    def test_the_grant_is_on_the_one_database_and_is_not_global(self) -> None:
        grants = [
            line
            for line in entry.create_statements("ghost_blog", "PW").splitlines()
            if "GRANT" in line
        ]
        self.assertEqual(len(grants), 1)
        self.assertIn("ON `ghost\\_blog`.*", grants[0])
        self.assertNotIn("*.*", grants[0])
        self.assertNotIn("GRANT OPTION", grants[0])

    def test_the_existence_query_asks_for_the_account_at_any_host_and_the_database(self) -> None:
        query = entry.existence_query("ghost_blog")
        self.assertIn("FROM mysql.user WHERE User = 'ghost_blog')", query)
        self.assertNotIn("Host", query)
        self.assertIn("SCHEMA_NAME = 'ghost_blog'", query)

    def test_only_one_row_of_zero_and_zero_means_free(self) -> None:
        self.assertTrue(entry.counts_say_free("0\t0\n"))
        for output in [
            "1\t0\n",
            "0\t1\n",
            "1\t1\n",
            "",
            "0\t0\n0\t0\n",
            "0\t0\nextra\n",
            "0",
            "\n",
            "error",
        ]:
            with self.subTest(output=output):
                self.assertFalse(entry.counts_say_free(output))


class CreateTests(unittest.TestCase):
    def test_a_free_name_makes_the_database_the_account_and_prints_the_password_once(self) -> None:
        runtime = FakeRuntime()
        result = serve("create-tenant-db my-blog", runtime)
        self.assertEqual(result.status, entry.EXIT_CREATED)
        self.assertEqual(
            result.stdout.splitlines(),
            ["database=ghost_my_blog", "user=ghost_my_blog@10.20.1.201", f"password={PASSWORD}"],
        )
        self.assertEqual(result.stderr, "")
        self.assertEqual(runtime.databases, {"ghost_my_blog"})
        self.assertEqual(runtime.users, {"ghost_my_blog"})

    def test_the_password_reaches_the_container_on_standard_input_only(self) -> None:
        runtime = FakeRuntime()
        serve("create-tenant-db blog", runtime)
        for argv, _stdin in runtime.calls:
            self.assertFalse(any(PASSWORD in argument for argument in argv), argv)
        self.assertEqual([PASSWORD in sql for sql in runtime.sql_sent()], [False, True])

    def test_the_password_is_in_no_log_line_and_no_error_line(self) -> None:
        runtime = FakeRuntime()
        result = serve("create-tenant-db blog", runtime)
        self.assertEqual(result.log, ["created database=ghost_blog"])
        self.assertNotIn(PASSWORD, "\n".join(result.log) + result.stderr)

    def test_the_default_password_is_a_fresh_url_safe_token_of_43_characters(self) -> None:
        seen = {entry.create_tenant_database("blog", run=FakeRuntime()).password for _ in range(5)}
        self.assertEqual(len(seen), 5)
        for password in seen:
            self.assertRegex(password, r"\A[A-Za-z0-9_-]{43}\Z")

    def test_an_existing_account_is_refused_and_nothing_is_made_or_printed(self) -> None:
        runtime = FakeRuntime()
        runtime.users.add("ghost_blog")
        result = serve("create-tenant-db blog", runtime)
        self.assertEqual(result.status, entry.EXIT_EXISTS)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "branchleft-tenant-db-entry: refused reason=exists\n")
        self.assertEqual(runtime.creates(), [])
        self.assertEqual(runtime.databases, set())

    def test_an_existing_database_without_an_account_is_refused(self) -> None:
        runtime = FakeRuntime()
        runtime.databases.add("ghost_blog")
        result = serve("create-tenant-db blog", runtime)
        self.assertEqual(result.status, entry.EXIT_EXISTS)
        self.assertEqual(runtime.creates(), [])
        self.assertEqual(runtime.users, set())

    def test_a_name_that_differs_only_by_hyphen_or_underscore_is_the_same_name(self) -> None:
        runtime = FakeRuntime()
        runtime.users.add("ghost_my_blog")
        self.assertEqual(serve("create-tenant-db my-blog", runtime).status, entry.EXIT_EXISTS)

    def test_a_second_request_for_the_same_name_is_refused_and_prints_no_password(self) -> None:
        runtime = FakeRuntime()
        first = serve("create-tenant-db blog", runtime)
        second = serve("create-tenant-db blog", runtime)
        self.assertEqual((first.status, second.status), (entry.EXIT_CREATED, entry.EXIT_EXISTS))
        self.assertNotIn(PASSWORD, second.stdout + second.stderr)
        self.assertEqual(len(runtime.creates()), 1)

    def test_another_name_is_not_touched_by_a_request_for_this_one(self) -> None:
        runtime = FakeRuntime()
        runtime.users.add("ghost_other")
        runtime.databases.add("ghost_other")
        serve("create-tenant-db blog", runtime)
        self.assertEqual(runtime.users, {"ghost_other", "ghost_blog"})

    def test_the_server_is_never_contacted_for_a_request_that_is_refused(self) -> None:
        for request in [None, *SHELL_REQUESTS, *QUOTE_REQUESTS, *BAD_NAME_REQUESTS]:
            with self.subTest(request=(request or "")[:40]):
                runtime = FakeRuntime()
                result = serve(request, runtime)
                self.assertEqual(result.status, entry.EXIT_REFUSED)
                self.assertEqual(runtime.calls, [])
                self.assertEqual(result.stdout, "")

    def test_an_argument_is_refused_before_the_request_is_read(self) -> None:
        runtime = FakeRuntime()
        result = serve("create-tenant-db blog", runtime, argv=["--other"])
        self.assertEqual(result.status, entry.EXIT_REFUSED)
        self.assertEqual(result.stderr, "branchleft-tenant-db-entry: refused reason=arguments\n")
        self.assertEqual(runtime.calls, [])

    def test_a_refusal_writes_one_line_of_fixed_text_and_never_the_request(self) -> None:
        marker = "REQUEST_TEXT_MARKER"
        for request in [f"{marker}", f"create-tenant-db {marker}", f"create-tenant-db a'{marker}"]:
            result = serve(request, FakeRuntime())
            self.assertNotIn(marker, result.stderr + "\n".join(result.log))
            self.assertRegex(
                result.stderr, r"\Abranchleft-tenant-db-entry: refused reason=[a-z-]+\n\Z"
            )


class DatabaseFailureTests(unittest.TestCase):
    def test_no_container_is_a_failure_before_any_statement(self) -> None:
        runtime = FakeRuntime()
        runtime.containers = []
        result = serve("create-tenant-db blog", runtime)
        self.assertEqual(result.status, entry.EXIT_FAILED)
        self.assertEqual(result.stderr, "branchleft-tenant-db-entry: refused reason=no-database\n")
        self.assertEqual(runtime.sql_sent(), [])

    def test_two_containers_are_refused_rather_than_one_chosen(self) -> None:
        runtime = FakeRuntime()
        runtime.containers = [CONTAINER, "b2" * 32]
        self.assertEqual(serve("create-tenant-db blog", runtime).status, entry.EXIT_FAILED)
        self.assertEqual(runtime.sql_sent(), [])

    def test_an_identifier_that_is_not_64_hex_digits_is_refused(self) -> None:
        for identifier in [
            "",
            "abc",
            "A1" * 32,
            "a1" * 31,
            "a1" * 33,
            "--help",
            "a1" * 31 + "z1",
            "a1 " * 21 + "a",
        ]:
            with self.subTest(identifier=identifier):
                runtime = FakeRuntime()
                runtime.containers = [identifier] if identifier else []
                self.assertEqual(serve("create-tenant-db blog", runtime).status, entry.EXIT_FAILED)
                self.assertEqual(runtime.sql_sent(), [])

    def test_a_failed_listing_is_a_failure(self) -> None:
        runtime = FakeRuntime()
        runtime.ps_returncode = 1
        self.assertEqual(serve("create-tenant-db blog", runtime).status, entry.EXIT_FAILED)

    def test_the_container_is_found_by_the_compose_project_and_service_and_running_state(
        self,
    ) -> None:
        runtime = FakeRuntime()
        serve("create-tenant-db blog", runtime)
        listing = runtime.calls[0][0]
        self.assertEqual(listing[0], "/usr/bin/docker")
        for needle in [
            "label=com.docker.compose.project=dbt1",
            "label=com.docker.compose.service=mysql",
            "status=running",
        ]:
            self.assertIn(needle, listing)

    def test_the_client_runs_in_that_container_with_the_statements_on_standard_input(self) -> None:
        runtime = FakeRuntime()
        serve("create-tenant-db blog", runtime)
        argv = runtime.calls[1][0]
        self.assertEqual(argv[:4], ["/usr/bin/docker", "exec", "--interactive", CONTAINER])
        self.assertEqual(argv[4:6], ["sh", "-c"])
        self.assertEqual(len(argv), 7)

    def test_a_server_error_is_a_failure_and_its_text_is_not_relayed(self) -> None:
        runtime = FakeRuntime()
        runtime.fail_sql = True
        result = serve("create-tenant-db blog", runtime)
        self.assertEqual(result.status, entry.EXIT_FAILED)
        self.assertEqual(result.stderr, "branchleft-tenant-db-entry: refused reason=sql-failed\n")
        self.assertNotIn(SERVER_TEXT, result.stdout + result.stderr + "\n".join(result.log))
        self.assertEqual(result.stdout, "")

    def test_a_program_that_cannot_run_is_a_failure(self) -> None:
        def missing(argv: Sequence[str], stdin: str) -> subprocess.CompletedProcess[str]:
            raise RefusalError("no-database", entry.EXIT_FAILED)

        with self.assertRaises(RefusalError):
            entry.find_container(missing)

    def test_the_root_value_is_not_in_any_argument_or_in_the_program_source(self) -> None:
        runtime = FakeRuntime()
        serve("create-tenant-db blog", runtime)
        source = Path(entry.__file__).read_text(encoding="utf-8")
        for argv, _stdin in runtime.calls:
            self.assertNotIn("PASSWORD=", " ".join(argv).replace("MYSQL_PWD", ""))
        # The shell inside the container moves the value; the program only names the variable.
        self.assertEqual(entry.CLIENT_SCRIPT.count("$MYSQL_ROOT_PASSWORD"), 1)
        self.assertNotIn("dbt1.env", source)
        self.assertNotIn("os.environ[", source)
        self.assertNotIn("/etc/", source)


class RunCommandTests(unittest.TestCase):
    def test_the_child_gets_a_fixed_environment_and_no_shell(self) -> None:
        with mock.patch.object(subprocess, "run", return_value=_process("ok")) as run:
            with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": "create-tenant-db blog"}):
                result = entry.run_command(["/bin/true", "x"], "input")
        self.assertEqual(result.stdout, "ok")
        run.assert_called_once_with(
            ["/bin/true", "x"],
            input="input",
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            timeout=entry.DOCKER_TIMEOUT_SECONDS,
        )

    def test_a_missing_program_is_a_refusal(self) -> None:
        with self.assertRaises(RefusalError) as missing:
            entry.run_command(["/nonexistent/EXAMPLE_PROGRAM"], "")
        self.assertEqual(missing.exception.reason, "no-database")
        self.assertEqual(missing.exception.status, entry.EXIT_FAILED)

    def test_a_program_that_runs_past_the_time_limit_is_a_refusal(self) -> None:
        with mock.patch.object(entry, "DOCKER_TIMEOUT_SECONDS", 0.2):
            with self.assertRaises(RefusalError) as slow:
                entry.run_command(["/bin/sleep", "5"], "")
        self.assertEqual(slow.exception.reason, "no-database")


class LockTests(unittest.TestCase):
    def test_a_second_request_while_one_runs_is_refused_as_busy(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            path = str(Path(scratch) / "lock")
            holder = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(holder, fcntl.LOCK_EX)
                runtime = FakeRuntime()
                result = serve("create-tenant-db blog", runtime, lock_path=path)
            finally:
                os.close(holder)
        self.assertEqual(result.status, entry.EXIT_BUSY)
        self.assertEqual(result.stderr, "branchleft-tenant-db-entry: refused reason=busy\n")
        self.assertEqual(runtime.calls, [])

    def test_the_lock_is_released_when_the_request_ends(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            path = str(Path(scratch) / "lock")
            self.assertEqual(serve("create-tenant-db one", FakeRuntime(), lock_path=path).status, 0)
            self.assertEqual(serve("create-tenant-db two", FakeRuntime(), lock_path=path).status, 0)

    def test_the_lock_is_released_after_a_failure_too(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            path = str(Path(scratch) / "lock")
            broken = FakeRuntime()
            broken.containers = []
            self.assertEqual(
                serve("create-tenant-db one", broken, lock_path=path).status, entry.EXIT_FAILED
            )
            self.assertEqual(serve("create-tenant-db one", FakeRuntime(), lock_path=path).status, 0)

    def test_a_lock_path_that_is_a_link_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "target"
            target.write_text("EXAMPLE", encoding="utf-8")
            link = Path(scratch) / "lock"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                entry.main(
                    [],
                    {"SSH_ORIGINAL_COMMAND": "create-tenant-db blog"},
                    io.StringIO(),
                    io.StringIO(),
                    run=FakeRuntime(),
                    lock_path=str(link),
                    log=lambda _message: None,
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "EXAMPLE")


class DeliveryTests(unittest.TestCase):
    def test_a_password_that_could_not_be_written_is_reported_and_logged_without_it(self) -> None:
        class Broken(io.StringIO):
            def write(self, text: str, /) -> int:
                raise BrokenPipeError

        stderr = io.StringIO()
        log: list[str] = []
        with tempfile.TemporaryDirectory() as scratch:
            status = entry.main(
                [],
                {"SSH_ORIGINAL_COMMAND": "create-tenant-db blog"},
                Broken(),
                stderr,
                run=FakeRuntime(),
                lock_path=str(Path(scratch) / "lock"),
                log=log.append,
                password_factory=lambda: PASSWORD,
            )
        self.assertEqual(status, entry.EXIT_FAILED)
        self.assertEqual(
            stderr.getvalue(), "branchleft-tenant-db-entry: failed reason=undelivered\n"
        )
        self.assertEqual(log, ["created-undelivered database=ghost_blog"])
        self.assertNotIn(PASSWORD, stderr.getvalue() + "\n".join(log))

    def test_the_syslog_writer_logs_a_line_under_the_program_name(self) -> None:
        with (
            mock.patch.object(syslog, "openlog") as opened,
            mock.patch.object(syslog, "syslog") as logged,
        ):
            entry._log("created database=ghost_blog")  # noqa: SLF001 - the writer is the unit under test
        self.assertEqual(opened.call_args.args[0], "branchleft-tenant-db-entry")
        self.assertEqual(logged.call_args.args[1], "created database=ghost_blog")


if __name__ == "__main__":
    unittest.main()
