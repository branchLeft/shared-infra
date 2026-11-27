"""The program of the exporter-account service, run for real against a fake MySQL client.

The program (files/exporter_account.sh) is what makes the exporter's account in the database on
every start of the stack, so that the first deploy on a fresh data directory passes with no hand
step. These tests run it with `sh`, a credentials file in a scratch directory and a fake `mysql`
on the path that records what it was given: its arguments, its standard input and the value of
the root credential it read from its environment. They need no Docker and no network. The real
client, the real server and a real fresh data directory were exercised once in a container; the
pull request records it.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
PROGRAM = ROLE / "files" / "exporter_account.sh"
FILE_VALUE = "Abcdefghij0123456789xyz"
ROOT_VALUE = "RootValue0123456789abcdefghijklmnop"
GOOD_GRANTS = (
    "GRANT PROCESS, REPLICATION CLIENT ON *.* TO `exporter`@`localhost`\n"
    "GRANT SELECT ON `performance_schema`.* TO `exporter`@`localhost`\n"
)

# A client that records every call. A call with --defaults-file is the health check's login: it
# prints FAKE_GRANTS and exits FAKE_LOGIN_STATUS. Any other call is the root client: it records
# its arguments and standard input, and exits FAKE_ROOT_STATUS for the probe `SELECT 1`.
FAKE_MYSQL = """#!/bin/sh
printf '%s\\n' "$*" >>"$FAKE_DIR/calls"
case " $* " in
    *" --defaults-file="*)
        printf '%s' "$FAKE_GRANTS"
        exit "${FAKE_LOGIN_STATUS:-0}"
        ;;
esac
printf '%s\\n' "${MYSQL_PWD:-unset}" >>"$FAKE_DIR/root_values"
case " $* " in
    *" SELECT 1 "*) exit "${FAKE_ROOT_STATUS:-0}" ;;
esac
cat >>"$FAKE_DIR/stdin"
"""
FAKE_SLEEP = """#!/bin/sh
printf '%s\\n' "$*" >>"$FAKE_DIR/sleeps"
"""


class Run:
    """One run of the program and everything the fake client saw."""

    def __init__(self, directory: Path, completed: subprocess.CompletedProcess[str]) -> None:
        self.status = completed.returncode
        self.output = completed.stdout + completed.stderr
        self.calls = self._read(directory / "calls")
        self.stdin = self._read(directory / "stdin")
        self.root_values = self._read(directory / "root_values")
        self.sleeps = self._read(directory / "sleeps")

    @staticmethod
    def _read(path: Path) -> str:
        return path.read_text(encoding="utf-8") if path.exists() else ""


def run_program(
    mode: str | None,
    *,
    cnf: str | None = None,
    env: dict[str, str] | None = None,
) -> Run:
    """Run the program in a scratch directory with the fakes first on the path."""
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(scratch)
        fake_bin = directory / "bin"
        fake_bin.mkdir()
        for name, text in (("mysql", FAKE_MYSQL), ("sleep", FAKE_SLEEP)):
            (fake_bin / name).write_text(text, encoding="utf-8")
            (fake_bin / name).chmod(0o755)
        cnf_path = directory / "exporter.my.cnf"
        if cnf is None:
            cnf = f"[client]\nuser = exporter\npassword = {FILE_VALUE}\nsocket = /x.sock\n"
        cnf_path.write_text(cnf, encoding="utf-8")
        environment = {
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "FAKE_DIR": str(directory),
            "FAKE_GRANTS": GOOD_GRANTS,
            "EXPORTER_ACCOUNT_CNF": str(cnf_path),
            "EXPORTER_ACCOUNT_SOCKET": str(directory / "mysqld.sock"),
            "EXPORTER_ACCOUNT_WAIT_STEPS": "0",
            "MYSQL_ROOT_PASSWORD": ROOT_VALUE,
        }
        environment.update(env or {})
        argv = ["sh", str(PROGRAM)] + ([] if mode is None else [mode])
        completed = subprocess.run(  # noqa: S603 - the program under test, fixed arguments
            argv, env=environment, capture_output=True, text=True, check=False, timeout=60
        )
        return Run(directory, completed)


class MakingTheAccount(unittest.TestCase):
    """The default and `apply` modes."""

    def test_it_creates_the_account_idempotently_with_the_least_grants_and_no_binary_log(
        self,
    ) -> None:
        result = run_program("apply")
        self.assertEqual(result.status, 0, result.output)
        statements = [line for line in result.stdin.splitlines() if line]
        self.assertEqual(
            statements,
            [
                "SET @@SESSION.SQL_LOG_BIN=0;",
                f"CREATE USER IF NOT EXISTS 'exporter'@'localhost' IDENTIFIED BY '{FILE_VALUE}'"
                " WITH MAX_USER_CONNECTIONS 3;",
                f"ALTER USER 'exporter'@'localhost' IDENTIFIED BY '{FILE_VALUE}'"
                " WITH MAX_USER_CONNECTIONS 3;",
                "GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'exporter'@'localhost';",
                "GRANT SELECT ON performance_schema.* TO 'exporter'@'localhost';",
            ],
        )

    def test_it_logs_in_as_root_over_the_socket_with_the_root_value_in_the_environment(
        self,
    ) -> None:
        result = run_program("apply")
        self.assertEqual(result.status, 0, result.output)
        for call in result.calls.splitlines():
            self.assertIn("--protocol=socket", call)
            self.assertIn("-uroot", call)
        self.assertEqual(set(result.root_values.splitlines()), {ROOT_VALUE})

    def test_no_value_reaches_an_argument_or_the_output(self) -> None:
        result = run_program("apply")
        self.assertEqual(result.status, 0, result.output)
        for value in (FILE_VALUE, ROOT_VALUE):
            self.assertNotIn(value, result.calls)
            self.assertNotIn(value, result.output)

    def test_apply_ends_and_serve_idles(self) -> None:
        self.assertEqual(run_program("apply").sleeps, "")
        self.assertEqual(run_program("serve").sleeps, "infinity\n")
        self.assertEqual(run_program(None).sleeps, "infinity\n")

    def test_it_waits_for_the_database_and_gives_up_without_writing_anything(self) -> None:
        result = run_program("apply", env={"FAKE_ROOT_STATUS": "1"})
        self.assertNotEqual(result.status, 0)
        self.assertEqual(result.stdin, "")
        self.assertIn("did not answer", result.output)
        self.assertNotIn(FILE_VALUE, result.output)

    def test_it_refuses_a_root_value_that_is_missing(self) -> None:
        result = run_program("apply", env={"MYSQL_ROOT_PASSWORD": ""})
        self.assertNotEqual(result.status, 0)
        self.assertEqual(result.stdin, "")

    def test_an_unknown_mode_does_nothing(self) -> None:
        result = run_program("destroy")
        self.assertNotEqual(result.status, 0)
        self.assertEqual((result.calls, result.stdin), ("", ""))


class RefusingAFileTheStatementsCannotCarry(unittest.TestCase):
    """The file is checked before the database is touched, and no refusal prints a value."""

    def refused(self, cnf: str, reason: str) -> None:
        result = run_program("apply", cnf=cnf)
        self.assertNotEqual(result.status, 0, reason)
        self.assertEqual((result.calls, result.stdin), ("", ""), reason)
        self.assertNotIn(FILE_VALUE, result.output, reason)
        self.assertIn("exporter-account:", result.output, reason)

    def test_another_user_than_the_one_the_account_is_made_for(self) -> None:
        self.refused(f"[client]\nuser = root\npassword = {FILE_VALUE}\n", "user root")

    def test_no_user(self) -> None:
        self.refused(f"[client]\npassword = {FILE_VALUE}\n", "no user")

    def test_no_value(self) -> None:
        self.refused("[client]\nuser = exporter\n", "no value")

    def test_a_value_that_is_too_short(self) -> None:
        self.refused("[client]\nuser = exporter\npassword = Abcdefghij012345678\n", "19 chars")

    def test_a_value_with_a_character_that_would_break_the_statement(self) -> None:
        for bad in ("'", '"', "\\", " ", "$", "`", ";", "%", "\t"):
            with self.subTest(bad=repr(bad)):
                self.refused(
                    f"[client]\nuser = exporter\npassword = Abcdefghij0123456789{bad}xyz\n",
                    f"character {bad!r}",
                )

    def test_a_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            missing = str(Path(scratch) / "absent")
        result = run_program("apply", env={"EXPORTER_ACCOUNT_CNF": missing})
        self.assertNotEqual(result.status, 0)
        self.assertEqual(result.stdin, "")


class ReadingTheAccountBack(unittest.TestCase):
    """The `check` mode: the container's health check."""

    def test_it_is_healthy_when_the_exporter_logs_in_and_holds_both_grants(self) -> None:
        result = run_program("check")
        self.assertEqual(result.status, 0, result.output)

    def test_it_logs_in_as_the_exporter_with_the_file_alone_and_writes_nothing(self) -> None:
        result = run_program("check")
        self.assertEqual(result.stdin, "")
        self.assertEqual(result.root_values, "")
        self.assertEqual(len(result.calls.splitlines()), 1)
        self.assertIn("--defaults-file=", result.calls)
        self.assertIn("SHOW GRANTS", result.calls)
        self.assertNotIn(FILE_VALUE, result.calls)
        self.assertNotIn("-uroot", result.calls)

    def test_it_is_unhealthy_when_the_login_fails(self) -> None:
        result = run_program("check", env={"FAKE_LOGIN_STATUS": "1", "FAKE_GRANTS": ""})
        self.assertNotEqual(result.status, 0)
        self.assertIn("cannot connect", result.output)

    def test_it_is_unhealthy_when_the_global_grants_are_missing(self) -> None:
        grants = "GRANT SELECT ON `performance_schema`.* TO `exporter`@`localhost`\n"
        result = run_program("check", env={"FAKE_GRANTS": grants})
        self.assertNotEqual(result.status, 0)

    def test_it_is_unhealthy_when_the_performance_schema_grant_is_missing(self) -> None:
        grants = "GRANT PROCESS, REPLICATION CLIENT ON *.* TO `exporter`@`localhost`\n"
        result = run_program("check", env={"FAKE_GRANTS": grants})
        self.assertNotEqual(result.status, 0)

    def test_it_is_unhealthy_when_only_the_usage_grant_exists(self) -> None:
        # An account made by hand with no privilege reads `GRANT USAGE`; the exporter would log
        # in and report almost nothing.
        result = run_program("check", env={"FAKE_GRANTS": "GRANT USAGE ON *.* TO `exporter`@`l`\n"})
        self.assertNotEqual(result.status, 0)


class TheFileItself(unittest.TestCase):
    """What a reader of the program should not have to find by eye."""

    def test_the_program_traces_nothing_and_prints_no_file_line(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        self.assertNotIn("set -x", text)
        self.assertNotIn("set -eux", text)

    def test_the_binary_log_is_switched_off_before_any_statement(self) -> None:
        text = PROGRAM.read_text(encoding="utf-8")
        self.assertLess(text.index("SQL_LOG_BIN=0"), text.index("CREATE USER"))


if __name__ == "__main__":
    unittest.main()
