"""Unit tests for control_plane_db_login: the verifier, the credential file and the plan.

The server's own answers are stood in for by a fake database that records what it was sent. That the
SQL is accepted by a real PostgreSQL, and that the login it makes can connect and migrate, is
shown by hetzner/provision/test_control_plane_migrator_login_server.py against the stack's
pinned image.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from unittest import mock

import control_plane_db_login as login
from ansible.module_utils.basic import AnsibleModule

LOGIN = "portal_migrator_login"
DATABASE = "portal"
HOST = "db"
# Made for the test run; none is a real secret.
THROWAWAY = "THROWAWAY-password-0123456789abcdef"  # noqa: S105
GOOD_ROW = ["f", "f", "f", "f", "f", "t", ""]


class FakeModule:
    """Stands in for AnsibleModule where the module writes a file."""

    def atomic_move(self, src: str, dest: str, unsafe_writes: bool = False) -> None:
        """Replace dest with src, as the real one does."""
        os.replace(src, dest)


def completed(
    stdout: str = "", returncode: int = 0, stderr: str = ""
) -> "subprocess.CompletedProcess[str]":
    """A finished program."""
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Server:
    """A fake database container: answers the module's questions and records its writes."""

    def __init__(self, role_row: str = "", owner: str = "postgres", left: int = 0) -> None:
        self.role_row = role_row
        self.owner = owner
        self.left = left
        self.calls: list[tuple[list[str], str]] = []

    def __call__(self, argv: Sequence[str], stdin: str) -> "subprocess.CompletedProcess[str]":
        self.calls.append((list(argv), stdin))
        if stdin.startswith("select rolsuper"):
            return completed(self.role_row)
        if stdin.startswith("select pg_catalog.pg_get_userbyid(datdba)"):
            return completed(self.owner + "\n" if self.owner else "")
        if stdin.rstrip().endswith("select count(*) from owned;"):
            return completed(f"{self.left}\n")
        return completed()

    def writes(self) -> list[str]:
        """The statements that change the server: everything but the three questions."""
        questions = ("select rolsuper", "select pg_catalog.pg_get_userbyid(datdba)")
        return [
            sql
            for _, sql in self.calls
            if not sql.startswith(questions)
            and not sql.rstrip().endswith("select count(*) from owned;")
        ]


def database(server: Server) -> login.Database:
    """A database handle over a fake server."""
    return login.Database("docker", "control-plane-db-1", LOGIN, DATABASE, server)


class VerifierTests(unittest.TestCase):
    def test_the_verifier_has_postgresql_s_stored_shape_and_is_keyed_by_the_salt(self) -> None:
        # That a real server accepts the verifier and the password connects with it is shown by
        # hetzner/provision/test_control_plane_migrator_login_server.py; here only the shape and
        # the keying.
        made = login.scram_verifier(THROWAWAY, b"0123456789abcdef")
        self.assertRegex(
            made,
            r"\ASCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{24}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}\Z",
        )
        self.assertNotEqual(made, login.scram_verifier(THROWAWAY, b"fedcba9876543210"))
        self.assertNotIn(THROWAWAY, made)

    def test_a_verifier_matches_its_own_password_and_no_other(self) -> None:
        made = login.scram_verifier(THROWAWAY, b"0123456789abcdef")
        self.assertTrue(login.verifier_matches(THROWAWAY, made))
        self.assertFalse(login.verifier_matches(THROWAWAY + "x", made))

    def test_a_malformed_or_empty_verifier_matches_nothing(self) -> None:
        for text in (
            "",
            "plain-text",
            "md5abcdef",
            "SCRAM-SHA-256$4096:!!!$a:b",
            "SCRAM-SHA-256$x:aa$b:c",
        ):
            with self.subTest(text=text):
                self.assertFalse(login.verifier_matches(THROWAWAY, text))


class CredentialFileTests(unittest.TestCase):
    def test_the_url_names_the_login_the_host_the_port_and_the_database(self) -> None:
        url = login.credential_url(LOGIN, THROWAWAY, HOST, DATABASE)
        self.assertEqual(url, f"postgres://{LOGIN}:{THROWAWAY}@db:5432/portal\n")

    def test_the_password_is_read_back_from_a_url_of_this_login_only(self) -> None:
        url = login.credential_url(LOGIN, THROWAWAY, HOST, DATABASE)
        self.assertEqual(login.password_in_url(url, LOGIN, HOST, DATABASE), THROWAWAY)
        for other in (
            url.replace(LOGIN, "portal_owner_login"),
            url.replace("@db:", "@elsewhere:"),
            url.replace(":5432", ":5433"),
            url.replace("/portal", "/postgres"),
            url.replace("postgres://", "mysql://"),
            url.rstrip("\n") + "?sslmode=disable\n",
            f"postgres://{LOGIN}@db:5432/portal\n",
            "",
        ):
            with self.subTest(other=other):
                self.assertIsNone(login.password_in_url(other, LOGIN, HOST, DATABASE))

    def test_a_password_that_is_not_one_url_component_of_enough_length_is_refused(self) -> None:
        short = login.credential_url(LOGIN, "short", HOST, DATABASE)
        self.assertIsNone(login.password_in_url(short, LOGIN, HOST, DATABASE))
        odd = f"postgres://{LOGIN}:{'a' * 23}%2F@db:5432/portal\n"
        self.assertIsNone(login.password_in_url(odd, LOGIN, HOST, DATABASE))

    def test_a_file_is_a_credential_only_while_the_server_holds_its_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "url"
            self.assertIsNone(login.credential_state(path, LOGIN, HOST, DATABASE, "x"))
            path.write_text(
                login.credential_url(LOGIN, THROWAWAY, HOST, DATABASE), encoding="utf-8"
            )
            right = login.scram_verifier(THROWAWAY, b"0123456789abcdef")
            wrong = login.scram_verifier("another-password-0123456789abc", b"0123456789abcdef")
            self.assertEqual(login.credential_state(path, LOGIN, HOST, DATABASE, right), THROWAWAY)
            self.assertIsNone(login.credential_state(path, LOGIN, HOST, DATABASE, wrong))
            self.assertIsNone(login.credential_state(path, LOGIN, HOST, DATABASE, ""))

    def test_the_file_is_created_0600_and_replaced_whole_with_no_wider_moment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "url"
            modes: list[int] = []
            real = login.tempfile_in

            def watch(parent: Path) -> tuple[int, str]:
                descriptor, name = real(parent)
                modes.append(stat.S_IMODE(os.stat(name).st_mode))
                return descriptor, name

            with mock.patch.object(login, "tempfile_in", watch):
                login.write_credential(cast(AnsibleModule, FakeModule()), path, "content\n")
            self.assertEqual(modes, [0o600])
            self.assertEqual(path.read_text(encoding="utf-8"), "content\n")
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["url"])


class PlanTests(unittest.TestCase):
    def role(self, **changes: bool) -> login.RoleRow:
        """The login as the manifest wants it, with changes."""
        values = {
            "superuser": False, "createrole": False, "createdb": False, "bypassrls": False,
            "replication": False, "canlogin": True,
        }  # fmt: skip
        values.update(changes)
        return login.RoleRow(verifier="v", **values)

    def test_a_host_with_nothing_makes_the_login_and_its_credential(self) -> None:
        plan = login.decide(None, False, "postgres", LOGIN, 7)
        self.assertEqual(
            plan.names(),
            [
                "made the login",
                "set the login's password and wrote its credential file",
                "handed the portal database to the login",
                "handed what the administrator owned in the portal database to the login",
            ],
        )

    def test_a_converged_host_has_nothing_to_do(self) -> None:
        self.assertEqual(login.decide(self.role(), True, LOGIN, LOGIN, 0).names(), [])

    def test_a_lost_or_stale_credential_sets_a_new_password_and_nothing_else(self) -> None:
        self.assertEqual(
            login.decide(self.role(), False, LOGIN, LOGIN, 0).names(),
            ["set the login's password and wrote its credential file"],
        )

    def test_a_wrong_attribute_is_put_right_without_a_new_password(self) -> None:
        for attribute in ("createdb", "createrole", "bypassrls", "replication"):
            with self.subTest(attribute=attribute):
                plan = login.decide(self.role(**{attribute: True}), True, LOGIN, LOGIN, 0)
                self.assertEqual(plan.names(), ["put the login's attributes right"])
        self.assertEqual(
            login.decide(self.role(canlogin=False), True, LOGIN, LOGIN, 0).names(),
            ["put the login's attributes right"],
        )

    def test_a_superuser_of_the_name_is_refused_not_altered(self) -> None:
        with self.assertRaises(login.LoginError) as caught:
            login.decide(self.role(superuser=True), True, LOGIN, LOGIN, 0)
        self.assertIn("superuser", str(caught.exception))

    def test_a_missing_database_is_not_handed_over(self) -> None:
        self.assertEqual(login.decide(self.role(), True, None, LOGIN, 0).names(), [])


class ApplyTests(unittest.TestCase):
    PARAMS = {"database": DATABASE, "login": LOGIN, "host": HOST, "container": "control-plane-db-1"}

    def apply(
        self, server: Server, directory: str, plan: login.Plan, role: login.RoleRow | None
    ) -> Path:
        """Apply a plan to a fake server and return the credential file's path."""
        path = Path(directory) / "url"
        params = {**self.PARAMS, "credential_file": str(path)}
        login.apply_plan(cast(AnsibleModule, FakeModule()), database(server), plan, role, params)
        return path

    def test_the_login_is_made_with_the_manifest_attributes_and_a_verifier_never_a_password(
        self,
    ) -> None:
        server = Server()
        with tempfile.TemporaryDirectory() as directory:
            plan = login.decide(None, False, "postgres", LOGIN, 3)
            path = self.apply(server, directory, plan, None)
            password = login.password_in_url(
                path.read_text(encoding="utf-8"), LOGIN, HOST, DATABASE
            )
            self.assertIsNotNone(password)
            self.assertGreaterEqual(len(cast(str, password)), 24)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        statements = server.writes()
        self.assertTrue(
            statements[0].startswith(f'create role "{LOGIN}" with login nosuperuser nocreatedb')
        )
        self.assertIn("nocreaterole noreplication nobypassrls", statements[0])
        self.assertIn("password 'SCRAM-SHA-256$4096:", statements[0])
        self.assertEqual(statements[1], f'alter database "{DATABASE}" owner to "{LOGIN}";\n')
        self.assertIn("\\gexec", statements[2])
        for argv, stdin in server.calls:
            self.assertNotIn(cast(str, password), stdin)
            self.assertNotIn(cast(str, password), " ".join(argv))

    def test_no_secret_is_in_any_argument(self) -> None:
        server = Server()
        with tempfile.TemporaryDirectory() as directory:
            self.apply(server, directory, login.decide(None, False, "postgres", LOGIN, 0), None)
        for argv, _ in server.calls:
            self.assertEqual(argv[:6], ["docker", "exec", "-i", "control-plane-db-1", "sh", "-c"])
            self.assertIn('"${POSTGRES_PASSWORD:?', argv[6])
            self.assertEqual(len(argv), 11)
            self.assertEqual(argv[7], "sh")
            self.assertEqual(argv[9:], [LOGIN, DATABASE])

    def test_an_existing_login_is_altered_not_created(self) -> None:
        server = Server()
        existing = login.RoleRow(False, False, True, False, False, True, "old")
        with tempfile.TemporaryDirectory() as directory:
            self.apply(server, directory, login.decide(existing, False, LOGIN, LOGIN, 0), existing)
        self.assertTrue(
            server.writes()[0].startswith(f'alter role "{LOGIN}" with login nosuperuser')
        )

    def test_a_converged_host_sends_no_statement_and_writes_no_file(self) -> None:
        server = Server()
        with tempfile.TemporaryDirectory() as directory:
            right = login.RoleRow(False, False, False, False, False, True, "v")
            path = self.apply(server, directory, login.decide(right, True, LOGIN, LOGIN, 0), right)
            self.assertFalse(path.exists())
        self.assertEqual(server.calls, [])

    def test_the_file_is_written_after_the_server_so_a_failed_statement_leaves_none(self) -> None:
        def refuse(argv: Sequence[str], stdin: str) -> "subprocess.CompletedProcess[str]":
            return completed("", 1, "ERROR: permission denied")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "url"
            params = {**self.PARAMS, "credential_file": str(path)}
            handle = login.Database("docker", "c", LOGIN, DATABASE, refuse)
            with self.assertRaises(login.LoginError):
                login.apply_plan(
                    cast(AnsibleModule, FakeModule()),
                    handle,
                    login.decide(None, False, None, LOGIN, 0),
                    None,
                    params,
                )
            self.assertFalse(path.exists())

    def test_a_failure_never_quotes_the_password_or_the_verifier(self) -> None:
        captured: list[str] = []

        def echo(argv: Sequence[str], stdin: str) -> "subprocess.CompletedProcess[str]":
            captured.append(stdin)
            return completed("", 1, f"ERROR: syntax error LINE 1: {stdin}")

        handle = login.Database("docker", "c", LOGIN, DATABASE, echo)
        with tempfile.TemporaryDirectory() as directory:
            params = {**self.PARAMS, "credential_file": str(Path(directory) / "url")}
            with self.assertRaises(login.LoginError) as caught:
                login.apply_plan(
                    cast(AnsibleModule, FakeModule()),
                    handle,
                    login.decide(None, False, None, LOGIN, 0),
                    None,
                    params,
                )
        message = handle.redact(str(caught.exception))
        verifier = [
            word
            for word in captured[0].replace("'", " ").split()
            if word.startswith("SCRAM-SHA-256$")
        ][0]
        self.assertNotIn(verifier, message)
        self.assertIn("<hidden>", message)


class ParameterTests(unittest.TestCase):
    GOOD = {"database": DATABASE, "login": LOGIN, "host": HOST, "container": "control-plane-db-1"}

    def test_a_good_set_of_parameters_is_accepted(self) -> None:
        login.check_params(self.GOOD)

    def test_a_name_that_is_not_the_shape_of_what_it_names_is_refused_before_anything_runs(
        self,
    ) -> None:
        for change in (
            {"database": 'portal"; drop database x; --'},
            {"login": "Portal"},
            {"login": ""},
            {"host": "db; reboot"},
            {"container": "--privileged"},
            {"container": "two words"},
        ):
            with self.subTest(change=change):
                with self.assertRaises(login.LoginError):
                    login.check_params({**self.GOOD, **change})


class DocumentationTests(unittest.TestCase):
    def test_the_documented_options_are_the_ones_the_module_takes(self) -> None:
        from ruamel.yaml import YAML

        documented = cast(dict[str, dict[str, object]], YAML(typ="safe").load(login.DOCUMENTATION))[
            "options"
        ]
        source = Path(login.__file__).read_text(encoding="utf-8")
        for name in documented:
            self.assertIn(f'"{name}":', source, name)
        self.assertEqual(
            set(documented), {"container", "database", "login", "credential_file", "host", "docker"}
        )

    def test_the_module_reads_no_password_and_puts_none_in_an_argument(self) -> None:
        source = Path(login.__file__).read_text(encoding="utf-8")
        self.assertNotIn("PGPASSWORD=", source.replace('PGPASSWORD="${POSTGRES_PASSWORD', ""))
        self.assertEqual(source.count("control-plane.env"), 1, "only the docstring names the file")


if __name__ == "__main__":
    unittest.main()
