#!/usr/bin/env python3
"""Runs the migration login's module against a real PostgreSQL at the stack's pinned image.

The unit tests stand a fake in for the server. This starts the image the stack pins, builds a
database as the earlier provision left it (owned by the administrator), and shows that the module's
SQL is accepted, that the login it makes connects with the password in its file (the server checks
it: the connection is not to the image's trusted loopback address), does the work a migration does
and nothing a migrator may not, and that a second run changes nothing. It needs a local Docker and
the image; without one it fails, because a skipped role test is a control that does not run.
"""

# The programs are docker and the test's own SQL on a throwaway container: nothing is untrusted.

import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import cast

import control_plane_db_login as login
from ansible.module_utils.basic import AnsibleModule

COMPOSE = (
    Path(__file__).resolve().parents[5] / "hetzner" / "control-plane" / "stack" / "compose.yml"
)
IMAGE_PIN = re.compile(r"^\s*image:\s*(\S*postgres\S*@sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
TEST_RUN_LABEL = "branchleft.test-run"
LOGIN = "portal_migrator_login"
DATABASE = "portal"
HOST = "db"
START_TIMEOUT_SECONDS = 90
COMMAND_TIMEOUT_SECONDS = 60

# A database made before the login existed: every kind of object the migrations make, owned by the
# administrator, as the earlier provision left them.
OLD_STYLE_DATABASE = """
create schema drizzle;
create table drizzle.__drizzle_migrations (id serial primary key, hash text);
create type public.state as enum ('a', 'b');
create table public.tenant (id serial primary key, s public.state);
create view public.tenant_view as select * from public.tenant;
create sequence public.standalone;
create function public.identity(x integer) returns integer language sql as 'select x';
"""


class Module:
    """Stands in for AnsibleModule where the module writes its file."""

    def atomic_move(self, src: str, dest: str, unsafe_writes: bool = False) -> None:
        """Replace dest with src, as the real one does."""
        os.replace(src, dest)


def docker_problem() -> str | None:
    """Why this test cannot use a local container engine, or None when it can."""
    if os.environ.get("DOCKER_HOST"):
        return "DOCKER_HOST is set, so the engine may be remote; this test uses a local one only"
    if shutil.which("docker") is None:
        return "there is no docker command"
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "the docker engine did not answer"
    return None if result.returncode == 0 else "the docker engine is not running"


def image_reference() -> str:
    """The database image exactly as the stack pins it, read from compose.yml.

    Raises:
        AssertionError: compose.yml does not hold exactly one PostgreSQL image pin.
    """
    found = IMAGE_PIN.findall(COMPOSE.read_text(encoding="utf-8"))
    if len(found) != 1:
        message = f"expected one PostgreSQL image pin in compose.yml, found {len(found)}"
        raise AssertionError(message)
    return str(found[0])


class MigratorLoginAgainstARealServerTests(unittest.TestCase):
    """The module's SQL, its verifier and its file, shown on a server and not on a stand-in."""

    run_id: str
    container: str

    @classmethod
    def setUpClass(cls) -> None:
        problem = docker_problem()
        if problem is not None:
            message = f"this test needs a local Docker and cannot skip: {problem}"
            raise AssertionError(message)
        cls.run_id = uuid.uuid4().hex[:12]
        cls.container = f"cpdb-login-test-{cls.run_id}"
        # The administrator's password, as the stack gives the container: in its environment.
        admin_password = f"throwaway-{secrets.token_hex(12)}"
        started = subprocess.run(
            [
                "docker", "run", "--detach", "--rm", "--name", cls.container,
                "--label", f"{TEST_RUN_LABEL}={cls.run_id}",
                "--env", "POSTGRES_USER=postgres",
                "--env", f"POSTGRES_PASSWORD={admin_password}",
                image_reference(),
            ],
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT_SECONDS,
            check=False,
        )  # fmt: skip
        if started.returncode != 0:
            message = f"the database container did not start: {started.stderr.strip()[:300]}"
            raise AssertionError(message)
        cls.addClassCleanup(cls.remove)
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            # The image restarts its server once after initialising: one answer is not enough.
            ready = [cls.admin("postgres", "select 1") for _ in range(3)]
            if all(answer == "1" for answer in ready):
                return
            time.sleep(1)
        message = "the database did not become ready in time"
        raise AssertionError(message)

    @classmethod
    def remove(cls) -> None:
        """Remove the container this class started."""
        subprocess.run(
            ["docker", "rm", "--force", "--volumes", cls.container],
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )

    @classmethod
    def admin(cls, database: str, sql: str) -> str:
        """Run SQL as the administrator inside the container and return its trimmed output."""
        done = subprocess.run(
            ["docker", "exec", "-i", cls.container, "sh", "-c",
             'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U postgres -d "$1" '
             "-v ON_ERROR_STOP=1 -qtA", "sh", database],
            input=sql,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )  # fmt: skip
        output = done.stdout if done.returncode == 0 else f"ERROR {done.stderr[:200]}"
        return output.strip()

    def as_login(self, password: str, sql: str) -> subprocess.CompletedProcess[str]:
        """Run SQL as the migration login, with its password checked by the server.

        The image's own rules trust the loopback address, so the connection is made to the
        container's own address, where the rule asks for a SCRAM password.
        """
        shell = 'exec psql -h "$(hostname -i)" -U "$1" -d "$2" -v ON_ERROR_STOP=1 -qtA'
        return subprocess.run(
            ["docker", "exec", "-i", "--env", f"PGPASSWORD={password}", self.container,
             "sh", "-c", shell, "sh", LOGIN, DATABASE],
            input=sql,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )  # fmt: skip

    def handle(self) -> login.Database:
        """A handle on the database through the real docker."""
        return login.Database("docker", self.container, LOGIN, DATABASE, login.run_process)

    def run_module(self, directory: Path) -> list[str]:
        """Do what the module does in one run, and return the actions it names."""
        handle = self.handle()
        role = login.read_role(handle)
        rows = handle.query("postgres", login.DATABASE_SQL)
        owner = rows[0][0] if rows else None
        left = 0
        if owner is not None:
            counted = handle.query(
                DATABASE, login.OWNED_BY_ADMIN_SQL + "select count(*) from owned;\n"
            )
            left = int(counted[0][0])
        path = directory / "migrator-url"
        ok = (
            role is not None
            and login.credential_state(path, LOGIN, HOST, DATABASE, role.verifier) is not None
        )
        plan = login.decide(role, ok, owner, LOGIN, left)
        params = {
            "container": self.container, "database": DATABASE, "login": LOGIN,
            "credential_file": str(path), "host": HOST,
        }  # fmt: skip
        login.apply_plan(cast(AnsibleModule, Module()), handle, plan, role, params)
        return plan.names()

    def reset(self) -> None:
        """Put the server back to a database made before the login existed."""
        self.admin("postgres", f"drop database if exists {DATABASE}; drop role if exists {LOGIN};")
        self.admin("postgres", f"create database {DATABASE};")
        self.assertEqual(self.admin(DATABASE, OLD_STYLE_DATABASE), "")

    def test_an_old_database_is_handed_to_a_login_that_connects_migrates_and_can_do_no_more(
        self,
    ) -> None:
        self.reset()
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            actions = self.run_module(where)
            self.assertEqual(len(actions), 4, actions)
            path = where / "migrator-url"
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            password = login.password_in_url(
                path.read_text(encoding="utf-8"), LOGIN, HOST, DATABASE
            )
            self.assertIsNotNone(password)
            # The login connects with the file's password and does the work a migration does.
            work = self.as_login(
                str(password),
                "create table made_by_a_migration (id integer); "
                "alter table made_by_a_migration add column note text; "
                "alter table public.tenant add column note text; "
                "drop table made_by_a_migration; select 'migrated'",
            )
            self.assertEqual(
                (work.returncode, work.stdout.strip().splitlines()[-1]),
                (0, "migrated"),
                work.stderr,
            )
            # What the manifest forbids a migrator, each refused for want of privilege.
            for forbidden in (
                "create role made_by_the_migrator",
                "select count(*) from pg_authid",
                "alter system set work_mem = '8MB'",
            ):
                with self.subTest(forbidden=forbidden):
                    refused = self.as_login(str(password), forbidden)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertIn("permission denied", refused.stderr)
            # The server holds what the manifest says of the login, and the objects are the login's.
            self.assertEqual(
                self.admin(
                    "postgres",
                    "select rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, "
                    "rolcanlogin "
                    f"from pg_roles where rolname = '{LOGIN}'",
                ),
                "f|f|f|f|f|t",
            )
            self.assertEqual(
                self.admin(
                    "postgres",
                    f"select pg_get_userbyid(datdba) from pg_database where datname = '{DATABASE}'",
                ),
                LOGIN,
            )
            self.assertEqual(
                self.admin(
                    DATABASE,
                    "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace "
                    "where n.nspname in ('public', 'drizzle') and c.relkind in ('r', 'S', 'v') "
                    f"and pg_get_userbyid(c.relowner) <> '{LOGIN}'",
                ),
                "0",
            )
            # Nothing else changed hands: the other databases are still the administrator's.
            self.assertEqual(
                self.admin(
                    "postgres",
                    "select pg_get_userbyid(datdba) from pg_database where datname = 'postgres'",
                ),
                "postgres",
            )
            # A second run has nothing to do and writes nothing.
            before = path.read_text(encoding="utf-8")
            self.assertEqual(self.run_module(where), [])
            self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_a_lost_credential_is_replaced_and_the_old_password_stops_working(self) -> None:
        self.reset()
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            self.run_module(where)
            path = where / "migrator-url"
            old = str(
                login.password_in_url(path.read_text(encoding="utf-8"), LOGIN, HOST, DATABASE)
            )
            path.unlink()
            self.assertEqual(
                self.run_module(where), ["set the login's password and wrote its credential file"]
            )
            new = str(
                login.password_in_url(path.read_text(encoding="utf-8"), LOGIN, HOST, DATABASE)
            )
            self.assertNotEqual(old, new)
            self.assertEqual(self.as_login(new, "select 1").returncode, 0)
            self.assertNotEqual(self.as_login(old, "select 1").returncode, 0)

    def test_a_wrong_attribute_is_put_right_and_the_password_is_kept(self) -> None:
        self.reset()
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            self.run_module(where)
            path = where / "migrator-url"
            kept = path.read_text(encoding="utf-8")
            self.admin("postgres", f"alter role {LOGIN} createdb createrole")
            self.assertEqual(self.run_module(where), ["put the login's attributes right"])
            self.assertEqual(path.read_text(encoding="utf-8"), kept)
            self.assertEqual(
                self.admin(
                    "postgres",
                    f"select rolcreatedb, rolcreaterole from pg_roles where rolname = '{LOGIN}'",
                ),
                "f|f",
            )

    def test_a_superuser_of_the_name_is_refused_and_left_as_it_is(self) -> None:
        self.reset()
        self.admin("postgres", f"create role {LOGIN} login superuser")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(login.LoginError):
                self.run_module(Path(directory))
        self.assertEqual(
            self.admin("postgres", f"select rolsuper from pg_roles where rolname = '{LOGIN}'"), "t"
        )


if __name__ == "__main__":
    unittest.main()
