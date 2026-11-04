#!/usr/bin/env python3
"""Starts a real PostgreSQL on the control-plane pg_hba.conf and connects to it.

See test_control_plane_hba_server.md.
"""

import concurrent.futures
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

if sys.version_info < (3, 10):
    raise RuntimeError(
        "test_control_plane_hba_server.py requires Python 3.10 or newer; running under "
        f"{sys.version.split()[0]}. On macOS, `/usr/bin/python3` is the system 3.9."
    )

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_control_plane_stack as stack  # noqa: E402  (needs the path above when run by file)

IMAGE_PIN = re.compile(r"^\s*image:\s*(\S*postgres\S*@sha256:[0-9a-f]{64})\s*$", re.MULTILINE)

# A login the file must refuse on every database, and a database that exists in
# no stack: a rule that names neither is still seen to refuse them.
STRANGER = "stranger"
PROBED_LOGINS = (*sorted(stack.EXPECTED_DATABASES), STRANGER)
PROBED_DATABASES = ("postgres", "zitadel", "portal", "template1")

# What the server says. pg_hba.conf is matched before the password is asked for, so
# the first line means the file refused the connection and the second means the file
# admitted it to authentication, where a wrong password then failed it.
REFUSED_BY_THE_FILE = "pg_hba.conf rejects connection"
ADMITTED_TO_AUTHENTICATION = "password authentication failed"

# A wrong password on purpose: the probe never needs a real one, and a value that
# worked would be a secret to keep. It is the same for every probe.
PROBE_PASSWORD = "wrong-on-purpose-for-the-hba-probe"

# The login the full provision's last step and every migrate-only run connect as. The
# manifest (ghost-platform, portal/data/provision/manifest.ts) makes it not a superuser,
# with no BYPASSRLS, owning the portal database. This test cannot run that program, so it
# stands the login in with Postgres' own defaults and shows what the server does with it.
MIGRATOR = "portal_migrator_login"

# Three actions only a superuser may take. Each is run as the migrator on a server where it
# has no attribute, where the server must refuse it for want of privilege, and again on a
# server where the administrator made it a superuser, where each must succeed, so a probe
# that could not tell the two apart would not pass.
SUPERUSER_ONLY_ACTIONS = {
    "create a role": "create role made_by_the_migrator",
    "read the password verifiers": "select count(*) from pg_authid",
    "alter the server's settings": "alter system set work_mem = '8MB'",
}
REFUSED_FOR_WANT_OF_PRIVILEGE = "permission denied"
# DDL in its own database: what a migration does.
OWN_DATABASE_DDL = "create table migrated (id integer); alter table migrated add column note text; drop table migrated"

START_TIMEOUT_SECONDS = 90
COMMAND_TIMEOUT_SECONDS = 60

RULE_PROVISIONER = re.compile(r"^host\s+portal\s+portal_provisioner_login\s.*\n", re.MULTILINE)
RULE_MIGRATOR = re.compile(r"^host\s+portal\s+portal_migrator_login\s.*\n", re.MULTILINE)
RULE_MIGRATOR_DATABASES = re.compile(r"^(host\s+)portal(\s+portal_migrator_login\b)", re.MULTILINE)
RULE_OWNER_DATABASES = re.compile(r"^(host\s+)portal(\s+portal_owner_login\b)", re.MULTILINE)
FIRST_REJECT = re.compile(r"^local\s+all\s+all\s+reject", re.MULTILINE)


def image_reference() -> str:
    """The database image exactly as the stack pins it, read from compose.yml."""
    found = IMAGE_PIN.findall(stack.compose_text())
    if len(found) != 1:
        raise AssertionError(f"expected one PostgreSQL image pin in compose.yml, found {len(found)}")
    return found[0]


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
    if result.returncode != 0:
        return "the docker engine is not running"
    return None


def dropping_the_provisioner_rule(text: str) -> str:
    """The file with the provisioner login's rule deleted."""
    return RULE_PROVISIONER.sub("", text)


def dropping_the_migrator_rule(text: str) -> str:
    """The file with the migrator login's rule deleted."""
    return RULE_MIGRATOR.sub("", text)


def letting_the_migrator_into_the_administrators_database(text: str) -> str:
    """The file with the migrator login's rule widened to the postgres database."""
    return RULE_MIGRATOR_DATABASES.sub(r"\1portal,postgres\2", text, count=1)


def letting_the_sign_in_login_into_portal(text: str) -> str:
    """The file with one more rule: the sign-in service's login on the portal database."""
    return FIRST_REJECT.sub("host portal zitadel samenet scram-sha-256\n\\g<0>", text, count=1)


def letting_the_owner_login_into_the_sign_in_database(text: str) -> str:
    """The file with the owner login's rule widened to the sign-in service's database."""
    return RULE_OWNER_DATABASES.sub(r"\1portal,zitadel\2", text, count=1)


# Each sabotage is a change to a copy of the real file that must make the server
# admit or refuse a pair the table says it should not. The cells are the pairs
# that must flip, so a sabotage that changed nothing, or the wrong thing, is red.
SABOTAGES = {
    "no_provisioner_rule": (dropping_the_provisioner_rule, {("portal_provisioner_login", "portal"): False}),
    "no_migrator_rule": (dropping_the_migrator_rule, {("portal_migrator_login", "portal"): False}),
    "migrator_in_postgres_database": (
        letting_the_migrator_into_the_administrators_database,
        {("portal_migrator_login", "postgres"): True},
    ),
    "sign_in_login_in_portal": (letting_the_sign_in_login_into_portal, {("zitadel", "portal"): True}),
    "owner_login_in_sign_in_database": (
        letting_the_owner_login_into_the_sign_in_database,
        {("portal_owner_login", "zitadel"): True},
    ),
}


def expected_matrix() -> dict[tuple[str, str], bool]:
    """For each login and database, whether the file admits the pair to authentication."""
    return {
        (login, database): database in stack.EXPECTED_DATABASES.get(login, frozenset())
        for login in PROBED_LOGINS
        for database in PROBED_DATABASES
    }


class Server:
    """One throwaway PostgreSQL container, started on a given pg_hba.conf."""

    def __init__(self, run_id: str, label: str, hba_text: str, admin_password: str, directory: pathlib.Path) -> None:
        self.name = f"cp-hba-{run_id}-{label}"
        self.run_id = run_id
        self.hba_file = directory / f"{label}-pg_hba.conf"
        # A bind mount keeps the host's mode, and the server's account is not the owner.
        self.hba_file.write_text(hba_text, encoding="utf-8")
        self.hba_file.chmod(0o644)
        self._admin_password = admin_password
        self._migrator_password = ""
        self.started = False

    def start(self) -> None:
        """Start the container and wait until the real server, not the setup one, answers."""
        self.started = True
        # The administrator's password goes by the environment, never on the command
        # line, so it is in no process listing and in no file.
        subprocess.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                self.name,
                "--label",
                f"branchleft.test-run={self.run_id}",
                "--env",
                "POSTGRES_PASSWORD",
                "--volume",
                f"{self.hba_file}:/etc/postgresql/pg_hba.conf:ro",
                image_reference(),
                "postgres",
                "-c",
                "hba_file=/etc/postgresql/pg_hba.conf",
            ],
            env={**os.environ, "POSTGRES_PASSWORD": self._admin_password},
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS * 4,
            check=True,
        )
        deadline = START_TIMEOUT_SECONDS
        for _ in range(deadline):
            ready = subprocess.run(
                ["docker", "exec", self.name, "pg_isready", "-h", "127.0.0.1", "-p", "5432"],
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
            if ready.returncode == 0:
                return
            time.sleep(1)
        raise AssertionError(f"{self.name} did not accept connections in {deadline}s:\n{self.logs()}")

    def logs(self) -> str:
        """The last lines the server printed; it prints no password."""
        result = subprocess.run(
            ["docker", "logs", "--tail", "40", self.name],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        return result.stdout + result.stderr

    def probe(self, login: str, database: str) -> bool:
        """True when the file admitted this login on this database to authentication."""
        result = subprocess.run(
            [
                "docker",
                "exec",
                "--env",
                f"PGPASSWORD={PROBE_PASSWORD}",
                self.name,
                "psql",
                "--host=127.0.0.1",
                "--port=5432",
                f"--username={login}",
                f"--dbname={database}",
                "--no-password",
                "--no-psqlrc",
                "--command=select 1",
            ],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        if ADMITTED_TO_AUTHENTICATION in result.stderr:
            return True
        if REFUSED_BY_THE_FILE in result.stderr:
            return False
        raise AssertionError(f"{login} on {database}: neither refused by the file nor failed at the password: {result.stderr!r}")

    def psql(
        self,
        login: str,
        database: str,
        password: str,
        *,
        command: str | None = None,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run psql as a login that really exists. The password reaches psql by environment name only."""
        arguments = [
            "docker",
            "exec",
            "--interactive",
            "--env",
            "PGPASSWORD",
            self.name,
            "psql",
            "--host=127.0.0.1",
            "--port=5432",
            f"--username={login}",
            f"--dbname={database}",
            "--no-password",
            "--no-psqlrc",
            "--set=ON_ERROR_STOP=1",
            "--tuples-only",
            "--no-align",
        ]
        arguments.append(f"--command={command}" if command is not None else "--file=-")
        return subprocess.run(
            arguments,
            env={**os.environ, "PGPASSWORD": password},
            input=stdin or "",
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )

    def create_migrator(self, migrator_password: str, *, superuser: bool) -> None:
        """Have the administrator make the portal database and the migrator, as the manifest's owner of it.

        The role is made with Postgres defaults, so no attribute is granted: not superuser,
        not createrole, not createdb, not replication, not bypassrls. The superuser case adds
        the one attribute the boundary rests on. The migrator's password goes by standard
        input, so it is in no argument, no file and no process listing.
        """
        attribute = " SUPERUSER" if superuser else ""
        result = self.psql(
            "postgres",
            "postgres",
            self._admin_password,
            stdin=(
                f"CREATE ROLE {MIGRATOR} LOGIN{attribute} PASSWORD '{migrator_password}';\n"
                f"CREATE DATABASE portal OWNER {MIGRATOR};\n"
            ),
        )
        if result.returncode != 0:
            # The first line only: a later one can quote the statement, and the statement holds the password.
            first_line = result.stderr.splitlines()[0] if result.stderr else ""
            raise AssertionError(f"{self.name} could not make the migrator: {first_line!r}")
        self._migrator_password = migrator_password

    def as_migrator(self, database: str, command: str) -> subprocess.CompletedProcess[str]:
        """Run one command as the migrator, through the delivered file."""
        return self.psql(MIGRATOR, database, self._migrator_password, command=command)

    def migrator_attributes(self) -> str:
        """The migrator's superuser, createrole, createdb, replication and bypassrls flags, read by the administrator."""
        result = self.psql(
            "postgres",
            "postgres",
            self._admin_password,
            command=(
                "select rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls "
                f"from pg_roles where rolname = '{MIGRATOR}'"
            ),
        )
        return result.stdout.strip()

    def matrix(self) -> dict[tuple[str, str], bool]:
        """The admit-or-refuse answer for every probed login and database."""
        pairs = [(login, database) for login in PROBED_LOGINS for database in PROBED_DATABASES]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            return dict(zip(pairs, pool.map(lambda pair: self.probe(*pair), pairs), strict=True))

    def remove(self) -> None:
        """Remove this run's container and its anonymous volume, and nothing else."""
        subprocess.run(
            ["docker", "rm", "--force", "--volumes", self.name],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )


def differences(actual: dict[tuple[str, str], bool], expected: dict[tuple[str, str], bool]) -> dict[tuple[str, str], bool]:
    """The cells where the server's answer is not the expected one, with the server's answer."""
    return {cell: answer for cell, answer in actual.items() if answer != expected[cell]}


class ControlPlaneHbaServerTests(unittest.TestCase):
    servers: dict[str, Server]
    superuser_server: Server
    matrices: dict[str, dict[tuple[str, str], bool]]
    vacuous: set[str]
    _directory: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        problem = docker_problem()
        if problem is not None:
            if os.environ.get("CI"):
                raise AssertionError(f"CI must run the real-server proof, and {problem}")
            raise unittest.SkipTest(f"the real-server proof needs a local docker engine: {problem}")
        cls._directory = tempfile.TemporaryDirectory(prefix="cp-hba-")
        cls.addClassCleanup(cls._directory.cleanup)
        run_id = uuid.uuid4().hex[:12]
        admin_password = secrets.token_urlsafe(32)
        real = stack.PG_HBA.read_text(encoding="utf-8")
        directory = pathlib.Path(cls._directory.name)
        cls.servers = {"real": Server(run_id, "real", real, admin_password, directory)}
        cls.vacuous = set()
        for label, (sabotage, _flips) in SABOTAGES.items():
            sabotaged = sabotage(real)
            if sabotaged == real:
                # Its own test fails, and the others still run against the real file.
                cls.vacuous.add(label)
                continue
            cls.servers[label] = Server(run_id, label, sabotaged, admin_password, directory)
        # Registered before anything starts, so a failed start still removes what began.
        for server in cls.servers.values():
            cls.addClassCleanup(server.remove)
        # The control server: the same real file, but the administrator makes the migrator a superuser.
        cls.superuser_server = Server(run_id, "superuser", real, admin_password, directory)
        cls.addClassCleanup(cls.superuser_server.remove)
        everything = [*cls.servers.values(), cls.superuser_server]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(everything)) as pool:
            list(pool.map(lambda server: server.start(), everything))
        cls.matrices = {label: server.matrix() for label, server in cls.servers.items()}
        # After the matrix, which is read before any login exists, the migrator is made on the
        # real file's server with Postgres' defaults and on the control server as a superuser.
        # Random per run, and never printed.
        cls.servers["real"].create_migrator(secrets.token_urlsafe(32), superuser=False)
        cls.superuser_server.create_migrator(secrets.token_urlsafe(32), superuser=True)

    def test_the_real_file_admits_each_login_to_its_own_database_and_refuses_the_rest(self) -> None:
        self.assertEqual(differences(self.matrices["real"], expected_matrix()), {})

    def test_the_provisioner_login_reaches_authentication_on_the_portal_database(self) -> None:
        self.assertTrue(self.matrices["real"][("portal_provisioner_login", "portal")])

    def test_the_migrator_login_reaches_authentication_on_the_portal_database_alone(self) -> None:
        matrix = self.matrices["real"]
        self.assertTrue(matrix[(MIGRATOR, "portal")])
        for database in PROBED_DATABASES:
            if database != "portal":
                self.assertFalse(matrix[(MIGRATOR, database)], database)

    def test_dropping_the_migrator_rule_is_seen(self) -> None:
        self._assert_sabotage_flips("no_migrator_rule")

    def test_letting_the_migrator_into_the_postgres_database_is_seen(self) -> None:
        self._assert_sabotage_flips("migrator_in_postgres_database")

    def test_the_migrator_made_with_postgres_defaults_holds_no_attribute(self) -> None:
        # rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
        self.assertEqual(self.servers["real"].migrator_attributes(), "f|f|f|f|f")
        # A superuser's other flags are stored false; rolsuper alone is what the control server changes.
        self.assertEqual(self.superuser_server.migrator_attributes(), "t|f|f|f|f")

    def test_the_migrator_can_change_its_own_database_through_the_delivered_file(self) -> None:
        result = self.servers["real"].as_migrator("portal", OWN_DATABASE_DDL)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_migrator_is_refused_each_superuser_only_action(self) -> None:
        for action, command in SUPERUSER_ONLY_ACTIONS.items():
            with self.subTest(action=action):
                result = self.servers["real"].as_migrator("portal", command)
                self.assertNotEqual(result.returncode, 0, f"the migrator was allowed to {action}")
                self.assertIn(REFUSED_FOR_WANT_OF_PRIVILEGE, result.stderr)

    def test_the_migrator_is_refused_by_the_file_on_another_database_even_with_its_own_password(self) -> None:
        result = self.servers["real"].as_migrator("postgres", "select 1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(REFUSED_BY_THE_FILE, result.stderr)

    def test_a_migrator_made_a_superuser_is_allowed_each_action_so_the_probes_can_tell(self) -> None:
        for action, command in SUPERUSER_ONLY_ACTIONS.items():
            with self.subTest(action=action):
                result = self.superuser_server.as_migrator("portal", command)
                self.assertEqual(result.returncode, 0, f"the superuser could not {action}: {result.stderr}")

    def test_dropping_the_provisioner_rule_is_seen(self) -> None:
        self._assert_sabotage_flips("no_provisioner_rule")

    def test_letting_the_sign_in_login_into_the_portal_database_is_seen(self) -> None:
        self._assert_sabotage_flips("sign_in_login_in_portal")

    def test_letting_the_owner_login_into_the_sign_in_database_is_seen(self) -> None:
        self._assert_sabotage_flips("owner_login_in_sign_in_database")

    def _assert_sabotage_flips(self, label: str) -> None:
        _sabotage, flips = SABOTAGES[label]
        self.assertNotIn(label, self.vacuous, f"the sabotage {label} changed nothing, so this control case proves nothing")
        self.assertEqual(differences(self.matrices[label], expected_matrix()), flips)


if __name__ == "__main__":
    unittest.main()
