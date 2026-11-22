#!/usr/bin/python3
"""The forced command of the tenant database host: create one tenant's database, and nothing else.

sshd runs this program as root through `sudo -n` for the controller's key, whatever the client
asked for, and leaves the client's request in SSH_ORIGINAL_COMMAND. That request is untrusted text
and is accepted in exactly one shape, `create-tenant-db NAME`, where NAME follows the tenant-name
rule. Anything else is refused before the database is contacted.

For a valid, free name the program makes the database `ghost_NAME`, one account that may connect
only from the application host, and one grant on that database alone. It writes the generated
password to standard output once, which is the delivery channel, and never to a file, the journal
or an argument. A name whose database or account already exists is refused and nothing is changed.

The database's root value is not read here: the running container's own client reads it from the
container's environment.

Standard error carries one line, `branchleft-tenant-db-entry: <outcome> reason=<code>`, built from
a fixed code. Exit status: 0 created, 2 refused request, 3 name exists, 4 busy, 5 the database
could not be reached or a statement failed. The role's README holds the full reasoning.
"""

from __future__ import annotations

import fcntl
import os
import re
import secrets
import subprocess
import sys
import syslog
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Final

# ----- The request -----

# The only command word. A request is this word, one space and a name, and nothing else.
COMMAND_WORD: Final = "create-tenant-db"

# Longer than any valid request by a wide margin: a request this long is refused before it is
# matched, so a pattern never runs over unbounded input.
MAX_REQUEST_LENGTH: Final = 128

# The tenant-name rule of ghost-platform's db/provision/naming.py, copied: this role may not import
# from it (ANS-12), and a test holds the two equal. \A and \Z, never ^ and $, because $ also
# matches before a trailing line break.
TENANT_NAME_PATTERN: Final = re.compile(r"\A[a-z]([a-z0-9-]*[a-z0-9])?\Z")
TENANT_DB_PREFIX: Final = "ghost_"
MAX_MYSQL_ACCOUNT_NAME_LENGTH: Final = 32
MAX_TENANT_NAME_LENGTH: Final = MAX_MYSQL_ACCOUNT_NAME_LENGTH - len(TENANT_DB_PREFIX)

REQUEST_PATTERN: Final = re.compile(rf"\A{re.escape(COMMAND_WORD)} (?P<name>[a-z0-9-]+)\Z")

# ----- The database -----

# The only address the tenant's account may connect from: the application host's private address
# (hetzner-host/addressPlan.ts, TENANTS_HOST_IPS.appT1; a test holds the two equal). A narrower
# scope than the subnet: no other host of the project can use a tenant's password.
TENANT_USER_HOST: Final = "10.20.1.201"
MAX_USER_CONNECTIONS: Final = 10

# Where the stack's database container is found: the compose project and service the db_t1 role
# renders. Exactly one running container must match.
COMPOSE_PROJECT: Final = "dbt1"
COMPOSE_SERVICE: Final = "mysql"
DOCKER: Final = "/usr/bin/docker"
CONTAINER_ID_PATTERN: Final = re.compile(r"\A[0-9a-f]{64}\Z")

# Run inside the container, whose environment holds the root value. The client is told nothing
# secret on its command line: the value is moved into the client's own environment by the shell
# the container already has, and the statements arrive on standard input.
CLIENT_SCRIPT: Final = (
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --protocol=socket '
    "--socket=/var/run/mysqld/mysqld.sock --user=root --batch --skip-column-names"
)

LOCK_PATH: Final = "/run/lock/branchleft-tenant-db-entry.lock"
SYSLOG_IDENT: Final = "branchleft-tenant-db-entry"

# A request that must not be allowed to wait for ever.
DOCKER_TIMEOUT_SECONDS: Final = 120

EXIT_CREATED: Final = 0
EXIT_REFUSED: Final = 2
EXIT_EXISTS: Final = 3
EXIT_BUSY: Final = 4
EXIT_FAILED: Final = 5


class RefusalError(Exception):
    """A request the program will not serve: a fixed reason code and the exit status it carries."""

    def __init__(self, reason: str, status: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class Created:
    """What a successful request made. The password is the only copy there will be."""

    database: str
    user: str
    host: str
    password: str


# Runs one fixed argument list with the given standard input and returns the finished process. The
# default is `run_command`; the tests pass a stand-in for the container runtime.
Runner = Callable[[Sequence[str], str], "subprocess.CompletedProcess[str]"]


# ----- Parsing -----


def parse_request(original: str | None) -> str:
    """The tenant name in a request. The request is the whole of SSH_ORIGINAL_COMMAND.

    Raises:
        RefusalError: the request is absent, too long, not the one command, or names a bad tenant.
    """
    if original is None:
        raise RefusalError("no-command", EXIT_REFUSED)
    if len(original) > MAX_REQUEST_LENGTH:
        raise RefusalError("request-too-long", EXIT_REFUSED)
    match = REQUEST_PATTERN.match(original)
    if match is None:
        raise RefusalError("bad-command", EXIT_REFUSED)
    name = match.group("name")
    if TENANT_NAME_PATTERN.match(name) is None:
        raise RefusalError("bad-name", EXIT_REFUSED)
    if len(name) > MAX_TENANT_NAME_LENGTH:
        raise RefusalError("bad-name", EXIT_REFUSED)
    return name


def database_name(tenant_name: str) -> str:
    """The database and account name for a validated tenant name."""
    return f"{TENANT_DB_PREFIX}{tenant_name.replace('-', '_')}"


def grant_pattern(database: str) -> str:
    """The database name as a GRANT target; an unescaped underscore is a wildcard."""
    return database.replace("\\", "\\\\").replace("_", "\\_").replace("%", "\\%")


# ----- Statements -----


def existence_query(database: str) -> str:
    """One row of two counts: accounts of this name at any host, and databases of this name."""
    # `database` is a validated tenant name, never request text.
    return (
        f"SELECT (SELECT COUNT(*) FROM mysql.user WHERE User = '{database}'), "  # noqa: S608
        f"(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '{database}');\n"
    )


def create_statements(database: str, password: str) -> str:
    """The statements that make the database, its account and its one grant."""
    account = f"'{database}'@'{TENANT_USER_HOST}'"
    # `database` is a validated tenant name and `password` a generated URL-safe token.
    return (  # noqa: S608
        f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
        f"CREATE USER {account} IDENTIFIED BY '{password}' "
        f"WITH MAX_USER_CONNECTIONS {MAX_USER_CONNECTIONS};\n"
        f"GRANT ALL PRIVILEGES ON `{grant_pattern(database)}`.* TO {account};\n"
        "FLUSH PRIVILEGES;\n"
    )


# ----- The database container -----


def _clean_environment() -> dict[str, str]:
    """What a child process gets: a fixed path and nothing that arrived with the request."""
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def run_command(argv: Sequence[str], stdin: str) -> subprocess.CompletedProcess[str]:
    """Run one fixed argument list with the given standard input, and capture what it prints.

    Raises:
        RefusalError: the program could not be started or did not finish in time.
    """
    try:
        return subprocess.run(  # noqa: S603 - an argument list the module builds, never a shell line
            list(argv),
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            env=_clean_environment(),
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RefusalError("no-database", EXIT_FAILED) from error


def find_container(run: Runner) -> str:
    """The id of the one running database container.

    Raises:
        RefusalError: no container, or more than one, matches.
    """
    argv = [
        DOCKER,
        "ps",
        "--quiet",
        "--no-trunc",
        "--filter",
        f"label=com.docker.compose.project={COMPOSE_PROJECT}",
        "--filter",
        f"label=com.docker.compose.service={COMPOSE_SERVICE}",
        "--filter",
        "status=running",
    ]
    result = run(argv, "")
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != 1 or CONTAINER_ID_PATTERN.match(lines[0]) is None:
        raise RefusalError("no-database", EXIT_FAILED)
    return lines[0]


def run_sql(run: Runner, container: str, statements: str) -> str:
    """Run statements in the container's client and return what it printed.

    The server's own error text is never relayed: it can quote a statement, and a statement can
    carry the password. Only the fixed reason `sql-failed` leaves this function.

    Raises:
        RefusalError: the client exited with an error.
    """
    argv = [DOCKER, "exec", "--interactive", container, "sh", "-c", CLIENT_SCRIPT]
    result = run(argv, statements)
    if result.returncode != 0:
        raise RefusalError("sql-failed", EXIT_FAILED)
    return result.stdout


def counts_say_free(output: str) -> bool:
    """True only when the existence query returned exactly one row, 0 and 0."""
    return output.splitlines() == ["0\t0"]


# ----- The request, served -----


def create_tenant_database(
    tenant_name: str,
    *,
    run: Runner = run_command,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
) -> Created:
    """Make one tenant's database if neither its account nor its database exists.

    Raises:
        RefusalError: the container is not found, the name exists, or a statement failed.
    """
    database = database_name(tenant_name)
    container = find_container(run)
    if not counts_say_free(run_sql(run, container, existence_query(database))):
        raise RefusalError("exists", EXIT_EXISTS)
    password = password_factory()
    run_sql(run, container, create_statements(database, password))
    return Created(database=database, user=database, host=TENANT_USER_HOST, password=password)


def _hold_lock(path: str) -> IO[str]:
    """One request at a time. The caller keeps the returned file open until it is done.

    Raises:
        RefusalError: another request holds the lock.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    handle = os.fdopen(descriptor, "w")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        handle.close()
        raise RefusalError("busy", EXIT_BUSY) from error
    return handle


def _log(message: str) -> None:
    syslog.openlog(SYSLOG_IDENT, syslog.LOG_PID, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_INFO, message)


def serve(
    argv: Sequence[str],
    environ: Mapping[str, str],
    *,
    run: Runner,
    lock_path: str,
    password_factory: Callable[[], str],
) -> Created:
    """Check the request and make the database.

    Raises:
        RefusalError: any reason the request is not served.
    """
    if len(argv) != 0:
        raise RefusalError("arguments", EXIT_REFUSED)
    name = parse_request(environ.get("SSH_ORIGINAL_COMMAND"))
    lock = _hold_lock(lock_path)
    try:
        return create_tenant_database(name, run=run, password_factory=password_factory)
    finally:
        lock.close()


def main(
    argv: Sequence[str],
    environ: Mapping[str, str],
    stdout: IO[str],
    stderr: IO[str],
    *,
    run: Runner = run_command,
    lock_path: str = LOCK_PATH,
    log: Callable[[str], None] = _log,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
) -> int:
    """Serve the request in SSH_ORIGINAL_COMMAND and return the exit status."""
    try:
        created = serve(
            argv, environ, run=run, lock_path=lock_path, password_factory=password_factory
        )
    except RefusalError as refusal:
        log(f"refused reason={refusal.reason}")
        stderr.write(f"{SYSLOG_IDENT}: refused reason={refusal.reason}\n")
        return refusal.status
    try:
        stdout.write(
            f"database={created.database}\n"
            f"user={created.user}@{created.host}\n"
            f"password={created.password}\n"
        )
        stdout.flush()
    except OSError:
        # The account exists and the only copy of its password went nowhere. A retry is refused
        # as `exists`, so the owner has to remove the tenant's database and account by hand.
        log(f"created-undelivered database={created.database}")
        stderr.write(f"{SYSLOG_IDENT}: failed reason=undelivered\n")
        return EXIT_FAILED
    log(f"created database={created.database}")
    return EXIT_CREATED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], os.environ, sys.stdout, sys.stderr))
