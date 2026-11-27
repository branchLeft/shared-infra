#!/usr/bin/python
"""Makes the control plane's migration login, and keeps its credential on the host, root-only.

The login is the one the image's migration program connects as: not a superuser, no BYPASSRLS, no
CREATEROLE, no CREATEDB, no REPLICATION, and the owner of the portal database and of what the
migrations create in it. The owner's ruling of 27 Nov 2026 has the delivery make it with the
database administrator's password the host already holds and keep its credential in a root-only
file, so no step is the owner's.

The administrator's password is never read here. SQL goes to the database container through
``docker exec`` on standard input, and the shell that runs ``psql`` inside the container takes the
password from the container's own ``POSTGRES_PASSWORD``, the value
``/etc/branchleft/control-plane.env`` gave it. So no secret is in an argument, and the module
holds none of the administrator's.

The new login's password is made here, written only to the credential file (created 0600, so never
wider), and sent to the server as a SCRAM-SHA-256 verifier, which PostgreSQL stores as it is, so the
password itself is in no statement, no server log and no output. The file is the only copy.

What it does, each part only when needed, so a second run changes nothing:

* makes the login, or puts its attributes right, and sets its password when the credential file is
  absent, malformed or holds a password the server's stored verifier does not match;
* hands the portal database and what the administrator owns in it to the login, so the program's
  own check of ownership passes (a database made before the login existed was the administrator's);
* sets the owner, group and mode of the credential file on every run.

A superuser of that name is refused, never altered: it was not made by this module.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import quote, unquote, urlsplit

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: control_plane_db_login
short_description: Make the control plane's migration login and keep its credential root-only
description:
  - Makes the not-superuser login the migration program connects as, through the database container,
      with the administrator's password the container already holds. The module never reads that
      password and puts no secret in an argument.
  - Writes the login's credential as a connection URL file (0600, root) and sets the login's
      password to match, as a SCRAM-SHA-256 verifier, only when the file is absent, malformed or
      does not match the server.
  - Hands the portal database and the objects the administrator owns in it to the login.
  - Reports changes by name and never returns a password or a verifier.
version_added: "1.0.0"
author:
  - branchLeft
options:
  container:
    description: The database container, as Docker names it.
    type: str
    required: true
  database:
    description: The portal database.
    type: str
    required: true
  login:
    description: The migration login's name.
    type: str
    required: true
  credential_file:
    description: Where the login's connection URL is kept.
    type: path
    required: true
  host:
    description: The host name in the connection URL, as the applications reach the database.
    type: str
    required: true
  docker:
    description: The Docker program. Only a test changes it.
    type: path
    default: docker
attributes:
  check_mode:
    support: full
    details: Reads the server and the file, changes neither, and reports what a run would do.
"""

EXAMPLES = r"""
- name: Make the migration login and keep its credential
  control_plane_db_login:
    container: control-plane-db-1
    database: portal
    login: portal_migrator_login
    credential_file: /etc/branchleft/control-plane/migrator-url
    host: db
    owner: root
    group: root
    mode: '0600'
  no_log: true
"""

RETURN = r"""
actions:
  description: What was done, or in check mode would be done, by name. No value, no secret.
  returned: always
  type: list
  elements: str
"""

IDENTIFIER: Final = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
# A name for the host part of the URL: lower-case labels, digits and hyphen, dots between.
HOST_NAME: Final = re.compile(
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)
# The password's shape: one URL component, at least 24 long (the same rule the role holds for the
# passwords the owner places), so a URL built from it needs no escaping.
PASSWORD: Final = re.compile(r"[A-Za-z0-9._~-]{24,}\Z")
VERIFIER: Final = re.compile(
    r"SCRAM-SHA-256\$(?P<iterations>[0-9]{1,7}):(?P<salt>[A-Za-z0-9+/=]+)"
    r"\$(?P<stored>[A-Za-z0-9+/=]+):(?P<server>[A-Za-z0-9+/=]+)\Z"
)
ITERATIONS: Final = 4096
PORT: Final = 5432
# Bytes of randomness in a new password. token_urlsafe gives 4 characters for every 3 bytes,
# from the letters, digits, hyphen and underscore, all of which PASSWORD allows.
PASSWORD_BYTES: Final = 32
SALT_BYTES: Final = 16
# What a failed statement may quote back is cut to this many characters.
SHOWN: Final = 300

# The shell the database container runs. The password comes from the container's own environment,
# so it is in no argument. $1 is the database, $2 the login and $3 the portal database.
CONTAINER_SHELL: Final = (
    'PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set in the db container}"; '
    "export PGPASSWORD; "
    'exec psql --username=postgres --dbname="$1" --no-password --no-psqlrc --quiet '
    "--set=ON_ERROR_STOP=1 --tuples-only --no-align --field-separator='|' "
    '--set=login="$2" --set=portal="$3"'
)

# What the server says about the login: its attributes and its stored password verifier. One row, or
# none when the login is absent.
ROLE_SQL: Final = (
    "select rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, rolcanlogin, "
    "coalesce(rolpassword, '') from pg_catalog.pg_authid where rolname = :'login';"
)
# The owner of the portal database: one row, or none when the database is absent.
DATABASE_SQL: Final = (
    "select pg_catalog.pg_get_userbyid(datdba) from pg_catalog.pg_database "
    "where datname = :'portal';"
)
# Everything the administrator owns in the connected database, as the statements that hand it over,
# in an order where a schema and a table go before what is inside them. System schemas, objects that
# belong to an extension and an owned sequence (it follows its table) are left out. The same text is
# counted (to ask whether any is left) and run (\gexec), so the two cannot disagree.
OWNED_BY_ADMIN_SQL: Final = r"""
with owned (ord, ddl) as (
  select 1, format('alter schema %I owner to %I', n.nspname, :'login')
    from pg_catalog.pg_namespace n
   where n.nspowner = (select oid from pg_catalog.pg_roles where rolname = current_user)
     and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
     and not exists (select 1 from pg_catalog.pg_depend d
                      where d.classid = 'pg_namespace'::regclass and d.objid = n.oid
                        and d.deptype = 'e')
  union all
  select 2, format('alter %s %I.%I owner to %I',
                   case c.relkind when 'v' then 'view' when 'm' then 'materialized view'
                                  when 'f' then 'foreign table' else 'table' end,
                   n.nspname, c.relname, :'login')
    from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where c.relowner = (select oid from pg_catalog.pg_roles where rolname = current_user)
     and c.relkind in ('r', 'p', 'v', 'm', 'f')
     and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
     and not exists (select 1 from pg_catalog.pg_depend d
                      where d.classid = 'pg_class'::regclass and d.objid = c.oid
                        and d.deptype = 'e')
  union all
  select 3, format('alter sequence %I.%I owner to %I', n.nspname, c.relname, :'login')
    from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where c.relowner = (select oid from pg_catalog.pg_roles where rolname = current_user)
     and c.relkind = 'S'
     and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
     and not exists (select 1 from pg_catalog.pg_depend d
                      where d.classid = 'pg_class'::regclass and d.objid = c.oid
                        and d.deptype in ('a', 'i', 'e'))
  union all
  select 4, format('alter %s %I.%I(%s) owner to %I',
                   case p.prokind when 'p' then 'procedure' when 'a' then 'aggregate'
                                  else 'function' end,
                   n.nspname, p.proname,
                   pg_catalog.pg_get_function_identity_arguments(p.oid), :'login')
    from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
   where p.proowner = (select oid from pg_catalog.pg_roles where rolname = current_user)
     and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
     and not exists (select 1 from pg_catalog.pg_depend d
                      where d.classid = 'pg_proc'::regclass and d.objid = p.oid
                        and d.deptype = 'e')
  union all
  select 5, format('alter type %I.%I owner to %I', n.nspname, t.typname, :'login')
    from pg_catalog.pg_type t join pg_catalog.pg_namespace n on n.oid = t.typnamespace
   where t.typowner = (select oid from pg_catalog.pg_roles where rolname = current_user)
     and (t.typtype in ('e', 'd') or (t.typtype = 'c' and t.typrelid = 0))
     and n.nspname !~ '^pg_' and n.nspname <> 'information_schema'
     and not exists (select 1 from pg_catalog.pg_depend d
                      where d.classid = 'pg_type'::regclass and d.objid = t.oid
                        and d.deptype = 'e')
)
"""


class LoginError(Exception):
    """A refusal. Its text is fixed words and names; it carries no password and no verifier."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True)
class RoleRow:
    """The server's view of the login."""

    superuser: bool
    createrole: bool
    createdb: bool
    bypassrls: bool
    replication: bool
    canlogin: bool
    verifier: str

    def attributes_are_right(self) -> bool:
        """True when the login has exactly the attributes the manifest gives it."""
        return (
            self.canlogin
            and not self.superuser
            and not self.createrole
            and not self.createdb
            and not self.bypassrls
            and not self.replication
        )


Run = Callable[[Sequence[str], str], "subprocess.CompletedProcess[str]"]


def run_process(argv: Sequence[str], stdin: str) -> subprocess.CompletedProcess[str]:
    """Run a program with text on standard input, capturing both output streams."""
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)  # noqa: S603


def scram_verifier(password: str, salt: bytes, iterations: int = ITERATIONS) -> str:
    """The SCRAM-SHA-256 verifier PostgreSQL stores for a password (RFC 7677, as PostgreSQL's)."""
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = base64.b64encode
    return (
        f"SCRAM-SHA-256${iterations}:{encode(salt).decode('ascii')}"
        f"${encode(stored_key).decode('ascii')}:{encode(server_key).decode('ascii')}"
    )


def verifier_matches(password: str, verifier: str) -> bool:
    """True when the stored verifier is the one this password makes with the stored salt."""
    parsed = VERIFIER.match(verifier)
    if parsed is None:
        return False
    try:
        salt = base64.b64decode(parsed["salt"], validate=True)
    except ValueError:
        return False
    made = scram_verifier(password, salt, int(parsed["iterations"]))
    return hmac.compare_digest(made, verifier)


def credential_url(login: str, password: str, host: str, database: str) -> str:
    """The connection URL the migration program reads, with a newline as a file ends."""
    return (
        f"postgres://{quote(login, safe='')}:{quote(password, safe='')}@{host}:{PORT}/{database}\n"
    )


def password_in_url(text: str, login: str, host: str, database: str) -> str | None:
    """The password of a credential file, or None when it is not exactly this login's URL."""
    parts = urlsplit(text.rstrip("\r\n"))
    if parts.scheme != "postgres" or parts.username is None or parts.password is None:
        return None
    if unquote(parts.username) != login or parts.hostname != host or parts.port != PORT:
        return None
    if parts.path != f"/{database}" or parts.query or parts.fragment:
        return None
    password = unquote(parts.password)
    return password if PASSWORD.match(password) else None


class Database:
    """The database container, reached through docker exec with SQL on standard input."""

    def __init__(self, docker: str, container: str, login: str, portal: str, run: Run) -> None:
        self.docker = docker
        self.container = container
        self.login = login
        self.portal = portal
        self.run = run
        self.secrets: list[str] = []

    def query(self, database: str, sql: str) -> list[list[str]]:
        """Run SQL as the administrator in a database and return its rows, split on the separator.

        Raises:
            LoginError: The database refused the SQL or could not be reached.
        """
        argv = [
            self.docker, "exec", "-i", self.container, "sh", "-c", CONTAINER_SHELL, "sh",
            database, self.login, self.portal,
        ]  # fmt: skip
        done = self.run(argv, sql)
        if done.returncode != 0:
            raise LoginError(
                "database", self.redact(f"refused or could not be reached: {self.shown(done)}")
            )
        return [line.split("|") for line in done.stdout.splitlines() if line != ""]

    def shown(self, done: subprocess.CompletedProcess[str]) -> str:
        """The start of a failure, cut. A password or verifier in it is removed by redact."""
        text = " ".join((done.stderr or done.stdout or "").split())
        return f"exit {done.returncode}: {text[:SHOWN]}"

    def redact(self, text: str) -> str:
        """Remove every secret this module made from a message."""
        for secret in self.secrets:
            text = text.replace(secret, "<hidden>")
        return text


def read_role(database: Database) -> RoleRow | None:
    """The login as the server holds it, or None when it does not exist.

    Raises:
        LoginError: The server's answer has an unexpected shape.
    """
    rows = database.query("postgres", ROLE_SQL)
    if not rows:
        return None
    row = rows[0]
    if len(row) != 7:
        raise LoginError("shape", "the server's answer about the login has an unexpected shape")
    flags = [value == "t" for value in row[:6]]
    return RoleRow(flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], row[6])


def role_statement(login: str, exists: bool, verifier: str | None) -> str:
    """CREATE or ALTER the login to the manifest's attributes, with a password if one is given."""
    verb = "alter" if exists else "create"
    password = f" password '{verifier}'" if verifier is not None else ""
    return (
        f'{verb} role "{login}" with login nosuperuser nocreatedb nocreaterole noreplication '
        f"nobypassrls inherit{password};\n"
    )


def credential_state(path: Path, login: str, host: str, database: str, verifier: str) -> str | None:
    """The password a file holds when it is this login's credential and the server accepts it."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        return None
    password = password_in_url(text, login, host, database)
    if password is None or not verifier_matches(password, verifier):
        return None
    return password


def write_credential(module: AnsibleModule, path: Path, content: str) -> None:
    """Write the file so that no moment of it is readable by anyone but its owner, then replace."""
    directory = path.parent
    descriptor, temporary = tempfile_in(directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        module.atomic_move(temporary, str(path), unsafe_writes=False)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def tempfile_in(directory: Path) -> tuple[int, str]:
    """A new file in the directory, created 0600 and failing if it exists."""
    name = directory / f".{secrets.token_hex(8)}.new"
    return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), str(name)


@dataclass(frozen=True)
class Plan:
    """What a run does, decided from what it read."""

    make_role: bool
    fix_attributes: bool
    new_password: bool
    hand_database: bool
    hand_objects: bool

    def names(self) -> list[str]:
        """The actions, named for the result and for check mode."""
        out: list[str] = []
        if self.make_role:
            out.append("made the login")
        elif self.fix_attributes:
            out.append("put the login's attributes right")
        if self.new_password:
            out.append("set the login's password and wrote its credential file")
        if self.hand_database:
            out.append("handed the portal database to the login")
        if self.hand_objects:
            out.append("handed what the administrator owned in the portal database to the login")
        return out


def decide(
    role: RoleRow | None, credential_ok: bool, database_owner: str | None, login: str, left: int
) -> Plan:
    """The plan from the server's state.

    Raises:
        LoginError: A superuser of the name exists, which is refused and never altered.
    """
    if role is not None and role.superuser:
        raise LoginError(
            "superuser",
            f"the role {login} on the server is a superuser, so this module did not make it; "
            "refusing to change it",
        )
    return Plan(
        make_role=role is None,
        fix_attributes=role is not None and not role.attributes_are_right(),
        new_password=role is None or not credential_ok,
        hand_database=database_owner is not None and database_owner != login,
        hand_objects=left > 0,
    )


def apply_plan(
    module: AnsibleModule,
    database: Database,
    plan: Plan,
    role: RoleRow | None,
    params: dict[str, str],
) -> None:
    """Carry out the plan, the server first and the file after it.

    A failure between the two is retried by the next run, which finds the file not matching.
    """
    login, portal = params["login"], params["database"]
    verifier: str | None = None
    password = ""
    if plan.new_password:
        password = secrets.token_urlsafe(PASSWORD_BYTES)
        verifier = scram_verifier(password, secrets.token_bytes(SALT_BYTES))
        database.secrets.extend([password, verifier])
    if plan.make_role or plan.fix_attributes or plan.new_password:
        database.query("postgres", role_statement(login, role is not None, verifier))
    if plan.hand_database:
        # The names are checked identifiers (check_params), quoted as identifiers.
        database.query("postgres", f'alter database "{portal}" owner to "{login}";\n')  # noqa: S608
    if plan.hand_objects:
        database.query(
            portal,
            OWNED_BY_ADMIN_SQL + "select ddl from owned order by ord, ddl\n\\gexec\n",  # noqa: S608
        )
    if plan.new_password:
        write_credential(
            module,
            Path(params["credential_file"]),
            credential_url(login, password, params["host"], portal),
        )


def check_params(params: dict[str, str]) -> None:
    """Refuse a parameter that is not the shape of what it names, before anything is run.

    Raises:
        LoginError: A parameter is not the shape of what it names.
    """
    for name in ("database", "login"):
        if not IDENTIFIER.match(params[name]):
            raise LoginError("parameter", f"{name} must be a lower-case identifier")
    if not HOST_NAME.match(params["host"]):
        raise LoginError("parameter", "host must be a host name")
    if (
        not params["container"]
        or params["container"].startswith("-")
        or any(c.isspace() for c in params["container"])
    ):
        raise LoginError("parameter", "container must be a container name")


def main() -> None:
    """The module's entry point."""
    module = AnsibleModule(
        argument_spec={
            "container": {"type": "str", "required": True},
            "database": {"type": "str", "required": True},
            "login": {"type": "str", "required": True},
            "credential_file": {"type": "path", "required": True},
            "host": {"type": "str", "required": True},
            "docker": {"type": "path", "default": "docker"},
        },
        add_file_common_args=True,
        supports_check_mode=True,
    )
    p = module.params
    params = {k: str(p[k]) for k in ("container", "database", "login", "credential_file", "host")}
    database = Database(
        str(p["docker"]), params["container"], params["login"], params["database"], run_process
    )
    try:
        check_params(params)
        role = read_role(database)
        owner_rows = database.query("postgres", DATABASE_SQL)
        database_owner = owner_rows[0][0] if owner_rows else None
        left = 0
        if database_owner is not None:
            counted = database.query(
                params["database"],
                OWNED_BY_ADMIN_SQL + "select count(*) from owned;\n",  # noqa: S608
            )
            left = int(counted[0][0]) if counted else 0
        credential_ok = (
            role is not None
            and credential_state(
                Path(params["credential_file"]),
                params["login"],
                params["host"],
                params["database"],
                role.verifier,
            )
            is not None
        )
        plan = decide(role, credential_ok, database_owner, params["login"], left)
        if not module.check_mode:
            apply_plan(module, database, plan, role, params)
    except LoginError as error:
        module.fail_json(msg=database.redact(f"control_plane_db_login: {error}"))
    changed = bool(plan.names())
    # The file's owner, group and mode are set on every run, after any write, and count as a change.
    if not module.check_mode and os.path.exists(params["credential_file"]):
        file_args = module.load_file_common_arguments(module.params, path=params["credential_file"])
        changed = module.set_fs_attributes_if_different(file_args, changed)
    module.exit_json(changed=changed, actions=plan.names())


if __name__ == "__main__":
    main()
