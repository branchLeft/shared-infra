# test_control_plane_hba_server.py

## Module overview

`pg_hba.conf` is the control-plane database's access boundary: it decides which
login may reach which database, before any password is asked for. The static test in
`test_control_plane_stack.py` reads the file's text. This test starts a real
PostgreSQL on the file and connects, because a file can read right and still be
wrong in a way only a server shows. The first provisioning of the portal database
was found this way: the provisioner login, which the provisioning program connects
as after its transaction commits, had no rule and was refused.

## What it does

It reads the PostgreSQL image from `compose.yml` (the single home of the pin) and
starts one container on the repository's own `pg_hba.conf`, mounted read-only. It
then connects from inside the container as every login the stack knows (and a
stranger) to every database it probes, each with a password that is wrong on
purpose. The file is matched before the password, so the server's answer says which
happened: `pg_hba.conf rejects connection` means the file refused the pair, and
`password authentication failed` means the file admitted it to authentication. The
result must equal the one table in `test_control_plane_stack.py`
(`EXPECTED_DATABASES`), which the static test also reads. No SQL is run and no real
login is used, so no secret is read or needed.

Five control cases run the identical server on sabotaged copies of the file, and
each must differ from the table in exactly the cells the sabotage changes: the
provisioner rule deleted, the migrator rule deleted, the migrator let into the
`postgres` database, the sign-in service's login let into the portal database, and
the owner login let into the sign-in service's database. A copy that the sabotage
left unchanged fails the setup, so a control case cannot pass by proving nothing.

## The migrator is not a superuser

The migrator login (`portal_migrator_login`) is the one the full provision's last step
and every migrate-only run connect as, in place of the administrator. Its whole value is
that it can change the portal database and do nothing a superuser alone can, so the
file's rule is shown with the server's own behaviour and not the text alone.

After the matrix is read, the administrator makes the portal database and the migrator
on two servers that hold the repository's real file. On the first the migrator is made
with Postgres' defaults and no attribute granted (not superuser, no create-role, no
create-database, no replication, no BYPASSRLS), owning the portal database. On the second
(the control case) the administrator makes it a superuser. Then, connected as the
migrator through the file:

- on the first server it must succeed at DDL in the portal database (create, alter and
  drop a table), and each of three superuser-only actions must be refused with `permission
denied`: create a role, read `pg_authid` (the password verifiers) and `alter system`; and
  its connection to the `postgres` database must be refused by the file, with its own
  correct password;
- on the second server each of the same three actions must succeed.

The test asserts both outcomes, so it is red if the login is ever a superuser on the
first server, and red if the three actions could not tell a superuser from anyone else.
The migrator's password is random for the run and goes to the server by standard input,
and to psql by environment name; it is in no argument, no file and no output.

**Named limit.** This shows the file and Postgres' default boundary on a stand-in login.
That the applications image's program creates the real migrator with the manifest's
attributes is the Ghost platform repository's test, and is cited here, not copied.

## Safety

- It uses a local engine only. When `DOCKER_HOST` is set it does not run, because
  the engine may be remote; locally it skips with the reason, and when `CI` is set it
  fails instead, so CI cannot pass without having run it.
- The container is named with a run id and labelled with it. The test removes only
  the containers it started, with their anonymous volumes. It publishes no port.
- The administrator's password is random for the run. It reaches the container
  through the environment, never the command line, and is never printed or written.
  The migrator's is the same, and reaches the server on standard input.
- The server's log (printed only when a server does not start) carries no password.

Bump `EXPECTED_TEST_COUNT` in `test_suite_size.py` with any change here.
