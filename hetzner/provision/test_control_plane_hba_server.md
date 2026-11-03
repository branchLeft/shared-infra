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

Three control cases run the identical server on sabotaged copies of the file, and
each must differ from the table in exactly the cells the sabotage changes: the
provisioner rule deleted, the sign-in service's login let into the portal database,
and the owner login let into the sign-in service's database. A copy that the
sabotage left unchanged fails the setup, so a control case cannot pass by proving
nothing.

## Safety

- It uses a local engine only. When `DOCKER_HOST` is set it does not run, because
  the engine may be remote; locally it skips with the reason, and when `CI` is set it
  fails instead, so CI cannot pass without having run it.
- The container is named with a run id and labelled with it. The test removes only
  the containers it started, with their anonymous volumes. It publishes no port.
- The administrator's password is random for the run. It reaches the container
  through the environment, never the command line, and is never printed or written.
- The server's log (printed only when a server does not start) carries no password.

Bump `EXPECTED_TEST_COUNT` in `test_suite_size.py` with any change here.
