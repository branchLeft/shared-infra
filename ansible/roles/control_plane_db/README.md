# control_plane_db

This role runs the control plane's three one-off steps on its host: apply a pending
database migration, run the identity reconciler, and create the portal database with
its roles and logins. Each step runs only when it is asked for by name and confirmed,
and each is recorded so that it does not run twice by accident.

This README follows the order the standard sets for a role README (ANS-14). It is
written for a maintainer who has not seen the role before.

## What the role does, and what it does not

On a **plain apply** it makes one directory, `/etc/branchleft/control-plane/provision`
(root, group 1000, mode 0750), where the owner places a step's inputs, and it runs no
step. It refuses to build under a configuration directory that is absent, not root's,
or open to others. Nothing else changes, so a second plain apply reports no change.

On a **step request** it runs one of three steps, each in the applications image, as a
one-off container on the stack's network (or the host's, for the reconciler):

| Step        | What it does                                                                                                                                                           | Inputs the owner places                                                                       |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `migrate`   | Applies the pending migrations with the image's `--migrate-only` mode, connecting as the migration login, never as the administrator. It creates no role, no password. | `migrator-url`                                                                                |
| `identity`  | Renders the reconciler's configuration, runs it against the sign-in service, installs its identifiers.                                                                 | none (the token is the sign-in service's own file)                                            |
| `provision` | Creates the database, schema, roles and logins (the migration login among them), then writes the two connection URL files.                                             | `admin-url`, `tenant-password`, `owner-password`, `provisioner-password`, `migrator-password` |

The grants themselves are not written here. The image's program holds a closed manifest
of every role, login, grant and default privilege, checks the server against it before
and after it acts, and refuses to repair anything that differs. The role does not carry
SQL. What the role controls is who can reach the program's inputs, what the container is
allowed, and whether a step may run at all.

Before `provision` reads any input it checks the database's access rules (`tasks/_hba.yml`).
It reads the `pg_hba.conf` the `control_plane` role delivered and requires an accepting rule
for each of the four portal logins in it. It then reads the file the running `db` container
actually holds, with `docker exec ... cat`, and requires it to equal the delivered file byte
for byte. It then asks the server what it has loaded (`files/server_loaded_hba.sh`, run inside
the `db` container with the container's own `POSTGRES_PASSWORD`, which the role never holds):
the server's `hba_file` setting must be that file, `pg_hba_file_rules` must show no error, and
`pg_conf_load_time()` must be later, in whole seconds, than the file's last modification and
change times. The program connects as the provisioner login and as the migration login after its
transaction commits, so a database without either rule would create the roles and then be
refused its own proof, leaving no marker. The stack mounts the file's directory
(`postgres/`) into the container, and the `control_plane` role reloads the server after
every deploy, so a delivered file is the one in force without a hand step. The two reads
prove different things. The byte comparison proves the container sees the delivered file, and
refuses a container still on the old single-file mount. It does not prove the server loaded
it: the container sees a delivered file at once, whether or not the reload ran. The server
read proves that, and refuses by name the case where an apply delivered a changed file and
failed before its reload. `pg_hba_file_rules` alone could not show it, because that view reads
the file on disk each time it is queried, not the copy the server loaded; so the proof is the
load time against the file's times, with the view only to show the file parses. A reload in the
same second as the delivery is refused, not guessed at, which fails closed. Each refusal names
the cause and says to ask for the `control_plane` apply, not to reload or recreate the `db`
container by hand. Neither read involves a secret the role holds.

It does not generate or choose a secret, create the sign-in service's token, restart a
service, write the deploy wrapper's pin, apply itself to a host, or wire itself into a
host's playbook or into the gated pull's step allow-list. Wiring is separate work, and for
ops1 it is done (`playbooks/ops1.yml`, `owner_vars/ops1.yml`, `checks/host_roles.yml`).

## Who holds what

Each login of the control-plane database, what it can do, where it is defined and how it is
reached. The role holds no SQL; the grants are the applications image's closed manifest
(`portal/data/provision/manifest.ts` in the Ghost platform repository), which the program
checks before and after it acts and refuses to repair.

| Login                      | What it can do                                                                                                                             | Defined by                                                | Reached how                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `postgres` (administrator) | Everything. `provision` runs as it for the steps that need a superuser (creating roles and the database); `migrate` does not.              | The `db` image's first start                              | `admin-url`, owner-placed, read by one container, removed on every exit; `pg_hba.conf`: three databases                          |
| `zitadel`                  | Owns its own database and runs the sign-in service's own setup migrations there (so it holds DDL there).                                   | The sign-in service's `init` phase, run once by the owner | The stack network; `pg_hba.conf`: its own database only                                                                          |
| `portal_tenant_login`      | Member of `portal_tenant` alone: the tenant portal's access; no BYPASSRLS; nothing beyond the manifest.                                    | The program's manifest, created by `provision`            | The tenant portal's URL file; `pg_hba.conf`: `portal` only                                                                       |
| `portal_owner_login`       | Member of `portal_owner` alone: the operator console's access; the role (not the login) with BYPASSRLS.                                    | The program's manifest, created by `provision`            | The console's URL file; `pg_hba.conf`: `portal` only                                                                             |
| `portal_provisioner_login` | Member of `portal_provisioner` alone: INSERT and SELECT on the demo-state and hostname-register tables only.                               | The program's manifest, created by `provision`            | No URL file; provisioning connects as it once; `pg_hba.conf`: `portal` only                                                      |
| `portal_migrator_login`    | Not a superuser, no BYPASSRLS. Owns the `portal` database and its objects: applies migrations and the manifest's grants, and nothing else. | The program's manifest, created by `provision`            | `migrator-url`, owner-placed per `migrate`, removed on every exit; `provision` connects as it once; `pg_hba.conf`: `portal` only |

The migration role is the migration login, `portal_migrator_login`, and not the administrator.
`migrate` is given its URL alone (`migrator-url`): the administrator's file is neither checked,
mounted nor named in that step, and the program, which connects only as the login its URL names,
refuses a URL that names another. The URL is placed by the owner for each `migrate` request and
removed on every way out, so no standing file on the host holds the credential of the login that
owns the schema. The administrator still runs the first steps of `provision` (it creates the
roles and the database, which only a superuser can), through the owner-placed `admin-url`, which
the step also removes on every exit. Neither credential is given to a runtime service
(`hetzner/provision/test_control_plane_stack.py` fails if a compose service names either). The
manifest, the attributes of the login and the program's pre- and post-checks that refuse a server
which differs are the Ghost platform repository's; this role holds the login's name only.

What bounds each login is two things the repository tests. `pg_hba.conf` admits each login to
its own database and refuses every other pair, shown against a real PostgreSQL by
`hetzner/provision/test_control_plane_hba_server.py`. That test also shows the migration login,
made on that server with Postgres' defaults, refused a role creation, a read of `pg_authid` and an
`alter system`, and allowed all three on a control server where it is a superuser (a named limit,
below). The tenant login's lack of DDL is shown
by the program's own boundary check (a tenant login creating in the `public` schema must be
refused), which is cited and not copied. The owner and provisioner logins are not probed for
DDL there; the manifest's ACL checks cover their schema rights. The zitadel login's rights inside its
own database are the vendor's, not ours to narrow: it is bounded by `pg_hba.conf` alone, and that is a
named limit below.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the inputs and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. No input is a secret.

| Variable                              | Default | Meaning                                                                                                                  |
| ------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------ |
| `control_plane_db_step`               | empty   | The step this run confirms. The gated pull sets it on the command line. Never in an inventory.                           |
| `control_plane_db_apps_image`         | empty   | The applications image, `NAME@sha256:` and 64 hex digits. Required by every step. Set for ops1 in `owner_vars/ops1.yml`. |
| `control_plane_db_identity_hostnames` | empty   | `console`, `portal` and `identity` hostnames. Required by `identity`.                                                    |
| `control_plane_db_identity_tenants`   | `[]`    | The reconciler's tenant list. Empty. See the limits.                                                                     |

The fixed values (every path, the modes, the logins, the patterns an image, a password
and a hostname must match) are in `vars/main.yml`, not in the interface, so an inventory
cannot loosen them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that
  version.
- No collection beyond `ansible.builtin`.
- Target: the control-plane host, with Docker, after the `control_plane` role has run:
  `/etc/branchleft/control-plane` must exist as a directory of root with mode 0750.
- An applications image that carries the migration login (`migrate` checks for
  `PORTAL_MIGRATOR_URL_FILE` and `provision` for `PORTAL_MIGRATOR_PASSWORD_FILE` before it runs
  the step), which also carries the `--migrate-only` mode and the provisioner login.

## What it changes on a host

- `/etc/branchleft/control-plane/provision` (root, group 1000, 0750), on every apply.
- `/var/lib/branchleft/control-plane-db` (root, 0755) and one marker in it per step that
  ran: `migrate-<digest>`, `identity-<hash>` and `provision-migrator`, each root, 0644,
  holding its own name. The provision marker is not the step's id: the program now also
  creates the migration login, and a changed effect needs a new key (see "How to change it
  safely"), so a host that ran the earlier provision reaches the program on its next request
  and is refused by name (the program's refusal of an ownership that differs) instead of
  being skipped silently.
- `provision`: `/etc/branchleft/control-plane/portal-database-url` (the tenant login) and
  `console-database-url` (the owner login), each root, group 1000, 0640.
- `identity`: `/etc/branchleft/control-plane/identity-outputs.json` (root, group 1000,
  0640), and, while it runs, the working directory
  `/var/lib/branchleft/control-plane/reconciler-work` (uid 1000, 0700).
- It removes the owner-placed `migrator-url` on every way out of `migrate`, `admin-url` on
  every way out of `provision`, and the four password files (the migrator's among them) once
  `provision` is recorded. No standing file holds the migration login's credential.
- Containers are started with `--rm` and leave nothing. No package, user, service, port
  or firewall rule.

## The guard

A step has two conditions and both must hold.

1. **The tag.** Each step is imported with the tags `never` and `control_plane_db_<id>`.
   Ansible runs a `never` task only when its tag is named with `--tags`. A plain apply
   and `--tags all` skip it.
2. **The confirmation.** `control_plane_db_step` must equal the step's id. A step named
   by its tag without it stops with a message that begins `REFUSED:`. The gated pull
   sets both from one request, and refuses an id that is not on the host's step
   allow-list or whose word does not match, before it runs anything.

No task carries the `always` tag, so a step run is the step's own tasks and nothing a
plain apply would repeat. The step ids are the closed list `migrate`, `identity` and
`provision`, the same list the gated pull holds; a unit test fails when they differ. The
calling playbook must include the role with `roles:` (a static import), or with
`include_role` and `tags: always`; a dynamic include with no tag runs nothing under a
named tag. `--tags never` would run every step in turn and stop at the second, so a
request names one step.

## Controls

Each is shown to fail except C20 (see its row): the exact edit is made, the test is
seen red, the edit is reverted, and the test is seen green. C3 (link), C17 (URL write)
and C19 are shown red by the unit tests only; the container scenario stays green for
those edits.

| Control                                                                         | Edit that must turn it red                                                                      | Where it is shown                                                  |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| C1 a plain apply runs no step                                                   | drop the `never` tag of a step                                                                  | unit test, `plain` section                                         |
| C2 the step id must equal the confirmation                                      | drop the comparison in `_guard.yml`                                                             | `guard` section                                                    |
| C3 an input file is root's, group 1000, 0640, regular, not empty                | accept 0644, or accept a link                                                                   | `inputs` section, unit test                                        |
| C4 the input directory is root:1000 0750, and a plain apply restores it         | set 0755 in `main.yml`                                                                          | `plain` and `inputs` sections                                      |
| C5 the configuration directory is not open to others                            | drop its assertion                                                                              | `plain` section                                                    |
| C6 the image is pinned by digest                                                | loosen `control_plane_db_image_pattern`                                                         | `guard` section, unit test                                         |
| C7 the image carries what the step needs                                        | drop `_image.yml`                                                                               | `migrate_preconditions`, `provision_failures`                      |
| C8 the stack network must exist                                                 | drop the network check                                                                          | `migrate_preconditions`                                            |
| C9 a step ends clean or is refused                                              | drop the output assertion                                                                       | `migrate_failures`, `provision_failures`, `identity_failures`      |
| C10 the marker is written after the effect and its checks                       | write it first                                                                                  | `migrate_failures`, unit test                                      |
| C11 the credential URL file a step was given is removed on every exit           | drop the `always` section                                                                       | `inputs`, `migrate_failures`                                       |
| C12 a marker is keyed by what the step acts on                                  | key `migrate` by a constant                                                                     | `migrate`, `identity`                                              |
| C13 each URL file holds its own login, and no file holds the provisioner's      | swap the two logins                                                                             | `provision` section, unit test                                     |
| C14 a password must survive as one URL component                                | drop the shape check                                                                            | `provision_refusals`                                               |
| C15 provision does not rotate the passwords the applications hold               | drop the URL file comparison                                                                    | `provision_refusals`                                               |
| C16 no secret in a container's arguments or environment, and no added privilege | add `--privileged`, or a password in an `-e`                                                    | `migrate`, `provision`, unit test                                  |
| C17 a task that handles a secret has `no_log`                                   | remove it                                                                                       | `migrate_failures`, `provision_failures`, unit test                |
| C18 the service account token is the sign-in service's, regular, 0600           | accept 0644, or a link                                                                          | `identity_refusals`                                                |
| C19 a working directory this run did not make is not removed                    | remove it unconditionally                                                                       | `identity_refusals`                                                |
| C20 a check-mode request starts no container and writes no marker               | not shown to fail: the container tasks are skipped in check mode                                | `check_mode` section (asserts the outcome only)                    |
| C21 the running server has loaded the delivered rules                           | drop the byte comparison, or the load-time comparison in `server_loaded_hba.sh`, or the ask     | `provision_hba` section (not-reloaded case), unit test             |
| C22 the delivered rules admit each of the four portal logins                    | drop the per-login rule check in `_hba.yml`, or the migrator from `control_plane_db_hba_logins` | `provision_hba` section, unit test                                 |
| C23 the rules are checked before any secret file is looked at or read           | move the import after the input check in `_provision.yml`                                       | unit test (task order)                                             |
| C24 migrate is given the migrator's URL file and never the administrator's      | put the administrator's mount or `PORTAL_ADMIN_URL_FILE` back into `_migrate.yml`               | `migrate` section (exact argument and environment list), unit test |
| C25 the migrator's URL file is removed on every exit of migrate                 | drop the `always` removal of `migrator-url` in `_migrate.yml`                                   | `migrate_failures` section, unit test                              |

## What the owner does

The role never creates a secret and never fetches one. The owner places each input on
the host as root, by standard input, so that no value appears in an argument or in a
shell history. Placeholders are in capitals; the real values come from the owner's
password manager.

0. Nothing, for a changed `pg_hba.conf`. The `control_plane` role delivers the file into the
   `postgres/` directory that the `db` container mounts, and reloads the server after every
   deploy (`SELECT pg_reload_conf()`, which drops no connection). `provision` still refuses
   by name until the running file equals the delivered one and the server has reloaded since
   it was delivered, and the refusal tells the owner to ask for the `control_plane` apply. The first apply after the directory mount shipped
   recreates the `db` container once, on the new mount, with its volume kept.

1. Place the administrator URL before `provision` (only `provision` reads it now). It is
   a connection URL for the database administrator,
   `postgres://postgres:ADMIN_PASSWORD@db:5432/postgres`:

   ```text
   read -rs ADMIN_URL; printf '%s\n' "$ADMIN_URL" | ssh OPS_HOST_ALIAS 'install -m 0640 -o root -g 1000 /dev/stdin /etc/branchleft/control-plane/provision/admin-url'; unset ADMIN_URL
   ```

   After the step ran, `ls /etc/branchleft/control-plane/provision` shows no `admin-url`.

2. Place the four login passwords before `provision`, each 24 or more of letters,
   digits, dot, underscore, tilde and hyphen, and each different. For each of
   `tenant-password`, `owner-password`, `provisioner-password` and `migrator-password`:

   ```text
   read -rs LOGIN_PASSWORD; printf '%s\n' "$LOGIN_PASSWORD" | ssh OPS_HOST_ALIAS 'install -m 0640 -o root -g 1000 /dev/stdin /etc/branchleft/control-plane/provision/PASSWORD_FILE_NAME'; unset LOGIN_PASSWORD
   ```

   Save each password in the password manager before the request: the role removes the
   files once `provision` is recorded, and the connection URL files are the only copy
   left on the host. A failed `provision` keeps them for the retry.

3. Place the migrator URL before **each** `migrate` request. It is the migration login's
   connection URL, with the password from step 2 (the same value, saved in the password
   manager), `postgres://portal_migrator_login:MIGRATOR_PASSWORD@db:5432/portal`. The program
   refuses a URL that names another login. The step removes the file on every exit, so a
   second `migrate` needs a second placement:

   ```text
   read -rs MIGRATOR_URL; printf '%s\n' "$MIGRATOR_URL" | ssh OPS_HOST_ALIAS 'install -m 0640 -o root -g 1000 /dev/stdin /etc/branchleft/control-plane/provision/migrator-url'; unset MIGRATOR_URL
   ```

   After the step ran, `ls /etc/branchleft/control-plane/provision` shows no `migrator-url`.

4. For `identity`, the sign-in service has already written its service account token.
   If it has not, the role refuses by name and does not create one.

5. Ask for the step through the gated pull (below). The owner does not run Ansible by
   hand.

A control-plane database already provisioned under `postgres` (before the migration login
existed) is not repaired by the role or by the program: both refuse it by name. Converting it
(`REASSIGN OWNED`, `ALTER DATABASE ... OWNER`, the grants) is a hand step through the owner's
gate. Do not bump `control_plane_db_apps_image` to an image that carries the migration login
until this role and the delivered `pg_hba.conf` are live, or `migrate` refuses.

A connection URL file already on a host that has no `provision` marker (a rebuilt host)
stops `provision` unless it holds the URL the placed passwords make; the owner decides
how to proceed, because a provision gives each login a new stored password.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
.venv/bin/python -m unittest discover -s ansible/roles/control_plane_db/tests/unit -p 'test_*.py'
.venv/bin/python ansible/harness/run_harness.py ansible/roles/control_plane_db
```

The second needs Docker. The scenario runs one container, replaces `docker` in it with
a stand-in (`molecule/default/files/fake_docker.py`) that records each call with the
state of each file it mounts and answers as the image's programs do, and then asserts
the outcome in sections (`verify.yml`; `verify_sections` runs one). The throwaway
secrets are made from the run id; the verify play looks for them, plain and as base64,
in the output of every request and in the log of the whole run.

## How it is delivered

Only through the gated pull. A plain apply of the host's playbook delivers the input
directory. A step is requested with the commit, the step id and the step's word, over the
step key, and the pull runs the playbook with `--tags control_plane_db_<id> -e
control_plane_db_step=<id>`. The host's step allow-list names the id, this role's tag and
the word. For ops1 the role is in the host's playbook (last, after `control_plane`), on the
host's role list, and the allow-list is in `owner_vars/ops1.yml`. The applications image
digest is an owner value in `owner_vars/ops1.yml`; the identity step refuses by name
while `control_plane_db_identity_hostnames` is unset. The one-time host steps a step request needs
are in the pull_trigger README, "Step requests".

## How to change it safely

1. A new step is a new id in `pull_trigger`'s closed list, the spec's choices, this
   role's `control_plane_db_step_ids`, a new `_<id>.yml` and a new tagged import. A unit
   test fails if the lists differ.
2. Keep the order inside a step: guard, preconditions, effect, output checks, marker.
   Keep the `always` removal around everything that reads an input.
3. A changed effect needs a new marker key, because a marker says a step ran, not what
   it did.
4. Never turn `no_log` off on a real host to see why a step failed. A failed step shows
   the program's own refusal lines; read the container's output on a lab host with
   throwaway values.
5. Extend `verify.yml` and the unit tests with the change, and show the new control red.

## Named limits

- **The Docker calls are not exercised against Docker.** The stand-in proves the
  arguments, the mounts and the order. The first live run through the gated pull is the
  proof that the image's programs accept them.
- **The program's refusal lines are shown.** A failed step prints the lines the program
  prints that begin with its refusal words, cut to 200 characters. The program redacts
  what it prints; the role relies on that and withholds every other line.
- **The manifest check replaces a by-hand comparison.** The earlier hand procedure
  compared each role's identifier and stored password verifier before and after a
  migration. The image's `--migrate-only` mode creates no role and sets no password, and
  refuses a server that differs from its manifest; the role carries no SQL to show the
  identifiers unchanged.
- **The access-rule check reads the rules, it does not connect.** It proves the running
  container holds the delivered file and that the file has an accepting rule for each portal
  login. It does not evaluate rule order; that the file admits exactly the right pairs is
  shown by `hetzner/provision/test_control_plane_hba_server.py`, against a real server, on
  the repository's copy of the file. A check-mode request skips the comparison with the
  container, because a command is skipped in check mode.
- **The container is named by Compose's convention.** The check reads `control-plane-db-1`;
  a unit test pins the name to the compose file's project and service. A renamed container
  stops `provision` with the refusal, never lets it through.
- **The sign-in service's login is the vendor's.** It runs its own setup migrations as itself
  on its own database, so it holds DDL there. What bounds it is `pg_hba.conf` (its own
  database only). Its role attributes are the vendor's `init` phase's doing and are not
  checked by a CI test (the vendor image is heavy); the owner can read them with
  `\du zitadel` on the host.
- **The boundary is shown on the file and on Postgres' defaults, on a stand-in login.**
  `hetzner/provision/test_control_plane_hba_server.py` shows the file admits the migration
  login to `portal` only, and that a login made with Postgres' defaults and owning a database
  is refused the superuser-only actions. It cannot run the applications image's program, so that
  the program creates the real login with the manifest's attributes (not a superuser, no
  BYPASSRLS) and refuses a server that differs is the Ghost platform repository's test, cited and
  not copied.
- **The administrator's rule is not narrowed.** `pg_hba.conf` still admits the administrator to
  `postgres`, `zitadel` and `portal` over the stack network, because the sign-in service's
  first-start initialisation and the full `provision` use it. The sign-in service's own login is
  the vendor's and is out of scope.
- **`migrate` does not read the running access rules.** Only `provision` runs the access-rule
  check. A `migrate` against a database not yet reloaded on the delivered file is refused by
  the server (the migration login has no rule in the running file) and shows the program's
  refusal lines; the `control_plane` apply that delivers the file reloads the server, so
  this happens only before that apply has run (step 0).
- **The migrator URL is placed for every `migrate`.** No standing file holds the login that
  owns the schema, at the cost of one placement per request. A standing, group-readable file
  written by `provision` would be a small follow-up if that cost is too high.
- **The marker is host-local and is not a lock.** A rebuilt host has none; two requests
  at once could both run. The gated pull serialises requests.
- **A marker says a step ran, not what it did.** After an outside change to the identity
  service, an unchanged configuration is skipped; the reconciler's own `unchanged`
  report is the second line when it is asked again under a new configuration.
- **A leftover `admin-url` or `migrator-url` stays until the next request.** A plain apply
  does not remove a file the owner placed for a request that has not come yet.
- **A tenant's identity must not be committed here.** The tenant list is an input,
  empty by default; a non-empty list needs a source the owner chooses.
- **`control_plane_db_step` set in an inventory defeats the second key.** It is meant
  for the command line.
- **The input directory is checked for owner, group and mode, not for who is in the
  group.** Group 1000 is the image's user; no other member is expected, and the role
  does not look.
- **A check-mode request shows the checks and none of the effect.** A container run is
  skipped in check mode, and the gated pull refuses a step in check mode anyway.
