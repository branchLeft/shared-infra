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

| Step        | What it does                                                                                            | Inputs the owner places                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `migrate`   | Applies the pending migrations with the image's `--migrate-only` mode. It creates no role, no password. | `admin-url`                                                              |
| `identity`  | Renders the reconciler's configuration, runs it against the sign-in service, installs its identifiers.  | none (the token is the sign-in service's own file)                       |
| `provision` | Creates the database, schema, roles and logins, then writes the two connection URL files.               | `admin-url`, `tenant-password`, `owner-password`, `provisioner-password` |

The grants themselves are not written here. The image's program holds a closed manifest
of every role, login, grant and default privilege, checks the server against it before
and after it acts, and refuses to repair anything that differs. The role does not carry
SQL. What the role controls is who can reach the program's inputs, what the container is
allowed, and whether a step may run at all.

Before `provision` reads any input it checks the database's access rules (`tasks/_hba.yml`).
It reads the `pg_hba.conf` the `control_plane` role delivered and requires an accepting rule
for each of the three portal logins in it. It then reads the file the running `db` container
actually holds, with `docker exec ... cat`, and requires it to equal the delivered file byte
for byte. The program connects as the provisioner login after its transaction commits, so a
database without that rule would create the roles and then be refused its own proof, leaving
no marker. The stack mounts the file as a single bind mount, and a file replaced on the host
keeps its old content inside a container that was not recreated, so the delivered file alone
proves nothing about the server. The refusal names the cause and says to recreate the `db`
container. Neither read involves a secret.

It does not generate or choose a secret, create the sign-in service's token, restart a
service, write the deploy wrapper's pin, apply itself to a host, or wire itself into a
host's playbook or into the gated pull's step allow-list. Wiring is separate work, and for
ops1 it is done (`playbooks/ops1.yml`, `owner_vars/ops1.yml`, `checks/host_roles.yml`).

## Who holds what

Each login of the control-plane database, what it can do, where it is defined and how it is
reached. The role holds no SQL; the grants are the applications image's closed manifest
(`portal/data/provision/manifest.ts` in the Ghost platform repository), which the program
checks before and after it acts and refuses to repair.

| Login                      | What it can do                                                                                               | Defined by                                                | Reached how                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `postgres` (administrator) | Everything. It is the migration role: `migrate` and `provision` run as it, and nothing else does.            | The `db` image's first start                              | `admin-url`, owner-placed, read by one container, removed on every exit; `pg_hba.conf`: three databases |
| `zitadel`                  | Owns its own database and runs the sign-in service's own setup migrations there (so it holds DDL there).     | The sign-in service's `init` phase, run once by the owner | The stack network; `pg_hba.conf`: its own database only                                                 |
| `portal_tenant_login`      | Member of `portal_tenant` alone: the tenant portal's access; no BYPASSRLS; nothing beyond the manifest.      | The program's manifest, created by `provision`            | The tenant portal's URL file; `pg_hba.conf`: `portal` only                                              |
| `portal_owner_login`       | Member of `portal_owner` alone: the operator console's access; the role (not the login) with BYPASSRLS.      | The program's manifest, created by `provision`            | The console's URL file; `pg_hba.conf`: `portal` only                                                    |
| `portal_provisioner_login` | Member of `portal_provisioner` alone: INSERT and SELECT on the demo-state and hostname-register tables only. | The program's manifest, created by `provision`            | No file: the program connects as it once to prove the boundary; `pg_hba.conf`: `portal` only            |

The migration role is the administrator. It is a named login, reached only through the
owner-placed `admin-url` file that the step removes on every way out, and it is never given
to a runtime service (`hetzner/provision/test_control_plane_stack.py` fails if a runtime
service names the credential). A dedicated migration login without the administrator's
rights would change the applications program and its manifest, which belong to the Ghost
platform repository, so it is a follow-up there and not built here.

What bounds each login is two things the repository tests. `pg_hba.conf` admits each login to
its own database and refuses every other pair, shown against a real PostgreSQL by
`hetzner/provision/test_control_plane_hba_server.py`. The portal logins' lack of DDL is shown
by the program's own boundary check (a tenant login creating in the `public` schema must be
refused), which is cited and not copied. The zitadel login's rights inside its own database
are the vendor's, not ours to narrow: it is bounded by `pg_hba.conf` alone, and that is a
named limit below.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the inputs and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. No input is a secret.

| Variable                              | Default | Meaning                                                                                        |
| ------------------------------------- | ------- | ---------------------------------------------------------------------------------------------- |
| `control_plane_db_step`               | empty   | The step this run confirms. The gated pull sets it on the command line. Never in an inventory. |
| `control_plane_db_apps_image`         | empty   | The applications image, `NAME@sha256:` and 64 hex digits. Required by every step.              |
| `control_plane_db_identity_hostnames` | empty   | `console`, `portal` and `identity` hostnames. Required by `identity`.                          |
| `control_plane_db_identity_tenants`   | `[]`    | The reconciler's tenant list. Empty. See the limits.                                           |

The fixed values (every path, the modes, the logins, the patterns an image, a password
and a hostname must match) are in `vars/main.yml`, not in the interface, so an inventory
cannot loosen them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that
  version.
- No collection beyond `ansible.builtin`.
- Target: the control-plane host, with Docker, after the `control_plane` role has run:
  `/etc/branchleft/control-plane` must exist as a directory of root with mode 0750.
- An applications image that carries the program's `--migrate-only` mode and the
  provisioner login (the role checks both before it runs the step).

## What it changes on a host

- `/etc/branchleft/control-plane/provision` (root, group 1000, 0750), on every apply.
- `/var/lib/branchleft/control-plane-db` (root, 0755) and one marker in it per step that
  ran: `migrate-<digest>`, `identity-<hash>` and `provision`, each root, 0644, holding
  its own name.
- `provision`: `/etc/branchleft/control-plane/portal-database-url` (the tenant login) and
  `console-database-url` (the owner login), each root, group 1000, 0640.
- `identity`: `/etc/branchleft/control-plane/identity-outputs.json` (root, group 1000,
  0640), and, while it runs, the working directory
  `/var/lib/branchleft/control-plane/reconciler-work` (uid 1000, 0700).
- It removes the owner-placed `admin-url` on every way out of `migrate` and `provision`,
  and removes the three password files once `provision` is recorded.
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

| Control                                                                         | Edit that must turn it red                                       | Where it is shown                                             |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------- |
| C1 a plain apply runs no step                                                   | drop the `never` tag of a step                                   | unit test, `plain` section                                    |
| C2 the step id must equal the confirmation                                      | drop the comparison in `_guard.yml`                              | `guard` section                                               |
| C3 an input file is root's, group 1000, 0640, regular, not empty                | accept 0644, or accept a link                                    | `inputs` section, unit test                                   |
| C4 the input directory is root:1000 0750, and a plain apply restores it         | set 0755 in `main.yml`                                           | `plain` and `inputs` sections                                 |
| C5 the configuration directory is not open to others                            | drop its assertion                                               | `plain` section                                               |
| C6 the image is pinned by digest                                                | loosen `control_plane_db_image_pattern`                          | `guard` section, unit test                                    |
| C7 the image carries what the step needs                                        | drop `_image.yml`                                                | `migrate_preconditions`, `provision_failures`                 |
| C8 the stack network must exist                                                 | drop the network check                                           | `migrate_preconditions`                                       |
| C9 a step ends clean or is refused                                              | drop the output assertion                                        | `migrate_failures`, `provision_failures`, `identity_failures` |
| C10 the marker is written after the effect and its checks                       | write it first                                                   | `migrate_failures`, unit test                                 |
| C11 the administrator URL file is removed on every exit                         | drop the `always` section                                        | `inputs`, `migrate_failures`                                  |
| C12 a marker is keyed by what the step acts on                                  | key `migrate` by a constant                                      | `migrate`, `identity`                                         |
| C13 each URL file holds its own login, and no file holds the provisioner's      | swap the two logins                                              | `provision` section, unit test                                |
| C14 a password must survive as one URL component                                | drop the shape check                                             | `provision_refusals`                                          |
| C15 provision does not rotate the passwords the applications hold               | drop the URL file comparison                                     | `provision_refusals`                                          |
| C16 no secret in a container's arguments or environment, and no added privilege | add `--privileged`, or a password in an `-e`                     | `migrate`, `provision`, unit test                             |
| C17 a task that handles a secret has `no_log`                                   | remove it                                                        | `migrate_failures`, `provision_failures`, unit test           |
| C18 the service account token is the sign-in service's, regular, 0600           | accept 0644, or a link                                           | `identity_refusals`                                           |
| C19 a working directory this run did not make is not removed                    | remove it unconditionally                                        | `identity_refusals`                                           |
| C20 a check-mode request starts no container and writes no marker               | not shown to fail: the container tasks are skipped in check mode | `check_mode` section (asserts the outcome only)               |
| C21 the running database holds the delivered rules, byte for byte               | drop the comparison in `_hba.yml`                                | `provision_hba` section, unit test                            |
| C22 the delivered rules admit each of the three portal logins                   | drop the per-login rule check in `_hba.yml`                      | `provision_hba` section, unit test                            |
| C23 the rules are checked before any secret file is looked at or read           | move the import after the input check in `_provision.yml`        | unit test (task order)                                        |

## What the owner does

The role never creates a secret and never fetches one. The owner places each input on
the host as root, by standard input, so that no value appears in an argument or in a
shell history. Placeholders are in capitals; the real values come from the owner's
password manager.

0. After the apply that delivers a changed `pg_hba.conf`, recreate the `db` container of the
   stack, so the running server holds the delivered rules. This is a brief restart of the
   control-plane database (the sign-in service, the portal and the console reconnect). The
   role never does it, because the `control_plane` role never recreates a container on a
   running stack. `provision` refuses by name until the running file equals the delivered
   one.

1. Place the administrator URL before `migrate` or `provision`. It is a connection URL
   for the database administrator, `postgres://postgres:ADMIN_PASSWORD@db:5432/postgres`:

   ```text
   read -rs ADMIN_URL; printf '%s\n' "$ADMIN_URL" | ssh OPS_HOST_ALIAS 'install -m 0640 -o root -g 1000 /dev/stdin /etc/branchleft/control-plane/provision/admin-url'; unset ADMIN_URL
   ```

   After the step ran, `ls /etc/branchleft/control-plane/provision` shows no `admin-url`.

2. Place the three login passwords before `provision`, each 24 or more of letters,
   digits, dot, underscore, tilde and hyphen, and each different. For each of
   `tenant-password`, `owner-password` and `provisioner-password`:

   ```text
   read -rs LOGIN_PASSWORD; printf '%s\n' "$LOGIN_PASSWORD" | ssh OPS_HOST_ALIAS 'install -m 0640 -o root -g 1000 /dev/stdin /etc/branchleft/control-plane/provision/PASSWORD_FILE_NAME'; unset LOGIN_PASSWORD
   ```

   Save each password in the password manager before the request: the role removes the
   files once `provision` is recorded, and the connection URL files are the only copy
   left on the host. A failed `provision` keeps them for the retry.

3. For `identity`, the sign-in service has already written its service account token.
   If it has not, the role refuses by name and does not create one.

4. Ask for the step through the gated pull (below). The owner does not run Ansible by
   hand.

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
digest and the identity hostnames are not set, so every step refuses by name until a
later owner change sets them. No step can be requested until the sender and the owner's
one-time host steps exist (see the pull_trigger README, "Step requests").

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
- **The marker is host-local and is not a lock.** A rebuilt host has none; two requests
  at once could both run. The gated pull serialises requests.
- **A marker says a step ran, not what it did.** After an outside change to the identity
  service, an unchanged configuration is skipped; the reconciler's own `unchanged`
  report is the second line when it is asked again under a new configuration.
- **A leftover `admin-url` stays until the next request.** A plain apply does not remove
  a file the owner placed for a request that has not come yet.
- **A tenant's identity must not be committed here.** The tenant list is an input,
  empty by default; a non-empty list needs a source the owner chooses.
- **`control_plane_db_step` set in an inventory defeats the second key.** It is meant
  for the command line.
- **The input directory is checked for owner, group and mode, not for who is in the
  group.** Group 1000 is the image's user; no other member is expected, and the role
  does not look.
- **A check-mode request shows the checks and none of the effect.** A container run is
  skipped in check mode, and the gated pull refuses a step in check mode anyway.
