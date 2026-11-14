# db_t1

This role prepares the tenant database host's Percona Server stack and, when it is
given an attested image, deploys it once, on an empty host. It does not install the
engine as a package: the engine is a container image, pinned by digest, pulled and
started by the host's deploy program.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does, in order:

1. Refuses an image that is not `ghcr.io/branchleft/NAME@sha256:` and 64 lower-case
   hex digits (or empty), and refuses a project directory that holds a second compose
   file or a compose environment file.
2. Creates the stack's directories, renders the compose file and the MySQL
   configuration, and enables the stack's unit without starting it.
3. When an image is given and the host has no image pin: checks the shape of the
   owner-placed root file, then runs `branchleft-deploy dbt1 <image>`, which verifies
   the image's attestation, writes the pin and starts the stack and waits for its health
   check.

It does not:

- start, stop, restart or recreate a running database. After the first deploy a
  different image is refused, not applied, because replacing the image of a database
  that holds data restarts it for every tenant and may upgrade the data in place.
- write the image pin or the root file, or read the root value. The pin is the deploy
  program's. The root file is the owner's.
- create a database, an account, a grant, a backup, a replica or a firewall rule. Those
  are other roles and other steps.
- open any port. The server listens on loopback only and the compose file publishes
  nothing (see "What it changes on a host").
- register the image with the deploy program. The register is by image name, in
  `hetzner/provision/branchleft_deploy.py`: the deploy program verifies the attestation
  of a registered name against its workflow, and pins a name that is not registered
  without verifying it. The name `ghcr.io/branchleft/percona-server` is registered, so a
  digest of it that the Percona image workflow did not sign is refused. A test holds the
  name in the register.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the one input,
`db_t1_image`, and [`defaults/main.yml`](defaults/main.yml) gives it the digest of the
image to deploy. Empty prepares the stack and deploys nothing, and is accepted. No
variable is a secret (ANS-16). Everything else is fixed in [`vars/main.yml`](vars/main.yml)
with the reason beside it, and an inventory value does not move it.

The default is `ghcr.io/branchleft/percona-server@sha256:20e400e5...3696`: the digest that
ghost-platform's Percona image workflow pushed on `main` at commit `1289eb507b95` (run
`43331723453`), scanned with no blocking finding (the exemptions in that repository's
`.image-scan-exemptions.json` lapse on 10 and 12 December 2026) and attested. The contract
test holds the full value. A new digest is a new image: change the register entry's tests
and this value in one pull request, so a reviewer reads both together.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; no collection beyond
  `ansible.builtin`.
- Debian 13 with Docker and Compose, `branchleft-compose@.service` and
  `/usr/local/sbin/branchleft-deploy`, all installed by other roles earlier in the
  host's play (the host baseline and `deploy_tooling`, class `internal`). The verifier
  role comes before this one so a registered image can be checked.
- The root file `/etc/branchleft/dbt1.env`, placed by the owner before the first deploy
  (below).

## What it changes on a host

- Directories `/etc/branchleft` and `/opt/branchleft` (root, `0755`), the project
  directory `/opt/branchleft/dbt1` with `conf.d` and `run`, and the socket directory
  `run/mysqld`, owned by the numeric user the image runs as (`1001`) so mysqld can create
  its socket there.
- `/opt/branchleft/dbt1/compose.yml` and `conf.d/branchleft.cnf` (root, `0644`).
- The unit `branchleft-compose@dbt1.service`, enabled.
- With an image, once: the pin `/etc/branchleft/dbt1.image.env` (written by the deploy
  program, root, `0600`), the container, and the Docker volume `dbt1_mysql-data` that
  holds the data on the host's root disk.

Decisions a reviewer should know the reasons for:

- **Loopback only.** `bind-address = 127.0.0.1`, host networking, nothing published, and
  the X protocol listener switched off (`mysqlx = OFF`), because it listens on every
  address whatever the bind address says. The cloud firewall does not filter the private
  network, so the only reliable "no inbound" is a server that does not listen there.
  Opening it to the application host is a later change that brings a host firewall in
  the same step.
- **Root only on the socket.** The image's entrypoint creates root for every host unless
  `MYSQL_ROOT_HOST` is set. It is set to `localhost`. Read from the public image
  entrypoint source, not from the pinned image, which is why the compose file states it.
- **No call-home.** The image starts a telemetry agent unless
  `PERCONA_TELEMETRY_DISABLE` is non-zero. It is `1`.
- **One configuration file, mounted over one path** (`/etc/my.cnf.d/branchleft.cnf`), not
  a directory, so the image's own option files stay in force.
- **GTID mode and the binary log from the first start**, server id `2`, row format. The
  isolation proof seeded its replica by GTID set, because file and position coordinates
  lost committed rows on this engine. Turning GTID mode on later is a staged procedure.
- **The health check is a real query**, over the socket, that returns `ready` only when
  the server is the pinned build (`8.0.46-37`), is not in its socket-only start-up phase,
  and reads back the settings above. A configuration file that was not read fails it, and
  a failed health check rolls the deploy back or refuses it. The root value reaches the
  client through the container's environment, never through the compose file.
- **Where the data lives.** A named Docker volume on the root disk, as on the other
  database host. A separate block volume would be spend, which is the owner's.
- **Root file and secrets.** The role takes no secret as input. The owner places
  `/etc/branchleft/dbt1.env` (root, group root, mode `0600`) with exactly one line,
  `MYSQL_ROOT_PASSWORD=` followed by 32 to 128 letters and digits. The alphabet is what
  the image's first-start script can put into a SQL string and what the unit's
  environment-file parser keeps whole; any other character breaks the first start and
  leaves a half-initialised data directory. The unit reads this file after the pin, and
  systemd lets a later file override an earlier one, so any other line (an `IMAGE=` line
  above all) is refused. The value is used on the first start only: changing the file
  later does not change the database's password.
- **Why the deploy is once.** See "What the role does". Two further refusals protect data:
  a pin that exists and differs from the input, and an initialised data directory with no
  pin.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
python3 ansible/harness/run_harness.py ansible/roles/db_t1
```

The unit tests run without Docker: from `ansible/roles/db_t1`, run
`python -m unittest discover -b -s tests/unit`. They hold the rendered files to the
properties above and each task refusal to its condition.

The Molecule scenarios run in a systemd container with no Docker and a stand-in deploy
program (a Python program that records its arguments and writes the pin the way the real
one does). `default` converges with an image and checks the files, modes, the unit and the
single deploy call; the second converge must change nothing. `refusals` runs one case per
refusal and checks each wrote nothing. They cannot prove the container, the first
initialisation, the health check or the attestation check: those are proven only by the
first live apply.

## How it is delivered

Only through the gated workflow (ANS-17): the plan in check mode, the approval, the pull
of that exact commit on the host, and a second run that must report no change. The host's
playbook applies this role last, after `deploy_tooling`, so that a refusal here holds
nothing else back. With the default image the apply creates the directories and files and
enables the unit, and starts nothing.

Check mode shows less than an apply, and the gaps are named: on a fresh host the unit
template does not exist during a plan, so the plan does not show the unit's enablement,
and the directories the plan does not create gate the file tasks (they appear in the
second plan). A skipped command reports no change, so the deploy itself would be invisible
in a plan: a separate task, `Report in check mode that the image would be pinned and the
stack started`, runs `true` in check mode only and reports changed when a deploy is due. A
plan with the pin in place, or with no image, reports no change. The role's behaviour tests
run both plans for real. The plan reads the owner's root file and fails if it is not in
place when an image is given, which is intended.

What the first apply of the host's play puts on db-t1, besides this role's files: the
deploy tooling role (before this role in the play) installs the deploy wrapper and the
compose template unit, and tells systemd to reload. That role does not write the sudoers
drop-in; the host's first-boot configuration did, and the role refuses a host without it.
The grant it checks is `deploy ALL=(root) NOPASSWD: /usr/local/sbin/branchleft-deploy`. So
adding the role to this host's play makes the host depend on that grant, and whoever holds
the `deploy` account's key on db-t1 can run `sudo branchleft-deploy dbt1 <image>` at any
time, outside this role's never-replace guard. The wrapper accepts only an image in its
attested register, and a failed health check on a replaced image rolls the pin back, so the
cost of misuse is downtime, not data. Three images are registered today
(`ghost-tenant`, `portal-apps` and `percona-server`).

The order of the first deploy: the owner places the root file; the image is built, scanned
and registered with the deploy program; the same change sets `db_t1_image`; the apply
deploys it. Until the root file is in place the plan fails, which is intended: the pull
that carries the digest does not apply on a host without it. The owner steps are in the
change that introduced the role.

## How to change it safely

1. A pin changes in one place: the version in `vars/main.yml`, the digest in
   `defaults/main.yml`, and the test that holds them.
2. Do not turn a refusal into a warning to make a run pass. The refusals are the only
   thing between an apply and a running tenant database.
3. Never add a `ports` key, a second service, a literal image, or a bind address other
   than loopback without adding the host firewall in the same change.
4. The image the organisation derives must keep the contract this role relies on: mysqld
   runs as user `1001`, the option directory is `/etc/my.cnf.d`, and the entrypoint honours
   `MYSQL_ROOT_HOST`, `MYSQL_ROOT_PASSWORD` and `PERCONA_TELEMETRY_DISABLE`. If it does not,
   the health check fails loudly on the first start.
5. A task that reads the root file keeps `no_log` and `diff: false`, and keeps checking the
   shape without printing a line. The file's value is never printed, copied or compared.

## Named limits

- **A half-finished first start can leave root without a password.** The container's
  restart policy brings the server back after a crash before the image's start-up script
  has set the root password. The role cannot see this. Afterwards it refuses on its own:
  the data directory exists and the pin was deleted by the failed first start, so a retry
  stops at "holds an initialised database". Every retry must be preceded by
  `docker compose -p dbt1 down` (no `-v`), so that nothing keeps serving a server with an
  empty root password. The role keeps refusing until the owner has looked at the volume
  `dbt1_mysql-data` and decided by hand whether the half-made data is removed. This
  follows the public build files of the image and is not proven on the pinned image.
- The role cannot check that the digest is Percona Server 8.0.46-37. The container's health
  check does, on every start.
- The data-directory refusal looks at Docker's default data root. A moved data root makes it
  never fire, which fails open for that one refusal; the pin refusal still holds.
- The image's own defaults were read from its public build files, not from the pinned
  image, and not on a running server.
- A change to the compose file or the configuration reaches the running database only at a
  restart, which the owner chooses.
- Backup, monitoring, replication and tenant provisioning are not here.

## Clauses this role exercises

ANS-3 (modules before commands), ANS-9, ANS-10 (check mode), ANS-11 (idempotent), ANS-12
(no role imports another), ANS-14, ANS-15, ANS-16 (no secret reaches a log) and ANS-17.
