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
2. Creates the stack's directories, renders the compose file, delivers the program that makes the
   exporter's account (below) and renders the MySQL
   configuration (which binds the host's private address), and installs the database port
   rule: a program, its boot unit and a drop-in that makes Docker follow and require that
   unit, then loads the rule and reads it back (see "The listener rule").
3. Enables the stack's unit without starting it.
4. When an image is given and the host has no image pin: checks the shape of the
   owner-placed root file, then runs `branchleft-deploy dbt1 <image>`, which verifies
   the image's attestation (anonymously: the package is public), writes the pin and
   starts the stack and waits for its health check.

It does not:

- start, stop, restart or recreate a running database. After the first deploy a
  different image is refused, not applied, because replacing the image of a database
  that holds data restarts it for every tenant and may upgrade the data in place.
- write the image pin or the root file, or read the root value. The pin is the deploy
  program's. The root file is the owner's.
- create a tenant database, a tenant account, a backup or a replica. Those are other roles and
  other steps. The one account the stack makes is the metrics exporter's, by a service of the
  stack itself, not by a task of this role ("The exporter's account", below). The one firewall
  rule the role creates is the database port's (below).
- open any port to any host but one. The server listens on the private address and only the
  application host's address is admitted to it, the exporter listens on loopback, and the
  compose file publishes nothing (see "The listener rule").
- register the image with the deploy program. The register is by image name, in
  `hetzner/provision/branchleft_deploy.py`: the deploy program verifies the attestation
  of a registered name against its workflow, and pins a name that is not registered
  without verifying it. The name `ghcr.io/branchleft/percona-server` is registered, so a
  digest of it that the Percona image workflow did not sign is refused. A test holds the
  name in the register.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares one input, `db_t1_image`, and
[`defaults/main.yml`](defaults/main.yml) gives it the digest of the image to deploy. Empty prepares
the stack and deploys nothing, and is accepted. The role takes and handles no secret. Everything else
is fixed in [`vars/main.yml`](vars/main.yml) with the reason beside it, and an inventory value does not
move it.

The default is `ghcr.io/branchleft/percona-server@sha256:20e400e5...3696`: the digest that
ghost-platform's Percona image workflow pushed on `main` at commit `1289eb507b95` (run
`43331723453`), scanned with no blocking finding (the exemptions in that repository's
`.image-scan-exemptions.json` lapse on 10 and 12 December 2026) and attested. The contract
test holds the full value. A new digest is a new image: change the register entry's tests
and this value in one pull request, so a reviewer reads both together.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; no collection beyond
  `ansible.builtin`.
- `iptables` and `iptables-restore`, which the role does not install (the same package the
  `egress_nat` role needs, from the host baseline), and systemd. The program refuses to run
  without them and names the role that installs them. Docker's unit `docker.service` is the
  one the drop-in orders.
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
- `/opt/branchleft/dbt1/compose.yml`, `conf.d/branchleft.cnf` and `exporter-account.sh` (root,
  `0644`). The compose file holds three services: the database, the service that makes the
  exporter's account, and the MySQL metrics exporter.
- The unit `branchleft-compose@dbt1.service`, enabled.
- The database port rule: the program `/usr/local/sbin/branchleft-dbt1-listener-rule`
  (root, `0755`), the unit `/etc/systemd/system/branchleft-dbt1-listener-rule.service`
  (enabled and started), the drop-in
  `/etc/systemd/system/docker.service.d/20-branchleft-dbt1-listener-rule.conf` (root, `0644`)
  and, in the kernel's filter table, the chain `BRANCHLEFT-DBT1-IN` with one jump to it at
  the top of `INPUT`. Nothing else of the firewall is written.
- With an image, once: the pin `/etc/branchleft/dbt1.image.env` (written by the deploy
  program, root, `0600`), the container, and the Docker volume `dbt1_mysql-data` that
  holds the data on the host's root disk.

Decisions a reviewer should know the reasons for:

- **The private address, one source.** `bind-address = 10.20.1.200` (db-t1's own address,
  from `hetzner-host/addressPlan.ts`), `port = 3306`, host networking, nothing published, and
  the X protocol listener switched off (`mysqlx = OFF`), because it listens on every
  address whatever the bind address says. The cloud firewall does not filter the private
  network, so the bind and the host firewall rule that admits only the application host
  (`10.20.1.201`) are delivered in the same run, and the rule is loaded before a server can
  start with the new configuration. Never a wildcard, never loopback: nothing local needs
  TCP (the administrative accounts and the exporter use the socket).
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
- **The metrics exporter (ws#1810).** A second service, the same attested
  `ghcr.io/branchleft/mysqld-exporter` image db1 runs, pinned by digest in `vars/main.yml`
  (`db_t1_exporter_image`). It uses the host network and listens on `127.0.0.1:9104`, never on
  the private address and never on a published port, because nothing on the tenants network
  has a reason to read it directly (the database port rule covers port 3306 only): db1's replica
  tunnel forwards its own port 9105 to this one, and Prometheus on edge1 reads it there
  (`hetzner/monitoring/render.ts`, the `db_t1_replica` job). It reads the database over the
  socket as the MySQL account `exporter`, with a credentials file the owner places (see "Owner
  step for the exporter"). The file is mounted by name with `create_host_path: false`, so a
  missing file fails the start loudly instead of Docker creating a directory in its place. The
  exporter starts only once the database is healthy and the `exporter-account` service is
  healthy (the account exists and the file's login works), and its own health check is
  `mysql_up 1`, not an HTTP 200, as on db1.
- **A bounded log.** Both services use Docker's `json-file` driver with three files of 10 MB
  each (`db_t1_log_max_size`, `db_t1_log_max_file`): at most 30 MB of container log per
  service, rotated, whatever the age. Docker's default is one file that grows without bound.
  The host's own journal is bounded by `host_baseline` (30 days; see that role's README). This
  host's stated local log retention is therefore: system journal 30 days, container logs 30 MB
  per container.
- **Where the data lives.** A named Docker volume on the root disk, as on the other
  database host. A separate block volume would be spend, which is the owner's.
- **Root file and secrets.** The root value is not an input: the role never reads or writes it. The owner places
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

## How the image is pulled

`ghcr.io/branchleft/percona-server` is a public package, so the host pulls the image, and the deploy
program reads its attestation, with no login. This is the owner's ruling of 26 Nov 2026: the hardened
build is published publicly rather than read through a token. The role writes no Docker config, sets no
`DOCKER_CONFIG`, makes no `/etc/branchleft/registry` directory, takes no registry input and holds no
registry secret. (The deploy program and the Compose unit still name a shared Docker config directory
for other stacks; on this host it does not exist, and an absent directory is an anonymous pull.) The
`mysqld-exporter` image is public too.

The attestation check is unchanged: the deploy program still verifies the digest against the Percona
image workflow before it pins it. What changed is only that it reads the registry anonymously.
**The package must be public before the first apply.** While it is private the anonymous read is
refused (`unauthorised`) and the deploy stops with the deploy program's own message, with nothing
started and no pin written; making the package public is the owner's step from the Desk, never an
agent's.

## The listener rule

The database listens with host networking, so a connection to it reaches the host's `INPUT`
chain. It does not reach `DOCKER-USER`, which sees only forwarded traffic (the
`node_exporter` README says the same of its port). The cloud firewall does not filter the
private network, so without a host rule every host on `10.20.1.0/24` could open a connection
to port 3306 the moment mysqld binds the private address.

The role installs `branchleft-dbt1-listener-rule` (`files/branchleft_dbt1_listener_rule.py`),
run as root by its own unit. It owns one iptables chain, `BRANCHLEFT-DBT1-IN`, and one jump to
it from `INPUT`:

```text
-A INPUT -j BRANCHLEFT-DBT1-IN
-A BRANCHLEFT-DBT1-IN -s 10.20.1.201/32 -p tcp -m tcp --dport 3306 -j ACCEPT
-A BRANCHLEFT-DBT1-IN -p tcp -m tcp --dport 3306 -j DROP
```

| Traffic                                 | Result                                                      |
| --------------------------------------- | ----------------------------------------------------------- |
| TCP to 3306 from `10.20.1.201` (app-t1) | Accepted by the chain; MySQL still needs TLS and an account |
| TCP to 3306 from any other source       | Dropped, this host's own address included                   |
| Any other port, SSH included            | Matches neither rule and falls back to `INPUT` unchanged    |
| Every other chain, every policy         | Not read, not written                                       |

The addresses are the role's variables (`db_t1_private_address`, `db_t1_client_address`),
held by a test to `TENANTS_HOST_IPS` (`dbT1`, `appT1`) in `hetzner-host/addressPlan.ts`; no
template writes one. Why iptables and why its own chain: the host already has `iptables` (the
NAT unit of `egress_nat`, Docker and fail2ban use it), `patterns/firewall_nat_sysctl` is
default-drop and takes over the whole ruleset (not adopted), and a chain of its own means the
program can say exactly what it owns.

How the program behaves:

- The chain is made in one `iptables-restore --noflush` transaction that declares, empties and
  refills it, so a reload never leaves it empty for a moment. No other chain is named.
- The jump is inserted as rule 1 of `INPUT` when absent. When present it may sit under
  fail2ban's own jumps (`-j f2b-*`, which fail2ban puts at the top whenever it starts) and
  under nothing else; a jump under any other rule is a refusal, not a repair, because a rule
  under an earlier accept is not a rule. Two copies of the jump are a refusal.
- It reads the table again after the load and fails if it differs from what is wanted.
- At boot it tries again, up to five attempts with a wait that grows (2, 4, 6 and 8 seconds,
  `--retry-delay`), when a command fails or gives no answer: the xtables lock held longer than
  its 10-second wait, or a restore that fails once. A failed unit means no Docker, and nothing
  starts Docker again, so a transient failure is worth five tries. A refusal (a misplaced jump,
  a missing tool, a load that did not take effect) is never retried, and neither is `--check`.
  The unit's `TimeoutStartSec=300` bounds the whole run.
- `--check` changes nothing, prints each difference (`+` to add, `-` to remove) and exits 3
  when there is one, 0 when not. Any other status is a refusal. The role runs it in a plan
  (`check_mode: false`, read only), so the plan shows whether the loaded rule would change and
  what the difference is; an unreadable table fails the plan.
- Every address and port is checked first (one IPv4 host address, not loopback or a wildcard;
  a port from 1024 to 65535) and every command runs from an argument list under a timeout.

Boot order, which is the part a firewall proof most often misses:

- `branchleft-dbt1-listener-rule.service` is a `oneshot` with `RemainAfterExit` and
  `Before=docker.service`. A drop-in (`docker.service.d/20-branchleft-dbt1-listener-rule.conf`)
  gives Docker `Requires=` and `After=` that unit. The order has to bind the Docker daemon and
  not only the stack's unit: a container with `restart: unless-stopped` is started by the
  daemon itself, without the stack's unit. With the `Requires=`, a host where the rule failed
  runs no database container at all.
- The role reloads the unit (`ExecReload` runs the same program) and never restarts it,
  because a restart of a required unit restarts the unit that requires it, which here is
  Docker and with it the database. The unit has no `ExecStop`: stopping it leaves the rule in
  place, but it does stop Docker, as any stop of a required unit does.
- The read-back task asks systemd, after the load, that the unit is active and enabled and
  that `docker.service` lists it under `Requires` and `After`.

The rule is loaded in the same run that renders `branchleft.cnf`, and the configuration
reaches the server only at a start the owner or the deploy chooses, so the server never binds
the private address before the rule is in place.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
python3 ansible/harness/run_harness.py ansible/roles/db_t1
```

The unit tests run without Docker: from `ansible/roles/db_t1`, run
`PYTHONPATH=files python -m unittest discover -b -s tests/unit`. They hold the rendered files
to the properties above and each task refusal to its condition.
`test_listener_rule_program.py` runs the real program against a fake `iptables` and
`iptables-restore` that keep a filter table in a file. `test_db_t1_behaviour.py` runs the
rule's task file for real with `ansible-playbook` on localhost, against the same fakes: a plan
before the rule is loaded, the apply, the plan and the second apply after it, and a loaded rule
that admits another source.

The Molecule scenarios run in a systemd container with no Docker and a stand-in deploy
program (a Python program that records its arguments and writes the pin the way the real
one does). The container has `NET_ADMIN` and a real `iptables`, so the rule is loaded into
the container's own network namespace, and a stand-in `docker.service` carries the drop-in.
`default` converges with an image and checks the files, modes, the unit, the single deploy
call, the loaded chain and the jump, and that systemd lists the rule unit in the stand-in
Docker's `Requires` and `After`; the second converge must change nothing. `refusals` runs one
case per refusal and checks each wrote nothing. They cannot prove the container, the first
initialisation, the health check or the attestation check, and they do not reboot: those, and
the boot order across a real boot, are proven only by the first live apply and a reboot drill
on the host.

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
3. Never add a `ports` key, another service beyond the database and its exporter, another
   literal image, a bind address other than the private address, or a second admitted source
   or port, without changing the rule program, the unit and the tests that hold them in the
   same change. The exporter is the one literal image; its name must be in the deploy
   program's register (`ATTESTED_IMAGES`), or the first deploy refuses the whole stack.
4. The image the organisation derives must keep the contract this role relies on: mysqld
   runs as user `1001`, the option directory is `/etc/my.cnf.d`, and the entrypoint honours
   `MYSQL_ROOT_HOST`, `MYSQL_ROOT_PASSWORD` and `PERCONA_TELEMETRY_DISABLE`. If it does not,
   the health check fails loudly on the first start.
5. A task that reads the root file keeps `no_log` and `diff: false`, and keeps checking the
   shape without printing a line. The file's value is never printed, copied or compared.

## The exporter's account

The exporter's health check needs `mysql_up 1`, which needs a MySQL account named `exporter`.
`branchleft-compose@.service` runs `docker compose up -d --wait`, so on a fresh data directory a
missing account made the exporter unhealthy about two minutes after the database came up, the
deploy program rolled the pin back to nothing, and the first deploy failed every time. The
account used to be a hand step to run inside that window. It is now made by the stack.

How: a third service, `exporter-account`, runs the database image (the only image with a MySQL
client) as uid 65534, the one user that can read the owner-placed `0400` credentials file, with no
network. Its program, [`files/exporter_account.sh`](files/exporter_account.sh), starts once the
database is healthy and, on **every** start of the stack:

1. reads the `exporter` user and its value from the credentials file and refuses a file that names
   another user, a value under 20 characters, or a character outside `A-Za-z0-9._~-` (the same
   rule as the file's creation step), before it touches the database;
2. connects as root over the shared socket with the root value from its environment, the same
   environment the database gets from `/etc/branchleft/dbt1.env`;
3. runs `CREATE USER IF NOT EXISTS`, `ALTER USER` (so the account's value always equals the
   file's), `GRANT PROCESS, REPLICATION CLIENT ON *.*` and `GRANT SELECT ON performance_schema.*`,
   with `SQL_LOG_BIN=0` so a replica carries no transaction of its own (no errant GTID);
4. idles. Its health check connects as the exporter with the credentials file alone and reads
   both grants back, so the service is healthy only when the exporter can really log in.

The exporter `depends_on` that service being healthy. The value goes from the file to the
database client's standard input only: never an argument, never printed, never in the repository,
a task result or a log. The role's tasks never read the file (a test holds this); the program
reads it inside the container.

Fresh data directory and an existing one are the same path, so the same mechanism repairs a host
whose database has data and no account, at the next start of the stack.

Why this and not the alternatives, read from the base image's entrypoint (the Dockerfile in
ghost-platform `db/percona` adds nothing to it):

- **An init script in `/docker-entrypoint-initdb.d`.** The entrypoint runs `*.sh` and `*.sql`
  there only when `$DATADIR/mysql` does not exist, as uid 1001 (the image's `USER`), against a
  socket-only server whose binary log is on. It never runs on an existing data directory, so it
  does not repair a host that already has one, it needs the value readable by uid 1001 (the file
  is `0400` for uid 65534, so the role would have to copy the value into a second file), and it
  logs the statements to the binary log unless it switches that off. Rejected.
- **A role task that runs `docker exec` after the deploy.** The deploy program blocks inside
  `docker compose up --wait` and has already deleted the pin by the time the task could run, and
  the role never touches a running database. Rejected.
- **A health check that ignores the account.** The account is still missing, and the check was
  made `mysql_up 1` on purpose, because the exporter reports a healthy container that exports
  nothing otherwise. Rejected.
- **A one-shot service that exits.** An exited container of the pinned image reads as "not up"
  to the deploy program's rollback decision (`pinned_image_is_up`), which would make a failed
  restart roll back for a cause that is not the image. The service idles, healthy, instead.

### A host whose first deploy already failed on this

On db-t1 today the data directory `dbt1_mysql-data` exists, the account does not and the pin was
deleted by the deploy program. The role's refusal ("a data directory that has no pin") is kept as
it is, and it fires in the plan too, so the delivery's plan fails for db-t1 and the host is never
applied: it receives no files at all until the directory is gone. The volume holds no tenant data.
The one hand step, in this order:

1. This change merges first. An older commit delivered between the step below and the merge would
   deploy the old compose file, fail the same way and delete the pin again.
2. The owner runs on db-t1:

   ```text
   sudo docker compose -p dbt1 down -v
   ```

   It stops the dbt1 containers and deletes the volume `dbt1_mysql-data` (empty database files; it
   cannot be undone, and nothing else lives in it).

3. The next delivery run's plan passes for db-t1, and its one approved apply delivers the compose
   file and the program and deploys in the same run, so the stack comes up with the account made
   by the stack. Good looks like `mysql_up 1` from
   `curl -s http://127.0.0.1:9104/metrics | grep -x 'mysql_up 1'` on db-t1, and a second apply that
   reports no change.

## Owner step for the exporter

Before the first deploy (the stack refuses to start without the file), on db-t1, as the owner, place
the credentials file. It is the only secret step left; the account it names is made by the stack.
The step reads the value from the shell, never from a file or an argument, and it must be at least 20
characters of letters, digits and `._~-` (the exporter's parser reads any other character as syntax;
the stack's program refuses anything else). Record it in the owner's password manager; nothing else
reads it. The file is owned by uid 65534, the user the exporter image runs as, mode `0400`:

```text
read -rs EXPORTER_PW; export EXPORTER_PW
printf '[client]\nuser = exporter\npassword = %s\nsocket = /var/run/mysqld/mysqld.sock\n' "$EXPORTER_PW" | sudo install -o 65534 -g 65534 -m 0400 /dev/stdin /etc/branchleft/dbt1-exporter.my.cnf
unset EXPORTER_PW
```

The user line must read `exporter`. The deploy program refuses the stack while
`ghcr.io/branchleft/mysqld-exporter` is not in its register (branchLeft/shared-infra#944, an owner
merge), so that change lands first.

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
  restart, which the owner chooses. The rule, by contrast, is live at the apply. On a host
  whose database is already running on loopback, the apply loads the rule first and the new bind
  comes at the owner's restart.
- The rule trusts the source address. Another host on the private network could forge
  app-t1's address; the database still needs TLS (`require_secure_transport`) and an account.
- The rule is IPv4 only. The server binds one IPv4 address, so nothing listens on IPv6.
- A client on db-t1 itself connecting to the private address is dropped (its source is this
  host's own address); the socket is the local path.
- The rule matches port 3306 only. The X protocol (33060) is off and nothing else is opened
  by this role; a port another role opens is that role's to guard.
- Docker requires the rule unit, so a failed rule unit means no Docker on db-t1. That is the
  point: a host with no Docker also runs no database.
- mysqld binds a specific address. If the private interface is not up when Docker starts,
  mysqld fails to bind and its container restarts until the address is there; nothing is
  exposed meanwhile, and the stack's unit waits for `network-online.target`.
- fail2ban's jump may sit above ours. A rule another program puts above ours and that
  accepts the database port makes the program refuse at the next run; it never moves it.
- Not proven by a reboot: that the rule unit runs before Docker on a cold boot. The unit text
  and the drop-in say it, a test holds them, and Molecule reads the drop-in's effect back from
  systemd; the first reboot of the real host is the proof.
- The role does not check the exporter's credentials file (its owner, its mode or its shape);
  the `exporter-account` service does, at every start. A missing file fails the start loudly. A
  file that names another user, or holds a value the statements cannot carry, makes that service
  exit non-zero, so the deploy fails at once with the program's own line in the container log
  (`docker logs dbt1-exporter-account-1`), and no value in it.
- The account's value is synced from the file at each start of the stack, not while it runs. A
  value changed in the file reaches the database at the next start of the `exporter-account`
  service (`docker compose -p dbt1 restart exporter-account`). The sync also means a wrong value
  in the file replaces a working account value at the next start; the health check then fails
  and the exporter does not start, which is loud, not silent. The service's root value is in its
  container environment, as the database's is; the trust boundary is the Docker socket in both
  cases.
- The program hands the value to the client through a here-document. The image's shell (bash)
  does that through a pipe for a body this small, so no temporary file holds it; a shell that
  used a temporary file under `/tmp` would write it to the container's filesystem briefly.
- The service's program is shell, not Python, because the only image it can run in (the database
  image) carries no Python; it passes `shellcheck` and its tests run it against a fake client.
- The statements write to the database, so a server later run read-only (`super_read_only`) makes
  the service exit non-zero at each start. Change the program in the same change that makes it
  read-only.
- The exporter reaches Prometheus only through db1's replica tunnel, which is for the
  migration. When the tunnel is torn down, the path to this host's database metrics is a
  separate change (ws#1810 follow-up).
- Backup, replication and tenant provisioning are not here.

## Clauses this role exercises

ANS-3 (modules before commands; the rule program has no module), ANS-9, ANS-10 (check mode), ANS-11 (idempotent), ANS-12
(no role imports another), ANS-14, ANS-15, ANS-16 (no secret reaches a log) and ANS-17.
