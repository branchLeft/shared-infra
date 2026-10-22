# db1_stack

This role prepares the database host and delivers its database stack. Part one
installs the host's prerequisites (`age` and a MySQL 8.0 client toolchain held to
that line) and renders the credentials file of the database's metrics exporter
from a password given at run time. Part two writes the database's compose file
and MySQL configuration, removes the legacy writer of the exporter file, and
enables the unit that runs the stack, without starting it. Together they replace
the hand-run steps that did these jobs: two scripts for part one, and the
database's runbook steps for part two.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does four groups of things on a Debian 13 host.

1. It installs the host prerequisites. It delivers the MySQL repository as a key
   file, a source file and an apt pin that holds the toolchain to the 8.0 line;
   it downloads one pinned package file and installs it; it installs `age` and
   the two MySQL packages; and it checks that the two MySQL packages are on the
   8.0 line.
2. It writes the exporter's credentials file, `/etc/branchleft/db-exporter.my.cnf`,
   from a password the caller supplies, owned by the account the exporter runs
   as, readable by that account only.
3. It removes the drop-in that wrote that same file before every start of the
   stack, `/etc/systemd/system/branchleft-compose@db.service.d/override.conf`, and
   reloads systemd. This is the second writer, and it is removed before the
   exporter file is written in the same run.
4. It renders the database's compose file, `/opt/branchleft/db/compose.yml`, and
   its MySQL configuration, `/opt/branchleft/db/conf.d/branchleft.cnf`, creates
   the directories they need, and enables `branchleft-compose@db.service`. It
   does not start it.

It does not start, stop, restart or recreate any container, does not run
`docker compose`, removes no volume and no data, and creates no user. A
restart of the database is an owner's step, not this role's.

It refuses to run, before it changes anything, when a second compose file, a
compose override file or a `.env` file sits beside `compose.yml`. It refuses when the database image pin that
`branchleft-deploy` writes is absent or is not the one line that program writes,
but that check runs after the compose file is rendered and before the unit is
enabled (see "The database image pin" for why, and for the bootstrap order).

The role has not been applied to the host. The live run waits on the database
host's enrolment, which the owner has not yet decided, and on the gated workflow (see
"How it is delivered"). After it is applied, the hand-run prerequisites script
must not be run again: it would put back the repository entry the role removes
(see "What it changes on a host").

It does not decide where the exporter password comes from, create the database
account the password belongs to, or rotate the password in the database. The
role makes the file match a password it is given; putting the same password in
the database is a separate step, and the exporter account itself is in runbook
section 4, outside this role (see "Named limits").

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every input, and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. Ansible checks
the inputs when the role starts.

| Variable                      | Default                    | Meaning                                                                                   |
| ----------------------------- | -------------------------- | ----------------------------------------------------------------------------------------- |
| `db1_stack_exporter_password` | none, required, **secret** | The exporter account's password: at least 20 characters of `A-Za-z0-9._~-`, nothing else. |
| `db1_stack_apt_packages`      | `age`, the two MySQL ones  | Packages installed from the apt index.                                                    |
| `db1_stack_downloads`         | the `libaio1` package file | Pinned downloads: `url`, `dest` and a `sha256:` or `sha512:` `checksum`.                  |
| `db1_stack_debs`              | the same package file      | Local package files installed by path; each must be the `dest` of a download.             |

Part two adds no input. Its one secret input, the root password, is not an
input: see "Where the database's secrets are, and what the role does not read".

**The password is the only secret this role takes.** It reaches the role as a
variable supplied at run time, never as a default and never in a file of this
repository. Every task that reads, templates or passes it sets `no_log: true`,
and `diff: false` where a diff would show it (ANS-16). Where the value comes from,
and how it reaches a host that pulls its commit, is the owner's decision (PRIN-6)
and not this role's; until it is made, nothing can supply the password on a real
host.

The pins that are not inputs (the repository, its suite and component, the key
digest, the version line, the packages the pin file covers, the exporter's uid and
the file mode, the password rules, the stack's paths, the exporter image digest)
are in [`vars/main.yml`](vars/main.yml), each with the reason for it. An inventory
value does not change them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` in
  `meta/main.yml` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and `python3-apt`. Debian 13 is the release
  every production host runs.
- A host that can reach `deb.debian.org` (the download runs on the host, not on
  the controller) and `repo.mysql.com` (the index). The test needs neither.
- For part two: the host's provisioning has installed `branchleft-compose@.service`
  and the deploy program `/usr/local/sbin/branchleft-deploy` (both from
  `shared-infra`), and `branchleft-deploy db` has written
  `/etc/branchleft/db.image.env` at least once. The role does not install either.

## What it changes on a host

Part one:

- `/var/cache/db1-stack/` (root, `0755`) and the pinned package files in it
  (root, `0644`).
- `/etc/apt/keyrings/mysql-community.asc` (root, `0644`): the vendored repository
  keys. `/etc/apt/sources.list.d/mysql-community.sources` (root, `0644`): the
  repository, signed by that file. `/etc/apt/preferences.d/mysql-community-8.0`
  (root, `0644`): the pin that holds the toolchain to the 8.0 line, with priority
  1001 so a newer candidate is never chosen.
- Removes `/etc/apt/sources.list.d/mysql-community.list` and
  `/usr/share/keyrings/mysql.gpg`, which the hand-run script made. They name the
  same repository with another key file, and apt refuses two entries for one
  repository that disagree about the key. If either was there, the role refreshes
  the apt index.
- Installs the packages in `db1_stack_debs` and `db1_stack_apt_packages`.
- `/etc/branchleft/` (root, `0755`), the directory the host's provisioning
  creates; the role states its owner and mode so a run puts them back.
- `/etc/branchleft/db-exporter.my.cnf`: owner and group uid 65534 (`nobody`, the
  user the exporter image runs as), mode `0400`. Content: `[client]`, then the
  `user`, `password` and `socket` lines.

Part two:

- Removes `/etc/systemd/system/branchleft-compose@db.service.d/override.conf`
  (the legacy drop-in). Then, on a host where systemd runs, it reloads systemd and
  writes `/var/cache/db1-stack/legacy-drop-in-reloaded` (root, `0644`, no content).
  It reloads whenever the file is gone and that marker is absent, so a run that
  stopped between the two steps reloads on the next run. A run that removes the
  file also deletes the marker first, so a drop-in put back by hand and removed
  again is followed by a reload, not skipped.
- `/opt/branchleft` (root, `0755`), `/opt/branchleft/db` (root, `0755`),
  `/opt/branchleft/db/conf.d` (root, `0755`), `/opt/branchleft/db/run` (root,
  `0755`) and `/opt/branchleft/db/run/mysqld` (uid `999`, the database's uid, mode
  `0755`). The directory is owned by the database, so mysqld can create its socket
  in it and no other local account can add an entry to it. A `0755` directory
  lets clients search it, so the healthcheck, the grants program and the exporter
  open the socket from it, and mysqld creates the socket world-connectable. The
  root password is sent over that socket, so a squatter's socket in this directory
  would receive it; a sticky `1777` directory would not stop one, because the
  sticky bit only keeps other accounts from removing an entry, not from creating
  one.
- `/opt/branchleft/db/compose.yml` (root, `0644`) and
  `/opt/branchleft/db/conf.d/branchleft.cnf` (root, `0644`), rendered from the
  templates in this role.
- Enables `branchleft-compose@db.service` on a host where systemd runs. It does
  not start it.

It reads, and never writes, `/etc/branchleft/db.image.env` (the database image
pin that `branchleft-deploy` writes). That is the one environment file it reads.
It never reads `/etc/branchleft/db.env`, and it does not check the environment the
unit loads from elsewhere (see "Named limits").

## How to run its test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/db1_stack
```

The harness runs lint, yamllint, a fresh-state check-mode run, converge, a second
converge that must change nothing, verify, a configured-state check-mode run,
Molecule's own check action and destroy. It needs Docker on the machine and
creates one container with no network. It never touches a host.

CI runs the harness over every role and every pattern (the Ansible workflow), so
this scenario runs on each pull request.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan job in check mode,
the approval of the protected environment, a pull of that exact commit of `main`
on the host, and a second run that must report zero changes. Nothing in this
repository applies the role by hand, and an author's local run is the container
test. The live run is waiting on the database host's enrolment and the gated
workflow being available for this host; until then this role is tested and not
delivered.

The first live apply on the database host must not recreate or restart the
running MySQL. The role does not do either, so the check-mode plan of that run is
the thing to read for it: a plan that shows the compose file or the configuration
as changed is expected on the first run, and a plan that shows a container
recreated or started is not.

## How to change it safely

- A pin changes in one place and in one change: the value in `vars/main.yml` or
  `defaults/main.yml`, the digest or text the test expects in
  `molecule/default/verify.yml` or `tasks/verify_part_two.yml`, and (for the key)
  the key file.
- Run the whole harness, not only the step you touched. Every control below is
  asserted by a test, and the part two table records the removal that made it fail;
  a new control should be removed and recorded the same way.
- A new task file, a new module, a new task keyword or a new module option fails
  `molecule/default/tasks/verify_role_source.yml` until the allowlist there names
  it. Widen the allowlist in the same change and say why in the pull request.
- Never turn `no_log` off to see why a task failed on a real host. Reproduce on a
  lab host with a throwaway value.
- Never loosen `scan-downloads.j2` (in the `packages_and_downloads` pattern), the
  assertions at the top of `tasks/main.yml`, or the password rules to make a run
  pass. A download that cannot satisfy the first, or a password the second
  refuses, is the thing to fix.
- Never add a literal digest for the database image to the compose file. The
  deploy program refuses a compose file that does not read its image from
  `${IMAGE}`, and a literal would stop the pin file controlling the image (see
  "Part two: the database stack").

## Part two: the database stack

### The compose file

`templates/compose.yml.j2` is rendered to `/opt/branchleft/db/compose.yml`. That
is the name the deploy program checks, and the one the systemd template runs with
`WorkingDirectory=/opt/branchleft/db`. The unit runs `docker compose up` there with
no `-f`, so Compose reads whatever default file names it finds, and the deploy
program checks only `compose.yml`. The role refuses to run while any of eight
other names sits in the same directory. Three are base files that Compose would
read in place of `compose.yml`: `compose.yaml`, `docker-compose.yml` and
`docker-compose.yaml`. Four are override files that Compose would merge into
`compose.yml`, where they could swap the image, publish a port or add a service
without the deploy program's check seeing it: `compose.override.yml`,
`compose.override.yaml`, `docker-compose.override.yml` and
`docker-compose.override.yaml`. The eighth is `.env`: Compose reads it from the
project directory, and a `COMPOSE_FILE` line in it names the files Compose reads
(any file, or a second one to merge), a `COMPOSE_PROJECT_NAME` line makes it act
on another project and its containers, and a `COMPOSE_PROFILES` line starts
profile services, none of which the deploy program's check sees. The role writes
none of the eight. The `compose_stack` pattern refuses the same override names,
for the same reason; it does not refuse `.env`, and its own README names that as
a limit.

- The database image is `image: ${IMAGE}`. `branchleft-deploy` writes the digest
  into `/etc/branchleft/db.image.env`, and the stack's unit reads it as its
  mandatory environment file. The compose file is the one the deploy program
  checks, and that program refuses any compose file that does not read its image
  from `${IMAGE}`. So the role does not write the digest into the file. A literal
  would stop the pin file controlling the image, make a rollback a no-op, and make
  the nightly drift check report a difference after every deploy.
- The compose-wide digest assertion of the `compose_stack` pattern is not used
  here, for the reason above. The pattern's own README says to copy its shape,
  not to call it, and `website_app1` made the same decision for the same reason.
  The role checks the one digest that is pinned inline instead: the exporter's.
- The exporter image is `prom/mysqld-exporter:v0.20.0@sha256:abed8dac117b4ae5b70757f988e44795935b9a72c3b58d720c67ba688f8cb79e`.
  That is the line `db/stack/compose.yml` in `ghost-platform` carries on
  `origin/main` at commit `5e52f78`, read on 21 October. Nothing else writes it.
- The mysql healthcheck and the exporter healthcheck are the ones the source file
  has. The exporter's gate is `grep -qx "mysql_up 1"`, not a process check and not
  an HTTP 200: an exporter that cannot authenticate serves `/metrics` and reports
  nothing.
- No service publishes a port. Both containers use the host network, and the root
  and service accounts connect over the socket only.

### The database image pin

`branchleft-deploy` writes the database image pin with `write_image_env` in
`hetzner/provision/branchleft_deploy.py`: the file `/etc/branchleft/db.image.env`,
mode `0600`, owned by root, holding one line, `IMAGE=<reference>`, and a line
break. The reference is a digest of the form `name@sha256:<64 lower-case hex>`.
A failed first deploy removes the file (runbook section 3), so the role's first
check is that it is present.

The role reads the file and never writes it. It refuses, before it enables the
unit, when the file is absent, is empty, has no `IMAGE=` key, has two lines, has
a tag without a digest, or has upper-case hex. The compose file and the exporter
file are written before that check, because the compose file must exist for
`branchleft-deploy` to read it before it writes the pin: on a rebuilt host the
bootstrap order is (1) run the role, which renders the compose file and then
stops at the pin check, (2) run `branchleft-deploy db`, which writes the pin, and
(3) run the role again, which completes. The unit cannot start without the pin, so
rendering the compose file before it is harmless. The pattern is
`^IMAGE=mysql:<tag>@sha256:<64 lower-case hex>\n\Z`. The test derives its fixture
from the writer's format: the same single line, with a made-up digest and no
image pulled.

### The unit, and the first live apply

The role enables `branchleft-compose@db.service` and does not start it. Enabling
means the unit starts at the next boot. Nothing else starts the stack, and the role
triggers no restart.

A change to the MySQL configuration (`/opt/branchleft/db/conf.d/branchleft.cnf`)
reaches the running database only when its container restarts. A bind-mounted
file that changes under a running `mysqld` has no effect until then, and this
role never restarts it. The owner's live steps say when to restart.

The legacy drop-in is removed before the exporter file is written in the same
run, and the daemon is reloaded straight after its removal. Order is the control
here: a systemd that still holds the legacy `ExecStartPre` would run the legacy
writer on any later restart, and rewrite the exporter file from `db.env`.

The first live apply must not recreate or restart the running MySQL. The role
cannot do either, and the plan's output is the thing to read for it.

Live steps for the owner, after the role has been applied and the database has
been restarted by the owner so that it runs the rendered configuration:

1. Read the check-mode plan of the first apply before approving it: the compose
   file and the configuration may show as changed, and nothing may show a
   container created, started or recreated.
2. Run the exporter account step in the database runbook (section 4), so the
   account the exporter file names exists in the database.
3. Check that the socket is world-connectable. On the database host, list the
   socket: `ls -l /opt/branchleft/db/run/mysqld/mysqld.sock`. The mode must read
   `srwxrwxrwx`. The exporter runs as uid 65534 and connects over that socket;
   the official image creates it with that mode, but nothing in the container
   test runs a database, so nothing has shown it. If the mode is anything
   narrower, `mysql_up` reads 0 and the exporter's healthcheck fails, which is
   loud, not silent: the stack reports the exporter unhealthy.
4. Read the exporter's metric: `mysql_up` must read 1 from the exporter's
   `/metrics` address, which is the same condition the healthcheck gates on.

### Where the database's secrets are, and what the role does not read

The root password (`MYSQL_ROOT_PASSWORD`) is in the host's own
`/etc/branchleft/db.env`. The database's unit reads that file, and the compose
file reads the root password from the unit's environment. The file is
hand-written and holds the backup and Object Storage credentials too, so this role
does not read it, and it takes no root-password input. A second input would be
a second writer of a value the host already owns, and a value that differed from
the database would make MySQL unhealthy and the deploy roll back.

Two things change because of this, and the database's runbook must say them:

- `EXPORTER_MYSQL_PWD` in `db.env` is dead. The drop-in that read it is removed,
  so nothing reads that key. Removing it from `db.env` is an owner's step.
- The runbook's rotation recipe for the exporter (edit `db.env`, restart the
  stack) no longer rotates the exporter file. The exporter file is written from
  `db1_stack_exporter_password`, which the caller supplies. Rotating the exporter
  password is therefore a change to this role's input, not to `db.env`.

### Two homes until cutover

The compose file and the configuration exist in two places until the owner's live
cutover: here, as templates, and in `ghost-platform` (`db/stack/compose.yml`,
`db/stack/conf.d/branchleft.cnf`, `db/systemd/db.override.conf`, the two contract
tests and `db/RUNBOOK-db.md`). The `ghost-platform` copies are not deleted by this
change. The drop-in there is the live writer until cutover. This role removes
`/etc/systemd/system/branchleft-compose@db.service.d/override.conf` on every run
that finds it, so a hand copy of that drop-in is removed again on the next run
and is not left in place. The owner's cutover must stop reinstalling it.

The divergence was checked against `ghost-platform` commit `5e52f78` (its
`origin/main` on 21 October). In the rendered output, every non-comment line of
the compose file and of the configuration is the same as the source. The only
differences are comments. The commit is recorded here, not in the templates. The
follow-up that removes the `ghost-platform` copies is filed
after cutover, and it runs the same comparison again before it deletes anything.

## What the test proves

The test runs in one Debian 13 container with no network. Each control in part one's
table is removed in turn, by a single edit, and the whole harness is run: each
removal makes a named step fail with the message shown, and the file is restored
afterwards. A control that does not make the test fail when it is removed is not
claimed.

Part one:

| Control                                                            | Removed by                                  | The harness then fails at                                                                                                      |
| ------------------------------------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| The write task hides its result (`no_log`)                         | deleting `no_log` on the write              | verify, "Assert no sentinel reached the log": the log holds the whole-file text of the exporter file                           |
| The file mode is `0400`                                            | setting `0644`                              | verify, "Assert the exporter file is private to the exporter's account"                                                        |
| The file is owned by the exporter's uid                            | setting uid `0`                             | the same task: `mode 0400, uid 0`                                                                                              |
| The password is refused for a character outside the set            | the anchor `\Z` changed to `$`              | verify, the trailing-line-break case: the role accepted the input                                                              |
| The same, for every character class                                | the set opened to any text                  | verify, the first bad character: the role accepted the input (the test tries a list of different characters and others)        |
| The allowed set is exact                                           | adding one character to the set in `vars`   | verify, "Assert the password pattern accepts exactly the allowed ASCII characters": the code point is on the wrong side        |
| An existing wide file is closed before the write                   | deleting the close task                     | verify, "Assert the wide file was closed by the task that runs before the write"                                               |
| A link at the file path is removed before the write                | dropping the link test from the removal     | verify, "Assert the link was removed and a closed file created in its place"                                                   |
| A directory holding only a hidden file is not removed              | `hidden: false` on the listing              | verify, the hidden-file case: the role accepted the input                                                                      |
| A directory holding only a subdirectory is not removed             | `file_type: file` on the listing            | verify, the subdirectory case: the role accepted the input                                                                     |
| A key change alone refreshes the index                             | dropping the key from the refresh condition | verify, the key case: "Expected the role to stop at 'Refresh the apt index after the repository files changed'"                |
| The password is refused when shorter than 20                       | the minimum lowered to 1                    | verify, the short case: the role accepted the input                                                                            |
| The exporter file is created empty and closed before it is written | disabling the task                          | verify, "The task that creates the exporter file empty and closed did not run, so the write created the file"                  |
| A directory left by Docker at the file path is removed             | disabling the removal                       | verify, the same assertion, because the directory stays in the way                                                             |
| The key file is compared with its pinned digest                    | deleting the comparison                     | verify, "Expected the role to stop at 'Refuse a repository key whose digest is not the pinned one'"                            |
| A download carries a sha256 or sha512 digest                       | deleting the form check                     | verify, "Expected the role to stop at 'Refuse a download entry that is not pinned by a sha256 or sha512 digest'"               |
| The download module checks the digest                              | deleting `checksum:` from `get_url`         | verify, the source scan: "Unpinned download in the role: ... get_url has no checksum"                                          |
| A package file is installed only from a pinned download            | deleting the destination check              | verify, "Expected the role to stop at 'Refuse a package file that is not the destination of a pinned download'"                |
| The toolchain is on the 8.0 line                                   | deleting the version match                  | verify, "Expected the role to stop at 'Refuse a MySQL toolchain that is not on the pinned line'"                               |
| The pin file holds the line                                        | priority `1001` changed to `500`            | verify, "The file /etc/apt/preferences.d/mysql-community-8.0 is not as declared"                                               |
| The hand-run installer's repository entry is removed               | disabling the removal                       | verify, "Expected the role to stop at 'Refresh the apt index after the repository files changed'": apt refuses the old entry   |
| The index is refreshed after a repository file changes             | disabling the refresh                       | verify, "Expected the role to stop at 'Refresh the apt index after the repository files changed'": the role accepted the input |
| No secret is a default                                             | adding one to `defaults/main.yml`           | verify, "The role's defaults/main.yml holds a variable the role does not declare, a password, or a sentinel"                   |
| The password option is secret in the argument spec                 | deleting `no_log` in `argument_specs.yml`   | verify, "The password option is not required and no_log, or has a default, or the spec holds a sentinel"                       |
| A second run changes nothing                                       | making the empty-file task rewrite each run | idempotence                                                                                                                    |

Part two. The checks that assert a file's content read the rendered file on the
instance, the order checks read the Ansible log, the source checks read the role's
own files on the controller, and the refusals run the role with the bad input and
require the named task to refuse, as part one does.

Every row below was removed or altered by one edit; verify then failed at the
named step with the message shown; the edit was reverted (`git status --porcelain`
showed only the test files); and verify passed again. How the rows were run:

- The content, order and source checks live in `verify_part_two.yml` and
  `verify_role_source.yml`. They were run on a converged instance as the play
  header of `verify.yml` followed by those two files, without the refusals in
  `verify_refusals.yml` (which run the role many times and are most of verify's run
  time, and which no row below exercises, other than the first two and the
  override rows).
- The rows for the override files and the rows for the paths a removal holds were
  added in the fourth review cycle and run against that head. The override rows
  were run on a converged instance as the play header of `verify.yml` followed by
  `verify_refusals.yml` alone: six cases for the image pin, then one case for each
  of the eight file names. The row names the case that failed, counted in that
  order. The `.env` row was added in the fifth review cycle and run the same way,
  against that head. The rows for the paths a removal holds need no instance: the file reads
  only the role's own files, so they were run on the controller as the role
  directory and its file list followed by `verify_role_source.yml`. In a full
  verify, the pins assertion in `verify.yml` compares the legacy file list with its
  own copy and comes earlier, so the legacy-list row would fail there first.
- A row that alters a rendered file or a task was converged again after the edit
  and after the revert, so the check read what the altered role wrote.
- The rows that read the order of tasks in the log were converged on a fresh
  instance, so the log held only that converge: the checks read the first
  occurrence of a task name, and an older run in the log would hide a reorder.
- The first two rows, the bind-address, TLS and row-format rows, the reorder row
  of the drop-in, the reload-name row, the socket directory row, the marker row and
  the render-before-pin row were recorded when they were added, against checks that
  have not changed since. Every other row was run against the head of the cycle
  that added it, and the checks those rows exercise have not been edited since.

| Control                                                           | Removed by                                                                                                                 | The harness then fails at                                                                                                                                                                |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The database image pin is one line of the writer's form           | the pattern accepts a tag with no digest (`(@sha256:HEX64)?`)                                                              | verify, the tag-only case: "Expected the role to stop at ... it stopped at 'NOTHING: the role accepted the input'"                                                                       |
| A second compose file beside `compose.yml` is refused             | `compose.yaml` removed from `db1_stack_other_compose_names`                                                                | verify, the first of the eight file cases: "Expected the role to stop at 'Refuse a second compose file in the database directory'; it stopped at 'NOTHING: the role accepted the input'" |
| An override file beside `compose.yml` is refused (1 of 4)         | `compose.override.yml` removed from `db1_stack_other_compose_names`                                                        | verify, the fourth of the eight file cases: the same message                                                                                                                             |
| An override file beside `compose.yml` is refused (2 of 4)         | `compose.override.yaml` removed from `db1_stack_other_compose_names`                                                       | verify, the fifth of the eight file cases: the same message                                                                                                                              |
| An override file beside `compose.yml` is refused (3 of 4)         | `docker-compose.override.yml` removed from `db1_stack_other_compose_names`                                                 | verify, the sixth of the eight file cases: the same message                                                                                                                              |
| An override file beside `compose.yml` is refused (4 of 4)         | `docker-compose.override.yaml` removed from `db1_stack_other_compose_names`                                                | verify, the seventh of the eight file cases: the same message                                                                                                                            |
| A `.env` file beside `compose.yml` is refused                     | `.env` removed from `db1_stack_other_compose_names`                                                                        | verify, the eighth of the eight file cases: the same message                                                                                                                             |
| The mysql image is read from `${IMAGE}`                           | `image: ${IMAGE}` changed to `image: mysql:8.0.43` in `compose.yml.j2`                                                     | "The compose file does not read the mysql image from ${IMAGE}."                                                                                                                          |
| The exporter image is the pinned digest                           | `abed8dac` changed to `abed8dad` in `db1_stack_exporter_image` in `vars/main.yml`                                          | "The exporter image in the compose file is not the pinned digest."                                                                                                                       |
| The exporter's healthcheck is the `mysql_up 1` gate               | `grep -qx "mysql_up 1"` changed to `grep -q mysql_up` in `compose.yml.j2`                                                  | "The compose file does not gate the exporter on mysql_up 1 and a healthy database."                                                                                                      |
| No service publishes a port                                       | `ports:` with `'3306:3306'` added to the mysql service in `compose.yml.j2`                                                 | "The compose file publishes a port or does not read the exporter's socket."                                                                                                              |
| The exporter reads the socket                                     | `--mysqld.address=unix:///var/run/mysqld/mysqld.sock` changed to the private address and port 3306 in `compose.yml.j2`     | "The compose file publishes a port or does not read the exporter's socket." (the same assertion: its other two conditions held)                                                          |
| The MySQL configuration keeps its bind address                    | `bind-address = 0.0.0.0` in `branchleft.cnf.j2`                                                                            | verify, "Assert the MySQL configuration keeps its boundary and its replay settings"                                                                                                      |
| The MySQL configuration requires TLS                              | `require_secure_transport = OFF` in `branchleft.cnf.j2`                                                                    | verify, "Assert the MySQL configuration keeps its boundary and its replay settings"                                                                                                      |
| The MySQL binary log is row-based                                 | `binlog_format = STATEMENT` in `branchleft.cnf.j2`                                                                         | verify, "Assert the MySQL configuration keeps its boundary and its replay settings"                                                                                                      |
| The legacy drop-in is removed before the exporter file is written | the include moved after the exporter write in `main.yml`                                                                   | verify, "Assert the legacy drop-in is removed and reloaded before the exporter file is written"                                                                                          |
| The reload is required to be in the log (order guard)             | renaming the reload task in `_unit.yml`                                                                                    | verify, the same assertion, failing on its `>= 0` guard                                                                                                                                  |
| The exporter file is written before the compose file is rendered  | a second `include_tasks: _compose.yml` added after the `_unit.yml` include in `main.yml` (fresh instance)                  | "The compose file is rendered before the exporter file is written."                                                                                                                      |
| The compose file is rendered before the pin is checked            | the render task moved below the enable task in `_compose.yml`                                                              | verify, "Assert the compose file is rendered before the pin is refused and before the unit is enabled"                                                                                   |
| The role never writes the database image pin                      | a `copy` task in `_compose.yml` writing a different, well-formed pin to the pin path before the pin is read                | "The role changed the database image pin, which branchleft-deploy owns."                                                                                                                 |
| The reload marker is forgotten when the drop-in is found          | the forget task deleted from `_unit.yml`, after a fresh prepare that puts the marker in place                              | verify, "Assert the reload marker was forgotten when the legacy drop-in was found"                                                                                                       |
| The socket directory is uid 999 and mode `0755`                   | mode `1777` in the socket task of `_compose.yml`                                                                           | verify, "Assert the stack's files and directories have the owners and modes the role states"                                                                                             |
| Nothing starts, stops, restarts or removes, by text               | a comment line `# state: restarted` added to `_compose.yml`                                                                | "The role's task files start, stop, restart, recreate or remove something, which this role must not do."                                                                                 |
| Every task names a module on the allowlist                        | a task with `ansible.builtin.command: /usr/bin/id` and `when: false` added to `_compose.yml`                               | "A task runs a module the role does not allow, or carries a keyword it does not use: Run a command" (the count assertion: the module is not on the list)                                 |
| `args` is refused, not read as the module's options               | a `systemd_service` task (`name` only) with `args: {state: "{{ 'restarted' }}"}` and `when: false` added to `_unit.yml`    | the same assertion, "... or carries a keyword it does not use: Restart the unit through args": the task names two non-keyword keys, so the count of one fails first                      |
| An include names only the role's own task files                   | a task `include_tasks: _extra.yml` with `when: false` added to `_compose.yml`                                              | "An include names a task file outside main.yml, _compose.yml and _unit.yml, or a templated target: Include a task file outside the role's three"                                         |
| A module's arguments are never one string                         | `ansible.builtin.file: path=/var/lib/docker/volumes/db_mysql-data state=absent` with `when: false` added to `_compose.yml` | "A task gives a module its arguments as a string, which the option check cannot read: Remove the database volume through a free-form string"                                             |
| The systemd task takes only name, enabled and daemon_reload       | `state: "{{ 'started' }}"` added to the mapping of the enable task in `_compose.yml`                                       | "A systemd task takes an option other than name, enabled or daemon_reload: Enable the database stack's unit, without starting it"                                                        |
| A file task's state is a plain word the role uses                 | a file task on the docker volume path with `state: "{{ 'absent' }}"` and `when: false` added to `_compose.yml`             | "A file task has a state that is not a plain word the role uses: Remove the database volume with a templated state"                                                                      |
| A removal names only a path the role removes                      | a file task on the docker volume path with `state: absent` and `when: false` added to `_unit.yml`                          | "A file task removes a path the role does not remove: Remove the database volume by its literal path"                                                                                    |
| A removal variable holds the path the test names (marker)         | `db1_stack_reload_marker` set to `/etc/branchleft/db.env` in `vars/main.yml`                                               | "vars/main.yml sets db1_stack_reload_marker to a value other than the path a removal may reach. Expected /var/cache/db1-stack/legacy-drop-in-reloaded; found /etc/branchleft/db.env."    |
| A removal variable holds the path the test names (exporter file)  | `db1_stack_exporter_cnf_path` set to `/etc/branchleft/db.image.env`                                                        | the same assertion: "... sets db1_stack_exporter_cnf_path ... Expected /etc/branchleft/db-exporter.my.cnf; found /etc/branchleft/db.image.env."                                          |
| A removal variable holds the path the test names (drop-in)        | `db1_stack_legacy_drop_in` set to `/etc/branchleft/db.env`                                                                 | the same assertion: "... sets db1_stack_legacy_drop_in ... found /etc/branchleft/db.env."                                                                                                |
| A removal variable holds the paths the test names (legacy list)   | `/var/lib/docker/volumes/db_mysql-data` added to `db1_stack_legacy_files`                                                  | the same assertion: "... sets db1_stack_legacy_files ... found [... '/var/lib/docker/volumes/db_mysql-data']."                                                                           |
| The removal variables are the ones the test names a path for      | `db1_stack_download_directory` added to `db1_stack_verify_removal_names` in `verify_role_source.yml`                       | "Assert the variables a removal may name are the ones this test names a path for": the removal check allows a variable that this test names no path for, or the reverse.                 |
| A module takes only the options the role uses                     | `validate: /usr/bin/id %s` added to the compose render task in `_compose.yml`                                              | "A task gives a module an option the role does not use, such as validate: Render the compose file the deploy program reads"                                                              |
| No lookup but the file lookup runs, in any file the role renders  | a line `# {{ lookup('ansible.builtin.pipe', 'id') }}` added to `compose.yml.j2`                                            | "The role calls a lookup other than ansible.builtin.file, or names one without a quoted literal. Lookups named: ['ansible.builtin.file', 'ansible.builtin.pipe']"                        |
| The role has no handlers                                          | `handlers/main.yml` with a `systemd_service` task of `state: restarted` created                                            | "The role holds a path outside README.md, defaults, files, meta, molecule, tasks, templates and vars ... ['handlers', 'handlers/main.yml']"                                              |
| The tasks directory holds the three task files and no other       | `tasks/_extra.yml` (a `command` task) created and included by nothing                                                      | "The tasks directory holds a path other than main.yml, _compose.yml and _unit.yml: ['tasks/_compose.yml', 'tasks/_extra.yml', 'tasks/_unit.yml', 'tasks/main.yml']"                      |
| The role has no dependency                                        | `dependencies:` with one role added to `meta/main.yml`                                                                     | "meta/main.yml names a role dependency, whose tasks these checks do not read."                                                                                                           |
| A task carries only the keywords the role uses (no `notify`)      | `notify: Restart the database stack` added to the legacy drop-in removal task in `_unit.yml`                               | "A task runs a module the role does not allow, or carries a keyword it does not use: Remove the legacy drop-in file"                                                                     |
| The daemon-reload and the unit's enablement                       | not removed: no run can exercise them                                                                                      | the container has no systemd, so both tasks are skipped there (`/run/systemd/system` is absent); verify asserts their names, their order and their options, not their effect             |

The last row is a limit and not a control with a record: the reload branch (and the
marker it writes after the reload) and the enablement of the unit are skipped in the
container, so no removal of either can turn verify red, and nothing in the test
shows that they run. They are read by the owner's first live apply: the plan
reports them, and the second run must report no change. The marker's forget branch
is proven by its row, because the container does remove the drop-in.

The source of the included tasks is read, not run: `docker compose` is never run
in the container, so nothing here proves that the stack starts, that its healthcheck
gates a deploy, or that the cnf change takes effect. Those are the first live
apply's checks, listed in "The unit, and the first live apply".

The source check is a closed set at three levels, and a new file or option fails it
until a person adds it on purpose. The role directory holds the named
directories and no other, with the three task files, no handlers and no
dependency. Every task names one module on the allowlist, carries only the keywords
the role uses, gives the module a mapping of only the options the role uses, and the
only include is of one of the three task files. A file task's state is a plain word,
and a removal names only one of four variables (the list of the legacy repository
files, the exporter file, the legacy drop-in and the reload marker), each of which
`vars/main.yml` sets to the one path the test names for it. No lookup but the file
lookup appears in the tasks, templates, defaults or vars. This closes the gaps of
earlier drafts (an include of a file that was not read, `args`, free-form strings,
handlers, a removal variable whose value was changed) and it is a check on the text
of the role's own files, not a sandbox: a person who edits `verify_role_source.yml`
in the same change can widen it, which review of that file is for. The arguments it
leaves open are listed under "Named limits".

The log scan reads the whole log of every run (verbosity 3): the sentinel text,
its SHA-1, MD5 and SHA-256, and its base64 form (whole, and as the middle of the
encoding at the three alignments it can have inside a longer encoded blob), and
the same forms of the whole file, for the password and for the rotated password.
Its controls are a canary the converge prints, task names of the role, and a
digest the scan must find in its SHA-1, SHA-256 and base64 forms.

## Where the key comes from, and how a human renews it

`files/mysql-repo-keys.asc` is the vendor's two published signing key files
joined, the 2025 file first and the 2023 file after it. Both carry the same
primary key, fingerprint `BCA43417C3B485DD128EC6D4B7B3B788A8D3785C` (written
without spaces, as it is in the code), and differ in the dates of their
self-signatures. The 2025 file's signature expires on 2027-10-23; the 2023
file's expired on 2025-10-22. The older one is kept because it is the one that
still signs some published Release files.

Where the fingerprint was read: it is the constant in the hand-run prerequisites
script, whose notes say it was cross-checked against the value Oracle publishes
on its own page about checking the signature of a package. This change did not
read that page again, and did not fetch the key: it ran `gpg --show-keys` on the
vendored file and compared the result with the script's constant. A human who
renews the key reads the vendor's page afresh (step 1 below).

A human renews it. Nothing in this repository fetches the key, and no dependency
bot sees it.

1. Download the vendor's current signing key files from its repository host and
   read the fingerprint the vendor publishes in its documentation.
2. Run `gpg --show-keys --with-colons FILE` on each and compare the `fpr` lines
   with the published fingerprint.
3. Join the files into `files/mysql-repo-keys.asc`, compute `sha256sum` of it, and
   put that digest in `db1_stack_mysql_key_sha256` in `vars/main.yml` and in
   `verify_key_sha256` in `molecule/default/verify.yml` in the same change.
4. Run the whole harness.

## Named limits

- The test has no network. It proves the role refreshes the apt index when a
  repository file changes by letting that refresh fail offline, and the placeholder
  packages carry the real package names with versions made for the test. It does
  not prove that the repository serves the 8.0 line, that the key verifies its
  Release file, or that the pinned `libaio1` file installs on a Debian 13 host.
- The test's apt cache stamp is made by the prepare step and is valid for one hour
  (`cache_valid_time`). A run on the same instance after the hour, or after a
  refusal that failed the index refresh, sees the index as stale and fails at the
  install task, which the test does not intend. Re-create the instance to run the
  test from the start.
- The download runs against a `file://` URL in the test. The real URL, and the
  digest in `defaults/main.yml`, are checked by the download module on a real run
  and by nothing before it.
- Check mode skips the groups of tasks named in the task files, each with its reason:
  the install of the local package files, the version check of the installed
  toolchain, the index refresh, the directories below the stack's project directory
  (which check mode does not create), the rendering of the compose file and
  configuration (which need that directory), the enablement of the unit, and the
  daemon-reload. A plan does not show them.
- A write that fails half way cannot be provoked in the container, so the claim
  that a failed write leaves the old file whole rests on Ansible's atomic move, not
  on a test. The `no_log` on the step that computes the password's problems is
  reviewed, not tested.
- The window in which the file is open to others is closed by the order of the
  tasks. A missing file is created closed and an existing file is closed by its
  own task; the test checks that the task that applies to the case ran and
  changed something, and that the names come before the write in the log. It
  cannot watch the filesystem between them. The write moves the new file over
  the old one and the move copies the old file's owner and mode, which is why the
  existing file has to be closed first.
- The test container has no systemd and no Docker. The daemon-reload, the marker that
  records it and the unit's enablement are skipped there, because `/run/systemd/system`
  is absent; no test proves the marker, and the crash case it covers is reviewed,
  not run. The order of the legacy drop-in against the exporter file is read from
  the log, which shows a skipped task's name. Nothing runs `docker compose`, so the healthcheck,
  the start order and the cnf change are asserted in the rendered text and are not
  exercised.
- The compose file and the MySQL configuration are the same as `ghost-platform`'s
  except for comments, as checked at commit `5e52f78`. A later change to either
  side is caught only when someone runs the comparison again. The follow-up that
  removes the `ghost-platform` copies runs it before it deletes anything.
- The exporter account is in runbook section 4, outside this role, and the exporter's
  healthcheck needs it. On a rebuilt database host the role still converges, but the
  exporter cannot report `mysql_up 1` until section 4 is run by hand, so the stack's
  healthcheck gate fails. Running section 4 is an owner's live step.
- The role is not applied to db1 until the owner decides enrolment. When it is, the exporter password the role is given must be the
  password of the exporter account in the database; a mismatch makes the exporter's
  healthcheck fail, not the role.
- The plan limit on a host that was never applied: on a host whose apt index has
  never held the MySQL repository, the task that installs the named packages
  from the index fails even under `--check`, because the package is not known to
  apt. The `check-fresh` step passes only because the prepare step installs
  placeholder packages first, so it does not exercise a never-applied host. The
  database host already has the packages, so its plan works.
- The containers ran on one machine type (arm64 Docker Desktop). The role is not
  tested on an amd64 host.
- The role has not been applied to the host. After it is, the hand-run
  prerequisites script must not be run again.
- The source check is a closed set, not a check of every argument. It does not
  restrict where a `copy`, a `template` or a `file` task that does not remove
  writes: the destination can be any path, the database's data volume and
  `/etc/branchleft/db.env` included. It does not restrict what a `copy` or a
  `template` reads: `src` can be any path, an absolute path on the controller
  included, so a file outside the role, such as a key under the operator's home,
  would be delivered to the host. It does not restrict which package names `apt`
  installs, or where `get_url` fetches from and writes to (its checksum is
  required; its `url` and `dest` are not). It does not read the playbook that
  applies the role: role parameters take precedence over `vars/main.yml`, so the
  paths a removal holds are checked in the file and not in what a caller passes,
  and a task's `register` can reuse a variable name. A reviewer reads these
  arguments in any change to the tasks. They are filed as a follow-up item on the
  tracker, which the pull request names; each is closed there by a literal
  allowlist with a recorded sabotage row, or kept here with its reason.
- The project-directory check stops a second compose project only when it is named
  in the role's own files. It does not see the environment that the stack's unit
  loads from elsewhere. That is `/etc/branchleft/db.env`, a drop-in under
  `branchleft-compose@db.service.d`, a replaced unit file, `Environment=` lines, and
  the `DOCKER_*`, `COMPOSE_PATH_SEPARATOR` and `COMPOSE_ENV_FILES` variables. Any of
  these can set `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`, `COMPOSE_PROFILES` or
  `ExecStart`, and the deploy program checks none of them. The owner writes those
  files; the role reads none of them, because `db.env` holds secrets. The one
  environment file the role reads is `/etc/branchleft/db.image.env`. The follow-up
  is filed as an item on the tracker, which the pull request names.
- MySQL 8.0 reaches the end of its vendor support at a date this README does not
  state, because it was not checked here; the database's own ticket owns that.

## Clauses this role exercises

ANS-3 (no shell), ANS-9 (a module before a command), ANS-10 (check mode and what is
skipped in it), ANS-11 (a second run changes nothing), ANS-14 (this order), ANS-15
(the test runs in a container only), ANS-16 (secrets, `no_log`, no diff of a
secret) and ANS-17 (delivery through the gated workflow only).
