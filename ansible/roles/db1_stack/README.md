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

It refuses to run, before it changes anything, when a second compose file sits
beside `compose.yml`. It refuses when the database image pin that
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
  `0755`) and `/opt/branchleft/db/run/mysqld` (root, `1777`: world-writable with
  the sticky bit, so the database's uid can create its socket and no other local
  account can unlink or replace it. The healthcheck, the grants program and the
  exporter all open that socket as root).
- `/opt/branchleft/db/compose.yml` (root, `0644`) and
  `/opt/branchleft/db/conf.d/branchleft.cnf` (root, `0644`), rendered from the
  templates in this role.
- Enables `branchleft-compose@db.service` on a host where systemd runs. It does
  not start it.

It reads, and never writes, `/etc/branchleft/db.image.env` (the database image
pin that `branchleft-deploy` writes), and it never reads `/etc/branchleft/db.env`.

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
  asserted by a test; the part two table says which removals have been run and
  recorded, and a new removal should be run and recorded the same way.
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
`WorkingDirectory=/opt/branchleft/db`. The role refuses to run while
`compose.yaml`, `docker-compose.yml` or `docker-compose.yaml` sits in the same
directory: Compose would read it in place of `compose.yml`.

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

The test runs in one Debian 13 container with no network. Every control in the
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
instance, so they hold for the file the role wrote, and the refusals run the role
with the bad input and require the named task to refuse, as part one does.

| Control                                                           | Removed by                                                    | The harness then fails at                                                                                                                                  |
| ----------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The database image pin is one line of the writer's form           | the pattern accepts a tag with no digest (`(@sha256:HEX64)?`) | verify, the tag-only case: "Expected the role to stop at ... it stopped at 'NOTHING: the role accepted the input'"                                         |
| A second compose file beside `compose.yml` is refused             | `compose.yaml` removed from `db1_stack_other_compose_names`   | verify, the second-file case: "Expected the role to stop at 'Refuse a second compose file in the database directory'"                                      |
| The mysql image is read from `${IMAGE}`                           | (not sabotaged in this change)                                | verify, "Assert the compose file reads the mysql image from the pin file and never a literal"                                                              |
| The exporter image is the pinned digest                           | (not sabotaged in this change)                                | verify, "Assert the exporter image is the pinned digest from the source line"                                                                              |
| The exporter's healthcheck is the `mysql_up 1` gate               | (not sabotaged in this change)                                | verify, "Assert the exporter healthcheck is the mysql_up 1 gate"                                                                                           |
| No service publishes a port, and the exporter reads the socket    | (not sabotaged in this change)                                | verify, "Assert the exporter reads the socket and no service publishes a port"                                                                             |
| The MySQL configuration keeps its bind address                    | `bind-address = 0.0.0.0` in `branchleft.cnf.j2`               | verify, "Assert the MySQL configuration keeps its boundary and its replay settings" (red recorded, then green)                                             |
| The MySQL configuration requires TLS                              | `require_secure_transport = OFF` in `branchleft.cnf.j2`       | verify, "Assert the MySQL configuration keeps its boundary and its replay settings" (red recorded, then green)                                             |
| The MySQL binary log is row-based                                 | `binlog_format = STATEMENT` in `branchleft.cnf.j2`            | not run: the test container lost DNS during the run, so this row has no recorded red                                                                       |
| The legacy drop-in is removed before the exporter file is written | the include moved after the exporter write in `main.yml`      | verify, "Assert the legacy drop-in is removed and reloaded before the exporter file is written" (red recorded, then green)                                 |
| The reload is required to be in the log (order guard)             | renaming the reload task in `_unit.yml`                       | verify, the same assertion, failing on its `>= 0` guard (red recorded, then green)                                                                         |
| The exporter file is written before the compose file is rendered  | (not sabotaged in this change)                                | verify, "Assert the exporter file is written before the compose file is rendered"                                                                          |
| The role's task files start, stop, restart or remove nothing      | a line `state: restarted` added to `_compose.yml` (a comment) | verify, "Assert the role runs no compose command, no docker module, no command or shell, and starts, stops or restarts nothing" (red recorded, then green) |
| The role never writes the database image pin                      | (not sabotaged in this change)                                | verify, "Assert the role left the database image pin unchanged"                                                                                            |

The rows marked "red recorded, then green" were removed or altered, verify failed
at the named step, and the restored tree passed verify again. The rows marked
"not run" or "not sabotaged in this change" are asserted by verify and are not
proven by a sabotage run. These remain unproven: the STATEMENT binlog format, the
exporter image, the healthcheck gate, the socket and port rule, the exporter file
ordering against the compose render, the password pin, the reload marker (no
systemd in the container, so the daemon-reload branch is skipped there), and the
socket mode change to `1777`. A reviewer should not count them as proven.

The source of the included tasks is read, not run: `docker compose` is never run
in the container, so nothing here proves that the stack starts, that its healthcheck
gates a deploy, or that the cnf change takes effect. Those are the first live
apply's checks.

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
  not run. The order of the legacy drop-in against the exporter file is read from the log, which
  order of the legacy drop-in against the exporter file is read from the log, which
  shows a skipped task's name. Nothing runs `docker compose`, so the healthcheck,
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
- MySQL 8.0 reaches the end of its vendor support at a date this README does not
  state, because it was not checked here; the database's own ticket owns that.

## Clauses this role exercises

ANS-3 (no shell), ANS-9 (a module before a command), ANS-10 (check mode and what is
skipped in it), ANS-11 (a second run changes nothing), ANS-14 (this order), ANS-15
(the test runs in a container only), ANS-16 (secrets, `no_log`, no diff of a
secret) and ANS-17 (delivery through the gated workflow only).
