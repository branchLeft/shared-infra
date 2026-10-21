# monitoring_stack

This role puts the files of the monitoring Compose stack on a host, installs the
systemd drop-ins that belong to that stack, writes the stack's secrets file, and
restarts the stack's unit when what the unit runs from has changed. It is the
first part of moving the monitoring runbook into Ansible; the parts it leaves out
are listed below.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does four things:

1. It writes seven values into `/etc/branchleft/monitoring.env`, one key each,
   the other keys left in place: `SMTP_USERNAME`, `SMTP_PASSWORD`,
   `HEALTHCHECKS_PING_URL`, `ALERT_RECIPIENT_EMAIL`, `MAILHOST_PING_URL`,
   `GRAFANA_ADMIN_PASSWORD` and `SNDS_DATA_URL`. The values are inputs (see
   "Secrets" below). It creates the directory and the file when they are absent,
   and closes the file to `root:root` `0600` before any value is written.
2. It copies the eight committed files of the stack from
   `hetzner/monitoring/stack/` into the project directory on the host: the
   Compose file, the Prometheus configuration and alert rules, the Blackbox
   configuration, the Grafana datasource, the Alertmanager and ntfy templates and
   the Alertmanager email template. They are copied as files. Nothing is
   rendered, because the Compose file holds `${...}` and `$$` for Compose to read
   and the `.tmpl` files hold placeholders a later step fills.
3. It installs `hetzner/monitoring/systemd/monitoring.override.conf` as
   `/etc/systemd/system/branchleft-compose@monitoring.service.d/override.conf`,
   the destination `hetzner/provision/install-systemd-drop-ins.sh` uses for the
   instance named `monitoring`, and installs
   `hetzner/monitoring/systemd/edge.override.conf` as
   `/etc/systemd/system/branchleft-compose@edge.service.d/override.conf`. It
   reloads systemd when either file changed, or when a restart is due. No edge
   role exists yet, so the edge drop-in is installed here; moving it to an edge
   role is discovered work.
4. It restarts the monitoring unit when the fingerprint of what the unit runs
   from differs from the stamp of the last restart that was read back as active,
   and only when the unit is enabled (see "Restart").

It is the only role that delivers the eight stack files and the only role that
restarts `branchleft-compose@monitoring.service`.
`ansible/checks/test_monitoring_single_home.py` fails if another role names
either. It checks, and does not write, the renderer
`render_alertmanager_config.py`: `ntfy_pager` is its single delivery owner (see
"Order").

### Secrets

Each input is `no_log: true`, required, and has no default, so the role never
reads, generates or stores a value. The role checks, before any write, that each
input is a non-empty single line, and it names the key in the failure, never the
value. Every value task is `no_log: true` and `diff: false`, so no value reaches
the output, a `--diff` run, or the Ansible log. The secrets file is hashed on the
host and only the hash comes back, so no value is read into a variable. The keys
are fixed in `vars/main.yml`, so no caller can rename a key the stack reads.

Owner-supplied values:

- `GRAFANA_ADMIN_PASSWORD` is read by Grafana only when Grafana first creates its
  database. A later change to this input rewrites the file and restarts the
  stack, if it is enabled, but does not change the live Grafana password.
- `SNDS_DATA_URL` is read by `snds-collector.service` only. A change to it does not
  restart the stack. It expires every 30 days. Until runbook section 14 is retired,
  section 14 also writes this key by hand. There are then two writers of one key:
  the input given to this role must equal the value section 14 last wrote, or the
  next run of this role puts back the older URL. A rotation changes both, in that
  order, before this role runs again.

`STALWART_PROMETHEUS_SECRET` is not one of the seven. Its hand step stays in the
runbook, and the role does not write it. It is part of the fingerprint, because
the fingerprint covers the whole file but one line.

### Restart

No task in this role notifies a handler, and the role has none. A handler loses
its restart when a run fails between the write and the flush, because the rerun
finds nothing changed. Instead the role works out, at the end of every run, a
fingerprint of everything the unit runs from, as it is on disk now, and compares
it with a stamp that it writes only after a restart was read back as active.

- **The fingerprint** is a sha256 over the sha256 of each of: the eight stack
  files, the monitoring drop-in, and the renderer, and the sha256 of the secrets
  file with its `SNDS_DATA_URL` line removed. The list is `monitoring_stack_fingerprint_files`
  in `vars/main.yml`. The edge drop-in is not in it: it binds
  `branchleft-compose@edge`, which this role never restarts (runbook step 6 does).
  The `SNDS_DATA_URL` line is left out because only the collector reads it and it
  rotates every 30 days; a rotation must not recreate the stack.
- **The stamp** is `/var/lib/branchleft/monitoring.applied`: one sha256 and a
  newline, `root:root` `0600`. It is written last, after the restart and a
  read-back that finds the unit `active`. The directory `/var/lib/branchleft` is
  shared with `broker_deploy`, which sets it to `0755` `root:root`, so this role
  sets the same.
- **A restart is due** when the fingerprint differs from the stamp and the unit is
  enabled (`enabled` or `enabled-runtime`). The role sets the fact
  `monitoring_stack_restart_due` so a caller can see the decision.
- **Whatever state the unit is in**, a due restart is made: an `active` unit is
  recreated (the drop-in adds `--force-recreate`), a `failed` unit is started
  again when the cause was corrected, an `inactive` but enabled unit is started.
- **A unit that is not enabled is left alone.** It is a fresh host awaiting the
  owner's first start (runbook step 7a). The role neither starts nor stamps it,
  and says so in a debug message.
- **A run that fails anywhere leaves the stamp old**, so the next run restarts,
  however many runs it takes. Before the restart the role checks that the
  renderer is a root-owned regular file with no group or other write bit, and
  refuses if not, before a live alert stack is touched. After the restart it reads
  the unit back and refuses to write the stamp unless it is `active`.
- **The first run on a host that has no stamp and an enabled, running unit
  restarts the whole stack once**, even when nothing changed: with no stamp the
  fingerprint cannot match. The second run of the same commit reports zero
  changes. The runbook says this at step 3.
- **In check mode** the role reports the restart as a pending change and restarts
  nothing, writes no stamp, and does not read a value into the output. The
  fingerprint is worked out from the files as they are on the host, so a plan or
  a drift run sees a stale stamp as a pending restart.

The role does not restart `edge` and does not start `monitoring` for the first
time.

### Order

On a fresh host `ntfy_pager` runs first, and `monitoring_stack` second.

- `ntfy_pager` writes the four `NTFY_` lines and delivers the renderer.
  `monitoring_stack` hashes both, so a changed `NTFY_` line or a changed renderer
  restarts the unit on this role's next run, and the renderer is on the host
  before any restart.
- Either role creates the directory and the secrets file when it finds them
  absent, with the same owner, group and mode, so whichever runs first creates
  them and the second changes nothing.
- The renderer that `ntfy_pager` delivers is what the unit's `ExecStartPre` runs,
  so the unit can start only after `ntfy_pager` has run. The renderer check
  before the restart names this order in its failure.

No playbook in this repository runs either role. `ansible/playbooks/edge1.yml`
wires neither: a playbook that runs `monitoring_stack` must supply its seven
secret inputs, and how those inputs reach a run (the secrets pattern, not a file
in the repository) is settled with that wiring. So the order is written here and
tested role by role, not across the two roles. The fresh-host run across both is
open until the wiring exists.

Under `--check` on a fresh host no file exists, so the line tasks are skipped and
the fingerprint is worked out without a secrets file; the plan shows the files
and drop-ins as changes and the restart as not due while the unit is not enabled.

### How it relates to the patterns

The role applies two recipes from `ansible/patterns/`: `files_and_units` (explicit
owner, group and mode; a converge that asks systemd, straight after the role,
what it holds) and the file-delivery half of `compose_stack` (explicit modes on a
project directory and its files, no handler that starts the stack). It does not
call them: a pattern is a recipe a service role copies and renames, not a library,
and ANS-12 keeps composition in playbooks (the standard leaves open whether one
role may include another). So the tasks are written out here, as the recipes
direct. The restart by fingerprint is this role's own and is not a pattern.

Parts of the `compose_stack` recipe this role does not carry, and why:

- the apply-time refusal of an image not pinned by digest and of a compose override
  file in the project directory: the role never runs Compose, so nothing here reads
  either. The images are checked in the test instead (see below); an override file
  next to the Compose file would be merged by the unit's own `docker compose up`,
  and nothing refuses it until the role that starts the stack does;
- the `validate` of the Compose file with `docker compose config`, for the reason
  below;
- the `docker_compose_v2` call that brings the stack up, and the health check that
  fails the role when a service is not running and healthy. The unit brings the
  stack up; the role reads the unit back as `active` and does not look at the
  services.

### What it does not start or delete

It starts nothing for the first time. It restarts the monitoring unit only as
described under "Restart". The stack is brought up by the
`branchleft-compose@monitoring` unit, whose drop-in runs the Alertmanager renderer
first; bringing it up from here, before that renderer has written
`alertmanager/alertmanager.yml`, `ntfy/server.yml` and
`prometheus/mx1-metrics-password`, would make Docker create a directory at each
of those bind-mount paths. So the role has no `docker compose` task. The role
also does not check the Compose file with `docker compose config`: the Grafana
password is a required variable in that file, so the check fails on a host where
the secrets file does not exist yet.

It does not delete anything. The shell copy it replaces used `rsync --delete`,
so a file removed from the repository was removed from the host; this role
leaves such a file in place, and it must be removed by hand until a later change
decides how.

### Not in this role (and who owns it)

- Rendering `alertmanager.yml` and the ntfy `server.yml` from their templates,
  and delivering `render_alertmanager_config.py`: `ntfy_pager` owns the delivery.
  This role checks the renderer is there and does not write a second copy.
- Runbook section 14's hand write of `SNDS_DATA_URL` is not retired here. The
  runbook's live apply is owner-gated.
- `snds-collector.service`, `snds-collector.timer` and `snds/collect_snds_metrics.py`,
  and the `/var/lib/branchleft/snds-exporter` directory node-exporter mounts:
  the exporters and collectors ticket (the SNDS collector with its timer).
- `nextcloud1.override.conf`: `nextcloud_stack` installs it. This role does not
  copy it.
- Docker, the shared Compose unit template and the deploy tooling: the host
  baseline and deploy tooling tickets. The test installs a placeholder for the
  unit template; the real one is not tested here.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. There is one,
`monitoring_stack_project_dir`, the stack's project directory. It must equal the
`WorkingDirectory` the shared unit template derives from the instance name
(`/opt/branchleft/monitoring`), so a caller has no reason to change it. The seven
secret inputs of "Secrets" are required and have no default. The role never
generates or stores a value. The role sets one fact, `monitoring_stack_restart_due`.

`vars/main.yml` holds the constants of the stack (the directories, the files, the
drop-in directories, the fingerprint's file list, the stamp and the unit). They
are not inputs; a caller cannot override them.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 (the release every host runs and the test runs on) with
  Python 3, bash, `sed` and `sha256sum`, and systemd. The role runs as root.
- The files come from this repository: the role reaches them through a link in
  `files/` (below), so it must be run from a checkout of the whole repository,
  which is what the gated pull delivers (ANS-17).

## What it changes on a host

Every directory is `root:root`, mode `0755`, and every file is `root:root`,
mode `0644`, except the secrets file and the stamp. That is what the rsync it
replaces produced (`--no-owner --no-group --chmod=u=rwX,go=rX` followed by
`chown -R root:root`): the containers read their bind-mounted configuration as
their own user, so a file or directory tighter than this makes a container fail.

- The project directory `/opt/branchleft/monitoring` and under it the directories
  `alertmanager`, `blackbox`, `grafana/provisioning/datasources`, `ntfy` and
  `prometheus`.
- Files in it: `compose.yml`, `alertmanager/alertmanager.yml.tmpl`,
  `alertmanager/email.gotmpl`, `blackbox/blackbox.yml`,
  `grafana/provisioning/datasources/prometheus.yaml`, `ntfy/server.yml.tmpl`,
  `prometheus/alerts.yml` and `prometheus/prometheus.yml`.
- `/etc/systemd/system/branchleft-compose@monitoring.service.d/`, mode `0755`,
  holding `override.conf`, mode `0644`.
- `/etc/systemd/system/branchleft-compose@edge.service.d/`, mode `0755`, holding
  `override.conf`, mode `0644`, from `files/edge.override.conf`.
- `/etc/branchleft/`, mode `0755`, if absent, and `/etc/branchleft/monitoring.env`,
  created with `state: touch` if absent, mode `0600`, `root:root`, with the access
  and modification times preserved so a second run changes nothing.
- The seven keys of "Secrets", one line each.
- `/var/lib/branchleft`, mode `0755`, and the stamp `monitoring.applied` in it,
  mode `0600`, written only after a restart was read back as active.
- One `daemon-reload` of the systemd manager, only when a drop-in changed or a
  restart is due, run before the restart.
- A restart of the monitoring unit when "Restart" says so.
- No port, no user, no firewall rule, no container, no first start.

### One home for every file

The role holds no copy of the files it delivers. `files/stack` is a link to
`hetzner/monitoring/stack` and `files/monitoring.override.conf` is a link to
`hetzner/monitoring/systemd/monitoring.override.conf` and `files/edge.override.conf`
is a link to `hetzner/monitoring/systemd/edge.override.conf`, all relative, so a change
to the stack in its own directory is what the next apply delivers, and the role
cannot drift from it. The images stay pinned by tag and digest inside
`compose.yml`, where the dependency bot reads them.

What the link does not cover is the list of files. `vars/main.yml` names the files
and directories, and a file added to `hetzner/monitoring/stack/` is not delivered
until it is listed. The test closes that: it takes the list of what must be on the
host from the stack directory itself (every file under it except the few named in
`verify_not_carried`), so a file the role does not list is missing on the host and
`verify` fails. There is no second hand-written list of the files or directories
in the test.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/monitoring_stack
.venv/bin/python -m unittest discover -s ansible/checks
```

The harness lints the role and runs the scenario in `molecule/default/` on one
systemd container (the same Debian 13 image and settings as the
`files_and_units` pattern; the reason for each platform key is in `molecule.yml`).
It removes its container when it finishes and never touches a host.

What each part of the scenario does:

- `prepare.yml` installs a placeholder for the shared unit template
  (`branchleft-compose@.service`, with an `[Install]` section so an instance can be
  enabled), because systemd needs the template to apply a drop-in to an instance;
  a stand-in `docker` that appends its arguments to a calls log and fails when a
  flag file exists; and a stand-in renderer. The monitoring drop-in resets
  `ExecStart` to `docker compose up`, which is the stand-in here, so each restart
  of the instance is one line in the log.
- `converge.yml`, on an instance with no drop-in, first installs an earlier
  release of the drop-ins (a different `MemoryMax`), starts and enables the
  instance, and asks systemd, so that systemd holds the earlier value. It then
  applies the role and asks systemd again, straight away: a reload that is
  missing, or left to the end of the play, fails on `MemoryMax`. The first apply
  also restarts the enabled unit once (one more line in the calls log), because
  no stamp exists.
- `idempotence`: a second converge reports zero changed tasks.
- `verify.yml`, first part: works out the expected files and directories from the
  stack directory of the repository; every one exists with its owner, group and
  mode; every delivered file's SHA-256 equals the SHA-256 of its source read
  directly from the repository (not through the role's link); the drop-ins are
  where the unit template looks for them, equal their sources and are the ones
  systemd has loaded (`DropInPaths`, `MemoryMax`, `CPUWeight`); the secrets file is
  `root:root` `0600` and holds each key once; every image in the Compose file is
  pinned by digest; and the stamp is one sha256 and a newline, `0600`, in a
  directory of mode `0755`, and the fingerprint's list names the eight files, the
  monitoring drop-in and the renderer and not the edge drop-in.
- `verify.yml`, "Exercise the restart decision": each case applies the role (with
  `include_role`, overriding inputs where the case needs it), and compares
  snapshots of the stand-in's calls log, the stamp and systemd's `ActiveState` and
  `UnitFileState` before and after. The cases:
  - nothing changed: no restart, stamp unchanged;
  - `SMTP_PASSWORD` rotated: one restart, stamp moved; the same value again: none;
  - `SNDS_DATA_URL` rotated: the file holds the new value, no restart;
  - an `NTFY_` line changed the way `ntfy_pager` writes it: one restart on this
    role's next run; the same again: none;
  - the renderer changed: one restart;
  - the edge drop-in changed: put back and read by systemd, no restart of
    monitoring;
  - the unit stopped but enabled: started once;
  - the unit stopped and disabled: not started, nothing stamped; enabled and
    started again by the test, as at runbook step 7a: the next run restarts once
    and stamps;
  - the restart failing (the stand-in fails): the role fails, the unit is
    `failed`, the stamp is not moved; the stand-in repaired: the rerun restarts
    and stamps;
  - the restart succeeding but the unit not staying `active` (a template swap): the
    role fails on the read-back and does not stamp; repaired, the rerun stamps;
  - the renderer writable by its group: the role refuses before restarting, the
    unit keeps running, nothing is stamped;
  - a value with a second line: the role refuses before writing it, and the
    second line is not in the secrets file;
  - check mode with a changed key and a stale stamp: the restart is found due,
    nothing is restarted, nothing is written; the real run then restarts once and
    replaces the stale stamp.
- `verify.yml`, "Scan the log for the values": the converge ends with a harmless
  command given a canary argument, and the scenario's Ansible log is written at
  verbosity 3 with `--diff` always on. The scan finds the canary and the role's
  task names, and then none of the sentinel inputs or the rotated values. That is
  the proof that `no_log` and `diff: false` are on every task that handles a value.
- `check-fresh`, `check-configured` and `molecule-check`: the role runs under
  `--check --diff` before the first apply and against the configured instance and
  shows no drift.

### Sabotage rows

Each row is an edit made with the editor, one harness run (the whole harness over
this role, so the lint and every container step run), and a `git restore`
afterwards. Rows 1 to 7 were run on 2026-10-20 against the role as it was before
the restart moved into a fingerprint; the assertion each names is unchanged, and
CI at the head that carries this README is the run of the rest. The harness run is
the retrieval: make the row's edit and run it to see the message.

| Edit to the role                                                          | Step that fails | Assertion that names it                                                                                                                                                |
| ------------------------------------------------------------------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The task that installs the drop-in removed                                | `converge`      | "systemd does not hold the drop-in the role installed (MemoryMax 1073741824)"                                                                                          |
| The daemon-reload task removed (no reload)                                | `converge`      | the same assertion                                                                                                                                                     |
| Mode of the delivered files changed from `0644` to `0640`                 | `verify`        | "alertmanager/alertmanager.yml.tmpl is missing on the instance, is not a regular file owned by root with mode 0644, or differs from" the source (one failure per file) |
| `files/stack` replaced by a copy with one byte of `blackbox.yml` changed  | `verify`        | "blackbox/blackbox.yml is ... or differs from" its source in `hetzner/monitoring/stack`                                                                                |
| `compose.yml` removed from `monitoring_stack_files`                       | `verify`        | "compose.yml is missing on the instance, is not a regular file ..."                                                                                                    |
| The drop-in directory name changed by one character (`monitorinq`)        | `converge`      | the same assertion as the first row                                                                                                                                    |
| A new file added to `hetzner/monitoring/stack/` (not touched by the role) | `verify`        | "zz_probe_file.txt is missing on the instance, is not a regular file ..."                                                                                              |

The controls of the restart decision are proven by the same method, each run in a
fresh container on 2026-10-21 with the whole harness, the edit reverted after
each (the red assertion is in the pull request body):

| Control removed or changed                     | Step that fails | Assertion that names it                                                                                  |
| ---------------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------- |
| Stamp written before the read-back             | `verify`        | "The restart that left the unit not active did not fail the role, or moved the stamp"                    |
| The `enabled` gate in `restart_due`            | `verify`        | "A unit that is not enabled was started or stamped by the role"                                          |
| `SNDS_DATA_URL` line hashed                    | `verify`        | task "Assert the rotated SNDS_DATA_URL is in the file and restarted nothing"                             |
| Renderer left out of the fingerprint           | `verify`        | task "Assert the fingerprint hashes the eight stack files, the monitoring drop-in and the renderer"      |
| `no_log` removed from the line task            | `verify`        | "A sentinel value is in the Ansible log, so a task that handles it lacks no_log"                         |
| Single-line check of the secret values removed | `verify`        | "The value check did not refuse a value with a second line, or the second line reached the secrets file" |

Each red was one harness run. One green run of the reverted tree, with every step
passing, stands for every row, because the tree after each revert is the same. The red assertion of the
secrets-file hash row is censored by `no_log`, so the failing task is named
instead.

The first two rows share one message because it covers both causes (no drop-in, or
no reload). An earlier version of the converge started no unit, and the second row
stayed green: systemd unloads an inactive unit that nothing refers to and reads the
new drop-in from disk with no reload. The converge now starts the placeholder
instance so systemd keeps the earlier drop-in loaded. The control for the reload
is therefore the converge's question to systemd, not the verify play.

Reviewed or asserted, but not proven by a sabotage run (a control with no row above is
not shown to fail):

- the mode `0755` of the directories, and `owner`/`group` of every file and directory
  (the last cannot be told from a default on a root instance);
- the `DropInPaths` and `CPUWeight` assertions in `verify.yml` (`MemoryMax` is proven
  through the converge rows);
- the assertion that every image in the Compose file is pinned by digest;
- the assertion that each file named in `verify_not_carried` still exists;
- the always-changed variant of the idempotence step: the step is the harness's, not
  run against a deliberately non-idempotent edit of this role.

### Named limits

- **Real Compose and a real host are not exercised.** The test never starts the
  stack. It proves the files are on the host, byte for byte, with their modes, that
  systemd loads the drop-in, and that the restart decision is right against a
  stand-in `docker`; it does not prove the stack starts, that the render step
  works, or that the real unit template accepts the drop-in. The first live apply
  is the proof (ANS-17), and it waits on the enrolment of the hosts and on the gate.
- **The unit template is a placeholder in the test.** The drop-in is loaded
  against a oneshot whose `ExecStart` runs the stand-in. `MemoryMax` and
  `CPUWeight` are read from systemd's properties; the drop-in's `ExecStart`,
  `ExecStartPre`, `EnvironmentFile` and `AssertPathExists` resets are not exercised.
- **Reviewed, not tested: `owner: root` and `group: root`.** The instance runs as
  root, so omitting them gives the same result, and no file may belong to anyone
  else, so no test value tells the two apart.
- **A file removed from the repository stays on the host** (no `--delete`). See
  above.
- **An empty directory is not noticed.** The test derives the directories from
  the files, so a new directory with no file in it is neither required nor checked.
- **A silent skip passes.** The converge skips its earlier-release setup after the
  first run, and the line tasks skip in check mode on a host with no secrets file,
  because nothing is written there; the harness does not catch a silent skip, and
  this is the review of it (ANS-10).
- **A hand restart does not write the stamp.** The next run restarts the unit once
  more. That is harmless.
- **A link needs a checkout that keeps links.** A tool that copies the role
  directory without following the links gets a role with dangling links and the
  apply fails at the first file. The gated pull checks out the repository, so it
  keeps them.
- CI runs this scenario: the Ansible workflow runs the harness over every
  directory under `ansible/roles/` and `ansible/patterns/`.
- The image is the third-party Debian 13 systemd base the `files_and_units`
  pattern records, trusted by digest; nothing here bumps it.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after
the approval of its protected environment. A plan job shows the host's diff in
check mode first; after the approval the host pulls that exact commit and applies
it, and a second run must report zero changes. Nothing is applied from a laptop.
This role is not applied to any host yet: the live run waits on the enrolment of
the hosts (the enrolment ticket) and on the gate. The runbook keeps its hand
paths for steps 3, 4, 5, 13 and 14 until then; each is marked and listed in
`hetzner/provision/test_runbook_monitoring_hand_blocks.py`, and they are retired
together after the first gated converge.

## How to change it safely

1. To change what the stack is, change the files under `hetzner/monitoring/stack/`
   or the drop-in under `hetzner/monitoring/systemd/`; the role delivers them as
   they are, and a changed file restarts the unit on the next run. To add a file,
   add it to `monitoring_stack_files` (and its directory to
   `monitoring_stack_dirs`) in `vars/main.yml`; the test finds it by itself and
   fails until the role carries it. To leave one out on purpose, name it in
   `verify_not_carried` in `molecule/default/verify.yml`.
2. Keep every task able to run under `--check --diff`, and keep the modes explicit.
3. Do not add a `docker compose` task here without reading the paragraph above on
   why the role does not start the stack. Do not add a handler: the restart is the
   fingerprint's.
4. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
5. Run the test command above before opening a pull request, then break the
   control you touched (the table above) and see the same step fail.
