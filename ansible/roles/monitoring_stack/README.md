# monitoring_stack

This role puts the files of the monitoring Compose stack on a host and installs
the systemd drop-in that belongs to that stack. It is the first part of moving
the monitoring runbook into Ansible; the parts it leaves out are listed below.

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
2. It copies the committed files of the stack from `hetzner/monitoring/stack/`
   into the project directory on the host: the Compose file, the Prometheus
   configuration and alert rules, the Blackbox configuration, the Grafana
   datasource, the Alertmanager and ntfy templates and the Alertmanager email
   template. They are copied as files. Nothing is rendered, because the Compose
   file holds `${...}` and `$$` for Compose to read and the `.tmpl` files hold
   placeholders a later step fills.
3. It installs `hetzner/monitoring/systemd/monitoring.override.conf` as
   `/etc/systemd/system/branchleft-compose@monitoring.service.d/override.conf`,
   the destination `hetzner/provision/install-systemd-drop-ins.sh` uses for the
   instance named `monitoring`, and installs
   `hetzner/monitoring/systemd/edge.override.conf` as
   `/etc/systemd/system/branchleft-compose@edge.service.d/override.conf`. It
   reloads systemd when either file changed. No edge role exists yet, so the edge
   drop-in is installed here; moving it to an edge role is discovered work.
4. It restarts the monitoring unit when a key the stack reads changed, and only
   when that unit is already active (see "Restart").

It checks, and does not write, the renderer `render_alertmanager_config.py`. The
`ntfy_pager` role is its single delivery owner (see "Order").

### Secrets

Each input is `no_log: true`, required, and has no default, so the role never
reads, generates or stores a value. The role checks, before any write, that each
input is a non-empty single line, and it names the key in the failure, never the
value. Every value task is `no_log: true` and `diff: false`, so no value reaches
the output, a `--diff` run, or the Ansible log. The keys are fixed in
`vars/main.yml`, so no caller can rename a key the stack reads.

Owner-supplied values:

- `GRAFANA_ADMIN_PASSWORD` is read by Grafana only when Grafana first creates its
  database. A later change to this input rewrites the file and restarts the
  stack, if it is active, but does not change the live Grafana password.
- `SNDS_DATA_URL` is read by `snds-collector.service` only. A change to it does not
  restart the stack. It expires every 30 days.

`STALWART_PROMETHEUS_SECRET` is not one of the seven. Its hand step stays in the
runbook, and the role does not write it.

### Restart

The handler restarts `branchleft-compose@monitoring.service` only when one of
these is true: a key with `restarts_stack: true` changed, or its drop-in changed
(the drop-in change is a `daemon-reload` and nothing else; the restart is not
triggered by it). `SNDS_DATA_URL` does not restart the stack. The handler reads the
unit first and restarts it only when it is `active`, so a host where the unit is
not running is not started here. Runbook step 7a is the first start.

The role does not restart `edge` (runbook step 6 does that), and it does not
start `monitoring`.

Known gap: if a play also changes `ntfy_pager`, its `flush_handlers` can restart
the unit once before this role's handler is queued, so one play can restart the
unit twice. The role cannot prevent that; a single restart needs a change to
`ntfy_pager` or to the playbook order. Owner decision.

### Order

On a fresh host the two roles depend on each other, so neither can converge
alone. `monitoring_stack` needs `ntfy_pager` to have delivered the renderer (it
fails closed without it). `ntfy_pager` needs the monitoring secrets file to be
present and non-empty, and this role writes that file. The playbook that would
run them in an order that works is not in this repository: `ansible/playbooks/edge1.yml`
wires neither role. Until an owner decision names the order, a fresh host does
not converge. This is open: owner.

Within one play, the monitoring unit's `ExecStartPre` runs the renderer that
`ntfy_pager` delivers. This is the dependency the README above states.

### How it relates to the patterns

The role applies two recipes from `ansible/patterns/`: `files_and_units` (explicit
owner, group and mode; a notify and a handler for the daemon-reload; a
`flush_handlers` so the role returns with systemd current; a converge that asks
systemd, straight after the role, what it holds) and the file-delivery half of
`compose_stack` (explicit modes on a project directory and its files, no handler
that starts the stack). It does not call them: a pattern is a recipe a service role
copies and renames, not a library, and ANS-12 keeps composition in playbooks (the
standard leaves open whether one role may include another). So the tasks are
written out here, as the recipes direct.

Parts of the `compose_stack` recipe this role does not carry, and why:

- the apply-time refusal of an image not pinned by digest and of a compose override
  file in the project directory: the role never runs Compose, so nothing here reads
  either. The images are checked in the test instead (see below); an override file
  next to the Compose file would be merged by the unit's own `docker compose up`,
  and nothing refuses it until the role that starts the stack does;
- the `validate` of the Compose file with `docker compose config`, for the reason
  above;
- the stamp, the `docker_compose_v2` call that brings the stack up, and the health
  check that fails the role when a service is not running and healthy. The unit
  brings the stack up, and the health check belongs with whatever starts it.

### What it does not start or delete

It does not start or recreate anything. It restarts the monitoring unit only as
described under "Restart", and only when that unit is already active. The stack is
brought up by the `branchleft-compose@monitoring` unit, whose drop-in runs the
Alertmanager renderer first; bringing it up from here, before that renderer has written
`alertmanager/alertmanager.yml`, `ntfy/server.yml` and
`prometheus/mx1-metrics-password`, would make Docker create a directory at each
of those bind-mount paths. So the role has no `docker compose` task and no
stamp, and the health check of the `compose_stack` pattern is not carried. The
role also does not check the Compose file with `docker compose config`: the
Grafana password is a required variable in that file, so the check fails on a
host where the secrets file does not exist yet.

It does not delete anything. The shell copy it replaces used `rsync --delete`,
so a file removed from the repository was removed from the host; this role
leaves such a file in place, and it must be removed by hand until a later change
decides how.

### Not in this role (and who owns it)

- Rendering `alertmanager.yml` and the ntfy `server.yml` from their templates,
  and delivering `render_alertmanager_config.py`: `ntfy_pager` owns both. This
  role checks the renderer is there and does not write a second copy.
- Runbook section 14's hand write of `SNDS_DATA_URL` is not retired here, and
  the monthly rotation keeps that hand step until an owner decision gives the
  rotation a gated path. The runbook's live apply is owner-gated.
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
generates or stores a value.

`vars/main.yml` holds the constants of the stack (the directories, the files and
the drop-in directory). They are not inputs; a caller cannot override them.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 (the release every host runs and the test runs on) with
  Python 3 and systemd. The role runs as root.
- The files come from this repository: the role reaches them through a link in
  `files/` (below), so it must be run from a checkout of the whole repository,
  which is what the gated pull delivers (ANS-17).

## What it changes on a host

Every directory is `root:root`, mode `0755`, and every file is `root:root`,
mode `0644`. That is what the rsync it replaces produced
(`--no-owner --no-group --chmod=u=rwX,go=rX` followed by `chown -R root:root`):
the containers read their bind-mounted configuration as their own user, so a
file or directory tighter than this makes a container fail.

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
- One `daemon-reload` of the systemd manager, only when a drop-in changed,
  run before the role returns.
- A restart of the monitoring unit when "Restart" says so.
- No port, no user, no firewall rule, no container, no unit start or stop.

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
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
.venv/bin/python ansible/harness/run_harness.py ansible/roles/monitoring_stack
```

The harness lints the role and runs the scenario in `molecule/default/` on one
systemd container (the same Debian 13 image and settings as the
`files_and_units` pattern; the reason for each platform key is in `molecule.yml`).
It removes its container when it finishes and never touches a host.

What each part of the scenario does:

- `prepare.yml` installs a placeholder for the shared unit template
  (`branchleft-compose@.service`), because systemd needs the template to apply a
  drop-in to an instance.
- `converge.yml`, on an instance with no drop-in, first installs an earlier
  release of it (a different `MemoryMax`) and asks systemd about the instance, so
  that systemd holds the earlier value. It then applies the role and asks systemd
  again, straight away: a reload that is missing, or left to the end of the play,
  fails on `MemoryMax`.
- `idempotence`: a second converge reports zero changed tasks.
- `verify.yml`: works out the expected files and directories from the stack
  directory of the repository; every one exists with its owner, group and mode;
  every delivered file's SHA-256 equals the SHA-256 of its source read directly from
  the repository (not through the role's link), so a copy that differs from the
  source fails; the drop-in is where the unit template looks for it, equals its
  source and is the one systemd has loaded (`DropInPaths`, `MemoryMax`,
  `CPUWeight`); and every image in the Compose file is pinned by digest.
- `check-fresh`, `check-configured` and `molecule-check`: the role runs under
  `--check --diff` before the first apply and against the configured instance and
  shows no drift.

What breaks which step. Each row is an edit made with the editor, one harness run
(the whole harness over this role, so the lint and every container step run), and a
`git restore` with a clean tree afterwards, on 2026-10-20. The harness run is the
retrieval: make the row's edit and run it to see the message.

| Edit to the role                                                          | Step that fails | Assertion that names it                                                                                                                                                |
| ------------------------------------------------------------------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The task that installs the drop-in removed                                | `converge`      | "systemd does not hold the drop-in the role installed (MemoryMax 1073741824)"                                                                                          |
| The `notify` of the drop-in task removed (no daemon-reload)               | `converge`      | the same assertion                                                                                                                                                     |
| Mode of the delivered files changed from `0644` to `0640`                 | `verify`        | "alertmanager/alertmanager.yml.tmpl is missing on the instance, is not a regular file owned by root with mode 0644, or differs from" the source (one failure per file) |
| `files/stack` replaced by a copy with one byte of `blackbox.yml` changed  | `verify`        | "blackbox/blackbox.yml is ... or differs from" its source in `hetzner/monitoring/stack`                                                                                |
| `compose.yml` removed from `monitoring_stack_files`                       | `verify`        | "compose.yml is missing on the instance, is not a regular file ..."                                                                                                    |
| The drop-in directory name changed by one character (`monitorinq`)        | `converge`      | the same assertion as the first row                                                                                                                                    |
| A new file added to `hetzner/monitoring/stack/` (not touched by the role) | `verify`        | "zz_probe_file.txt is missing on the instance, is not a regular file ..."                                                                                              |

The first two rows share one message because it covers both causes (no drop-in, or no
reload); the rows differ in the edit, and each was run on its own. The row for the
copy also made the lint and yamllint steps fail, because a real copy puts the
stack's YAML under the lint: a second reason for the link.

An earlier version of the converge started no unit, and the second row stayed green:
systemd unloads an inactive unit that nothing refers to and reads the new drop-in from
disk with no reload. The converge now starts the placeholder instance so systemd keeps
the earlier drop-in loaded, and the second row went red. The control for the reload is
therefore the converge's question to systemd, not the verify play.

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
  stack. It proves the files are on the host, byte for byte, with their modes, and
  that systemd loads the drop-in; it does not prove the stack starts, that the
  render step works, or that the real unit template accepts the drop-in. The first
  live apply is the proof (ANS-17), and it waits on the enrolment of the hosts and
  on the gate.
- **The unit template is a placeholder in the test.** The drop-in is loaded
  against a oneshot that runs `/bin/true`. `MemoryMax` and `CPUWeight` are read
  from systemd's properties; the drop-in's `ExecStart`, `ExecStartPre`,
  `EnvironmentFile` and `AssertPathExists` resets are not exercised.
- **Reviewed, not tested: `owner: root` and `group: root`.** The instance runs as
  root, so omitting them gives the same result, and no file may belong to anyone
  else, so no test value tells the two apart.
- **A file removed from the repository stays on the host** (no `--delete`). See
  above.
- **An empty directory is not noticed.** The test derives the directories from
  the files, so a new directory with no file in it is neither required nor checked.
- **A silent skip passes.** The converge skips its earlier-release setup and its
  systemd questions in check mode because nothing is written there; the harness
  does not catch a silent skip, and this is the review of it (ANS-10).
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
check mode first; after the approval the host pulls that exact commit of `main`
and applies it, and a second run must report zero changes. Nothing is applied from
a laptop. This role is not applied to any host yet: the live run waits on the
enrolment of the hosts (the enrolment ticket) and on the gate, and on the second
part of the monitoring work, because starting the unit before the renderer is in
place makes it fail.

## How to change it safely

1. To change what the stack is, change the files under `hetzner/monitoring/stack/`
   or the drop-in under `hetzner/monitoring/systemd/`; the role delivers them as
   they are. To add a file, add it to `monitoring_stack_files` (and its directory
   to `monitoring_stack_dirs`) in `vars/main.yml`; the test finds it by itself and
   fails until the role carries it. To leave one out on purpose, name it in
   `verify_not_carried` in `molecule/default/verify.yml`.
2. Keep every task able to run under `--check --diff`, and keep the modes explicit.
3. Do not add a `docker compose` task here without reading the paragraph above on
   why the role does not start the stack.
4. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
5. Run the test command above before opening a pull request, then break the
   control you touched (the table above) and see the same step fail.
