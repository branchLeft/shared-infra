# monitoring_stack

This role puts the files of the monitoring Compose stack on a host and installs
the systemd drop-in that belongs to that stack. It is the first part of moving
the monitoring runbook into Ansible; the parts it leaves out are listed below.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does two things, both with `ansible.builtin.copy`:

1. It copies the committed files of the stack from `hetzner/monitoring/stack/`
   into the project directory on the host: the Compose file, the Prometheus
   configuration and alert rules, the Blackbox configuration, the Grafana
   datasource, the Alertmanager and ntfy templates and the Alertmanager email
   template. They are copied as files. Nothing is rendered, because the Compose
   file holds `${...}` and `$$` for Compose to read and the `.tmpl` files hold
   placeholders a later step fills.
2. It installs `hetzner/monitoring/systemd/monitoring.override.conf` as
   `/etc/systemd/system/branchleft-compose@monitoring.service.d/override.conf`,
   the destination `hetzner/provision/install-systemd-drop-ins.sh` uses for the
   instance named `monitoring`, and reloads systemd when that file changed.

It does not start, restart or recreate anything. The stack is brought up by the
`branchleft-compose@monitoring` unit, whose drop-in runs the Alertmanager
renderer first; bringing it up from here, before that renderer has written
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
  `render_alertmanager_config.py` (the program stays as code and is installed
  here by the second part of the monitoring work), the five monitoring secrets
  and the SNDS URL, the retirement of `hetzner/RUNBOOK-monitoring.md`, and the
  live apply: the second part of the work on the monitoring ticket.
- `snds-collector.service`, `snds-collector.timer` and `snds/collect_snds_metrics.py`,
  and the `/var/lib/branchleft/snds-exporter` directory node-exporter mounts:
  the exporters and collectors ticket (the SNDS collector with its timer).
- `nextcloud1.override.conf`: the Nextcloud ticket, whose scope says it
  installs the override.
- `edge.override.conf`: the monitoring ticket's scope lists it, but it belongs to
  the edge stack and no other ticket's scope names it; this role does not carry
  it and the gap is reported on the pull request.
- Docker, the shared Compose unit template and the deploy tooling: the host
  baseline and deploy tooling tickets. The test installs a placeholder for the
  unit template; the real one is not tested here.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. There is one,
`monitoring_stack_project_dir`, the stack's project directory. It must equal the
`WorkingDirectory` the shared unit template derives from the instance name
(`/opt/branchleft/monitoring`), so a caller has no reason to change it. None of
the role's variables is a secret and the role handles no secret.

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
- One `daemon-reload` of the systemd manager, only when `override.conf` changed,
  run before the role returns.
- No port, no user, no firewall rule, no container, no unit start or stop.

### One home for every file

The role holds no copy of the files it delivers. `files/stack` is a link to
`hetzner/monitoring/stack` and `files/monitoring.override.conf` is a link to
`hetzner/monitoring/systemd/monitoring.override.conf`, both relative, so a change
to the stack in its own directory is what the next apply delivers, and the role
cannot drift from it. The images stay pinned by tag and digest inside
`compose.yml`, where the dependency bot reads them.

What the link does not cover is the list of files. `vars/main.yml` names the files
and directories, and a file added to `hetzner/monitoring/stack/` is not delivered
until it is listed. The test closes that: its last play lists every file under the
stack directory and fails unless each is carried or named as deliberately not
carried (below).

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
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
- `verify.yml`: every directory and file exists with its owner, group and mode;
  every delivered file's SHA-256 equals the SHA-256 of its source read directly from
  the repository (not through the role's link), so a copy that differs from the
  source fails; the drop-in is where the unit template looks for it, equals its
  source and is the one systemd has loaded (`DropInPaths`, `MemoryMax`,
  `CPUWeight`); every image in the Compose file is pinned by digest; and every file
  under the stack directory is carried or named as not carried.
- `check-fresh`, `check-configured` and `molecule-check`: the role runs under
  `--check --diff` before the first apply and against the configured instance and
  shows no drift.

SABOTAGE_TABLE_PLACEHOLDER

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
- **The directory list is not completeness-checked.** The files are (the last
  play of `verify.yml`); a new directory under the stack that holds a new file
  fails that play, but a new empty directory is not noticed.
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
   to `monitoring_stack_dirs`) in `vars/main.yml` and to `verify_files` and
   `verify_carried` in `molecule/default/verify.yml`; to leave one out on purpose,
   name it in `verify_not_carried`.
2. Keep every task able to run under `--check --diff`, and keep the modes explicit.
3. Do not add a `docker compose` task here without reading the paragraph above on
   why the role does not start the stack.
4. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
5. Run the test command above before opening a pull request, then break the
   control you touched (the table above) and see the same step fail.
