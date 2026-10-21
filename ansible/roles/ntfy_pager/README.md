# ntfy_pager

This role is the part of the ntfy pager install that runs on the edge host: it
writes the four ntfy credential lines into the monitoring secrets file, delivers
the monitoring stack's files, and restarts the monitoring stack unit when either
changed. It ports sections 2 and 3 of the install runbook,
`ntfy-pager-install-runbook.md` in the private docs repository, into a role a
maintainer can read and rerun. The runbook's other sections (the credentials,
the edge site block, the DNS record, the phone, the test messages) are not in
this role.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. It closes the monitoring secrets file to root, mode `0600`, and then writes
   one line per key, `NTFY_PAGER_TOKEN`, `NTFY_WATCHER_TOKEN`,
   `NTFY_OWNER_PASSWORD_HASH` and `NTFY_MACHINE_PASSWORD_HASH`, with the values
   the caller gives. Any other line in the file is left in place.
2. It creates the project directory `/opt/branchleft/monitoring` and its
   subdirectories, and copies the committed files the unit runs from
   `hetzner/monitoring/stack/` into it, each owned by root with mode `0644`. That
   includes `render_alertmanager_config.py`, which the unit's drop-in runs before
   the stack starts (see "One home for the stack" for the files left out).
3. It restarts `branchleft-compose@monitoring.service` when a credential line or a
   stack file changed. The unit's drop-in runs the Alertmanager and ntfy renderer
   before the stack starts, so the restart is what applies the change.

It does not write a credential it was not given: there is no default for any of
the four values, and the role never reads, generates or stores one. It does not
create the secrets file (it must already exist and be non-empty), install the
unit's drop-in, render a template, delete a file, change the network, or start
the stack for the first time as a separate step (the restart is that step, and
it is reached only when something changed).

### How it relates to the patterns

The role follows the recipes of three patterns in `ansible/patterns/`, and does
not call them (a pattern is a recipe, not a library; ANS-12 keeps composition in
playbooks):

- `files_and_units`: explicit owner, group and mode on every file and directory,
  a handler for the unit, and a `flush_handlers` so the role returns with the
  stack restarted.
- `secrets_and_no_log`: the values are inputs that have no default, every task
  that handles a value sets `no_log: true` and `diff: false`, and no value is
  printed or registered.
- `compose_stack`: the file-delivery half only. The role does not run Compose, so
  the apply-time refusals and the health check of that pattern are not carried.
  The reasons are the same as in `monitoring_stack`.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables and
[`defaults/main.yml`](defaults/main.yml) holds the two paths:

| Variable                           | Default                          | Meaning                                              |
| ---------------------------------- | -------------------------------- | ---------------------------------------------------- |
| `ntfy_pager_project_dir`           | `/opt/branchleft/monitoring`     | The stack's project directory                        |
| `ntfy_pager_env_file`              | `/etc/branchleft/monitoring.env` | The monitoring secrets file                          |
| `ntfy_pager_pager_token`           | none, required                   | The value of `NTFY_PAGER_TOKEN` (`no_log`)           |
| `ntfy_pager_watcher_token`         | none, required                   | The value of `NTFY_WATCHER_TOKEN` (`no_log`)         |
| `ntfy_pager_owner_password_hash`   | none, required                   | The value of `NTFY_OWNER_PASSWORD_HASH` (`no_log`)   |
| `ntfy_pager_machine_password_hash` | none, required                   | The value of `NTFY_MACHINE_PASSWORD_HASH` (`no_log`) |

`vars/main.yml` holds the constants: the directories and files of the stack, the
unit's name, and the four key names. They are not inputs.

### Where the four values come from

The owner decides where the values come from and how they reach a host that
pulls its commit from `main`. Until the owner has decided, the role has no source
for them and must not be given one by a default. The values are not in this
repository, not in a playbook, and not in a test.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version`
  is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and systemd. The role runs as root.
- The stack files come from this repository through the link in `files/`, so the
  role must run from a checkout of the whole repository, as the gated pull provides.
- The monitoring secrets file must already exist and be non-empty, with the other
  keys the stack reads.
- The drop-in of the monitoring instance is not installed here. The stack's
  `monitoring_stack` role installs it, and the unit does not render its config
  without it.

## What it changes on a host

- `/etc/branchleft/monitoring.env`: the four `NTFY_` lines are replaced in place or
  added at the end; every other line is kept. The file is `root:root` mode `0600`.
- `/opt/branchleft/monitoring` and under it the directories `alertmanager`,
  `blackbox`, `grafana/provisioning/datasources`, `ntfy` and `prometheus` (and their
  parents): `root:root`, mode `0755`.
- The nine stack files the unit runs, each `root:root` mode `0644`, copied from the
  repository.
- `branchleft-compose@monitoring.service` restarted, once, when a credential line or
  a stack file changed. Not restarted on a second run with no change.

## Where this differs from the runbook, and why

Each difference is a choice the runbook's shell made that this role does not copy.

- **The credential lines are written one key at a time with `lineinfile`.** The
  runbook removed every `NTFY_` line with `grep -v`, appended four, and checked the
  count with `grep -c`. A `lineinfile` per key keeps the other keys of the file in
  place, is idempotent, and does not write a temporary copy of the whole file. The
  count check moved to the test: `verify.yml` checks each key once.
- **The file is closed before the values are written.** The runbook wrote to a
  temporary file under `umask 077` and then moved it. The role sets the owner and
  mode first, so no value is written to a file that is wider.
- **The stack is copied, not synced with `rsync --delete`.** The runbook's
  `--delete` removed a file from the host when it was removed from the repository.
  This role does not delete, for the reason the `monitoring_stack` role gives: a
  deletion needs its own decision (see the named limits). The modes and owners
  are the ones the runbook's `rsync --no-owner --no-group --chmod=u=rwX,go=rX`
  and `chown -R root:root` produced.
- **The unit is restarted on change, not on every run.** The runbook restarted it
  each time. A restart on every run would make every second run report a change,
  so the role restarts only when a credential line or a stack file changed. The
  restart still runs the renderer and reloads the stack with the new files.
- **The runbook's post-restart journal check is not carried over.** Section 3 of
  the runbook greps the unit's journal for the line "ntfy pager is DISABLED" after
  the restart and expects no match. The role has no such task. Its verify checks
  that the unit is `active` and that the files and the secrets file are as set,
  not the journal text. Whether to keep the journal check is the owner's call; if
  it is wanted, it is one task after the restart and is not added here.

## One home for the stack

`files/stack` is a link to `hetzner/monitoring/stack`, the same link the
`monitoring_stack` role uses, so the role holds no copy of the files. The file
list in `vars/main.yml` is the list that role carries, plus
`render_alertmanager_config.py`, because the unit's `ExecStartPre` runs it: the
unit rewrites `alertmanager.yml` and the ntfy `server.yml` from the `NTFY_` values
this role writes, so the role delivers the renderer it depends on rather than
assuming a copy from an earlier install.

Two files of the stack are left out, on purpose:

- `render_alertmanager_config.md`, the notes beside the renderer. Nothing on the
  host runs it, and the notes are for people reading the repository.
- `snds/collect_snds_metrics.py`. The unit does not run it: the `snds-collector`
  timer does, and that timer belongs to the exporters and collectors work named in
  the `monitoring_stack` README.

Two roles now deliver the same files, and the renderer is delivered by this role
too. Applying both to one host copies the same bytes twice, and each role restarts
the unit on its own change. Choosing one of them as the owner of the stack is a
later decision and is listed as discovered work in the pull request.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
python3 -m venv .venv
.venv/bin/pip install --require-virtualenv --require-hashes -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ntfy_pager
```

The harness lints the role and runs `molecule/default/` on one systemd container
(the same Debian 13 image and settings as `monitoring_stack`). It removes its
container when it finishes and never touches a host.

What each part of the scenario does:

- `prepare.yml` installs a placeholder for the shared unit template, writes an
  earlier monitoring secrets file (an old `NTFY_PAGER_TOKEN` and a `GRAFANA_` key the
  role must keep, in mode `0644`), and creates the project directory.
- `converge.yml` applies the role with four literal sentinel values. They are test
  strings, not credentials, and are literals so a second converge writes the same
  lines.
- `idempotence`: a second converge reports zero changed tasks.
- `converge.yml` ends with a harmless command given a canary argument, with no
  `no_log`. It is the control of the log scan.
- `molecule.yml` writes the Ansible log of the run to the scenario's directory at
  verbosity 3, so a task's arguments are in it.
- `verify.yml`: each `NTFY_` key holds its sentinel once, the other key is kept
  (the file is read under `no_log` and no value is printed); the file is `root:root`
  `0600`; every stack file is `root:root` `0644` and equal to its source through the
  role's link, the source read on the controller; the unit is `active` after the
  role ran; the log holds the canary and the role's task name, and holds none of the
  four sentinel values. The log scan is the proof that `no_log` is on the tasks that
  handle a value: removing it from the task that writes the lines makes the scan
  fail.
- `check-fresh`, `check-configured` and `molecule-check` run the role under
  `--check --diff` against the fresh and the configured container.

## Named limits

- **Real Compose and a real host are not exercised.** The test never starts the
  stack, never runs the renderer and never reaches ntfy. The unit template is a
  placeholder oneshot that runs `/bin/true`. The first live apply is the proof
  (ANS-17).
- **A removed stack file stays on the host.** There is no delete. See above.
- **Other `NTFY_` keys are not removed.** The runbook removed every `NTFY_` line;
  this role removes none. A key of another name left in the file by an earlier
  release stays until someone removes it.
- **The values are not checked for shape.** The role writes what it is given. A
  value with a newline would break the file, so the caller must give one line per
  value.
- **A silent skip passes.** The role has no task that is skipped in check mode.
  The restart runs only on a real converge, so a check-mode run shows it as
  pending and never as done; the harness does not see that, and review does.
- **The image is the third-party Debian 13 systemd base the `files_and_units`
  pattern records, trusted by digest; nothing here bumps it.**

## How it is delivered

Only the gated workflow applies this role, against `main`, after the approval of
its protected environment (ANS-17). A plan job shows the host's diff in check mode
first; after approval the host pulls that exact commit and applies it, and a
second run must report zero changes. Nothing is applied from a laptop.

## How to change it safely

1. To change what the stack is, change the files under `hetzner/monitoring/stack/`.
   To add a file, add it to `ntfy_pager_files` (and its directory to
   `ntfy_pager_dirs`) in `vars/main.yml`.
2. Keep every task able to run under `--check --diff`, the modes explicit, and every
   task that handles a value under `no_log: true`.
3. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
4. Run the test command above before opening a pull request.
