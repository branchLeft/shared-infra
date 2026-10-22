# ntfy_pager

This role is the part of the ntfy pager install that runs on the edge host: it
writes the four ntfy credential lines into the monitoring secrets file and
delivers the Alertmanager renderer that the monitoring stack's unit runs before
it starts. It restarts nothing. It ports sections 2 and 3 of the install
runbook, `ntfy-pager-install-runbook.md` in the private docs repository, into a
role a maintainer can read and rerun. The runbook's other sections (the
credentials, the edge site block, the DNS record, the phone, the test messages)
are not in this role.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. It creates `/etc/branchleft` and `/etc/branchleft/monitoring.env` when they
   are absent, closed to `root:root` mode `0600` before any value is written,
   and then writes one line per key, `NTFY_PAGER_TOKEN`, `NTFY_WATCHER_TOKEN`,
   `NTFY_OWNER_PASSWORD_HASH` and `NTFY_MACHINE_PASSWORD_HASH`, with the values
   the caller gives. Any other line in the file is left in place.
2. It creates the project directory `/opt/branchleft/monitoring` and copies one
   file into it, `render_alertmanager_config.py`, owned by root with mode `0644`.
   The unit's drop-in runs that renderer before the stack starts, and this role
   is its single delivery owner.

It does not write a credential it was not given: there is no default for any of
the four values, and the role never reads, generates or stores one. It does not
install the unit's drop-in, deliver the stack's other eight files, render a
template, delete a file, change the network, or restart or start anything.

### Order

`ntfy_pager` runs first, and `monitoring_stack` second. No playbook in this
repository runs either role yet, so the order is written here and held by the
pair of tests below, not by a playbook.

- This role creates the secrets file when it is absent. `monitoring_stack`
  creates it with the same owner, group and mode, so whichever runs first
  creates it and the second changes nothing. The order is therefore not needed
  to get the file; it is needed so that the file `monitoring_stack` hashes
  already holds the four `NTFY_` lines, and so that the renderer is on the host
  before a restart.
- `monitoring_stack` decides every restart of the monitoring unit. It hashes the
  secrets file (without its `SNDS_DATA_URL` line) and the renderer this role
  delivers, so a changed `NTFY_` line or a changed renderer restarts the unit on
  that role's next run. This role has no handler and no restart task.

`ansible/checks/test_monitoring_single_home.py` holds the split: it fails if this
role lists one of the stack's eight files, or if any role other than
`monitoring_stack` names the monitoring unit.

### How it relates to the patterns

The role follows the recipes of two patterns in `ansible/patterns/`, and does not
call them (a pattern is a recipe, not a library; ANS-12 keeps composition in
playbooks):

- `files_and_units`: explicit owner, group and mode on every file and directory.
  The unit and its restart are `monitoring_stack`'s.
- `secrets_and_no_log`: the values are inputs that have no default, every task
  that handles a value sets `no_log: true` and `diff: false`, and no value is
  printed or registered.

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

`vars/main.yml` holds the constants: the one file the role delivers and the four
key names. They are not inputs.

### Where the four values come from

The values are not in this repository, not in a playbook, and not in a test. How
they reach a host that pulls its commit from `main` is settled with the wiring of
the two roles into a playbook, and until then the role has no source for them and
must not be given one by a default.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; `min_ansible_version`
  is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and systemd. The role runs as root.
- The renderer comes from this repository through the link in `files/`, so the
  role must run from a checkout of the whole repository, as the gated pull provides.

## What it changes on a host

- `/etc/branchleft` (`root:root`, mode `0755`) and `/etc/branchleft/monitoring.env`,
  created if absent (`root:root`, mode `0600`, with the access and modification
  times preserved so a second run changes nothing). The four `NTFY_` lines are
  replaced in place or added at the end; every other line is kept.
- `/opt/branchleft/monitoring` (`root:root`, mode `0755`), holding
  `render_alertmanager_config.py` (`root:root`, mode `0644`), copied from the
  repository.
- No unit is started, stopped or restarted, and no drop-in is installed.

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
- **Only the renderer is delivered, not the stack.** The runbook synced the whole
  stack. The stack's eight other files are `monitoring_stack`'s, which does not
  delete either: a deletion needs its own decision (see the named limits).
- **The unit is not restarted here.** The runbook restarted it each time.
  `monitoring_stack` restarts it by fingerprint, so a change of a `NTFY_` line or
  of the renderer reaches the unit on that role's next run, and a second run with
  no change restarts nothing.
- **The runbook's post-restart journal check is not carried over.** Section 3 of
  the runbook greps the unit's journal for the line "ntfy pager is DISABLED" after
  the restart and expects no match. This role restarts nothing, so it has no
  restart to check; `monitoring_stack` reads the unit back as active before it
  records a restart, and does not read the journal text.

## One home for the stack

`files/stack` is a link to `hetzner/monitoring/stack`, the same link the
`monitoring_stack` role uses, so the role holds no copy of the file. The list in
`vars/main.yml` is one entry, `render_alertmanager_config.py`, because the unit's
`ExecStartPre` runs it: the unit rewrites `alertmanager.yml` and the ntfy
`server.yml` from the `NTFY_` values this role writes. The renderer is the ninth
file in that directory; the eight others are `monitoring_stack`'s alone.

Three files of the stack are left out of this role: `render_alertmanager_config.md`,
the notes beside the renderer, which nothing on the host runs;
`snds/collect_snds_metrics.py`, which the `snds-collector` timer runs and which
belongs to the exporters and collectors work; and the eight files above.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
python3 -m venv .venv
.venv/bin/pip install --require-virtualenv --require-hashes -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ntfy_pager
.venv/bin/python -m unittest discover -s ansible/checks
```

The harness lints the role and runs `molecule/default/` on one systemd container
(the same Debian 13 image and settings as `monitoring_stack`). It removes its
container when it finishes and never touches a host.

What each part of the scenario does:

- `prepare.yml` writes an earlier monitoring secrets file (an old
  `NTFY_PAGER_TOKEN` and a `GRAFANA_` key the role must keep, in mode `0644`) and
  creates the project directory. It installs no unit: this role touches none.
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
  `0600`; the renderer is `root:root` `0644` and equal to its source through the
  role's link, the source read on the controller; the project directory holds
  exactly the one renderer, a literal list in the test (it is not derived from
  `ntfy_pager_files`, so a file added to that list is noticed); the log holds the
  canary and the role's task name, and holds none of the four sentinel values. The
  log scan is the proof that `no_log` is on the tasks that handle a value:
  removing it from the task that writes the lines makes the scan fail.
- `check-fresh`, `check-configured` and `molecule-check` run the role under
  `--check --diff` against the fresh and the configured container.

Two sabotage rows were run for this scenario, each in a fresh container with the
edit reverted afterwards: the secrets-file task given mode `0644` fails `verify` at
"Assert the secrets file is owned by root and closed to everyone else", and a second
stack file (`compose.yml`) added to `ntfy_pager_files` fails `verify` at "Assert the
project directory holds the renderer and nothing else". The seam with
`monitoring_stack` is tested in that role's scenario, which runs this role.

## Named limits

- **Real Compose and a real host are not exercised.** The test never starts the
  stack, never runs the renderer and never reaches ntfy. The first live apply is
  the proof (ANS-17).
- **A removed stack file stays on the host.** There is no delete.
- **Other `NTFY_` keys are not removed.** The runbook removed every `NTFY_` line;
  this role removes none. A key of another name left in the file by an earlier
  release stays until someone removes it.
- **The values are not checked for shape here.** The role writes what it is given.
  A value with a newline would break the file, so the caller must give one line
  per value. `monitoring_stack` checks its own seven inputs; this role's four are
  not checked by it.
- **A silent skip passes.** The line task is skipped in check mode when the file
  does not exist yet, because there is nothing to edit; the harness does not see
  that, and review does.
- **The image is the third-party Debian 13 systemd base the `files_and_units`
  pattern records, trusted by digest; nothing here bumps it.**

## How it is delivered

Only the gated workflow applies this role, against `main`, after the approval of
its protected environment (ANS-17). A plan job shows the host's diff in check mode
first; after approval the host pulls that exact commit and applies it, and a
second run must report zero changes. Nothing is applied from a laptop.

## How to change it safely

1. To change the renderer, change `hetzner/monitoring/stack/render_alertmanager_config.py`.
   Do not add one of the stack's eight other files to `ntfy_pager_files`: the test in
   `ansible/checks` fails, because `monitoring_stack` is their one home.
2. Keep every task able to run under `--check --diff`, the modes explicit, and every
   task that handles a value under `no_log: true`.
3. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
4. Run the test command above before opening a pull request.
