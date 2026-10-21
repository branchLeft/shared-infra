# backup_worker

This role installs the per-tenant backup worker on its control host and writes
the files the worker reads. It ports sections 1 to 3 and the file-writing parts
of sections 4c, 5d and 6.2 of the ops1 install runbook (ghost-platform-docs,
`backup-worker-ops1-install-runbook.md`, commit `26fbfde`). The nightly timer
stays off unless a variable turns it on.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. **Stages a release** (runbook 1, 6.1). Each program and unit is downloaded
   with `get_url` from `branchLeft/ghost-platform` at a pinned full commit and
   held to a `sha256`. They land in `/opt/branchleft/backup-worker/releases/<commit>/`,
   owned by root and not writable by anyone else, which the installer requires.
   The release also holds what the `backup_restore` role installs from it (the
   restore drill, the state copy and `nextcloud_backup.py`, with their installers
   and units); this role stages them and never runs them.
2. **Installs the prerequisites** (runbook 2): when `age` or the `mysqldump` 8.0
   client is missing, it runs the pinned `install_host_prereqs.py` from that same
   release. Nothing runs when both are present.
3. **Creates the service account, repoints `current` and installs the two units**
   (runbook 3, 6.2 without the enable), then reloads systemd.
4. **Installs the database CA** (runbook 4c) from an input.
5. **Writes the tenants file, the recipients file and the environment file**
   (runbook 5d): the first two `root:backup-worker` `0640`, the environment file
   `root:root` `0600`.
6. **Holds the timer to a variable** (runbook 6.2): `backup_worker_timer_enabled`,
   default `false`. True enables and starts `branchleft-backup-worker.timer`. False
   leaves the timer as it is on the host, unless `backup_worker_timer_may_disable`
   is true; then it stops and disables it. A fresh host therefore stays off, and a
   timer enabled by hand is not stopped by a run with the defaults.

It does not run the ghost-platform installer to install. The installer enables
the timer itself once its inputs are present, which would bypass the variable,
so the role does each non-secret step natively. The one time it runs the
installer is `--check`, which changes nothing, when the timer is asked for.

### Owner steps the role does not do

These stay with the owner, in ghost-platform-docs. The role takes their results
as inputs.

| Runbook section | What                                                                                                                                                | Why the role does not                                                                                                                                                            |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 4a, 4b, 4e      | Make the database account and its password, create it on the database host with its grants, move an older account onto the bounded-snapshot grants. | Needs the database host's root password. The role takes the account name and password as inputs and never creates or alters an account. The grant host is only used in that SQL. |
| 4d              | Prove the account from the worker host.                                                                                                             | Prompts for the password.                                                                                                                                                        |
| 5a, 5b, 5c      | Make the age keypair, store the private half in the password manager, prove the stored key decrypts.                                                | The private key never reaches the host. The role takes only the public recipient.                                                                                                |
| 6.0 (a) to (c)  | Check the database host's own dump grants, and that the backup alerts are loaded on the monitoring host.                                            | Reads on other hosts.                                                                                                                                                            |
| 6.0 (d) and 6.4 | Prove the restore-drill key can list the bucket, then read the dump's header back.                                                                  | Mac-side secret-tool reads and the drill key.                                                                                                                                    |
| 6.3             | Take the first run by hand.                                                                                                                         | An owner decision, after the timer is staged.                                                                                                                                    |

### Not in this role

- **Section 7** (Prometheus and the backup alerts) covers `node_exporter` on the
  worker host. That belongs to the `exporters_and_collectors` role, not here.
- Deleting an old release directory. Releases accumulate; the role never removes one.

### Turning the timer on is a production apply

`backup_worker_timer_enabled: true` starts nightly dumps of production data. It
is a production apply and goes through the gated workflow (ANS-17), never a
laptop. The role first runs the installer's `--check` and fails if any input is
missing, so a half-prepared host does not get a timer.

Leaving the variable `false` does not change a timer the host already has on.
Turning the timer off is a second, explicit decision: set
`backup_worker_timer_may_disable: true` as well, and the role stops and disables
it. Both variables are production applies when they change a running timer.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable
and [`defaults/main.yml`](defaults/main.yml) holds the public ones.

**Private values are required inputs with no default.** This repository is
public. The database host address, the account name, the bucket, the S3
endpoint and region, the tenant slugs and the CA text come from the **private
inventory**, and the role asserts each is set and well formed. The three
credentials (`backup_worker_db_password`, `backup_worker_s3_access_key_id`,
`backup_worker_s3_secret_access_key`) are `no_log` inputs, supplied at run time.
The tests use documentation values only (`192.0.2.x`, `example.invalid`).

Public defaults: `backup_worker_timer_enabled` (`false`),
`backup_worker_timer_may_disable` (`false`), `backup_worker_install_prereqs` (`true`), `backup_worker_source_sha` (the
ghost-platform commit), `backup_worker_source_base_url` (the raw URL at that
commit, so a test can point it at a `file://` copy) and
`backup_worker_release_files` (each file with its `sha256`).

`vars/main.yml` holds the constants (paths, account name, the input patterns). A
caller cannot override them.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and systemd. The role runs as root.
- Network from the host to `raw.githubusercontent.com` on a real apply.

## What it changes on a host

- The `backup-worker` system account (no home, `/usr/sbin/nologin`).
- Directories `/opt/branchleft`, `/opt/branchleft/backup-worker`, `releases/`, the
  release directory and its eight subdirectories, and `/etc/branchleft`, all
  `root:root` `0755`.
- The release files, `root:root` `0644`, and the link `current` to the release.
- `/etc/systemd/system/branchleft-backup-worker.service` and `.timer`, `0644`,
  and one systemd reload when either changed.
- `/etc/branchleft/db1-ca.pem` `0644`; `backup-worker-tenants` and
  `backup-worker-recipients` `root:backup-worker` `0640`; `backup-worker.env`
  `root:root` `0600`.
- The timer's enabled and active state.
- When a probe finds `age` or the `mysqldump` 8.0 client missing: whatever
  `install_host_prereqs.py` does (an apt source, a pin, packages). This is not
  exercised by the tests (below).

### The environment file

An absent file is created empty at `root:root` `0600` first, and only then is the
value written. A file already there is kept, and its owner, group and mode are set
back to `root:root` `0600` on every run before the value is written. The values
come from `backup_worker_secret_files` in `vars/main.yml`, the one home. The
limit: the correction happens on each run, not continuously, so a file widened by
hand stays wide until the next run. The tasks that handle a value say
`no_log: true` and `diff: false`, the include in the test carries no `no_log` so
the role's own tasks must keep values out of the log, and the registered results
are not kept. No value is a default or in the tests except documentation values.
The file holds the nine names the installer requires and no age recipient.
Credentials may use letters, digits and `/ + = _ . -` only: the file is read by
systemd, which treats quotes and backslashes specially.

### Differences from the runbook

- The runbook copies three whole directories with `git archive`. The role
  downloads only the files the loop, the installer and the units need
  (`backup_worker_release_files`), each checksum-pinned, and never copies a
  program into this repository.
- The runbook says the release is `origin/main` at run time. It names no commit,
  so the role pins the ghost-platform `origin/main` commit at the time of writing
  (see `backup_worker_source_sha`); bump it with the checksums.
- The role writes the environment file from inputs where the runbook reads each
  value from a prompt.
- The role does not run the installer to install, for the reason above.
- The role writes the CA from an input where the runbook copies it from the
  database host's container.
- The runbook's timer step enables the timer; the role never does so unless
  `backup_worker_timer_enabled` is true, and a false value leaves an enabled
  timer alone unless `backup_worker_timer_may_disable` is true.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/backup_worker
```

The scenario runs the role on one systemd container (the same Debian 13 image and
settings as `monitoring_stack`; the reason for each key is in `molecule.yml`). It
needs no network: `prepare.yml` writes a test-only `file://` copy of four
placeholder programs and stand-ins for `age`, `mysql` and `mysqldump`.

- `converge.yml` applies the role, then applies it again with one wrong checksum
  and requires that the role stops at the download, naming the checksum. It then
  enables the timer, applies the role with the defaults, requires the timer to
  stay enabled, and disables it again so the later steps see the off state.
- `verify.yml` first widens the environment file by hand to `nobody:nogroup`
  `0644` and applies the role again, so the checks after it read the restored file.
  It is a regression check on the end state, not a sabotage control: the end state
  is the same with or without the attribute task.
- `verify.yml` then checks: the environment file is a plain file, `root:root`, mode
  `0600`, and holds exactly the nine names with the supplied values; the tenants
  and recipients files are `root:backup-worker` `0640` and the recipients file is
  one `slug recipient` line per tenant; the timer is installed, disabled and
  inactive; every release file has its pinned `sha256`, root and `0644`; `current`
  is a link to a release directory named for a commit; the units and CA are in
  place; and the service account is a system account with no login shell.
- `idempotence`, `check-fresh`, `check-configured` and `molecule-check` are the
  harness's own steps.

### What breaks which step

One row per edit, with the harness run over this role and a restore afterwards.
The retrieval is the run itself.

| Edit to the role                                                                                       | Step that fails | Assertion that names it                                                                                                |
| ------------------------------------------------------------------------------------------------------ | --------------- | ---------------------------------------------------------------------------------------------------------------------- |
| The environment file's mode `0600` changed to `0644` in `backup_worker_secret_files` (`vars/main.yml`) | `verify`        | "The environment file is missing, not a plain file, not root:root or not mode 0600."                                   |
| The `backup_worker_timer_may_disable` gate removed from the timer task                                 | `converge`      | "The default apply changed a timer that was enabled; the timer task must be gated on backup_worker_timer_may_disable." |

The order of the environment-file tasks is not in this table, because the harness
cannot see it. `tests/unit/test_backup_worker.py` fails when the attribute task is
removed, moved after the write, or given a literal owner, group or mode. Run it by
hand until ws#2522 wires it into CI, from the repository root:

```text
python3 -B -m unittest discover -b -s ansible/roles/backup_worker/tests/unit -p "test_*.py"
```

Reviewed or asserted, but not shown to fail by a sabotage run: the tenants and
recipients file modes, the timer being disabled in `verify`, the release-file
checksum assertion in `verify`, the wrong-checksum control in `converge`, the
service account assertion and the input checks at the top of `tasks/main.yml`.

### Named limits

- **The real programs are not run.** The test installs placeholder files in
  place of the ghost-platform programs and units (the `backup_restore` scenario
  reuses the same placeholders and the same test variables). It proves the download, the
  pin, the owner and the mode, not that the worker works. The first live apply is
  the proof (ANS-17).
- **The real pins are not downloaded by the test.** The defaults'
  `backup_worker_release_files` checksums were computed from the files at the
  pinned commit with `git show <commit>:<path> | shasum -a 256`; no test fetches
  them from `raw.githubusercontent.com`.
- **The timer-on path is not tested.** It needs the real installer's `--check`;
  the test has a placeholder. The default (off) and the default leaving an enabled
  timer alone are exercised; a true `backup_worker_timer_enabled` is not.
- **The prerequisite installer is not run.** The test provides stand-ins for the
  tools, so the probe finds them and the installer step is skipped.
- **A silent skip passes.** The download, unit and timer tasks are skipped in
  check mode on a host with no release directory yet, and the converge skips its
  wrong-checksum control in check mode, because nothing is written there; the
  harness does not catch a silent skip, and this is the review of it (ANS-10).
- **The window before the attributes are set** is not observable by Molecule. The
  template writes the value on every run and sets the attributes after it, so a
  widened file ends `root:root` `0600` with or without the attribute task. The
  order is proven by the unit test, which reads the task text and so cannot see a
  task that exists and does nothing (`when: false`, a wrong variable). The mode of
  the temporary file and the atomic move are Ansible's, not the test's.
- **The correction happens on each run, not continuously.** A file widened between
  two runs stays wide until the next one.
- **A release directory is never removed.** Old releases stay.
- CI runs this scenario: the Ansible workflow runs the harness over every
  directory under `ansible/roles/`.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after
the approval of its protected environment. The plan job shows the host's diff in
check mode first. Nothing is applied from a laptop. This role is not applied to
any host yet.

## How to change it safely

1. To change the release, change `backup_worker_source_sha` and every checksum in
   `backup_worker_release_files` together, using the command in the limits above.
   Change the same values in `meta/argument_specs.yml` as well as in
   `defaults/main.yml`: the spec repeats the pinned commit and the URL. A checksum
   that does not match fails the download.
2. Keep every task able to run under `--check --diff`, keep the modes explicit,
   and keep `no_log: true` and `diff: false` on any task that touches a value.
3. A private value never becomes a default.
4. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
5. Run the test command above before opening a pull request, then break the
   control you touched and see the step fail.
