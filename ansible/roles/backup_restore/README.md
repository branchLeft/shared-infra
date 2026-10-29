# backup_restore

This role installs the units of the nightly state copy and the weekly restore
drill on the control host, and writes the two environment files the installers
for them expect. It ports Part 4 of the state-bucket copy runbook
(ghost-platform-docs, `state-bucket-copy-runbook.md`) without its last step, and
the unit and environment parts of the two installers
(`install_state_copy.py`, `install_restore_drill.py` in
`branchLeft/ghost-platform`, commit `5e52f78`). Both timers stay off unless a
variable turns the state-copy one on, and the restore-drill timer cannot be
turned on at all yet.

This README is written for a maintainer who is new to the repository. It
follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role is applied **after `backup_worker`, in the same play**. It downloads
nothing: `backup_worker` stages every program and unit at a pinned commit and
points `current` at the release, and this role reads that release.

1. **Checks the release.** `current` must be a link to the pinned release, and
   every file the two installers list as required, plus the two installers and
   `nextcloud_backup.py`, must be in it. A missing file stops the role before it
   changes anything. (Runbook Part 4's "check the link".)
2. **Installs four units** from the release into `/etc/systemd/system`:
   `branchleft-state-copy.service` and `.timer`, `branchleft-restore-drill.service`
   and `.timer`, then reloads systemd.
3. **Creates `/etc/branchleft/secrets`**, root only, mode `0700`. The owner places
   each secret access key there, once.
4. **Reads the secret files that are placed** and writes the environment files
   from them and from named inputs: `/etc/branchleft/state-copy.env` (16 names)
   and, when `backup_restore_drill_env_enabled` is true,
   `/etc/branchleft/restore-drill.env` (9 names). Both are `root:root` `0600`.
5. **Holds the state-copy timer to a variable.** `backup_restore_state_copy_timer_enabled`
   (default `false`). True runs the installer's read-only `--check`, and enables
   and starts the timer only when it reports every input in place. False leaves
   the timer as it is on the host, unless `backup_restore_state_copy_timer_may_disable`
   is true; then it stops and disables it.
6. **Refuses the restore-drill timer.** `backup_restore_drill_timer_enabled: true`
   fails the role with a message. The drill reads each tenant's private age
   identity, and no identity is placed on this host: how one would be kept is an
   open owner decision. The only thing the role does to the drill timer is stop
   and disable it when `backup_restore_drill_timer_may_disable` is true.

It does not run the installers to install: they enable the timer themselves once
their inputs are present, which would bypass the variable. The one time it runs
one is `install_state_copy.py --check`, which changes nothing, when the
state-copy timer is asked for. It does not create a secret, an age keypair, a
bucket or a key, take the first copy, prove the alert, run a drill, or touch a
Pulumi state backend.

### Where Nextcloud comes in

Nextcloud backup section 1 (staging `nextcloud_backup.py` on the host) is done by
`backup_worker`, which pins and downloads the program with the rest of the
release; this role checks that it is there. Sections 2, 4 and 5 and the
off-site copy are not in this role (see "Not in this role").

### Owner steps the role does not do

| Step                                                                              | Why the role does not                                                                              |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Place each secret file (below), root-only, once                                   | A secret's source is the owner's (PRIN-6). The role reads the file and never writes it.            |
| State-copy runbook Part 5: the first copy by hand, and the check of its output    | An owner decision after the timer is staged. Owner-run, not retired by this role.                  |
| State-copy runbook Part 6: prove the alert by stopping and starting the unit      | Starts and stops production units to see an alert fire. Owner-run, not retired by this role.       |
| Turn the state-copy timer on, by setting the variable, after Part 5 has been seen | Starts a nightly copy of production state: a production apply through the gated workflow (ANS-17). |
| Everything about the restore drill's private identities                           | Open owner decision; the drill timer is refused until then.                                        |

### Not in this role

- **Nextcloud sections 2, 4 and 5 and the off-site copy.** A live dump and a restore
  on a small host, sealing, and the copy off the host. Their designs are not
  settled; they are filed separately.
- **The ops1 binding.** Which host applies the role, and the inventory entry that
  carries the private inputs, are filed separately. The role is applied to no
  host yet.
- **Where the estate and tenant bucket values come from.** They are inventory
  inputs; sourcing them from the infrastructure code's output is filed separately.
- **The restore-drill timer.** Refused, as above.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable and
[`defaults/main.yml`](defaults/main.yml) holds the public ones.

**What it reads from `backup_worker`, and does not redeclare.** In a play's
`roles:` list the variables of an earlier role are visible to the later ones;
in a task list, `include_role` with `public: true` exports them. Run without
`backup_worker` earlier in the play, the role refuses at once with a message
that names `backup_worker`.

| `backup_worker` variable                                                                  | Used for                                                                                      |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `backup_worker_bucket`, `_s3_endpoint`, `_s3_region`                                      | The state copy's destination (backup copy 1) and the drill's primary copy: one home, not two. |
| `backup_worker_current_link`, `_release_dir`, `_unit_dir`                                 | Where the release is, and where the units go.                                                 |
| `backup_worker_host_pattern`, `_bucket_pattern`, `_region_pattern`, `_credential_pattern` | The same shapes of value, held to the same patterns.                                          |

**Private values are required inputs with no default** (this repository is
public): the state-copy recipient (a public age key), the estate and tenant
buckets, endpoints, regions and key ids, and the destination's key id. They come
from the private inventory. The tests use documentation values only
(`example.invalid`). Each key id takes letters, digits and `/ + = _ . -` only,
because systemd reads the environment file.

**Secret access keys are never variables.** Each is a root-only file the owner
places once. The default paths, all directly in `/etc/branchleft/secrets`:

| Secret                                  | Variable                                       | Default file                                                      |
| --------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------- |
| Copy 1's put-only key (the destination) | `backup_restore_state_copy_dest_secret_file`   | `/etc/branchleft/secrets/state-copy-dest-secret-access-key`       |
| The estate state bucket's read-only key | `backup_restore_state_copy_estate_secret_file` | `/etc/branchleft/secrets/state-copy-estate-secret-access-key`     |
| The tenant state bucket's read-only key | `backup_restore_state_copy_tenant_secret_file` | `/etc/branchleft/secrets/state-copy-tenant-secret-access-key`     |
| The drill's read key (only if enabled)  | `backup_restore_drill_secret_file`             | `/etc/branchleft/secrets/restore-drill-primary-secret-access-key` |

The file must be a plain file (not a link), `root:root`, mode `0600`, holding one
credential on one line (letters, digits and `/ + = _ . -`, with at most one final
line break) and nothing else. A path outside the directory, or with a second
path segment, is refused. The estate and tenant files may be the same file when
one read-only key serves both.

**A secret file that is not placed yet** skips the environment file that needs it
and says which file is missing, and the run carries on. It does not fail: the
owner places the files after the first apply, and a failing pull would hold every
other change to the host until then. This is the same under `--check`, which
reads the files and writes nothing. A timer that needs the environment is
refused while its file is missing, and the message names the file. An
environment file already on the host is left as it is.

**A private age identity is refused everywhere.** The marker `AGE-SECRET-KEY-1`
in a secret file, or anywhere in the text of an environment file the role was
about to write, stops the role before anything is written.

`vars/main.yml` holds the constants: the two environment file paths, the secrets
directory, the unit names, the installers' lists, and the patterns. A caller
cannot override them.

### The restore drill is opt-in

`backup_restore_drill_env_enabled` defaults to `false`. With it false the role
writes no drill environment and needs none of the drill inputs (the drill's key
id, its secret file and four image digests), so the first apply does not wait on
a credential or on digests that would be stale on arrival. With it true, those
inputs are required and checked, and the image names must be pinned by digest. The
drill's timer stays refused either way.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 and systemd, with `backup_worker` applied
  earlier in the same play. The role runs as root.

## What it changes on a host

- The four unit files in `/etc/systemd/system`, `root:root` `0644`, and one systemd
  reload when any changed.
- `/etc/branchleft/secrets`, `root:root` `0700`. The role never creates a file in it.
- `/etc/branchleft/state-copy.env` and, when switched on, `/etc/branchleft/restore-drill.env`,
  each `root:root` `0600`, created empty first and then written, so no moment
  exists in which a value is in a wider file.
- The state-copy timer's enabled and active state, and the drill timer's only
  when its `may_disable` is true.

The tasks that handle a value say `no_log: true`, and the ones that write a file
say `diff: false`. The include in the test carries no `no_log`, so the role's own
tasks must keep values out of the log. The facts that hold a secret are emptied
at the end, after a failure too.

## Differences from the runbook

- The runbook writes `state-copy.env` from values read at a prompt. The role
  writes it from named inputs and from the secret files.
- The runbook ends Part 4 by running `install_state_copy.py`, which enables the
  timer. The role runs only `--check`, and enables the timer when the variable
  says so.
- The role takes the destination's bucket, endpoint and region from
  `backup_worker`: copy 1 is the same place the nightly dumps go.
- A first apply that has no secret file placed yet carries on, where the runbook
  stops at an empty prompt.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/backup_restore
.venv/bin/python ansible/harness/run_harness.py ansible/roles/backup_worker
```

The scenario runs both roles on one systemd container, as a play's `roles:` list
does, and needs no network: `backup_worker`'s scenario writes a `file://` copy of
placeholder programs, which this scenario reuses, and stand-ins for `age` and the
database tools.

- `converge.yml` applies `backup_worker`, then this role.
- `verify.yml` checks, in this order: the role refuses to run alone; each
  environment file is a plain file, `root:root`, mode `0600`, holding exactly the
  names its installer requires with the supplied values; the four units are
  `root:root` `0644` and equal to the release files; the secrets directory is
  `root:root` `0700`; both timers are installed and off. Then the cases below,
  then a captured run searched for every secret, then the match with the
  installers.
- `idempotence`, `check-fresh`, `check-configured` and `molecule-check` are the
  harness's own steps. A second run reporting no change is the second-run check.

### What breaks which step

One row per edit, with the scenario run and a restore afterwards. The assertion
named is the one that goes red.

| Edit to the role                                                      | Step that fails | Assertion that names it                                                                                       |
| --------------------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------- |
| `backup_restore_state_copy_timer_enabled` default changed to `true`   | `verify`        | "The state-copy timer is not off after a default apply; its default must be false."                           |
| The `may_disable` gate removed from the state-copy timer task         | `verify`        | "The default apply stopped a state-copy timer that was on; the timer task must be gated on ..."               |
| The `may_disable` gate removed from the drill timer task              | `verify`        | "The default apply stopped a restore-drill timer that was on; the task must be gated on ..."                  |
| The task that holds the drill timer off deleted                       | `verify`        | "The restore-drill timer is still on after an apply with may_disable true."                                   |
| The assert that refuses the drill timer deleted                       | `verify`        | "ACCEPTED: the role did not refuse the case drill timer asked for."                                           |
| The installer's `--check` task and its assert deleted                 | `verify`        | "ACCEPTED: ... state-copy timer asked for while the installer reports a missing input."                       |
| `no_log` removed from the task that assembles an environment          | `verify`        | "A secret reached the output of a run, in plain text or as the base64 slurp returns it. A no_log is missing." |
| `no_log` removed from the task that reads a secret file               | `verify`        | the same assertion                                                                                            |
| The private-identity assert on a secret file deleted                  | `verify`        | "Case secret file holds a private identity: the role did not refuse with the expected text ..."               |
| The private-identity assert on the assembled environment deleted      | `verify`        | "ACCEPTED: ... key id is a private identity."                                                                 |
| A pattern assert on an input deleted                                  | `verify`        | "ACCEPTED: ... estate bucket not a bucket name."                                                              |
| The three-buckets assert deleted                                      | `verify`        | "ACCEPTED: ... estate bucket is the destination."                                                             |
| The destination's bucket derived from the wrong variable              | `verify`        | "these names have a wrong or an extra value: STATE_COPY_DEST_BUCKET"                                          |
| The secret file's mode check deleted                                  | `verify`        | "ACCEPTED: ... secret file is open to the group."                                                             |
| The release-file stat assert deleted                                  | `verify`        | "ACCEPTED: ... a file an installer requires is not in the release."                                           |
| The missing-secret gate removed from the state-copy environment write | `verify`        | the role fails reading a file that is not there, in the case of a secret file that is not placed              |
| A pin in `backup_worker_release_files` changed                        | `verify`        | "The pin for ... in backup_worker_release_files is missing or is not the sha256 recorded ..."                 |
| A name in `backup_restore_state_copy_env_names` changed               | `verify`        | "The role's environment names differ from the names the installers and the drill require."                    |

Reviewed or asserted, but not shown to fail by a sabotage run: the unit
checksums in `verify`, the secrets directory mode, and the second-run check
(the harness's own step).

### Named limits

- **The real programs and installers are not run.** The test installs
  placeholders. It proves the checks, the files and the timers' states, not that
  the state copy or the drill works. The first live apply is the proof (ANS-17).
- **The recorded copy of the installers is a second copy, not the installers.**
  `molecule/default/files/installer_contract.yml` holds the lists and sha256 the
  installers had at the pinned commit; the scenario holds the role to it, and
  cannot see an installer that changed after that commit. Bumping the commit
  means reading the installers again and changing the record, the role's lists
  and the pins together.
- **The pins are not downloaded by the test.** `backup_worker`'s
  `backup_worker_release_files` checksums were computed from the files at the
  pinned commit with `git show <commit>:<path> | shasum -a 256`.
- **Check mode on a host `backup_worker` has never touched** stages nothing, so
  the checks and tasks that need the release are skipped there (`check-fresh`).
  The harness does not catch a silent skip, and this is the review of it (ANS-10).
  A real apply, and `check-configured`, do run them.
- **The restore-drill timer-on path does not exist**, so there is nothing to test.
- **The secret files are checked once, then read.** A plain file that is not a link,
  in a root-only directory, so only root could swap it between the check and the read.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after
the approval of its protected environment. The plan job shows the host's diff in
check mode first. Nothing is applied from a laptop. `ansible/playbooks/ops1.yml`
applies this role after `host_inputs`, which sets its inputs from the owner's
root-only file on the host (`roles/host_inputs/README.md`).

## How to change it safely

1. To change the release, change `backup_worker_source_sha` and every checksum in
   `backup_worker_release_files` together (`backup_worker`'s README says how),
   then read the installers at the new commit again and change
   `files/installer_contract.yml` and `vars/main.yml` to match. The scenario fails
   until they agree.
2. Keep every task able to run under `--check --diff`, keep the modes explicit,
   and keep `no_log: true` and `diff: false` on any task that touches a value.
3. A private value never becomes a default, and a secret never becomes a variable.
4. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
5. Run the test command above before opening a pull request, then break the
   control you touched and see the step fail.
