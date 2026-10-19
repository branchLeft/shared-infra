# program_and_timer

This role is a pattern. It is the recipe a maintainer follows when a shell script
runs an existing program on a timer: the program is written and tested elsewhere,
the role installs it with its owner and mode, runs the program's own install-time
check before the program replaces the installed one, enables the timer, and
restarts the timer once when the program changes. It configures one placeholder
program with placeholder names. Copy the shape, not the names.

## What it does, and what it does not

It delivers one program file unchanged, checks it, and delivers a oneshot service
and a timer that run it. It makes systemd load the units, then enables and starts
the timer. It restarts the timer once when the program file changes, and nothing
else.

It does not write the program, edit its text, or template it. It does not install a
package or a binary the program needs, create a user or a group, open a port, touch
a firewall, or apply itself to a host. The user and group that own the program must
exist before it runs. It does not supply the unit files of `files_and_units`: its
timer and oneshot service are its own copies of that recipe, with the program as
their `ExecStart`.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. None of them is a
secret. This role takes no credentials, so the `no_log` and `diff: false` rules do
not apply to it (see the named limits). The owner and group of the program are
variables so a service role can give the program to its service user; the units stay
`root:root`.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version`
  in `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin`. The test uses `community.docker`, pinned
  in `ansible/requirements.yml`.
- Target: a systemd host with `/bin/sh` and `python3`. The validator is the program
  itself, run by `/bin/sh` with `--check`.

## What it changes on a host

- The directory `/usr/local/lib/program_and_timer`, owner and group from
  `program_and_timer_program_owner` and `program_and_timer_program_group`, mode `0755`.
- The program at `program_and_timer_program_path`, the same owner and group, mode
  `0755`, byte for byte the source file.
- The event directory `/var/lib/program_and_timer/events`, `root:root`, mode `0755`.
  The handlers write one empty file there per restart and per daemon reload.
- `/etc/systemd/system/program_and_timer_tick.service`, mode `0644`, a oneshot that
  runs the program.
- `/etc/systemd/system/program_and_timer_tick.timer`, mode `0644`, which starts the
  oneshot. Enabled and started.
- One `daemon-reload` of the systemd manager, only when a unit file changed.
- One restart of the timer, only when the program file changed.
- No port, no user, no firewall rule.

## The recipe

### (a) The bash shape it replaces

```bash
install -o EXAMPLE_USER -g EXAMPLE_GROUP -m 0755 program.sh /usr/local/lib/EXAMPLE/program.sh
install -o root -g root -m 0644 example.service /etc/systemd/system/EXAMPLE_tick.service
install -o root -g root -m 0644 example.timer /etc/systemd/system/EXAMPLE_tick.timer
systemctl daemon-reload
systemctl enable --now EXAMPLE_tick.timer
systemctl restart EXAMPLE_tick.timer
```

That script restarts the timer on every run, whether or not the program changed,
installs the program before anything checks it, and reports nothing about what
changed. The reader must simulate it to learn the end state.

### (b) The Ansible shape

```yaml
- name: Install the program after its own check passes
  ansible.builtin.copy:
    src: '{{ program_and_timer_program_src }}'
    dest: '{{ program_and_timer_program_path }}'
    owner: '{{ program_and_timer_program_owner }}'
    group: '{{ program_and_timer_program_group }}'
    mode: '0755'
    validate: /bin/sh %s --check
  notify: Restart the program timer

- name: Load queued unit changes and restart the timer before it is enabled
  ansible.builtin.meta: flush_handlers

- name: Enable and start the timer
  ansible.builtin.systemd_service:
    name: program_and_timer_tick.timer
    enabled: true
    state: started
  when: program_and_timer_timer_unit.stat.exists
```

The program task notifies the topic `program changed`. Two handlers listen to that
topic: `Restart the program timer`, a `systemd_service` task with `state: restarted`,
and `Record the program timer restart`, which writes the counter file the test reads.
Ansible runs a handler once per play however many tasks notified its topic, and only
when one of them changed. A handler's name cannot be notified twice in one play, so
the topic is what lets one action and its record run together.

### (c) Why each parameter is set

- `owner`, `group`, `mode` are explicit. A copy without them takes the process's umask
  and the invoking user, so the end state depends on who ran it. The program's owner
  is a variable so the test can tell the parameter from the default (see the limits).
- `validate: /bin/sh %s --check` runs the program's own check on the temporary copy,
  before the file replaces the installed one. A program whose check fails is never
  installed: the task fails with the validator's message, and the previous program
  stays in place. `%s` is the temporary path. The check is the program's own
  `--check` argument; a program that has none fails its check, so a program must
  support one to be installed by this role.
- `copy` reports a change only when the content or the metadata differs. The
  idempotence step is what checks that claim for this role.
- `notify` on the program task, not an unconditional restart task. An unconditional
  restart reports a change on every run and fails ANS-11, and it restarts a timer whose
  program did not change.
- `meta: flush_handlers` before the enable. The restart and the daemon reload run at
  that point, so the enable starts the timer with the unit file as it now is on disk.
- The handler order in `handlers/main.yml`: the daemon reload first, then the restart.
  Handlers run in the order written, so a restart that follows a reload sees the new
  unit.
- The restart handler and its record are skipped in check mode only. Check mode writes
  no unit file, so a restart of a timer that no file defines would fail on a fresh
  host. This skip is stated here (ANS-10). Its record is skipped for the same reason.
- `systemd_service` (not `command` with `systemctl`) reports the unit's real state, so
  the module knows when a change has happened (ANS-9).
- The records are one empty file per restart and per reload, named by a microsecond
  timestamp, so a play counts them with `find` and no state is kept in the role. They
  are an audit trail of what the role did, and they are the counters the test reads.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/program_and_timer
```

The harness lints the role and runs the scenario in `molecule/default/` on one
container, and exits non-zero if any step fails. It removes its container when it
finishes.

What each part of the scenario does:

- `prepare.yml` creates the placeholder user and group that own the program. Their
  names are inventory variables in `molecule.yml`, so the role, the converge and the
  verify read one value.
- `check-fresh`: the converge in check mode against an instance on which nothing is
  installed. It completes. The restart and its record are skipped, and the enable is
  skipped, for the reasons in (c).
- `converge`: on an instance with no program it first applies the role with the
  placeholder program. It then replaces the program with the second version, having
  cleared the event records first, so the counters read only what that one edit did.
  Last, it applies the role with a program whose check fails, inside a block, and
  asserts the validator refused it.
- `idempotence`: a second converge reports zero changed tasks. The program is already
  the second version, so the edit is skipped, and the refused program is refused
  again without a change.
- `verify`: the program is the source file's bytes (sha256), with its owner, group and
  mode. The records show exactly one restart and no daemon reload from the edit. The
  unit files have their owner, group and mode. The timer is `enabled` and `active`
  with the rendered description.
- `check-configured` and `molecule-check`: the configured instance shows no drift.

What breaks which step. Each row was done by an edit, one harness run, and a restore;
the results are in the table after the limits.

### Named limits

- **The program's `owner` and `group` are tested with non-root values.** The test
  runs the program as the placeholder user, so the owner assertion can tell the
  parameter from the default. In production the program's owner should be `root`:
  a program run by root that a service user can write is a way for that user to run
  commands as root. The variable exists for a service that needs its own user, and the
  role does not decide that for the caller.
- **Reviewed, not tested.** The `owner: root` and `group: root` on the two unit files.
  The test runs as root, so omitting them gives the same result, and a unit must not be
  owned by anyone else, so there is no value that would tell the two apart.
- **The check runs at apply, not in check mode.** A check-mode run does not run
  `validate`, so a plan shows the program as a change. The refusal shows at apply.
- **The program's own check is what the role runs.** The role does not check the
  program's behaviour. A program whose `--check` passes and which then fails when the
  timer runs it is not caught here.
- **The restart is for the timer.** The oneshot service the timer starts is not
  restarted by a program change, because it is not running between runs.
- **No credentials.** The placeholder program takes no credentials file, so the rule
  that a secret is delivered with `no_log: true` and `diff: false`, and a log scan that
  proves it, is not exercised here. A service role whose program takes a credentials
  file must add that delivery and its own proof.
- **The event records are a side effect of the role.** They are written on every
  restart and reload to the event directory, and they grow with each change. A
  maintainer who prunes that directory loses the record, not the program.
- **The validator is `/bin/sh --check`, which is the program's own check.** It runs the
  temporary copy as a shell script. A program in another language needs its own
  validator, and the role does not pick one.
- The test proves the files' content and the systemd state on one container. It does
  not prove that the placeholder program does useful work, or that the timer fires at
  its calendar time.
- The owner, group and mode are checked on the files this role writes. A file another
  role writes is not covered.
- `check-fresh` skips the restart, its record and the enable (see (c)), and the harness
  does not catch a silent skip. This section is the review of it.
- **CI does not run this scenario today.** The Ansible workflow runs the harness over
  `ansible/roles` only. Until it lists `ansible/patterns`, a change here is proven by
  the local run above.
- The platform settings in `molecule.yml` are the sibling pattern's, with the same
  reasons. They were run here on Docker Desktop only. They are not measured on a
  GitHub runner for this pattern.
- The runner image `ubuntu-latest` moves to Ubuntu 26.04 in a rollout from 19 October 2026. This pattern has not been run on Ubuntu 26.04, so that move is unproven for it.
- The base image is Debian 13 with Python 3.13 and an `EXTERNALLY-MANAGED` marker that
  its Dockerfile tries to remove at a 3.11 path, so the marker stays and its unpinned
  `ansible` and `cryptography` installs rely on `--break-system-packages`. This is a
  fact of the image, not of this role.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. A plan job shows each host's diff in check
mode first; after the approval the host pulls that exact commit of `main` and applies
it, and a second run must report zero changes. Nothing is applied from a laptop. This
pattern is not applied to any host: it exists to be copied, and the trigger and the
reusable workflow are separate work.

## How a service role copies it

1. Make the new role from the skeleton, as `ansible/README.md` says, under
   `ansible/roles/`.
2. Copy `tasks/main.yml`, `handlers/main.yml`, `templates/` and the whole of
   `molecule/default/` over the new role's files, and the program file into the new
   role's `files/` directory. Keep `namespace` in `meta/main.yml`: Molecule links the
   role under it.
3. Rename. The variable prefix `program_and_timer_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, the tasks, the handlers, the
   templates and the group variables in `molecule.yml`. The unit names
   `program_and_timer_tick.service` and `program_and_timer_tick.timer` become the
   service's. The role name in `converge.yml` (`branchleft.program_and_timer`) becomes
   `branchleft.` and the new name. The same paths appear in `verify.yml` and
   `converge.yml`.
4. Replace the placeholders: the program's content (it must support `--check`), its
   `ExecStart` path, the calendar, and the ALL_CAPS values in `meta/`.
5. Keep the install-time check. A program in a language other than `/bin/sh` needs its
   own validator in `validate:`, and the scenario's second and bad programs must be
   written in that language.
6. Set the program's user and group in the scenario's group variables to placeholders
   for the real service's, and keep them non-root unless the program must be root-owned
   and the README says so.
7. Run the harness on the new role. Then break each control in the table below on the
   copy and see the same step fail: a control is yours only after you have broken it.
8. Do not give the scenario more privilege than this one, and reuse the image pin
   below rather than choosing another base.

## The systemd test base image (a third-party image, trusted by digest)

This scenario uses the same third-party systemd base as `files_and_units`, chosen by
the orchestrator's ruling and recorded there as the decision the owner reviews. Its
image, source, Dockerfile, trixie differences and the table of settings that let
systemd run are in
[`ansible/patterns/files_and_units/README.md`](../files_and_units/README.md) under
"The systemd test base image". The reference is
`geerlingguy/docker-debian13-ansible:latest@sha256:979c0d5e12b0035fff1c46bd4dfd00d67cd82fa48035194f14f32e01c8c02372`
in `molecule/default/molecule.yml`, and the platform block is copied from that
scenario with each key's reason kept beside it.

## How to change it safely

Change the tasks, the handlers, the templates and the converge and verify plays
together, run the harness, and break the control you touched (the table below) to see
it fail. A change to the digest is its own change, reviewed on its own. An edit to a
default value is a change of behaviour on every host that uses the role, not a rename.
Removing the `notify`, the flush, the validator, the mode or the enable removes a
control the table shows.
