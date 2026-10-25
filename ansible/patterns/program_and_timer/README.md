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
the timer. It restarts the timer once when the program file changes, and does nothing
else to systemd: the test shows that no other unit is touched and that the manager is
not reloaded for a program change (see "What the test counts").

It does not write the program, edit its text, or template it. It does not install a
package or a binary the program needs, create a user or a group, open a port, touch
a firewall, or apply itself to a host. The user and group that own the program must
exist before it runs. It does not supply the unit files of `files_and_units`: its
timer and oneshot service are its own copies of that recipe, with the program as
their `ExecStart`.

It refuses, before any task changes anything, an input it cannot use safely: see
"The rules the role enforces on its inputs".

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. None of them is a
secret. This role takes no credentials, so the `no_log` and `diff: false` rules do
not apply to it (see the named limits).

| Variable                             | Meaning                                                                       |
| ------------------------------------ | ----------------------------------------------------------------------------- |
| `program_and_timer_program_src`      | The program's source: a name under `files/`, or an absolute path (not empty). |
| `program_and_timer_program_dir`      | The dedicated directory the role creates and takes over for the program.      |
| `program_and_timer_program_name`     | The program's file name inside that directory.                                |
| `program_and_timer_service_user`     | The user that owns the program and runs it. Empty means root.                 |
| `program_and_timer_service_group`    | The group of the program and of the run. Declared with the user, or empty.    |
| `program_and_timer_unit_description` | The description written into both units.                                      |
| `program_and_timer_tick_calendar`    | The timer's `OnCalendar` value.                                               |

`vars/main.yml` holds internal values (the installed path, the input patterns and
the list of directories the role refuses). Role variables outrank a caller's, so a
caller cannot change them; they are not part of the interface.

## The rules the role enforces on its inputs

The role runs these assertions first. Each message names the rule and never
echoes the value it refused.

- **types**: every option is a string. The argument spec coerces a wrong type
  (a list passes a `str` check and the role still receives the list), so the role
  rejects it itself.
- **source**: the program source is not empty.
- **directory shape**: the program directory is an absolute path of plain
  characters, with no `.` or `..` component, no empty component and no trailing
  slash. The patterns end in `\Z`, not `$`, which would also pass one trailing
  line break.
- **dedicated directory**: the program directory is at least two components deep
  and is not one of the system directories in `vars/main.yml` (at least `/bin`,
  `/sbin`, `/usr`, `/usr/bin`, `/usr/sbin`, `/usr/local`, `/usr/local/bin`,
  `/usr/local/sbin`, `/etc`, `/lib`, `/var`, `/var/lib`, `/opt`). This list is a
  first screen only; the three host checks below do the real work.
- **real path**: `realpath -m` of the program directory equals the program
  directory, so no component of the path is a symbolic link and taking the
  directory over cannot reach another one.
- **foreign content**: if the path exists it is a directory (not a file, not a
  link) holding nothing but the program file. A directory with any other file,
  hidden files and sub-directories included, is not dedicated to this program.
  The message never lists what it found.
- **foreign owner**: if the directory exists, its owner is root or the declared
  service user, and its group is root or the declared group. A directory owned by
  anyone else is not the role's to take over.
- **program name**: the program name is one file name, with no path separator.
- **service identity**: the service user and the service group are declared
  together, each a plain name, or both left empty.

The role therefore changes the owner, group and mode of a directory only when it
creates it in that run (a missing parent of it is created with the same owner; a
parent that exists is not touched), or when it found it empty or holding only the
program, with no link in its path, owned by root or by the declared user and
group. What the checks cannot know: a directory that is empty, or holds only a
file of the same name, and belongs to another service. That directory looks
exactly like a new one, so the rule for a consumer is that the program directory
is used for this program and nothing else.

The owner rule behind the last one: the program is owned by root and the unit
runs as root, unless a service user is declared. When one is, the program, its
directory and the unit's `User=` and `Group=` are all that user and group. A
program a service user can write must never run as root, because that is a way for
that user to run commands as root; declaring the user in one place keeps the file
owner and the unit's user the same by construction.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version`
  in `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin`. The test uses `community.docker`, pinned
  in `ansible/requirements.yml`.
- Target: a systemd host with `/bin/sh` and `python3`. The validator is the program
  itself, run by `/bin/sh` with `--check`.

## What it changes on a host

- The directory `program_and_timer_program_dir` (default
  `/usr/local/lib/program_and_timer`), owner and group from the service user and
  group (root without them), mode `0755`.
- The program inside it, the same owner and group, mode `0755`, byte for byte the
  source file.
- `/etc/systemd/system/program_and_timer_tick.service`, mode `0644`, a oneshot that
  runs the program, as the service user when one is declared.
- `/etc/systemd/system/program_and_timer_tick.timer`, mode `0644`, which starts the
  oneshot. Enabled and started.
- One `daemon-reload` of the systemd manager, only when a unit file changed.
- One restart of the timer, only when the program file changed.
- Nothing else: no state directory, no record files, no port, no user, no firewall
  rule.

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
    owner: '{{ program_and_timer_service_user | default("root", true) }}'
    group: '{{ program_and_timer_service_group | default("root", true) }}'
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

The program task notifies the handler `Restart the program timer`, a
`systemd_service` task with `state: restarted`. The unit tasks notify
`Reload systemd manager`. Ansible runs a handler once per play however many tasks
notified it, and only when one of them changed.

### (c) Why each parameter is set

- `owner`, `group`, `mode` are explicit. A copy without them takes the process's umask
  and the invoking user, so the end state depends on who ran it. The owner comes from
  the service user so the test can tell the parameter from the default (see the limits).
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
- `state: started` on the enable task. The restart handler runs only when the program
  changed, so on a host where the timer was stopped by hand and nothing changed, only
  this start brings it back.
- The restart handler is skipped in check mode only. Check mode writes no unit file,
  so a restart of a timer that no file defines would fail on a fresh host. This skip
  is stated here (ANS-10).
- `systemd_service` (not `command` with `systemctl`) reports the unit's real state, so
  the module knows when a change has happened (ANS-9).
- The program directory is the role's own, and the role refuses any other (see the
  rules above). The unit has no `User=` for root, and has the service user when one is
  declared, so the file's owner and the process's user never differ.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

```text
python3 -m venv .venv
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
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
  installed. It completes. The restart and the enable are skipped, for the reasons in
  (c).
- `converge`: on an instance with no program it first plants what some refused
  inputs point at (an empty directory owned by another user, a regular file, a link to
  a root-only directory), then applies the role with each refused input in
  `converge.yml` (a relative path, a `..` component, a trailing slash or any other
  trailing line break, `/`, a top-level directory, shared system directories and the
  unit directory, the system directory `/etc/apt` with files of its own, a path that is
  a file, the foreign-owned directory, the link and a directory under the link, a
  program name with a separator, an empty source, a list for the user, a user without a
  group) and asserts that each is refused with its rule's message, that the directory
  it named or pointed at kept its owner, group and mode, and that nothing was left
  behind.
  It then applies the role with the placeholder program and writes a mark to the
  journal. Next it reads the installed program, the files next to it and the timer
  from systemd, applies a program whose check fails inside a block, and asserts that
  the refusal left the old program's bytes, mode and owner, the directory's only file
  and the timer's state, invocation and start time unchanged, and that the validator
  gave the refusal. Last it applies the second version of the program. Every later
  converge applies the role with the second version and changes nothing; the steps
  above are skipped there.
- `idempotence`: a second converge reports zero changed tasks. It runs the whole role
  with the second version, so the restart, the reload and every unit task are inside
  the proof.
- `verify`: the program is the source file's bytes (sha256), with its owner, group and
  mode, in a directory with its owner, group and mode. systemd's own log, read from the
  journal mark onward, shows exactly one stop and one start of the timer and no manager
  reload, and no message about any other unit (see "What the test counts"). The unit
  files have their owner, group and mode. The timer is `enabled` and `active`, needs no
  daemon reload, has the rendered description and is the invocation systemd logged
  last. systemd reports that the oneshot runs as the service user. Then the timer is
  stopped by hand and the role is applied again with nothing changed: the timer must be
  active afterwards. Last, the root default: the role is applied with no service user
  into a second directory, and the program, the directory and the unit must be root's
  with no `User=`; then it is applied with the scenario's variables again, so the
  instance ends as it was converged.
- `check-configured` and `molecule-check`: the configured instance shows no drift.

### What the test counts

The restart and reload counts come from systemd, not from the role. The converge
writes one line to the journal (`systemd-cat`), after the first install and before
the program is changed. The verify play reads what systemd's own process (`_PID=1`)
logged after that line:

- a restart of the timer is the pair of job messages for `program_and_timer_tick.timer`
  with `MESSAGE_ID` `9d1aaa27d60140bd96365438aad20286` (unit stopped) and
  `39f53479d3a045ac8e11786248231fbf` (unit started); one restart is one of each;
- a daemon reload is the manager's `Reloading...` line;
- "nothing else" is every other message with a `UNIT` field in that window: there must
  be none for any unit but the timer. The scenario's calendar is a time that never
  comes (a single instant in the year 2099, set in `molecule.yml`), so the timer cannot start the oneshot service during a
  test run; a start of the service in the window is therefore not a timer-fired run but
  something the role (or the test) did, and it fails. Five units of the base image's own
  daily timers (named in `verify.yml`) are excluded, because one of them may legitimately
  run in the window. A message about a unit the base image does not run daily is a
  defect.

The identifiers and the line were read from the journal of the test image's systemd
257 (JSON output, fields `MESSAGE_ID`, `UNIT`, `JOB_TYPE`, `MESSAGE`); they are not
taken from the role. A control case checks that the reload line this systemd writes
is the one the test matches, by finding it in the journal of the first install, so a
systemd that worded it differently fails the control instead of a count of zero
passing for nothing. The mark is written by the test only; the role writes nothing
for the test to read.

### What breaks which step

Each row was one edit, one harness run on the pattern role, and a restore with
`git restore`. Each red step is an assertion, not a crash; the always-changed row is
Molecule's own idempotence check, which names the task.

| Edit to the role or the scenario                                                      | Step that fails                                                                                                                   |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| The restart handler's `state: restarted` changed to `started`                         | `verify`, "systemd logged 0 stops and 0 starts of the timer"                                                                      |
| A second restart handler on the same notification                                     | `verify`, "systemd logged 2 stops and 2 starts"                                                                                   |
| A second handler that reloads the manager on the same notification                    | `verify`, "1 manager reloads"                                                                                                     |
| `state: started` removed from the enable task                                         | `verify`, "The role left a stopped timer stopped"                                                                                 |
| A task that changes on every run (a copy of `now()`) notifies the restart             | `idempotence`, naming the marker task and the restart                                                                             |
| `notify` removed from the program copy                                                | `verify`, "systemd logged 0 stops and 0 starts of the timer"                                                                      |
| The program copied and checked afterwards (the old program overwritten first)         | `converge`, "A program whose check fails changed what was installed"                                                              |
| `validate: /bin/sh %s --check` removed                                                | `converge`, the same assertion: the bad program replaced the old one                                                              |
| The program delivered as other bytes (content from a lookup, a trailing newline lost) | `verify`, "The installed program differs from the source file"                                                                    |
| `enabled: true` changed to `false` for the timer                                      | `verify`, the timer's enabled assertion                                                                                           |
| `mode: '0755'` changed to `'0644'` on the program                                     | `verify`, "owner, group or mode differs ... 0644"                                                                                 |
| The directory task without `owner` and `group`                                        | `verify`, "The program directory owner, group or mode differs"                                                                    |
| `User=` and `Group=` removed from the service unit                                    | `verify`, "The unit does not run the program as the user and group that own it"                                                   |
| The types rule made always true                                                       | `converge`, "did not refuse the input with the rule rule: types"                                                                  |
| The source rule made always true                                                      | `converge`, the same with "rule: source"                                                                                          |
| The directory shape rule made always true                                             | `converge`, the same with "rule: directory shape" (the relative path)                                                             |
| Only the `..` component test of the shape rule removed                                | `converge`, the same with "rule: directory shape" (the `..` path)                                                                 |
| Both conditions of the dedicated-directory rule made always true                      | `converge`, "The role changed the owner, group or mode of a directory it must not touch"                                          |
| Only the list of system directories removed from that rule                            | `converge`, the same for `/usr/local/bin`                                                                                         |
| The program name rule made always true                                                | `converge`, the same with "rule: program name"                                                                                    |
| The service identity rule made always true                                            | `converge`, the same with "rule: service identity"                                                                                |
| `\Z` replaced by `$` in the directory pattern                                         | `converge`, the same with "rule: directory shape" (the trailing line break)                                                       |
| `\Z` replaced by `$` in the name pattern                                              | `converge`, the same with "rule: program name" (the trailing line break)                                                          |
| `\Z` replaced by `$` in the user and group pattern                                    | `converge`, the same with "rule: service identity" (the trailing line break)                                                      |
| The real-path rule made always true                                                   | `converge`, the same with "rule: real path" (the link case: the foreign-content rule also refuses a link, so the message differs) |
| The foreign-content rule's "only the program" condition made always true              | `converge`, "The role changed the owner, group or mode of a directory it must not touch" (`/etc/apt`)                             |
| The foreign-content rule's "is a directory" condition made always true                | `converge`, the same with "rule: foreign content" (the path that is a file)                                                       |
| The foreign-owner rule made always true                                               | `converge`, the owner-changed assertion for the directory owned by another user                                                   |
| An extra handler that restarts the oneshot service on a program change                | `verify`, "systemd logged messages about units other than the timer ... program_and_timer_tick.service"                           |
| The directory task's root default owner changed to another user                       | `verify`, "With no service user, the program, its directory or the unit is not root's"                                            |

### Named limits

- **Reviewed, not tested.** The `owner: root` and `group: root` on the two unit files.
  The test runs as root, so omitting them gives the same result, and a unit must not be
  owned by anyone else, so there is no value that would tell the two apart.
- **The service user is a placeholder in the test.** The scenario declares a non-root
  service user so the owner, group and `User=` assertions can tell the parameters from
  the defaults. The test does not run the program as that user; it asks systemd what the
  unit is configured to run as.
- **An empty directory of another service looks like a new one.** The role refuses a
  path with a link in it, an existing path that is not a directory holding only the
  program, and a directory owned by anyone but root or the declared user; it checks
  these on the host, so `/etc/apt` is refused although it is in no list. It cannot
  know that an empty directory, or one holding only a file of the same name as the
  program, belongs to another service. The rule for a consumer is that the program
  directory is used for this program and nothing else.
- **A second `molecule verify` on the same instance is not supported.** The verify
  play counts what systemd logged after the converge's mark, and its own last phases
  stop and start the timer and reload the manager, so a second run without a fresh
  converge counts those and fails (measured: three stops and three starts, two
  reloads). The harness runs `verify` once, after a converge.
- **The root default is applied by the verify play.** It runs in the same instance as
  the service-user scenario and is followed by a reapply of the scenario's variables;
  it uses a second directory, so the first directory is left in place.
- **The check runs at apply, not in check mode.** A check-mode run does not run
  `validate`, so a plan shows the program as a change. The refusal shows at apply.
- **The program's own check is what the role runs.** The role does not check the
  program's behaviour. A program whose `--check` passes and which then fails when the
  timer runs it is not caught here.
- **The restart is for the timer.** The oneshot service the timer starts is not
  restarted by a program change, because it is not running between runs.
- **No credentials, so the `no_log` control is not exercised.** The placeholder program
  takes no credentials file, so the rule that a secret is delivered with `no_log: true`
  and `diff: false`, and a log scan that proves it, has nothing to prove here. This is a
  limit of this pattern. A service role whose program takes a credentials file adds the
  delivery task with `no_log: true` and `diff: false` on it, and adds its own proof that
  the secret is absent from the run's output.
- **The validator is `/bin/sh --check`, which is the program's own check.** It runs the
  temporary copy as a shell script. A program in another language needs its own
  validator, and the role does not pick one.
- **The count depends on the journal.** The test reads systemd's log through
  `journalctl`, so the base image must run `systemd-journald` (the pinned image does).
  The message identifiers and the reload line are systemd 257's; the control case above
  catches a change in the reload line, and the exactly-one assertions on stops and
  starts fail if the job messages change.
- The test proves the files' content and the systemd state on one container. It does
  not prove that the placeholder program does useful work, or that the timer fires at
  its calendar time.
- The owner, group and mode are checked on the files this role writes. A file another
  role writes is not covered.
- `check-fresh` skips the restart and the enable (see (c)), and the harness does not
  catch a silent skip. This section is the review of it.
- **CI.** The Ansible workflow on `main` (`.github/workflows/ansible.yml`) runs the
  harness over every role under `ansible/roles` and every pattern under
  `ansible/patterns`, and pins its runner image. A change here is run by it.
- The platform settings in `molecule.yml` are the sibling pattern's, with the same
  reasons. This README does not claim a measurement of them beyond what the harness and
  that workflow run.
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
2. Copy `tasks/main.yml`, `handlers/main.yml`, `vars/main.yml`, `templates/` and the
   whole of `molecule/default/` over the new role's files, and the program file into
   the new role's `files/` directory. Keep `namespace` in `meta/main.yml`: Molecule
   links the role under it.
3. Rename. The variable prefix `program_and_timer_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, `vars/main.yml`, the tasks, the
   handlers, the templates and the group variables in `molecule.yml`. The unit names
   `program_and_timer_tick.service` and `program_and_timer_tick.timer` become the
   service's. The role name in `converge.yml` and `verify.yml`
   (`branchleft.program_and_timer`) becomes `branchleft.` and the new name. The same
   paths appear in `verify.yml`, `converge.yml` and `tasks/refusal_case.yml`.
4. Replace the placeholders: the program's content (it must support `--check`), the
   calendar, and the ALL_CAPS values in `meta/`. Choose the program directory: one made
   for this program, deep enough and not a system directory, or the role refuses it.
5. Keep the install-time check. A program in a language other than `/bin/sh` needs its
   own validator in `validate:`, and the scenario's second and bad programs must be
   written in that language.
6. Set the service user and group in the scenario's group variables to placeholders for
   the real service's, and keep them non-root unless the program must be root-owned. Do
   not set the file owner without the unit's `User=`: the role declares both together.
7. Run the harness on the new role. Then break each control in the table above on the
   copy and see the same step fail: a control is yours only after you have broken it.
8. Do not give the scenario more privilege than this one, and reuse the image pin
   below rather than choosing another base.

## The systemd test base image (a third-party image, trusted by digest)

This scenario uses the same third-party systemd base as `files_and_units`. Its image,
source, Dockerfile, trixie differences and the table of settings that let systemd run
are in
[`ansible/patterns/files_and_units/README.md`](../files_and_units/README.md) under
"The systemd test base image". The reference is
`geerlingguy/docker-debian13-ansible:latest@sha256:979c0d5e12b0035fff1c46bd4dfd00d67cd82fa48035194f14f32e01c8c02372`
in `molecule/default/molecule.yml`, and the platform block is copied from that
scenario with each key's reason kept beside it.

## How to change it safely

Change the tasks, the handlers, the templates and the converge and verify plays
together, run the harness, and break the control you touched (the table above) to see
it fail. A change to the digest is its own change, reviewed on its own. An edit to a
default value is a change of behaviour on every host that uses the role, not a rename.
Removing the `notify`, the flush, the validator, the mode, the enable, the `User=`
line or a rule of the input checks removes a control the table shows.
