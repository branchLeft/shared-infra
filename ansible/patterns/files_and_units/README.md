# files_and_units

This role is a pattern. It is the recipe a maintainer follows when a shell script
installs a file, installs systemd units, and enables a service and a timer. It
configures one example service with placeholder names, and no real service.
Copy the shape, not the names.

## Terms and clauses

The clauses are rules in the standards repository, on its
[Ansible stack page](https://github.com/branchLeft/standards/blob/main/docs/stacks/ansible.md)
and its [containers page](https://github.com/branchLeft/standards/blob/main/docs/containers.md).
This page cites these:

- [ANS-9](https://github.com/branchLeft/standards/blob/main/docs/stacks/ansible.md#ans-9--a-module-before-a-command): a module before a command.
- [ANS-10](https://github.com/branchLeft/standards/blob/main/docs/stacks/ansible.md#ans-10--every-role-supports-check-mode): every role supports check mode.
- [ANS-11](https://github.com/branchLeft/standards/blob/main/docs/stacks/ansible.md#ans-11--a-second-run-changes-nothing): a second run changes nothing.
- [ANS-15](https://github.com/branchLeft/standards/blob/main/docs/stacks/ansible.md#ans-15--every-role-carries-a-container-only-molecule-test): every role carries a container-only Molecule test.
- [ANS-17](https://github.com/branchLeft/standards/blob/main/docs/stacks/ansible.md#ans-17--a-role-is-applied-only-by-the-gated-workflow): a role is applied only by the gated workflow.
- [CON-3](https://github.com/branchLeft/standards/blob/main/docs/containers.md#con-3--tag-and-digest): tag and digest.

The repository's words:

- **Harness**: `ansible/harness/run_harness.py`, which runs the steps in "How to run
  its test" for one role or pattern.
- **Lock**: `ansible/requirements.txt`, every package the tools need, each at an exact
  version and with its hash, so an install takes only what the lock names.
- **Skeleton**: `ansible/role_skeleton/`, the template that makes a new role.
- **Shard**: one CI job that runs the harness for one role, pattern or scenario, with
  its own time limit ([ansible/README.md](../../README.md), "Sharing steps between
  scenarios").
- **Merge queue**: GitHub's queue that tests a pull request on top of `main` before it
  merges. A commit the queue has tested is not run through lint and Molecule again on
  the push to `main`.
- **Owner**: the one account that approves a protected deployment (see "How it is
  delivered").

The test's words. Molecule is the tool that starts the container, runs the scenario's
plays in it and removes it.

- **Converge**: apply the role to the container, for real.
- **Idempotence**: a second converge that changes nothing (ANS-11).
- **Check mode**: a dry run (Ansible's `--check`). It reports what would change and
  changes nothing, so a plan can be shown before an apply.
- **Handler and `flush_handlers`**: a handler is a task that runs once per play, at the
  end of the play, only when a task notifies it. `meta: flush_handlers` runs the queued
  handlers at that point instead.

## What it does, and what it does not

It delivers one validated JSON configuration file and three systemd units: a
service, a timer and the timer's oneshot service. It makes systemd load the
units, then enables and starts the service and the timer.

It does not install a package or a binary, create a user or a group, open a port,
touch a firewall, or apply itself to a host. The user and group that own the
configuration file must exist before it runs.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. None of them is a
secret. The owner and group of the configuration file are variables because a
service role gives its configuration to its service user; the units stay
`root:root`.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version`
  in `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin` is used by the role. The test uses
  `community.docker`, which the `ansible` package pinned in `ansible/requirements.txt`
  brings with it (version 5.4.0 in `ansible` 14.5.0). `ansible/requirements.yml`
  lists no collection on purpose ([ansible/README.md](../../README.md), "Why the
  collections come with the `ansible` package").
- Target: a systemd host with `python3`. The validator below is the target's
  `python3 -m json.tool`.

## What it changes on a host

- The configuration file at `files_and_units_config_path`, owner and group from
  `files_and_units_config_owner` and `files_and_units_config_group`, mode `0640`.
- `/etc/systemd/system/files_and_units_svc.service`, mode `0644`, a `simple`
  service that runs `sleep infinity`. Enabled and started.
- `/etc/systemd/system/files_and_units_tick.service`, mode `0644`, a oneshot.
- `/etc/systemd/system/files_and_units_tick.timer`, mode `0644`, which starts the
  oneshot. Enabled and started.
- One `daemon-reload` of the systemd manager, only when a unit file changed.
- No port, no user, no firewall rule.

## The recipe

### (a) The bash shape it replaces

```bash
install -o EXAMPLE_USER -g EXAMPLE_GROUP -m 0640 example.json /etc/EXAMPLE.json
install -o root -g root -m 0644 example.service /etc/systemd/system/EXAMPLE.service
systemctl daemon-reload
systemctl enable --now EXAMPLE.service
```

A second run of that script reports nothing about what changed, reloads systemd
every time, and checks nothing about the file it installed. The reader must
simulate it to learn the end state.

### (b) The Ansible shape

```yaml
- name: Install the configuration file
  ansible.builtin.copy:
    src: example.json
    dest: '{{ files_and_units_config_path }}'
    owner: '{{ files_and_units_config_owner }}'
    group: '{{ files_and_units_config_group }}'
    mode: '0640'
    validate: python3 -m json.tool %s

- name: Render the service unit
  ansible.builtin.template:
    src: service.unit.j2
    dest: /etc/systemd/system/files_and_units_svc.service
    owner: root
    group: root
    mode: '0644'
  notify: Reload systemd manager

- name: Load queued unit changes before any unit is started
  ansible.builtin.meta: flush_handlers

- name: Read back the service unit file
  ansible.builtin.stat:
    path: /etc/systemd/system/files_and_units_svc.service
  register: files_and_units_svc_unit

- name: Enable and start the service
  ansible.builtin.systemd_service:
    name: files_and_units_svc.service
    enabled: true
    state: started
  when: files_and_units_svc_unit.stat.exists
```

The handler is `Reload systemd manager`, a `systemd_service` task with
`daemon_reload: true`. It runs once per play however many unit tasks notified it,
and only when one of them changed. The role does the same for the timer and its
oneshot.

### (c) Why each parameter is set

- `owner`, `group`, `mode` are explicit. A copy without them takes the process's
  umask and the invoking user, so the end state depends on who ran it. The
  configuration file takes a service user so the test can tell the parameter from
  the default (see the limits). The units are `root:root`: a unit a service user
  can write is a way for that user to run commands as root.
- `validate` runs on the target, on a temporary copy, before the file replaces the
  old one. A file that fails it is never installed and the task fails with the
  validator's message. `%s` is the temporary path. The validator needs no file name
  suffix, which is why a JSON file can use `python3 -m json.tool` directly.
- `copy` and `template` are used because they state the end state and report a
  change only when the content or the metadata differs. The idempotence step is
  what checks that claim for this role; a shell `install` is not checked at all.
- `notify` plus a handler, not an unconditional `daemon_reload` task. An
  unconditional reload reports a change on every run and fails ANS-11.
- `meta: flush_handlers` before the enable. A handler runs at the end of a play by
  default, so on a host that already has an earlier unit the role would return
  with systemd still holding the old definition. The converge asserts the loaded
  `Description` right after the role (see the test).
- The two `stat` tasks gate the enable and the start on the unit file being on
  disk. Check mode writes no file, so on a fresh host the enable would fail with
  "Could not find the requested service". The gated task is skipped in check mode
  only on that fresh state, and the skip is stated here (ANS-10). Ansible prints
  it as a bare `skipping`. `stat` runs in check mode as it does in a real run, so
  it needs no `check_mode: false`.
- `systemd_service` (not `command` with `systemctl`) reports the unit's real state,
  so the module knows when a change has happened (ANS-9).

### The validator on a unit file

`validate: systemd-analyze verify %s` is not set on the units. It was tried by
hand, and it behaves like this:

- Run by hand on a path with no unit suffix it fails:
  `systemd-analyze verify /tmp/validate_probe_unit` prints
  `Failed to prepare filename /tmp/validate_probe_unit: Invalid argument` and exits 1.
- Inside the role, Ansible hands `validate` a temporary copy that keeps the
  destination's suffix (`.source.service` in a `-vvv` run of this role), so the same
  validator accepts a good unit and rejects a bad one. With
  `ExecStart=/bin/no_such_binary_probe` it failed the task with
  `.source.service: Command /bin/no_such_binary_probe is not executable: No such file or directory`.
- So a unit can be validated, but the check runs at the moment of the task and looks
  for the `ExecStart` binary on the target: a role must deliver the binary before the
  unit. Here the units start `/bin/sleep` and `/bin/true`, which the base image has, so
  a validator would test the image and not the pattern. This probe is not part of the
  scenario, so no control covers it.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

Create the virtual environment and install the pinned tools with the one install
recipe in [ansible/README.md](../../README.md), "Run the harness". The install
commands are kept only there, so the recipe has one home; `.venv` is git-ignored.
A machine with no network uses the download-then-install route in that same file,
"Install, and install with no network". Then, from the repository root:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/files_and_units
```

The harness lints the role and runs the scenario in `molecule/default/` on one
container, and exits non-zero if any step fails. It removes its container when it
finishes, after a failure or an interrupt too. A run that is killed outright cannot;
its container then carries the `branchleft.role-test-run` label and can be removed by
that label ([ansible/README.md](../../README.md), "The one privileged fact").

What each part of the scenario does:

- `prepare.yml` creates the placeholder service group and user. Their names, and the
  description every unit carries, are inventory variables in `molecule.yml`, so the
  role, the converge and the verify read one value.
- `check-fresh`: the converge in check mode against an instance on which no unit
  exists. It completes; the enable and start are skipped for the reason in (c).
- `converge`: on an instance with no unit file it first applies the role with an
  earlier description, so that the real apply is an update. It then applies the
  role and asks systemd, straight away, for the loaded unit's `Description`. A
  reload that is missing, or left to the end of the play, fails that assertion.
- `idempotence`: a second converge reports zero changed tasks. This is the ANS-11
  proof for every task, including the handler. The earlier-release step is skipped
  once the units exist.
- `verify`: the owner, group and mode of each file, that the service and the timer
  are `enabled` and `active`, and that the loaded `Description` equals the
  rendered one.
- `check-configured` and `molecule-check`: the configured instance shows no drift.

What breaks which step. Each row was measured by hand on 2026-10-17: one edit, one
harness run, one restore. Two images are named.
**Trixie** is `geerlingguy/docker-debian13-ansible` at the digest pinned in
`molecule.yml`. **Historical** is an earlier Debian 12 image that this repository does
not name or pin. The rows measured on trixie are: the `notify` row for the three unit
tasks, the `flush_handlers` row, the owner and group row, the invalid-JSON row with
`validate` kept, the `command` row, and the timer's `enabled` row. Every other row is
historical: it was not run again on trixie, so a reader cannot reproduce it from this
repository.

| Edit to the role                                                    | Step that fails                                                                                           |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `notify` removed from the three unit tasks                          | `converge`, assertion "systemd still holds the earlier..."                                                |
| `meta: flush_handlers` removed                                      | `converge`, the same assertion                                                                            |
| `owner` and `group` removed from the configuration copy             | `verify`, the owner assertion                                                                             |
| Invalid JSON in `files/example.json`                                | `converge`, "failed to validate"                                                                          |
| Invalid JSON and `validate` removed                                 | none: all 14 steps pass                                                                                   |
| The two `when` gates on the enable removed                          | `check-fresh`, "Could not find the requested service"                                                     |
| A `command` task with `changed_when: true` added                    | `idempotence`, naming the task                                                                            |
| `notify` removed from the timer task only, or from its oneshot only | none: all 14 steps pass (not caught: the proof shows at least one unit task notifies, not that each does) |
| `enabled: true` changed to `false` for the timer                    | `verify`, the timer's `enabled` assertion                                                                 |

### Named limits

- **Reviewed, not tested.** The `owner: root` and `group: root` on the three unit
  files. The test runs as root, so omitting them gives the same result, and a unit
  must not be owned by anyone else, so there is no value that would tell the two
  apart. The configuration file's owner and group are tested because they are
  variables with a non-root test value.
- A check-mode run does not run `validate`. The invalid file in the table above
  passes `check-fresh` and fails at `converge`, so a plan shows the file as a change
  and the validator speaks at apply.
- The test proves the files' content and the systemd state on one container. It does
  not prove that `sleep infinity` or `/bin/true` do useful work, or that the timer
  fires at its calendar time.
- The owner and mode are checked on the files this role writes. A file another role
  writes is not covered.
- `check-fresh` skips the enable and start (see (c)), and the harness does not catch
  a silent skip. This section is the review of it.
- CI runs this scenario. The Ansible workflow (`.github/workflows/ansible.yml`) runs
  the harness over each role and pattern in its own shard. A pull request or a
  merge-queue entry runs this shard when its diff changes this pattern or a shared
  file (the harness, the lock, or the checks that select shards); the weekly sweep runs
  every shard; a push to `main` runs none, because the merge queue has already tested
  the tree. [`ansible/checks/README.md`](../../checks/README.md) gives the rules. The
  green run on `main` that ran this pattern's shard is
  https://github.com/branchLeft/shared-infra/actions/runs/40191479010 (job
  `Harness: ansible/patterns/files_and_units`, conclusion `success`, commit `7cd0d26`).
- The settings in `molecule.yml` are measured on two hosts: Docker Desktop (the
  owner's machine) and a GitHub `ubuntu-24.04` runner (cgroup v2, Docker 28.0.4), where
  the full harness passed with `cgroupns_mode: host` in place. The runner evidence is a
  diagnostic run of 2026-10-17, https://github.com/branchLeft/shared-infra/actions/runs/39073641288,
  whose step with the host namespace reports all 14 steps `PASS` and exit status 0. That
  job ends failed by design, on its temporary diagnostic step. The CI evidence for this
  pattern is the push run named above.
- The Ansible workflow's harness jobs run on `ubuntu-24.04`, not `ubuntu-latest`. The
  comment above their `runs-on` lines in `.github/workflows/ansible.yml` reads "Pinned
  until the harness is verified on the next Ubuntu LTS image".
- The base image is Debian 13 with Python 3.13 and an `EXTERNALLY-MANAGED` marker
  that its Dockerfile tries to remove at a 3.11 path, so the marker stays and its
  unpinned `ansible` and `cryptography` installs rely on `--break-system-packages`.
  This is a fact of the image, not of this role; it is named here so a reader does
  not take the install for a choice made by the role.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17). In shared-infra that
workflow is [`.github/workflows/ansible-delivery.yml`](../../../.github/workflows/ansible-delivery.yml).
It runs on a push to `main` and on nothing else. It calls a reusable workflow,
`ansible-gated-apply.yml` at tag `v1.0.19` of `branchLeft/github-workflows`, which lints
and runs Molecule over every role and pattern (`roles/*` and `patterns/*`). Two of its
jobs matter here:

- **Plan the apply (check mode on each host)**, the plan job. It asks each host, through
  a restricted route that accepts one commit id and nothing else, what an apply of that
  exact commit would change, and shows the answer. It changes nothing.
- **Apply the planned commit (after approval)**, the apply job. It runs only when the plan
  found a change. It waits on the **protected environment** `ansible-hosts`: GitHub holds
  the job until a required reviewer approves it, and only then can the job read the apply
  key. Afterwards each host applies that same commit, and a second run must report zero
  changes.

The protected environment is a GitHub deployment environment with one required reviewer
(the owner, alone), prevent self-review on, deployment branches limited to `main`, and
the apply key held as an environment secret. The header of
`.github/workflows/ansible-delivery.yml` lists these settings, and
[`ansible/checks/check_delivery.py`](../../checks/check_delivery.py) fails if one of them
is weakened. Nothing is applied from a laptop.

This pattern is not applied to any host: no playbook includes it. A role that follows it
reaches hosts through its own playbook, as `ansible/roles/db1_backup_timers` does through
`ansible/playbooks/db1.yml`.

## How a service role copies it

1. From the repository root, with the tools installed (see "How to run its test"), make
   the new role from the skeleton:

   ```text
   .venv/bin/ansible-galaxy role init --role-skeleton ansible/role_skeleton --init-path ansible/roles YOUR_ROLE_NAME
   ```

   `YOUR_ROLE_NAME` is lowercase letters, digits and underscores, and the role is made
   under `ansible/roles/`. [ansible/README.md](../../README.md), "Make a new role", says
   what the skeleton gives you.

2. Copy `tasks/main.yml`, `handlers/main.yml`, `templates/` and the whole of
   `molecule/default/` over the new role's files. Keep `namespace` in
   `meta/main.yml`: Molecule links the role under it.
3. Rename. Every `files_and_units` name in the copied files becomes the new role's name.
   Those files are `defaults/main.yml`, `meta/argument_specs.yml`, `tasks/main.yml`, the
   three templates in `templates/`, and every file in `molecule/default/` (`molecule.yml`,
   `prepare.yml`, `converge.yml` and `verify.yml`). In them, rename:
   - the variable prefix `files_and_units_`, including the register names in `verify.yml`;
   - the unit names `files_and_units_svc.service`, `files_and_units_tick.service` and
     `files_and_units_tick.timer`, and the unit paths that name them;
   - the configuration file's name, `/etc/files_and_units.json`, in `defaults/main.yml`
     and in the path `verify.yml` reads;
   - the role name in `converge.yml`, `branchleft.files_and_units`, which becomes
     `branchleft.` and the new name.

   `prepare.yml` creates the user and group that the `files_and_units_config_*` variables
   name, so it must be renamed with the rest, or it refers to variables that no longer exist.

4. Replace the placeholders:
   - `files/example.json`: the content, in place of `EXAMPLE_KEY` and `EXAMPLE_VALUE`;
   - `defaults/main.yml`: `EXAMPLE_UNIT_DESCRIPTION`, the description that all three units
     carry, and `files_and_units_tick_calendar` (`hourly`), the timer's `OnCalendar`;
   - `molecule/default/molecule.yml`: `SCENARIO_UNIT_DESCRIPTION`, the same description for
     the test, in the group variables;
   - `templates/service.unit.j2` and `templates/tick.service.j2`: the `ExecStart` lines
     (`/bin/sleep infinity` and `/bin/true`);
   - `AUTHOR_NAME` and `LICENSE_ID` in `meta/main.yml`, and `AUTHOR_NAME` in
     `meta/argument_specs.yml`.

   `EARLIER_UNIT_DESCRIPTION` in `converge.yml` is the test's earlier release, not a value
   for the service. Keep it or rename it.

5. Choose the validator for the configuration file's type. If the type has none,
   leave `validate` off and say why in the README, as step (c) does for units.
6. Set `files_and_units_config_owner` and `files_and_units_config_group` in the scenario's
   group variables (`molecule/default/molecule.yml`, under `provisioner`, `inventory`,
   `group_vars`, `all`) to placeholder names for the real service's user and group, and
   keep them non-root.
7. Run the harness on the new role. Then break each control in the table above on
   the copy and see the same step fail: a control is yours only after you have
   broken it.
8. Do not give the scenario more privilege than this one, and reuse the image pin
   below rather than choosing another base.

## The systemd test base image (a third-party image, trusted by digest)

The skeleton's platform has no init system, so this scenario uses a third-party
systemd base, chosen by a recorded ruling and written here for the owner to review.

- Image: `geerlingguy/docker-debian13-ansible`, referenced in
  `molecule/default/molecule.yml` as `name:latest@sha256:<digest>` (CON-3). The
  Debian 13 (trixie) release matches production, which runs Debian 13 on every
  host, so the test is not run on a different release. The
  digest is the pin and the tag beside it is informational. Upstream rebuilds on a
  weekly schedule (its build workflow has a cron, and the image's build attestation
  names `schedule` as the trigger), so `latest` moves every week; the digest does
  not.
- Source: the public repository `geerlingguy/docker-debian13-ansible` on GitHub
  (MIT licence), built `FROM debian:trixie`. Its Dockerfile
  installs `systemd` and `systemd-sysv`, Python, `pip` and build tools from Debian's
  repositories, then `ansible` and `cryptography` from PyPI without version pins, with
  `--break-system-packages`. The image's own Ansible is not used: Molecule runs the
  controller's pinned Ansible against the container.
- Trixie differences, read from the image and from a harness run on it. The harness
  passed on this image with no change to the role. Python on the image is 3.13
  (the Dockerfile's `rm -f /usr/lib/python3.11/EXTERNALLY-MANAGED` names a 3.11 path, so
  it does not remove the marker on this image; the pip install therefore relies on
  `--break-system-packages`). This is a base-image fact, named as a limit below.
- It replaces `/sbin/initctl` with a small script that maps the old `initctl`
  verbs to `service`, removes the getty target from multi-user, and sets
  `VOLUME ["/sys/fs/cgroup"]` and `CMD ["/lib/systemd/systemd"]`.
- The digest is read with `docker image inspect --format '{{index .RepoDigests 0}}'`
  after a pull, or from the registry with `docker buildx imagetools inspect`.
- A digest reference on Molecule's pre-built path (ANS-15 asks the first role to use
  one to record the result): the harness passes with the `name:tag@sha256:digest`
  form, every step, on the Docker Desktop below.

What the container needs to run systemd, measured on the pinned image on Docker
Desktop (engine 29.8.2, linux/arm64, cgroup v2), by creating the container and asking
`systemctl is-system-running --wait`:

| Settings                                                                                  | Result on the pinned image                                               |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| cgroup mount read-write, `/run` and `/run/lock` tmpfs, command (default cgroup namespace) | `degraded`; the container runs (`tmp.mount` and the journald units fail) |
| the same with `cgroupns_mode: host` added (the scenario)                                  | `degraded`; the container runs (`tmp.mount` fails)                       |
| `cgroupns_mode: host` and the mounts, without the tmpfs                                   | the container exits (code 255, no log)                                   |
| `cgroupns_mode: host` and the tmpfs, without the cgroup mount                             | the container exits (code 255, no log)                                   |

Every row is measured on the pinned Debian 13 image. The scenario's container reports
`degraded`, not `running`. The harness reads no system state (no file under
`ansible/harness` or `ansible/checks` asks systemd for it), so this fails no step, and
the full harness passes on the scenario in the push run named above.

So the scenario sets no `privileged` and no capabilities. It sets `cgroupns_mode: host`
because on the GitHub `ubuntu-24.04` runner (cgroup v2) a private cgroup namespace over
the read-write mount made systemd exit at once, and the full harness passed with the
host namespace. The host namespace is a stated exception (ANS-15): it gives the
container the host's cgroup view and, with the read-write mount, write access to the
host cgroup tree. The test image is trusted by digest and the job holds no credentials.
The Docker Desktop used for the table is engine 29.8.2, linux/arm64. The table's first
row shows the private namespace keeping the container running on Docker Desktop; the
runner result is the reason for the key.

Named limit: the image is trusted by its digest and by review. It is not built by
this repository, and its unpinned PyPI installs were resolved once, at its build and
are frozen by the digest. Whether Docker Hub keeps an old digest pullable
indefinitely is not established. Its contents change only when someone pins a new
digest. Later patterns that need systemd reuse this same pin rather than picking
another base.

## How to change it safely

Change the tasks, the handler, the templates and the converge and verify plays
together, run the harness, and break the control you touched (the table above) to
see it fail. A change to the digest is its own change, reviewed on its own. An edit
to a default value is a change of behaviour on every host that uses the role, not a
rename. Removing the owner and group variables, the `notify`, the flush or the
validator removes a control the table shows.
