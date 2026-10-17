# files_and_units

This role is a pattern. It is the recipe a maintainer follows when a shell script
installs a file, installs systemd units, and enables a service and a timer. It
configures one example service with placeholder names, and no real service.
Copy the shape, not the names.

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
- No collection beyond `ansible.builtin`. The test uses `community.docker`, pinned
  in `ansible/requirements.yml`.
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
hand on 2026-10-17, and it behaves like this:

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

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/files_and_units
```

The harness lints the role and runs the scenario in `molecule/default/` on one
container, and exits non-zero if any step fails. It removes its container when it
finishes.

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

What breaks which step. Each row was done by an edit, one harness run, and a
restore, on 2026-10-17:

| Edit to the role                                        | Step that fails                                            |
| ------------------------------------------------------- | ---------------------------------------------------------- |
| `notify` removed from the three unit tasks              | `converge`, assertion "systemd still holds the earlier..." |
| `meta: flush_handlers` removed                          | `converge`, the same assertion                             |
| `owner` and `group` removed from the configuration copy | `verify`, the owner assertion                              |
| Invalid JSON in `files/example.json`                    | `converge`, "failed to validate"                           |
| Invalid JSON and `validate` removed                     | none: all 14 steps pass                                    |
| The two `when` gates on the enable removed              | `check-fresh`, "Could not find the requested service"      |
| A `command` task with `changed_when: true` added        | `idempotence`, naming the task                             |

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
- CI does not run this scenario today: the Ansible workflow
  (`.github/workflows/ansible.yml`) runs the harness over `ansible/roles` only. Until
  it lists `ansible/patterns`, a change here is proven by the local run above.
- Tested on Docker Desktop only (see the image section). A Linux CI runner may need
  more than the settings in `molecule.yml`; if it does, add it back with the measured
  failure as the reason.

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
   `molecule/default/` over the new role's files. Keep `namespace` in
   `meta/main.yml`: Molecule links the role under it.
3. Rename. The variable prefix `files_and_units_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, the tasks, the templates, and the
   group variables in `molecule.yml`. The unit names
   `files_and_units_svc.service`, `files_and_units_tick.service` and
   `files_and_units_tick.timer` become the service's. The role name in
   `converge.yml` (`branchleft.files_and_units`) becomes `branchleft.` and the new
   name. The same unit paths appear in `verify.yml` and `converge.yml`.
4. Replace the placeholders: the content of `files/example.json`, the units'
   `ExecStart` lines and calendar, and the ALL_CAPS values in `meta/`.
5. Choose the validator for the configuration file's type. If the type has none,
   leave `validate` off and say why in the README, as step (c) does for units.
6. Set the service user and group in the scenario's group variables to placeholders
   for the real service's, and keep them non-root.
7. Run the harness on the new role. Then break each control in the table above on
   the copy and see the same step fail: a control is yours only after you have
   broken it.
8. Do not give the scenario more privilege than this one, and reuse the image pin
   below rather than choosing another base.

## The systemd test base image (a third-party image, trusted by digest)

The skeleton's platform has no init system, so this scenario uses a third-party
systemd base chosen by the orchestrator's ruling and recorded here as the decision
the owner reviews.

- Image: `geerlingguy/docker-debian12-ansible`, referenced in
  `molecule/default/molecule.yml` as `name:latest@sha256:<digest>` (CON-3). The
  digest is the pin and the tag beside it is informational. Upstream rebuilds on a
  weekly schedule (its build workflow has a cron, and the image's build attestation
  names `schedule` as the trigger), so `latest` moves every week; the digest does
  not.
- Source: the public repository `geerlingguy/docker-debian12-ansible` on GitHub
  (MIT licence), built `FROM debian:bookworm`. Its Dockerfile installs `systemd` and
  `systemd-sysv`, Python, `pip` and build tools from Debian's repositories, then
  `ansible` and `cryptography` from PyPI without version pins. The image's own
  Ansible is not used: Molecule runs the controller's pinned Ansible against the
  container.
- It replaces `/sbin/initctl` with a small script that maps the old `initctl`
  verbs to `service`, removes the getty target from multi-user, and sets
  `VOLUME ["/sys/fs/cgroup"]` and `CMD ["/lib/systemd/systemd"]`.
- The digest is read with `docker image inspect --format '{{index .RepoDigests 0}}'`
  after a pull, or from the registry with `docker buildx imagetools inspect`.
- A digest reference on Molecule's pre-built path (ANS-15 asks the first role to use
  one to record the result): the harness passes with the `name:tag@sha256:digest`
  form, every step, on the Docker Desktop below.

What the container needs to run systemd, measured on 2026-10-17 on Docker Desktop
with its Linux engine (cgroup v2), by creating the container and asking
`systemctl is-system-running`:

| Settings                                                                      | Result                                 |
| ----------------------------------------------------------------------------- | -------------------------------------- |
| cgroup mount read-write, `/run` and `/run/lock` tmpfs, command (the scenario) | `running`; the full harness passes     |
| the same with `cgroupns_mode: host` added                                     | `running`                              |
| `cgroupns_mode: host` and the mounts, without the tmpfs                       | the container exits (code 255, no log) |
| `cgroupns_mode: host` and the tmpfs, without the cgroup mount                 | the container exits                    |

So the scenario sets no `privileged`, no capabilities and no cgroup namespace
option: the mount, the tmpfs and the command are the whole set. That is one Docker
Desktop daemon (version 4.32.0, engine 27.0.3, linux/arm64). A Linux runner with a
different cgroup setup may need more, and the reason then belongs in the scenario
file with the measured failure.

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
