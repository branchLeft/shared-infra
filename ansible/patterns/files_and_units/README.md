# files_and_units

This role is a pattern. It is the recipe a maintainer follows when a shell script
installs a file, installs a systemd unit, and enables a service and a timer. It
configures one example service with placeholder names, and no real service.
Copy the shape, not the names.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables. None
is a secret. The config path, the unit description and the timer's `OnCalendar`
value are plain placeholders with defaults in [`defaults/main.yml`](defaults/main.yml).

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`.
- No collection beyond `ansible.builtin`. The test uses `community.docker`, pinned in
  `ansible/requirements.yml`.
- Target: a systemd host. The test runs on the systemd base image named below.

## What it changes on a host

- `/etc/files_and_units.conf`, owner `root`, group `root`, mode `0640`.
- `/etc/systemd/system/files_and_units_svc.service`, mode `0644`, a `simple` service
  that runs `sleep infinity`. Enabled and started.
- `/etc/systemd/system/files_and_units_tick.service`, mode `0644`, a oneshot.
- `/etc/systemd/system/files_and_units_tick.timer`, mode `0644`, which starts the oneshot.
  Enabled and started.
- No port, no user, no firewall rule.

## The recipe

### (a) The bash shape it replaces

```bash
install -o root -g root -m 0640 example.conf /etc/EXAMPLE.conf
install -o root -g root -m 0644 example.service /etc/systemd/system/EXAMPLE.service
systemctl daemon-reload
systemctl enable --now EXAMPLE.service
```

A second run of that script reports nothing about what changed. The reader must
simulate it to learn the end state.

### (b) The Ansible shape

```yaml
- name: Install the configuration file
  ansible.builtin.copy:
    src: example.conf
    dest: '{{ files_and_units_config_path }}'
    owner: root
    group: root
    mode: '0640'

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

- name: Enable and start the service
  ansible.builtin.systemd_service:
    name: files_and_units_svc.service
    enabled: true
    state: started
```

The handler is `Reload systemd manager`, a `systemd_service` task with
`daemon_reload: true`. It runs once per play, however many unit tasks notified it,
and only when one of them changed.

### (c) Why each parameter is set

- `owner`, `group`, `mode` are explicit. A copy without them takes the process's
  umask and the invoking user, so the end state depends on who ran it.
- `copy` and `template` are used because they state the end state and report a
  change only when the content or the metadata differs. The idempotence step is
  what checks that claim for this role; a shell `install` is not checked at all.
- `notify` plus a handler, not an unconditional `daemon_reload` task. An unconditional
  reload reports a change on every run and fails ANS-11.
- `meta: flush_handlers` before the enable. A handler runs at the end of a play by
  default, so a unit that was just written would otherwise be started before systemd
  had loaded it.
- The two `stat` tasks with `check_mode: false` are reads. They gate the enable and the
  start on the unit file being on disk. Check mode writes no file, so on a fresh host
  the enable would fail with "could not find the requested service". Each gated task
  is skipped in check mode only on that fresh state, and the skip is stated here (ANS-10).
- `systemd_service` (not `command` with `systemctl`) reports the unit's real state, so
  the module knows when a change has happened (ANS-9).
- No `validate` on the copy. The placeholder file has no validator. A unit file
  could take `systemd-analyze verify`, but that checks that the `ExecStart` binary is
  executable on the controller's path, which is a host property. Add a validator only
  where the file type has one that runs without the host.

### (d) What the test proves, and the named limits

The Molecule scenario (`molecule/default/`) runs on the systemd base image below.

- `check-fresh`: the converge in check mode against a container no task has touched
  completes. The enable and start are skipped for the reason in (c).
- `converge`, then `idempotence`: a second converge reports zero changed tasks. This is
  the ANS-11 proof for every task, including the handler.
- `verify`: the owner, group and mode of each file, that the service and the timer are
  `enabled` and `active`, and that the loaded unit's `Description` equals the rendered
  value (`files_and_units_unit_description`).
- `check-configured` and `molecule-check`: the configured container shows no drift.

Named limits:

- **The default sequence cannot see a missing reload.** A fresh converge loads each
  unit for the first time, so the `Description` check passes with or without the
  handler. The reload is proven by the edit-proof run below, which is not in the
  harness. A reviewer runs it when the handler, the notify lines or the unit
  templates change.
- The test proves the unit file's content and the systemd state on one container.
  It does not prove that `sleep infinity` or `/bin/true` do useful work, or that the
  timer fires at its calendar time.
- The owner and mode are checked on the files this role writes. A file another
  role writes is not covered.
- `check-fresh` skips the enable and start (see (c)). A silent skip under check mode
  is not caught by the harness; this section is the review of it.
- Nothing here applies to a host. Delivery is ANS-17 and is a separate ticket.

### Edit-proof run (manual, not in the harness)

Run from this directory, with the venv's `molecule` on `PATH`, the pinned
collections installed into a scratch path, and a unique `ROLE_TEST_RUN_ID`. The
steps prove that an edited description reaches systemd through one reload.

1. `molecule create` and `molecule converge`.
2. `molecule converge -- -e files_and_units_unit_description=EDITED_UNIT_DESCRIPTION`.
   The output shows `RUNNING HANDLER [Reload systemd manager]` once, and the two
   unit templates changed.
3. `molecule verify -- -e files_and_units_unit_description=EDITED_UNIT_DESCRIPTION`
   passes.
4. `molecule destroy`.

Without the handler, step 3 fails on the `Description` assertion.

## The systemd test base image (a third-party image, trusted by digest)

The skeleton's platform has no init system, so this scenario uses a third-party
systemd base chosen by the orchestrator's ruling and recorded here as the decision
the owner reviews.

- Image: `geerlingguy/docker-debian12-ansible`, pinned by the digest in
  `molecule/default/molecule.yml`.
- Source: the public repository `geerlingguy/docker-debian12-ansible` on GitHub
  (MIT licence), default branch last pushed 2025-03-25 (commit
  `e006db14a3db248614fdfed3e78de3e8098f33d9`). Docker Hub last updated 2026-10-11,
  which the image's README says is an automatic rebuild when the upstream OS is rebuilt.
- Built `FROM debian:bookworm`. Its Dockerfile installs `systemd` and `systemd-sysv`,
  Python, `pip` and build tools from Debian's repositories, then `ansible` and
  `cryptography` from PyPI without version pins. The image's own Ansible is not used:
  Molecule runs the controller's pinned Ansible against the container.
- It replaces `/sbin/initctl` with a small script that maps the old `initctl`
  verbs to `service`. It removes the getty target from multi-user, and sets
  `VOLUME ["/sys/fs/cgroup"]` and `CMD ["/lib/systemd/systemd"]`.
- The scenario sets `privileged: true` and `cgroupns_mode: host`, and mounts
  `/sys/fs/cgroup`, because systemd manages the cgroup tree. These are the image's
  documented run flags.
- Pulled and pinned on 2026-10-17 with `docker pull`. The digest is read with
  `docker image inspect --format '{{index .RepoDigests 0}}'`.

Named limit: the image is trusted by its digest and by review. It is not built by
this repository, and its unpinned PyPI installs were resolved once, at its build.
Its contents can change only when someone pins a new digest. Later patterns that
need systemd (firewall, timers, services) reuse this same pin rather than picking
another base.

## How to change it safely

Change the tasks, the handler and the templates together, and re-run the harness
and the edit-proof run. A change to the digest is its own change, reviewed on its
own. An edit to a default value is a change of behaviour on every host that uses
the role, not a rename.
