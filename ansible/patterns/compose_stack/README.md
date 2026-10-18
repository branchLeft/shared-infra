# compose_stack

This role is a pattern. It is the recipe a maintainer follows when a shell script
installs a Docker Compose file and its configuration files and runs
`docker compose up -d`. It delivers one example stack with placeholder names, and no
real service. Copy the shape, not the names.

## What it does, and what it does not

It refuses, before it writes anything, a compose file in which any image is not pinned
by digest. It then writes a project directory holding a configuration file, secret
files and the compose file, which is checked by the Compose CLI before it replaces the
old one. It brings the stack up only when one of those files changed, and it fails if
any service in the compose file has no container, is not running, or is unhealthy,
whether or not it just brought the stack up.

It never removes data. It runs no `down`, removes no volume and no orphan container, and
renews no anonymous volume.

It does not install Docker or the Compose plugin, create the user and group that own
the files, open a port, pull or build an image on its own (Compose pulls the digest
when it brings the stack up), rotate a secret, or apply itself to a host. A service
whose stack needs any of those has another role for it (ANS-12).

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. Two have no default and
must be supplied: the image, which must carry a digest, and the list of secret files.
The only secret is `compose_stack_secret_files[].content`. It is supplied at run time,
has no default (ANS-16) and is marked `no_log` in the specification. The compose file
refers to the secret files by name, so a service role that renames one renames it in
`templates/compose.yaml.j2` too.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, with `min_ansible_version` in
  `meta/main.yml` equal to it.
- The collection `community.docker`, pinned in `ansible/requirements.yml`, on the
  machine that runs Ansible.
- On the target: Debian 13 (the release the test runs on), Python 3, the Docker CLI
  and the Compose plugin at 2.21 or later. The module needs 2.18; the health check
  reads one JSON object per line from `docker compose ps`, which the module's own
  source dates to 2.21.
- The user and group named in `compose_stack_owner` and `compose_stack_group` exist
  before the role runs.

## What it changes on a host

- The project directory (`compose_stack_project_dir`): `root`, group
  `compose_stack_group`, mode `0750`.
- `app.conf` in it: owner and group from the variables, mode `0640`.
- One file per entry of `compose_stack_secret_files`: owner and group from the
  variables, mode `0600`.
- `compose.yaml` in it: `root:root`, mode `0644`. A service user that can write the
  compose file can start any container as root, so the file is not theirs.
- When any of the three kinds of file changed: the stack's containers are recreated
  and started, and the role waits up to `compose_stack_wait_timeout` seconds for them
  to be healthy. Compose keeps the data in volumes across a recreate (its documented
  behaviour, which the test cannot show; see the limits).
- No port, user, group, unit or firewall rule.

## The recipe

### (a) The bash shape it replaces

```bash
install -d -o root -g EXAMPLE_GROUP -m 0750 /opt/EXAMPLE
install -o EXAMPLE_USER -g EXAMPLE_GROUP -m 0640 app.conf /opt/EXAMPLE/app.conf
install -o root -g root -m 0644 compose.yaml /opt/EXAMPLE/compose.yaml
docker compose --project-directory /opt/EXAMPLE up -d
```

with `image: EXAMPLE:1.2` in the file. Every run starts the stack again and prints
nothing about whether it changed. A tag can be moved to a different image between two
runs. A stack that starts and then fails its health check is reported as a success.
Run under `set -x`, it also prints the secret file's content into the log.

### (b) The Ansible shape

```yaml
- name: Refuse a compose file whose images are not all pinned by digest
  ansible.builtin.assert:
    that:
      - compose_stack_rendered.services.values() | map(attribute='image') | reject('match', compose_stack_image_pattern) | list | length == 0
  vars:
    compose_stack_rendered: "{{ lookup('ansible.builtin.template', 'compose.yaml.j2') | from_yaml }}"
    compose_stack_image_pattern: '^[^\s@]+@sha256:[0-9a-f]{64}\Z'

- name: Deliver the secret files
  ansible.builtin.copy:
    content: '{{ item.content }}'
    dest: '{{ compose_stack_project_dir }}/{{ item.name }}'
    owner: '{{ compose_stack_owner }}'
    group: '{{ compose_stack_group }}'
    mode: '0600'
  loop: '{{ compose_stack_secret_files }}'
  no_log: true
  diff: false
  notify: Bring up the compose stack

- name: Deliver the compose file
  ansible.builtin.template:
    src: compose.yaml.j2
    dest: '{{ compose_stack_project_dir }}/compose.yaml'
    owner: root
    group: root
    mode: '0644'
    validate: docker compose --project-directory {{ compose_stack_project_dir }} --file %s config --quiet
  notify: Bring up the compose stack

- name: Bring up the stack now if a delivery changed, before the health check
  ansible.builtin.meta: flush_handlers
```

The handler, in `handlers/main.yml`:

```yaml
- name: Bring up the compose stack
  community.docker.docker_compose_v2:
    project_src: '{{ compose_stack_project_dir }}'
    project_name: '{{ compose_stack_project_name }}'
    state: present
    recreate: always
    build: never
    wait: true
    wait_timeout: '{{ compose_stack_wait_timeout }}'
    remove_orphans: false
    renew_anon_volumes: false
  when: compose_stack_compose_file_stat.stat.exists
```

The health check is one read-only `ansible.builtin.command` that runs
`docker compose ps --format json --all`, followed by an `assert` over its output (see
the decision below). The configuration file is a `template` task like the compose
file's, without `validate` and without `no_log`.

### (c) Why each parameter is set

- `owner`, `group` and `mode` are explicit on every file. Without them the file takes
  the umask and the user who ran Ansible. The configuration and secret files take a
  service user so the test can tell the parameter from the default (see the limits).
- `notify` on each delivery task, and a handler for `up`. A handler runs once however
  many tasks notified it and only if one reported a change, so a run that changes
  nothing never touches the stack, and the second run of the idempotence step reports
  zero changes. The three delivery tasks are the whole of the trigger: a file that is
  not delivered by a task that notifies cannot restart the stack.
- `meta: flush_handlers` before the health check. A handler runs at the end of the play
  by default, so without the flush the check would look at the old stack and the role
  would report it healthy before the new one existed.
- `recreate: always`. A config file that a container only bind-mounts is not part of the
  container's configuration as Compose reads it, so a plain `up` would leave the old
  file in use. Recreating the containers on every content change is the simple, safe
  reading. This is read from Compose's documentation and the module, and the test
  cannot show it (see the limits). It keeps named volumes.
- `build: never`. A stack that builds its own image has no digest to pin. The
  assertion refuses a service with a `build` key too.
- `wait: true` and a timeout. `up --wait` returns only when the services are running or
  healthy, and fails if one is unhealthy, so the failure comes with the `up` and not
  at a later run. The separate health check covers the runs where nothing changed.
- `remove_orphans: false` and `renew_anon_volumes: false` are the module's defaults,
  written out. The first would remove containers for services that were deleted from the
  file; the second throws away the data in every anonymous volume. Neither is for a
  deployment role, and writing them down is what lets the test assert on them. `state`
  is `present`: `absent` runs `down`.
- `validate` on the compose file runs `compose config --quiet` on a temporary copy
  before the file replaces the old one, so a file Compose cannot read is never
  installed and the stack keeps running on the old one. The secret and configuration
  files come first in the task order because `config` reads the `env_file` the
  compose file names. Check mode does not run `validate`.
- The compose file is parsed (`from_yaml`) before the digest check, not searched with a
  pattern, so a tag in quotes, in a flow mapping, behind an anchor or in a comment is
  judged by what YAML says it is. The pattern is `NAME@sha256:` and exactly 64
  lower-case hex digits, anchored at both ends; `\Z`, not `$`, because `$` also matches
  before a final newline. A service with no `image`, with `build`, with `extends`, or a
  top-level `include` is refused, because each can bring in an image the assertion did
  not read.
- `no_log: true` and `diff: false` on the secret task, and no `loop_control.label`. The
  loop item holds the secret; `no_log` prints it as "censored". With `no_log` off the
  loop prints the whole item, which is how the test sees the control go (see the
  limits for `diff`).
- The two `stat`-gated skips (the handler, the health check). Check mode writes no
  compose file, so on a fresh host there is nothing for a dry run of `up` or a look at
  the containers to read. They run whenever the file is really on disk. The skip on a
  fresh host is the only one, and it is stated here (ANS-10); Ansible prints it as a bare
  `skipping`.
- `check_mode: false` on the `ps` command only. It reads and changes nothing, and it
  has to run in check mode so a drift run sees an unhealthy stack.

### The decision for the reviewer and the owner: a module for `up`, a command for `ps`

ANS-9 says a module before a command. ANS-15 says the test never reaches a container
engine: the harness refuses a mounted engine socket and a `docker_host`, so the
instance has no Docker daemon and `docker compose` cannot really run in it. Those two
pull in different directions, and the pattern makes these choices.

**`up` uses `community.docker.docker_compose_v2`.** The module exists, so ANS-9 says use
it, and in check mode it runs `up --dry-run`, which a bare `command` would skip.
It can be exercised without an engine, because it drives the `docker` command line and
parses what that prints. Its source (the pinned 5.4.0) was read for the calls it
makes: `docker version --format '{{ json . }}'`, `docker compose version --format json`,
the `up` itself, whose progress it reads as JSON lines on standard error, then
`docker compose ps --format json --all --no-trunc` and `docker compose images --format
json`. The test installs a small stand-in for the `docker` command in the instance
(`molecule/default/files/docker_standin.sh`, installed by `prepare.yml`): it appends
its arguments to a log and prints canned answers in those shapes. The module runs
against it, and the verify play reads the log.

What that gets, and what it does not: the test proves the role calls the module exactly
when a file changed, with exactly the arguments in `verify.yml`, and that the role's
reading of the module's result and of `ps` output behaves as written. It does not prove
what Compose does. The module's own "changed" report comes from the progress lines the
stand-in prints, which were written from the module's source and not captured from a
real Compose, so the idempotence of `docker compose up` itself is not tested here.
The first live consumer's gated run is the real proof (ANS-17).

**The health check uses one `command`.** No module in the pinned collection reads a
Compose project's containers: `docker_compose_v2`, `_exec`, `_pull` and `_run` are the
four Compose modules, and `docker_container_info` talks to the engine's API socket,
which the test cannot have. Calling `docker_compose_v2` again to read the state would
run `up` on every run, against the rule that `up` runs only when a file changed. So the
role runs `docker compose ps --format json --all`, with `changed_when: false` and
`check_mode: false`. Its output is parsed in the `assert`, and ANS-9 says a command
whose output must be parsed becomes a Python module (ANS-2). A module would be a typed,
tested `library/` module for one role, and is the larger piece of work. Doing it later
is the cure; this pattern does not, and the owner can decide that it should. Until then
this is a stated deviation from the second sentence of ANS-9, not a hidden one.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/compose_stack
```

The harness lints the role and runs the scenario in `molecule/default/` on one
container, and exits non-zero if any step fails. It removes its container when it
finishes. There is no systemd in this scenario, so it takes none of the cgroup settings
`files_and_units` needs (the reasons for the three platform keys are in `molecule.yml`).

What each part of the scenario does:

- `prepare.yml` creates the placeholder service user and group, and installs the
  `docker` stand-in with its state directory: `argv.log` (the real calls), `dryrun.log`
  (calls made with `--dry-run`) and `ps.json` (what `compose ps` prints).
- `check-fresh`: the converge in check mode on an instance with nothing installed. It
  completes; the handler and the health check are skipped for the reason in (c).
- `converge`: on an instance with no stack it applies the role five times, counting the
  stand-in's real `up` calls around each. First application: one. Then the
  configuration file edited alone: one. The secret alone: one. The image alone, which
  edits the compose file: one. Then the same values again: none. A converge on an
  instance that already has the stack runs only the last of these.
- `idempotence`: a second converge reports zero changed tasks and, by the last step
  above, calls `up` zero times. This is the ANS-11 proof.
- `verify`:
  - owner, group and mode of the files and the directory;
  - every real `up` call is exactly the expected argument list, and every call the
    stand-in ever received is one of a short list: nothing else, in particular no `down`,
    `rm`, volume command or `--volumes`, `--remove-orphans` or `--renew-anon-volumes`;
  - `config --quiet` was run on a temporary copy and never on the installed file, and a
    refusing validator stops the role and leaves the installed file as it was;
  - the secret is not in any call;
  - twelve image references that are not pinned by digest (a tag, `latest`, no tag, an
    empty value, one taken from the environment, a short, a long and an upper-case
    digest, another algorithm, a trailing space, a tag and digest separated by a space,
    two digests) each stop the role at the digest check;
  - four states that `compose ps` can report (unhealthy, still starting, exited, nothing
    at all) each stop the role at the health check, and the healthy state passes again;
  - a plan with check mode on and an edited image logs a `--dry-run` `up` and no real
    one;
  - a scan of the whole run's log, kept by Ansible in a file in the scenario's
    ephemeral directory, for the throwaway secret, which is built from the harness's
    run id. The scan has a control: the converge prints a value on purpose, in a loop
    that does not set `no_log`, and the scan must find it. A scan that finds the control
    and not the secret is an all-clear that could have been red.
- `check-configured` and `molecule-check`: the configured instance shows no drift.

What breaks which step. Each row was done by an edit, one harness run, and a restore, on
2026-10-18, as an assertion failure and not a crash (one exception is marked):

| Edit to the role                                                                    | Step that fails                                                                                |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| A `command` task that always reports changed and notifies the handler               | `converge`, "Nothing edited: expected 0 real up call(s), the stand-in logged 1"                |
| `notify` removed from the compose file task                                         | `converge`, "Compose file edited: expected 1 real up call(s), the stand-in logged 0"           |
| `notify` removed from the configuration file task                                   | `converge`, "Configuration file edited: expected 1 ..."                                        |
| `notify` removed from the secret files task                                         | `converge`, "Secret file edited: expected 1 ..."                                               |
| `meta: flush_handlers` removed                                                      | `converge`, "First application: expected 1 real up call(s), the stand-in logged 0"             |
| The digest assertion removed                                                        | `verify`, "A tag alone: the role did not refuse the image with the digest check"               |
| A second service with a literal tag, `build:`, `extends:` or a top-level `include:` | `check-fresh`, the digest check, naming the failed condition                                   |
| `failed_when: false` on the health assertion                                        | `verify`, "A container that is unhealthy: the health check did not refuse the stack"           |
| `ignore_errors: true` on the health assertion                                       | `ansible-lint` (`ignore-errors`) and `verify`, the same message                                |
| The unhealthy, the not-running or the no-container condition removed, one at a time | `verify`, the case for that state                                                              |
| `no_log: true` removed from the secret task                                         | `verify`, "the secret reached the log"                                                         |
| `diff: false` removed from the secret task, `no_log: true` kept                     | none: all 14 steps pass (not caught; see the limits)                                           |
| `remove_orphans: true`, or `renew_anon_volumes: true`                               | `verify`, "Every real up call must carry exactly the expected arguments"                       |
| `state: absent` with `remove_volumes: true`                                         | `converge`, the stand-in refuses the `down` call ("Return code 64 is non-zero")                |
| A task that always reports changed                                                  | `idempotence`, naming the task                                                                 |
| `validate` removed from the compose file task                                       | `verify`, "The compose file must be checked with `compose config --quiet` on the temporary..." |
| `wait: true` turned off, or `recreate: always` turned to `auto`                     | `verify`, the exact-arguments message above                                                    |
| `check_mode: false` on the handler                                                  | `verify`, "A plan with a changed file must run `up --dry-run` and no real `up`"                |
| The handler's `when` (the compose file is on disk) removed                          | `check-fresh`, `"/opt/compose_stack_example" is not a directory`                               |
| `check_mode: false` removed from the `ps` command                                   | `verify`, the plan in check mode finds no container                                            |
| Owner and group removed from the configuration file, or the secret mode loosened    | `verify`, "A delivered file or the project directory has the wrong owner, group or mode"       |

### What the test proves, and its named limits

- **Real Compose is not exercised.** Parsing of the compose file, image pulls,
  networks, volumes, the meaning of `--wait`, `--force-recreate` and `healthcheck`, and
  whether `docker compose config --quiet` accepts a temporary file with the suffix
  Ansible gives it are all untested. The stand-in answers from the module's source; it
  is not captured output of a real Compose. The module's "changed" report is the
  stand-in's, so the idempotence of `up` on a real engine is untested.
- **Read from documentation, unverified:** that a plain `up` does not recreate a
  container whose bind-mounted file changed (the reason for `recreate: always`), and
  that `up --force-recreate` keeps the data in named volumes.
- **The failure of `up --wait` is not tested.** The stand-in's `up` never fails, so the
  path where the module itself reports an unhealthy stack is reviewed: the handler has
  no `ignore_errors` and no `failed_when`. The `ps`-based check is the one tested.
- **`diff: false` and `no_log: true` overlap.** A probe on the pinned ansible-core
  (2.21.5) showed `no_log: true` alone prints no diff, with `--check --diff` too, so
  the log scan cannot tell `diff: false` from its absence. ANS-16 asks for both and the
  role sets both; only `no_log` is shown by the test (removing it makes the scan fail,
  because the loop prints the item). `diff: false` is reviewed, not tested.
- **Reviewed, not tested.** `owner: root` and `group: root` on the compose file: the
  instance runs as root, so omitting them gives the same result, and the file must not
  belong to anyone else, so no test value tells the two apart. The configuration and
  secret files are tested because their owner is a non-root test value.
- **Secret file names are trusted.** A name with a `/` or `..` would write outside the
  project directory. The caller is a playbook the owner reviews, and the role does not
  check the names.
- **Compose features the assertion does not follow.** It reads the file the template
  renders. Image references taken from the environment (`${NAME}`) are refused because
  they do not match the pattern. A file a service pulls in by another route, such as an
  `env_file` that sets an image variable, is not read.
- **The health check reads the state at one moment.** A container that is healthy now
  and fails a minute later is a later run's failure.
- **The check-mode skip on a fresh host** is stated in (c); the harness does not catch
  a silent skip, and this section is the review of it.
- CI does not run this scenario today: the Ansible workflow
  (`.github/workflows/ansible.yml`) runs the harness over `ansible/roles` only. Until it
  lists `ansible/patterns`, a change here is proven by the local run above.
- The image is a third-party systemd-capable Debian 13 base used here for its Python
  and Ansible-ready layout. It is trusted by digest, as the `files_and_units` README
  records; this scenario uses the same pin and none of its systemd settings.

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
   `molecule/default/` over the new role's files. Keep `namespace` in `meta/main.yml`.
3. Rename. The variable prefix `compose_stack_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, the tasks, the handler, the
   templates and the group variables in `molecule.yml`. The role name
   `branchleft.compose_stack` becomes `branchleft.` and the new name in `converge.yml`,
   `verify.yml` and the `tasks/` files under `molecule/default/`. The project
   directory and project name appear in `converge.yml` and `verify.yml` too.
4. Replace the placeholders: the services in `templates/compose.yaml.j2`, the
   configuration file, and the ALL_CAPS values in `meta/`. Every service's `image:`
   line takes its value from a variable or a literal that carries a digest; add a
   variable per image to the argument specification and give each a digest-pinned
   value in `molecule.yml`.
5. List the service's secret files in `compose_stack_secret_files` and have the compose
   file name them. Take the real values from wherever the secrets pattern says
   (ANS-16 leaves that to it); the scenario keeps a throwaway built from the run id.
6. Keep the stand-in and its calls as they are. If the service's compose file uses a
   feature that makes the module call something new, the stand-in answers "call not
   expected" and the verify play's list of allowed calls says which. Add the call there
   on purpose; do not let the stand-in accept anything.
7. Run the harness on the new role. Then break each control in the table above on the
   copy and see the same step fail: a control is yours only after you have broken it.
8. Do not give the scenario more privilege than this one, and reuse the image pin
   rather than choosing another base. Never mount the engine's socket to run the
   real `docker compose`: ANS-15 forbids it, and the live proof is the gated run.

## How to change it safely

Change the tasks, the handler, the templates and the converge and verify plays
together, run the harness, and break the control you touched (the table above) to see it
fail. A change to the stand-in is a change to what the test believes the CLI does, so
review it against the module's source for the pinned collection version. A bump of
`community.docker` in `ansible/requirements.yml` is its own change: re-read the calls
the new module version makes against the stand-in and the verify play's list. An edit to
a default is a change of behaviour on every host that uses the role.
