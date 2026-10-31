# compose_stack

This role is a pattern. It is the recipe a maintainer follows when a shell script
installs a Docker Compose file and its configuration files and runs
`docker compose up -d`. It delivers one example stack with placeholder names, and no
real service. Copy the shape, not the names.

## What it does, and what it does not

It refuses, before it writes anything, a compose file in which any image is not pinned
by digest, and a project directory that holds a compose override file. It then writes a
project directory holding a configuration file, secret files and the compose file,
which is checked by the Compose CLI before it replaces the old one. It brings the stack
up when the content it delivers is not the content last recorded as healthy, or when
one of those files changed in this run, and it fails if any service in the compose file
has no container, is not running, or is unhealthy, whether or not it just brought the
stack up. It records the content as healthy only after both have succeeded, so a run
that fails part-way is followed by a run that tries again.

It never removes data. It runs no `down`, removes no volume and no orphan container, and
renews no anonymous volume.

It does not install Docker or the Compose plugin, create the user and group that own
the files, open a port, pull or build an image on its own (Compose pulls the digest
when it brings the stack up), rotate a secret, or apply itself to a host. A service
whose stack needs any of those has another role for it (ANS-12).

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. The argument specification
is the authority for which variables are required; none is required now, and the defaults
are the one-application recipe: `compose.yaml.j2` renders the compose file, and one
configuration file, `app.conf`, is rendered from `app.conf.j2`.

The contract a stack with more than one service, or with its own images, needs:

- `compose_stack_compose_template` names the template, in the role's `templates/`, the
  compose file is rendered from, and `compose_stack_compose_file` names the file in the
  project directory. Every image the file names must carry a digest, whatever the template.
- `compose_stack_config_files` is a list of `name`, `content` and `mode`. A name is a
  relative path of at most one directory level, each part starting with a letter or
  digit, so it cannot climb out of the project directory; a name that does not match is
  refused before anything is written. A file in a directory of its own gets that directory
  first, with `compose_stack_project_mode`. The default `mode` is `0640`.
- `compose_stack_secret_files` is optional and defaults to none. The only secret is
  `compose_stack_secret_files[].content`. It is supplied at run time, has no default
  (ANS-16) and is marked `no_log` in the specification. The compose file refers to the
  secret files by name, so a service role that renames one renames it in its template too.
- `compose_stack_http_check_url`, optional, is an endpoint the host asks with `GET` until it
  answers `200` within `compose_stack_wait_timeout`. Empty, the default, means no such check.
  The compose health check always runs and is not optional: a service with no container, one
  not running, or one whose healthcheck is not healthy fails the run.
- The stamp is written only after both checks pass, so a run that fails at either is followed
  by one that tries again.

The image variable `compose_stack_app_image` is used by the default template only. The
stamp covers the rendered compose file, every configuration file's name, mode and content,
and the secret files' names and content.

`compose_stack_services` is the list of services to recreate when a file changes; empty
means every service in the project. It exists so that a stack with a database next to
the app can recreate the app alone (see the limits for what that does and does not
protect).

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, with `min_ansible_version` in
  `meta/main.yml` equal to it.
- The collection `community.docker`, from the `ansible` package pinned in
  `ansible/requirements.txt`, on the machine that runs Ansible.
- On the target: Debian 13 (the release the test runs on), Python 3, the Docker CLI and
  the Compose plugin at the version `community.docker.docker_compose_v2` needs. The
  module reads it with `docker compose version --format json` and refuses an older one
  before it does anything else, with the message "need version 2.18.0 or later". The
  number is `MINIMUM_COMPOSE_VERSION` in `plugins/module_utils/_compose_v2.py` of the
  pinned collection; read it there after a bump of the collection. The role makes no
  second reading of the version: that would be a `command` whose output is parsed
  (ANS-9) on the same input the module already checks.
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
- `.compose_stack_stamp` in it: `root:root`, mode `0600`. It holds one SHA-256 digest
  of the compose file and the configuration file as rendered and of the secret files'
  names and content. No secret value is in it, but the digest is derived from them, so
  it is kept as closed as the secret files (only root reads it).
- When the stamp differs or a file changed: the containers of the services in
  `compose_stack_services` (every service if empty) are recreated and started, and the
  role waits up to `compose_stack_wait_timeout` seconds for them to be healthy. Whether
  Compose keeps the data in named volumes across a recreate is its documented
  behaviour and is not shown here (see the limits).
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
runs. A stack that starts and then fails its health check is reported as a success. A
`compose.override.yaml` left in the directory is merged without anyone reading it. Run
under `set -x`, it also prints the secret file's content into the log.

### (b) The Ansible shape

The deliveries do not notify anything. They register their result, and the stack is
brought up from the same play, by a task that reads the stamp:

```yaml
- name: Work out the stamp of the content this run delivers
  ansible.builtin.set_fact:
    compose_stack_stamp: >-
      {{ {'compose': compose_stack_compose_text, 'config': compose_stack_config_text, 'secrets': compose_stack_secret_files}
      | ansible.builtin.to_json(sort_keys=True) | ansible.builtin.hash('sha256') }}
  no_log: true

- name: Deliver the compose file
  ansible.builtin.template:
    src: compose.yaml.j2
    dest: '{{ compose_stack_project_dir }}/compose.yaml'
    owner: root
    group: root
    mode: '0644'
    validate: docker compose --project-directory {{ compose_stack_project_dir }} --file %s config --quiet
  register: compose_stack_compose_delivery

- name: Read the checksum of the recorded stamp
  ansible.builtin.stat:
    path: '{{ compose_stack_project_dir }}/.compose_stack_stamp'
    checksum_algorithm: sha256
  register: compose_stack_recorded_stamp

- name: Work out whether the stack must be brought up
  ansible.builtin.set_fact:
    compose_stack_up_needed: >-
      {{ compose_stack_compose_delivery is ansible.builtin.changed
      or not (compose_stack_recorded_stamp.stat.exists
      and compose_stack_recorded_stamp.stat.checksum == (compose_stack_stamp | ansible.builtin.hash('sha256'))) }}

- name: Bring up the stack
  community.docker.docker_compose_v2:
    project_src: '{{ compose_stack_project_dir }}'
    project_name: '{{ compose_stack_project_name }}'
    files:
      - compose.yaml
    services: '{{ compose_stack_services }}'
    state: present
    recreate: always
    build: never
    wait: true
    wait_timeout: '{{ compose_stack_wait_timeout }}'
    remove_orphans: false
    renew_anon_volumes: false
  when:
    - compose_stack_compose_file_stat.stat.exists
    - compose_stack_up_needed | ansible.builtin.bool

- name: Read the state of the stack's containers without changing it
  community.docker.docker_compose_v2:
    project_src: '{{ compose_stack_project_dir }}'
    project_name: '{{ compose_stack_project_name }}'
    files:
      - compose.yaml
    state: present
    build: never
    wait: false
  register: compose_stack_health
  check_mode: true
  changed_when: false

- name: Refuse a stack with a service that is missing, not running or not healthy
  ansible.builtin.assert:
    that:
      - compose_stack_missing | ansible.builtin.length == 0
      - compose_stack_not_running | ansible.builtin.length == 0
      - compose_stack_unhealthy | ansible.builtin.length == 0

- name: Record the content as brought up and healthy
  ansible.builtin.copy:
    content: '{{ compose_stack_stamp }}'
    dest: '{{ compose_stack_project_dir }}/.compose_stack_stamp'
    owner: root
    group: root
    mode: '0600'
  no_log: true
```

The snippet leaves out the other deliveries, the stat-gating and the variables of the
assertion, which are in [`tasks/main.yml`](tasks/main.yml). The digest check and the
override check come first in that file.

### (c) Why each parameter is set

- `owner`, `group` and `mode` are explicit on every file. Without them the file takes
  the umask and the user who ran Ansible. The configuration and secret files take a
  service user so the test can tell the parameter from the default (see the limits).
- **No handler.** A handler is notified by a task that reports a change, and the
  notification is lost if a later task fails in the same run: the next run finds every
  file already delivered, reports no change, and never calls `up`, while the health
  check keeps failing. That is the partial failure ANS-11 names. The stamp is the
  remedy: it is written last, only after `up` and the health check have succeeded, so
  every failure before that point leaves the old stamp and the next run brings the
  stack up again with no file changed. A side effect is that the role has no handler
  name, so two copies of the role in one play cannot trigger each other's `up` (see
  the limits for how that was checked).
- The stamp is compared by its checksum with `stat`, not read back. Reading a file's
  content needs the `slurp` module, which returns it encoded; `stat` returns the
  file's checksum, and the checksum of a file whose content is the stamp is a function
  of the stamp. The comparison then reports nothing as changed, so the second run of
  the idempotence step reports zero changes.
- The stack is also brought up when a delivery task reported a change in this run,
  even if the stamp matches. That is a file edited by hand and put back by the role: a
  container that bind-mounts one file keeps the inode it started with, so the
  container would otherwise keep running on the hand-edited file. The check mode of a
  plan reads the same results, so a plan shows the `up` it would make.
- A stack that has never been recorded healthy is brought up on every run until it
  passes, because every run finds the stamp missing or different. That recreates an
  unhealthy stack each time, which is the point; it is also the cost.
- `recreate: always`. A config file that a container only bind-mounts is not part of the
  container's configuration as Compose reads it, so a plain `up` would leave the old
  file in use. Recreating is the simple, safe reading. This is read from Compose's
  documentation and the module, and the test cannot show it (see the limits). It
  recreates every service in the project unless `compose_stack_services` names them.
- `build: never`. A stack that builds its own image has no digest to pin. The
  assertion refuses a service with a `build` key too.
- `wait: true` and a timeout. `up --wait` returns only when the services are running or
  healthy, and fails if one is unhealthy, so the failure comes with the `up`. The
  separate health check covers the runs where nothing changed.
- `remove_orphans: false` and `renew_anon_volumes: false` are the module's defaults,
  written out. The first would remove containers for services that were deleted from the
  file; the second throws away the data in every anonymous volume. Neither is for a
  deployment role, and writing them down is what lets the test assert on them. `state`
  is `present`: `absent` runs `down`.
- `files: [compose.yaml]` on both module calls. Without it Compose reads a
  `compose.override.yaml` that sits next to the compose file and merges it, and an
  image added there has not been through the digest check. Naming the file turns that
  merge off. The override check at the start of the role refuses such a file anyway,
  so the two do not rely on each other.
- `validate` on the compose file runs `compose config --quiet` on a temporary copy
  before the file replaces the old one, so a file Compose cannot read is never
  installed and the stack keeps running on the old one. The secret and configuration
  files come first in the task order because `config` reads the `env_file` the
  compose file names. Check mode does not run `validate`.
- The compose file is parsed (`ansible.builtin.from_yaml`) before the digest check, not
  searched with a pattern, so a tag in quotes, in a flow mapping, behind an anchor or in
  a comment is judged by what YAML says it is. The pattern is `NAME@sha256:` and exactly
  64 lower-case hex digits, anchored at both ends; `\Z`, not `$`, because `$` also
  matches before a final newline. A service with no `image`, with `build`, with
  `extends`, or a top-level `include` is refused, because each can bring in an image the
  assertion did not read.
- `no_log: true` and `diff: false` on the secret task, and no `loop_control.label`. The
  loop item holds the secret; `no_log` prints it as "censored". With `no_log` off the
  loop prints the whole item, which is how the test sees the control go (see the
  limits for `diff`). The stamp tasks are `no_log` too: the digest is derived from the
  secrets.
- The `stat`-gated skips (the `up`, the container read and the stamp). Check mode writes
  no compose file, so on a fresh host there is nothing for a dry run of `up` or a look at
  the containers to read. They run whenever the file is really on disk. The skip on a
  fresh host is the only one, and it is stated here (ANS-10); Ansible prints it as a bare
  `skipping`.
- `check_mode: true` on the container read. In that mode the module runs
  `up --dry-run` and then lists the containers, and changes nothing, in a real run as
  well as in a check run. It has to run in check mode so a drift run sees an unhealthy
  stack. The module's source for 5.4.0 (`plugins/modules/docker_compose_v2.py`:
  `cmd_up` passes `--dry-run` when `check_mode` is set, and `run` then calls
  `list_containers`) is what this rests on.

### The decision for the reviewer and the owner: modules for `up` and for the health read

ANS-9 says a module before a command. ANS-15 says the test never reaches a container
engine: the harness refuses a mounted engine socket and a `docker_host`, so the
instance has no Docker daemon and `docker compose` cannot really run in it. Those two
pull in different directions, and the pattern makes these choices.

**Both uses of Compose are the module `community.docker.docker_compose_v2`.** The
module exists, so ANS-9 says use it. It can be exercised without an engine, because it
drives the `docker` command line and parses what that prints. Its source (the pinned
5.4.0) was read for the calls it makes: `docker version --format '{{ json . }}'`,
`docker compose version --format json`, the `up` itself, whose progress it reads as
JSON lines on standard error, then `docker compose ps --format json --all --no-trunc`
and `docker compose images --format json`. The test installs a small stand-in for the
`docker` command in the instance (`molecule/default/files/docker_standin.sh`, installed
by `prepare.yml`): it appends its arguments to a log and prints canned answers in those
shapes. The module runs against it, and the verify play reads the log.

The health read is the same module in check mode, and its `containers` result carries
each container's `Service`, `State` and `Health`. An earlier version of this pattern
used a `command` for it, on the belief that calling the module again would run `up`;
in check mode it runs `up --dry-run` and lists the containers, and the module source
shows that. The `command` and its parse of `ps` output are gone.

What the stand-in can show: the role calls `up` for real exactly when the content
changed or a run failed before the stamp, with exactly the arguments in `verify.yml`
(the compose file named, the services scoped), that the role reads the module's
`containers` result as written, that an `up` that fails stops the role and is tried
again, and that a Compose version below the module's minimum is refused.
What it cannot show: that real Compose accepts those arguments (`--file`,
`--wait-timeout`, the temporary file name under `validate`), what real `up --dry-run`
does on an engine, in particular when images are not yet pulled and without `--wait`
(**unverified**), what real `up` reports as changed, or the real `ps` field set (the
stand-in sends a subset; the role reads only `Service`, `State` and `Health`). The
first live consumer's gated run is the real proof (ANS-17).

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

```text
python3 -m venv .venv
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/compose_stack
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/compose_stack --scenario widened
```

The first scenario is the one-application recipe. `molecule/widened/` is the caller's
contract: its own template, a configuration file in a directory of its own, a named compose
file, no secret, and the endpoint check. It refuses a configuration file name that climbs out
of the project directory, and an endpoint that does not answer; each refusal is asserted by
its own rescue. The harness lints the role and runs the scenario in `molecule/default/` on one
container, and exits non-zero if any step fails. It removes its container when it
finishes. There is no systemd in this scenario, so it takes none of the cgroup settings
`files_and_units` needs (the reason for each platform key is in `molecule.yml`).

What each part of the scenario does:

- `prepare.yml` creates the placeholder service user and group, and installs the
  `docker` stand-in with its state directory: `argv.log` (the real calls), `dryrun.log`
  (calls made with `--dry-run`) and `ps.json` (what `compose ps` prints). The switches
  in the directory that change the stand-in are `config_fails`, `up_fails` and
  `compose_version`.
- `check-fresh`: the converge in check mode on an instance with nothing installed. It
  completes; the `up`, the container read and the stamp are skipped for the reason in (c).
- `converge`: on an instance with no stack it applies the role in a series of phases
  (`converge.yml` lists them), counting the stand-in's real `up` calls around each.
  The first application, then each file edited alone (the configuration file, the
  secret, the compose file through the image): one `up` each. Then the retry phases:
  a run in which the stand-in's `up` fails, which must have called `up` once and
  stopped; the same values again, which must call `up` once; a run in which `up` works
  and a container then reports unhealthy, which must have called `up` once and
  stopped; the same values again, once; the same values a third time, none. Then the
  scenario's values with one service named, once, and a file changed by hand on the
  instance and put back, once. Last, the scenario's values with nothing edited: none. A
  converge on an instance that already has the stack runs only the last phase.
- `idempotence`: a second converge reports zero changed tasks and, by the last phase
  above, calls `up` zero times. This is the ANS-11 proof.
- `verify`:
  - owner, group and mode of the files and the directory;
  - every real `up` call is exactly one of the argument lists in `verify.yml` (the whole
    project, and scoped to one service), and every call the stand-in ever received is one of a
    short list: nothing else, in particular no `down`, `rm`, volume command or
    `--volumes`, `--remove-orphans` or `--renew-anon-volumes`;
  - `config --quiet` was run on a temporary copy and never on the installed file, and a
    refusing validator stops the role and leaves the installed file as it was;
  - the secret is not in any call;
  - the stamp file is a regular file owned by `root:root` with mode `0600`, holds one
    lower-case hex SHA-256 digest and nothing else, and holds neither the throwaway
    secret nor the secret files' names (the last check is defence in depth: it cannot
    fail while the digest-shape check passes);
  - each image reference in the list in `verify.yml` that is not pinned by digest stops
    the role at the digest check;
  - each state that `compose ps` can report in the list (unhealthy, still starting,
    exited, nothing at all) stops the role at the health check, and the healthy state
    passes again;
  - a Compose version below the module's minimum stops the role with the module's
    message;
  - a compose override file in the project directory, under each of the names Compose
    reads, stops the role at the override check;
  - a plan with check mode on and an edited image logs one `--dry-run` `up` that
    recreates and no real one, and every dry run names the compose file;
  - a scan of the whole run's log, kept by Ansible in a file in the scenario's
    ephemeral directory, for the throwaway secret, which is built from the harness's
    run id. The scan has a control: the converge prints a value on purpose, in a loop
    that does not set `no_log`, and the scan must find it. A scan that finds the control
    and not the secret is an all-clear that could have been red.
- `check-configured` and `molecule-check`: the configured instance shows no drift.

What breaks which step. Each row was done by an edit, one harness run, and a restore, as
an assertion failure and not a crash. The harness run is the retrieval: run it with the
row's edit made to see the message. The rows run in groups: the controls of the retry
rule and of the second-run rule, then the health states, then the other controls.

| Edit to the role                                                      | Step that fails                                                                            |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| The stamp comparison removed from the decision to bring the stack up  | `converge`, "Retried after a failed up: expected 1 real up call(s), the stand-in logged 0" |
| The stamp recorded before the health check instead of after           | `converge`, "Retried after a failed health check: expected 1 real up call(s) ... logged 0" |
| The "a delivery changed a file" terms removed from the decision       | `converge`, "File changed by hand and put back: expected 1 real up call(s) ... logged 0"   |
| The stack brought up on every run                                     | `converge`, "Settled after the retries: expected 0 real up call(s), the stand-in logged 1" |
| A `command` task that always reports changed                          | `idempotence`, naming the task                                                             |
| The not-running term removed from the health assertion                | `verify`, "A container that has exited: the health check did not refuse the stack"         |
| The unhealthy term removed                                            | `converge`, "Health check fails: the role did not stop for the expected reason"            |
| The no-container term removed                                         | `verify`, "No container reported at all: the health check did not refuse the stack"        |
| `failed_when: false` on the health assertion                          | `converge`, "Health check fails: the role did not stop for the expected reason"            |
| `check_mode: true` removed from the container read                    | `converge`, "First application: expected 1 real up call(s), the stand-in logged 2"         |
| The override assertion disabled                                       | `verify`, "compose.override.yaml: the role did not refuse the directory"                   |
| `files:` removed from the `up` call                                   | `verify`, "Every real up call must carry exactly the expected arguments"                   |
| `files:` removed from the container read                              | `verify`, "A call could remove volumes or was not expected" (a `ps` without `--file`)      |
| `services:` removed from the `up` call                                | `verify`, "Every real up call must carry exactly the expected arguments" (no scoped line)  |
| The stamp written from the unhashed content (the secret in the clear) | `verify`, "The stamp does not hold exactly one 64-character lower-case hex digest"         |
| The stamp written with mode `0644`                                    | `verify`, "The stamp file is missing, or is not a regular file owned by root"              |

Not repeated against this version of the role (they were each broken on the version
before it, and their tests are unchanged in kind): the digest assertion removed or
loosened, `no_log: true` removed from the secret task, `remove_orphans: true` or
`renew_anon_volumes: true`, `wait: true` turned off or `recreate: always` turned to
`auto`, `validate` removed, and the owner, group or mode of a delivered file loosened.
Treat those as reviewed controls until a copy breaks them again; the step to expect is
`verify` for each. `diff: false` removed with `no_log: true` kept is not caught (see
the limits). `state: absent` with `remove_volumes` is not an input (see the limits).

### What the test proves, and its named limits

- **Real Compose is not exercised.** Parsing of the compose file, image pulls,
  networks, volumes, the meaning of `--wait`, `--force-recreate` and `healthcheck`, and
  whether `docker compose config --quiet` accepts a temporary file with the suffix
  Ansible gives it are all untested. The stand-in answers from the module's source; it
  is not captured output of a real Compose. The module's "changed" report is the
  stand-in's, so the idempotence of `up` on a real engine is untested.
- **Read from documentation, unverified:** that a plain `up` does not recreate a
  container whose bind-mounted file changed (the reason for `recreate: always`), and
  that `up --force-recreate` keeps the data in named volumes. **Do not read this role
  as preserving volumes.** Compose's documentation says that `-V` recreates anonymous
  volumes and is silent on named ones; the role never passes `-V` and never removes a
  volume, but a recreate was not run against a real engine. A stack with a stateful
  service must list only its stateless services in `compose_stack_services`, so a
  change to the app's files does not recreate the database; a stack that lists nothing
  recreates the whole project.
- **The stand-in's failing `up` is not Compose's failing `up`.** The stand-in prints a
  plain line to standard error. Real Compose prints JSON error events, which the module
  turns into the message it reports. The stand-in reports a Compose version of 2.29.0 or
  later, so the module reads standard error with its JSON parser
  (`parse_json_events` in the pinned `_compose_v2.py`, chosen by `use_json_events`): that
  parser skips a line that is not JSON with a warning ("Cannot parse event from non-JSON
  line", visible in the harness log), and the module fails with "Return code 1 is
  non-zero" and the line in `stderr`. Only a reported version below 2.29.0 would make the
  module read the same line with its plain-text parser, which turns a lone line into a
  "General error" message; that path is not run here. The test reads the module's message
  and standard error together, so the control (a failed `up` is retried) is real; what the
  module reports for a real pull error is not shown. **UNVERIFIED** against a real
  engine.
- **UNVERIFIED, not run against real Compose:** whether `up --dry-run` works against an
  engine when images are not yet pulled; whether a scoped `up --force-recreate` with
  service names also recreates the named services' dependencies (the role's text says
  only the named services are recreated, which is read from documentation and not
  shown, so a service that another depends on may be recreated too); and whether
  named volumes survive a recreate. The first gated run is the proof (ANS-17).
- **The scope of `compose_stack_services` is a name check by Compose, not by the role.**
  A name that is not a service in the compose file is refused by Compose when it runs
  `up`, which the stand-in does not do. Tested: that the input reaches the module.
- **A stack that was healthy and later fails is reported, not restarted.** The health
  check fails every run until it is healthy again, but the stamp and the files are
  unchanged, so the role does not call `up`. Restarting such a stack is the restart
  policy's job or an operator's. The same holds for a healthy stack whose containers
  are later removed by hand: the stamp matches and no file changed, so every run
  reports it (the health check fails) and none repairs it, until an operator acts or a
  file changes. That is the price of calling `up` only on a content change; calling it
  on every health failure would recreate an unhealthy stack on each run. The reverse
  is also true: a stack that has never been recorded healthy is recreated on every run
  until it passes.
- **The stamp covers content, not metadata.** A change of `compose_stack_owner`,
  `compose_stack_group` or a mode alone is delivered, which reports a change and calls
  `up`, but is not in the digest. A stamp file that is deleted or edited makes the next
  run bring the stack up; that is the safe direction.
- **A weak secret could be guessed from the stamp by someone who can read it.** The
  digest is one-way and the file is root's, mode `0600`, as closed as the secret files
  themselves. It is not a secret store.
- **Two copies of the role in one play.** The earlier version shared a handler name,
  which makes two copies cross-fire: a change to one stack brought up the other. The
  handler is gone, and no `notify`, `listen` or `flush_handlers` is left in the role
  (a search of the role for those words finds none; it is the first check to repeat on
  a copy). The names the role does share across copies are its variables and its
  registered results, which carry the variable prefix that every copy renames, and
  the stamp file, which is inside the project directory. The scenario holds one role
  and no second copy, so a two-stack play cannot be written there without adding a
  second role directory; the check is by search, and it is not a test.
- **`state: absent` with `remove_volumes` is not an input.** The role hard-codes
  `state: present`. If a copy exposes either, it must refuse `remove_volumes` at the
  start of the role. Today the stand-in refuses a `down` call only incidentally, as an
  unknown call (exit 64), so the test does not name the control; it holds by
  default-deny, not by an assertion about volumes.
- **Services with no `healthcheck` pass on "running" alone.** The health check treats a
  container that is running and reports no health as healthy.
- **The compose file validator's output is not `no_log`.** If a malformed secret file
  named in `env_file` makes `compose config` print a line of it, the failure message
  would carry that line. This is from knowledge of Compose's error text and was not
  run; a copy whose secret files can be malformed should wrap the task and censor.
- **Other files Compose reads.** A `.env` file in the project directory is read by
  Compose for interpolation. The override check does not look for it, and the compose
  file is checked as rendered, so a `${NAME}` image is refused by the digest pattern,
  but a `.env` that changes some other field of a service is not seen.
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
- CI runs this scenario: the step "Run the harness over every role and pattern" in the
  Ansible workflow (`.github/workflows/ansible.yml`) expands `ansible/roles/*/` and
  `ansible/patterns/*/`, on a runner image the workflow pins. It runs the same harness
  as the local run above, on the runner's own Docker daemon.
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
2. Copy `tasks/main.yml`, `templates/` and the whole of `molecule/default/` over the new
   role's files. Do not add a handler: the stamp replaces it, and the role has no
   `notify`. Keep `namespace` in `meta/main.yml`.
3. Rename. The variable prefix `compose_stack_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, the tasks, the templates and the
   group variables in `molecule.yml`; this renames the registered results and the facts
   too. The role name `branchleft.compose_stack` becomes `branchleft.` and the new name
   in `converge.yml`, `verify.yml` and the `tasks/` files under `molecule/default/`. The
   project directory and project name appear in `converge.yml` and `verify.yml` too.
   Then search the new role for `notify`, `listen`, `handlers` and `flush_handlers`:
   none may be there.
4. Replace the placeholders: the services in `templates/compose.yaml.j2`, the
   configuration file, and the ALL_CAPS values in `meta/`. Every service's `image:`
   line takes its value from a variable or a literal that carries a digest; add a
   variable per image to the argument specification and give each a digest-pinned
   value in `molecule.yml`. Set `compose_stack_services` (under the new prefix) to the
   stateless services if the stack holds a database.
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

Change the tasks, the templates and the converge and verify plays together, run the
harness, and break the control you touched (the table above) to see it fail. A change
to the stand-in is a change to what the test believes the CLI does, so review it
against the module's source for the pinned collection version. A bump of the
`ansible` package in `ansible/requirements.txt` is its own change: re-read the calls
the new module version makes against the stand-in and the verify play's list, and the
minimum Compose version. An edit to a default is a change of behaviour on every host
that uses the role.
