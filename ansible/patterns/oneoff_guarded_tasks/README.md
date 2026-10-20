# oneoff_guarded_tasks

This role is a pattern. It is the recipe a maintainer follows when a shell script
runs a step once on a host, or runs a step that only a person may start, such as a
one-time data move, a step that needs a human's judgement, or a command that must
not run on an ordinary apply. It holds two placeholder steps that do nothing real.
Copy the shape, not the names.

## What it does, and what it does not

It makes a state directory that holds one marker file per one-off step that ran.
A step is skipped by a plain apply. It runs only when its tag is named on the
command line and `oneoff_guarded_tasks_confirm` names the same step id. A step
writes its marker only after its effect succeeded, and never in check mode, so a
step whose effect failed is tried again on the next request, and a step that ran
is not run again.

It does not run anything on a plain apply, does not decide what a real step does,
does not schedule anything, does not reach any host other than the one it is
applied to, and does not apply itself to a host. The steps it ships change one
placeholder file each, under `/var/tmp`, and nothing else.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. The step id
pattern is in `vars/main.yml`, not in the interface, so an inventory cannot loosen
it. No variable is a secret. A confirmation is a step id, a name and not a
credential.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version`
  in `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin`. The test uses `ansible-playbook` on the
  controller, which the harness puts on the path with the pinned tools.
- Target: a Linux host with `python3` and a root account. No systemd is needed:
  the role starts no service and reads no unit.

## What it changes on a host

- The state directory at `oneoff_guarded_tasks_state_dir`, owner `root`, group
  `root`, mode `0755`.
- One marker file per guarded step that ran, in that directory, named by the step
  id, owner `root`, group `root`, mode `0644`. Its content is the step id and a
  line break, and nothing else.
- The placeholder effects the scenario runs: `/var/tmp/EXAMPLE_STEP_ONE.effect`,
  mode `0640`, and a command that exits non-zero for `EXAMPLE_STEP_TWO`. A real
  role replaces these with its own effects.
- No package, no user, no service, no port, no firewall rule.

## The guard

A guarded step has two conditions and both must hold.

1. **The tag.** Each step is imported with two tags, `never` and the step's own
   tag (`oneoff_guarded_tasks_step_one`). Ansible runs a `never` task only when its
   tag is named with `--tags`. A plain apply, and `--tags all`, skip it.
2. **The confirmation.** `oneoff_guarded_tasks_confirm` must equal the step's id
   (`EXAMPLE_STEP_ONE`). A step that is named by its tag but not confirmed stops
   the play with a message that begins `REFUSED:`, and does not skip silently.

The tag alone is not enough, because a tag can be copied from one command to
another and a `--tags` list can name it by accident. The confirmation alone is not
enough, because a confirmation is only read when a tag asks for the step. Both are
needed, and the scenario proves each separately.

The confirmation check and the state directory carry the `always` tag, because
Ansible skips an untagged task under `--tags`. A confirmation is first checked
against the step id pattern in `vars/main.yml`, which ends with `\Z`, so a
confirmation with a line break in it is refused before any step reads it. A
confirmation that is not one text value (a list, a mapping or null) is refused by
the same check or by the step's own check, with the `REFUSED:` message.

**How the calling playbook must include the role.** The guard works only when the
role's tasks run under `--tags`. A playbook that calls the role with
`ansible.builtin.import_role`, or with `ansible.builtin.include_role` and
`tags: always` (as `molecule/default/request.yml` does), gets the `REFUSED:` message.
A playbook that calls it with `include_role` and no tag on the include exits 0 with
no task run and no message under a named tag, so the person believes the step ran.
That case is not refused by this role; the calling playbook must use one of the two
forms above.

The commands, with a placeholder step id:

```text
ansible-playbook -i INVENTORY_FILE PLAYBOOK_FILE --tags oneoff_guarded_tasks_step_one -e oneoff_guarded_tasks_confirm=EXAMPLE_STEP_ONE
```

Named with the tag and no confirmation, the same command stops with the `REFUSED`
message. A plain apply is the command without `--tags` and without the confirmation.

## The recipe

### (a) The bash shape it replaces

```bash
if [ ! -e /var/lib/EXAMPLE_STEP_ID.done ]; then
    EXAMPLE_COMMAND --EXAMPLE_ARGUMENT
    touch /var/lib/EXAMPLE_STEP_ID.done
fi
```

The script runs the one-off step on every apply that reaches the line, unless its
author remembered to guard it, and nothing stops a second run from another
caller. The guard is a convention a reader must find. A reader cannot tell from the
script whether the step is meant for an ordinary apply.

### (b) The Ansible shape

```yaml
- name: Guarded step EXAMPLE_STEP_ONE
  ansible.builtin.import_tasks: _step_one.yml
  tags:
    - never
    - oneoff_guarded_tasks_step_one
```

The imported file holds the confirmation check, the marker read, the effect and the
marker write:

```yaml
- name: Refuse EXAMPLE_STEP_ONE when its tag is named without its confirmation
  ansible.builtin.assert:
    that:
      - oneoff_guarded_tasks_confirm == 'EXAMPLE_STEP_ONE'
    quiet: true
    fail_msg: 'REFUSED: EXAMPLE_STEP_ONE was requested by its tag without oneoff_guarded_tasks_confirm set to EXAMPLE_STEP_ONE, so it did not run.'

- name: Read the marker of EXAMPLE_STEP_ONE
  ansible.builtin.stat:
    path: '{{ oneoff_guarded_tasks_state_dir }}/EXAMPLE_STEP_ONE'
  register: oneoff_guarded_tasks_step_one_marker

- name: Run the placeholder effect of EXAMPLE_STEP_ONE
  ansible.builtin.file:
    path: /var/tmp/EXAMPLE_STEP_ONE.effect
    state: touch
    owner: root
    group: root
    mode: '0640'
  when: not oneoff_guarded_tasks_step_one_marker.stat.exists

- name: Write the marker of EXAMPLE_STEP_ONE after its effect succeeded
  ansible.builtin.copy:
    content: "EXAMPLE_STEP_ONE\n"
    dest: '{{ oneoff_guarded_tasks_state_dir }}/EXAMPLE_STEP_ONE'
    owner: root
    group: root
    mode: '0644'
  when: not oneoff_guarded_tasks_step_one_marker.stat.exists
```

### (c) Why each parameter is set

- **`never` with a tag of its own.** `never` makes the step invisible to a plain
  apply. The step's own tag makes the request explicit, and a reader can search for
  it. `never` alone would let any `--tags never` run it, which names no step.
- **The confirmation.** The tag is a value a person types, and a tag can be copied.
  The confirmation names the step a second time, so a request states twice what it
  means to run. It is compared with `==`, which refuses a value with a line break in
  it, and it is checked against the pattern first so the refusal names the cause.
- **The state directory is root-owned, `0755`.** The markers are the record that a
  step ran, so the account a service runs as must not be able to delete or write
  them. The role sets the owner and the mode itself, so a directory left by an
  earlier release is corrected, not trusted.
- **The marker is written after the effect.** The write comes last, so a failed
  effect stops the play before a marker exists, and the next request tries again.
- **The marker holds the step id only.** It has no timestamp, so the file's content
  does not change between runs, and an unchanged marker reports no change.
- **The marker is gated on the stat.** The effect and the marker both run only when
  the marker is absent. A requested step that ran before does nothing on the next
  request.
- **The effect is `file` with `state: touch`.** It is the placeholder effect the
  scenario can read: a file with a mode. Touch reports a change on each run, so a
  step that is repeated when its marker exists is caught by the idempotence
  assertion, not missed.
- **Check mode.** The stat runs in check mode as it does in a real run, so a
  requested step in check mode reports the effect and the marker it would change,
  and writes neither. The `copy` of the marker supports check mode, so it reports the
  change it would make.
- **What check mode shows, and the true rule.** Ansible skips a task in check mode
  when the module does not support check mode, and `changed_when` does not apply to a
  skipped task. A skipped task reports nothing in the recap, so a check run cannot show
  that it would run. The placeholder effect of `EXAMPLE_STEP_ONE` (a `file` task, which
  supports check mode) and its marker (a `copy` task) are reported as changes in check
  mode, and the scenario asserts that per task. The command of `EXAMPLE_STEP_TWO` is
  skipped in check mode, so its check-mode result is "skipped", not "changed"; the
  pattern does not claim otherwise, and the limits name it. A real step whose effect
  must show in check mode uses a module that supports check mode, or a read-only
  command with `check_mode: false` and a stated reason (ANS-10).

### (d) What the test proves, and the named limits

Verify asserts these claims, in this order, and each assertion names the claim it
tests. Molecule's default sequence runs them, so each fails by default. A claim
marked "reviewed" is not run by the scenario.

- A plain apply runs neither step and writes no marker, and the state directory is
  root-owned, mode `0755`, over an account-owned directory.
- The tag alone, and a confirmation with a line break, are refused by name.
- Each wrong confirmation is refused by name: another step's id, a prefix, a list,
  and null, each with a step tag; and the second step's tag with the first step's id.
- The refusals changed no effect and no marker.
- A check-mode request reports the effect and the marker as changes per task, and
  writes neither.
- A request with its tag and confirmation runs the step, writes the marker with its
  owner, group, mode and text, and the effect has its mode.
- A second request changes nothing.
- A step whose effect fails writes no marker, and the next request runs the effect
  again (the command's failure text is asserted).
- A first request on a state directory that no plain apply made creates the directory
  and writes the marker in it.

Reviewed, not tested by the scenario: the marker task of `EXAMPLE_STEP_TWO` and its
group (see the limits), the `--tags never` run (see the limits), and forgery of a
marker by root (see the limits).

### (e) How a service role copies it

1. Copy `defaults/`, `vars/` (the step id pattern), `meta/argument_specs.yml` and
   `tasks/main.yml`, and rename the role. Keep the state directory and the marker
   naming, because the markers are the record.
2. Replace `_step_one.yml` and `_step_two.yml` with one file per real step. Give each
   file its step id (capitals, digits and underscore), its tag and its confirmation
   check, and import it in `tasks/main.yml` with the `never` tag and its own tag.
3. Keep the order inside each file: confirmation check, marker read, effect, marker
   write. Keep both marker conditions.
4. Replace the effects with the real ones. Use a module where one exists. A command
   needs `changed_when`, and it is an argument list with no shell (ANS-9).
5. Copy the test: `molecule/default/` with the platform block, the prepare, the
   converge, the request and the verify, with the step ids and paths of the real
   steps. Run the harness on the role.
6. Write the README for the service role, with the owner steps (see below) it needs.

## Owner steps: when a step is not automated

Choose a guarded task when the step is an effect the role can make on a host with
no judgement left to a person, and whose result a marker can record. Choose an
owner step when the step needs a decision, a value only a person holds, a
credential, or a step outside any host the role can reach: the role cannot record
those, so no marker is written for them. Do not put a credential or a host address
in this file.

An owner step is written in the role's README as a numbered step. The example below
is an owner step, not a guarded task. It is not run by the role.

### Step 1: EXAMPLE_OWNER_STEP_ONE

- **Who runs it:** THE_OWNER, from a terminal with the placeholder account
  EXAMPLE_OPERATOR.
- **Command:**

  ```text
  EXAMPLE_COMMAND --target EXAMPLE_TARGET --token-file EXAMPLE_TOKEN_FILE
  ```

- **What becomes true once it succeeds:** the file `EXAMPLE_TARGET_FILE` exists and
  holds the value `EXAMPLE_VALUE`.
- **How to tell it has been done:** the command
  `EXAMPLE_COMMAND --check --target EXAMPLE_TARGET` exits with status 0 and prints
  `EXAMPLE_ALREADY_DONE`.

Write each owner step with its step number, a name, who runs it, the exact command
with every value filled in as a placeholder in capitals, what is then true and how to
tell it has been done. An owner step writes no marker, so a repeat is the owner's
check to make, not the role's.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/oneoff_guarded_tasks
```

Run it through the harness, as the README above describes. The harness runs the
default Molecule sequence on the container, and the scenario does its requests
inside that sequence, in `verify.yml`.

What each part of the scenario does:

- `prepare.yml` makes the placeholder account and leaves the state directory owned by
  that account with mode `0700`, so the role must change both.
- `converge.yml` applies the role with no tag and no confirmation. Both steps are
  skipped.
- `idempotence` is the same converge run again, and reports no change.
- `verify.yml` runs, in order and each as an `ansible-playbook` run of `request.yml`
  on the controller against the same container:
  1. checks the plain apply left no effect and no marker, and the state directory is
     root-owned with mode `0755`;
  2. requests EXAMPLE_STEP_ONE by its tag alone, with a confirmation holding a line
     break, and with each wrong confirmation (another step's id, a prefix, a list, null,
     and the other step's tag with the first step's id), and asserts each is refused
     with its message;
  3. checks the refusals left no effect and no marker;
  4. requests EXAMPLE_STEP_ONE in check mode with the JSON callback, and asserts the
     effect and the marker are each reported as a change, then checks it wrote no
     marker and ran no effect;
  5. requests EXAMPLE_STEP_ONE with its tag and confirmation and checks the effect's
     mode, the marker's owner, group, mode and text;
  6. requests it a second time and asserts zero changes;
  7. requests EXAMPLE_STEP_TWO, whose effect fails, twice, and checks both fail, the
     second trying the effect again (the command's failure text), and that no marker was
     written;
  8. requests EXAMPLE_STEP_ONE on a state directory that no plain apply made, and checks
     the directory is created root-owned with mode `0755` and holds the marker.
- `check-configured` runs the converge in check mode on the configured container. It
  reports no change, because the steps are skipped.
- `molecule-check` is Molecule's own `check` action.

CI runs the same harness over every role and pattern, so the Ansible job runs this
test on each pull request that touches `ansible/`.

## How it is delivered

Nothing applies this role to a host from a laptop. ANS-17 describes the only
approved path: a gated workflow run against `main`, which applies the role with a
plan job before the approval and a second run that must report zero changes. The
trigger and the reusable workflow are separate work, and this pattern does not
wire them. A guarded step is requested by the approved workflow, not by a person at
a terminal, once that workflow exists. Until then no step runs on any host.

## How to change it safely

- A changed step needs a new step id. A marker already on a host carries the old
  id, and a step that keeps its id will be skipped as done on every host where it ran.
- Do not change the confirmation check, the `never` tag or the marker conditions to
  make a request pass. Each one is what a scenario assertion checks, so a change
  shows in `verify.yml`.
- Do not write the marker before the effect. Do not write it in check mode.
- A step's effect must support check mode, or it must report a change (see (c)).
- A new step is added with its own file, its own tag and its own confirmation. It
  does not reuse another step's tag or marker.
- The validators, the lint floor and the harness are not edited in a role pull
  request. A change to them is its own pull request.

## Named limits

- **The marker is host-local.** It is a file on the host, and a rebuilt host has none.
  A rebuilt host runs the step again when it is requested. A step that must run once
  for a whole fleet needs a record outside the host.
- **A changed step needs a new step id.** The role does not compare an effect with its
  marker. A marker says a step ran, not what it did.
- **A marker is not a lock.** Two requests run at once can both see no marker and
  both run the effect. The role does not coordinate requests.
- **The effects are placeholders.** `/var/tmp/EXAMPLE_STEP_ONE.effect` and the failing
  command do not stand for any real effect, so the test shows the guard and the marker,
  not that a real step is correct.
- **`file` with `state: touch` reports a change on each run.** That is what makes a
  repeated step visible to the idempotence assertion, and it means this pattern does
  not show a real effect's idempotence. A real step's effect must be idempotent itself
  or be gated by its marker, as here.
- **The command effect of `EXAMPLE_STEP_TWO` is not checked in check mode.**
  `ansible.builtin.command` is skipped in check mode, so the scenario makes no claim
  about the check-mode result of that step. A real command effect that must show its
  change in check mode needs a module, or a check of its own.
- **Step two's marker task never runs to completion.** Step two always fails, so the
  scenario never writes its marker. The marker task's text and group are the same
  template as step one's, and they are reviewed, not tested.
- **`--tags never` runs every never-tagged task, both steps included.** With a
  confirmation that names only one step, that step runs, then the other step refuses
  and the play stops: a partial effect followed by a failure. Each step still needs its
  own confirmation. A calling playbook must request one step per run.
- **A confirmation set as a variable in an inventory or a play is not a request.** It
  defeats the second key: any run that carries the variable runs the step whenever the
  tag is named. The confirmation is meant to be typed on the command line.
- **`oneoff_guarded_tasks_state_dir` takes any path.** A path that is not a host
  directory, or one shared with other users, is accepted, and the role sets it root
  `0755`. The caller chooses the directory; the role does not check it.
- **Root can forge a marker.** Anyone with root can create a file of a step's name, and
  the step is then skipped. The marker records that a step ran according to the host's
  own files; it is not a signed record.

## What it does not prove

- That a real step is correct, or that its effect is safe to run.
- That a step is run on the right host, or only once across hosts. The marker is
  host-local.
- That the approved delivery path runs it. That path is separate work.
- That every spelling of a command line is refused. The scenario tests the tag alone,
  the wrong confirmations listed above, the confirmation with a line break, and the tag
  with its confirmation; it does not test `--tags all` or other tag lists.
- That a changed role still refuses a tag without its confirmation. The scenario
  checks the two shipped steps; a new step needs its own check, which the README's
  "How a service role copies it" asks for.
