# tenant_compose

Delivers the compose stacks of an app host: one stack for each tenant, and the host's one mail spool.
The stacks are the output of the platform's renderer, and this role writes that output to the host
and restarts a stack when what it runs on has changed.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The renderer (the platform's `render-core`, in the Ghost platform repository) stays code. It
produces, for each tenant, a compose file, the list of secrets the tenant needs, and the image
pin; and for the host, the mail spool's compose file. The role takes that text as arguments and
delivers it. It never renders anything.

For each tenant the role:

1. Judges the text with the module `tenant_compose_check` and writes nothing if any stack is refused.
2. Asks the volume program to make the tenant's volumes, when the program does not list the
   tenant's uid. This replaces the generated `provision.sh`, which called the same program.
3. Writes the compose file, the secrets file and the image pin.
4. Enables the tenant's unit, `branchleft-compose@<slug>`, and restarts it only when it must (below).

When a mail spool is given it is delivered first, because the tenants' per-uid networks belong to
the spool's stack. It is delivered only after the host's firewall is read back and shown to fence
in the spool's drain bridge (below).

**The rule that no automated path may write a tenant's secrets file is retired.** The owner ruled
that automation writes them. The renderer's own header comments and other documents still say the
old rule; they are out of this role's reach and are corrected where they live.

What the role does not do:

- It does not render. A change to what a stack says is a change to the renderer.
- It does not install the volume program, the deploy wrapper, the compose template unit or the
  deploy lock. The tenant onboarding role installs the program (and the role fails closed, naming
  it, when the program is missing); the deploy tooling role installs the rest.
- It does not create the mail spool's data volume or give it its owner, and it does not write the
  spool's token file, `/etc/branchleft/mail-spool.env`, which the owner places.
- It does not advance an image. The deploy wrapper is the only writer that advances a tenant's pin.
- It never runs `down`, removes a volume, and never removes a tenant that drops out of the list.
  Decommissioning a tenant is a different job.
- It does not apply itself to a host. See "How it is delivered".

The role takes no secret from the repository. The secrets arrive as arguments at run time.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable, and
[`defaults/main.yml`](defaults/main.yml) holds the defaults. The role reads three:

- `tenant_compose_stacks` is required and has no default. It is a list with one entry for each
  tenant of this host: `slug`, `uid`, `compose_text`, `secrets_env_text` and `image_env_text`. The
  list names tenants, so it is never kept in this repository.
- `tenant_compose_mail_spool_text` is the mail spool's compose file. It is empty by default, which
  means this host has no spool to deliver.
- `tenant_compose_spool_isolation_required` is `true` by default. Leave it so.

**The secret variable is `tenant_compose_stacks[].secrets_env_text`.** It has no default (ANS-16),
is marked `no_log` in the specification, and every task that handles it hides its output.

The fixed paths, modes and unit name are in [`vars/main.yml`](vars/main.yml), and the inventory
cannot change them. The module's own interface is in its `DOCUMENTATION` block:

```text
.venv/bin/ansible-doc -t module -M ansible/roles/tenant_compose/library tenant_compose_check
```

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, with `min_ansible_version` in
  `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin`.
- On the target: Debian 13, `python3` with PyYAML (ansible-core itself depends on PyYAML, so a host
  that pulls its own playbooks has it), `flock` and `systemctl`, and `iptables` when a spool is given.
- Already on the host: `/opt/branchleft` and `/etc/branchleft` (the deploy tooling role makes them),
  the compose template unit `branchleft-compose@.service` (the deploy tooling role installs it), and
  the volume program at the path in `vars/main.yml` (the tenant onboarding role installs it).

## What it changes on a host

For each tenant `<slug>`:

- `/opt/branchleft/<slug>/`: `root:root`, `0755`.
- `/opt/branchleft/<slug>/compose.yml`: `root:root`, `0644`. A user who can write the compose file
  can start any container as root, so the file is not the tenant's.
- `/etc/branchleft/<slug>.env`: `root:root`, `0600`. It is made empty and closed first and the
  content goes into the existing file, so the content is never readable by others.
- `/etc/branchleft/<slug>.image.env`: `root:root`, `0600`. Created once, with the pin the renderer
  produced, and **never replaced afterwards**. The deploy wrapper advances the pin, and a run of this
  role must not roll an image back.
- `/opt/branchleft/<slug>/.tenant_compose_stamp`: `root:root`, `0600`. One SHA-256 digest of the
  compose text and the secrets text. It is derived from the secrets, so it is kept as closed as they are.
- `/etc/branchleft/<slug>.deploy.lock`: created by `flock` if absent. The deploy wrapper takes the same file.
- The tenant's volumes and its claim in the volume program's register, once, through the program.
- The unit `branchleft-compose@<slug>`: enabled, and restarted when the next section says so.

For the spool, `mail-spool` takes the place of `<slug>`, with no secrets file and no volume program
call. Its pin file is replaced whenever it differs, because it is derived from the digest in the
spool's compose file, which has no `${IMAGE}`.

No port is opened, no user or group is made, and no firewall rule is written. The role only reads
the firewall.

### When a stack is restarted

A restart goes through `flock` on the deploy lock, the lock the deploy wrapper takes around its own
read-modify-write-restart, waiting as long as the wrapper does. A restart reruns the unit's
`docker compose up --wait`, which is the health gate: it fails when a service is not running and
healthy. The stack is restarted when:

- a delivery changed a file in this run, which covers a file edited by hand and put back; or
- the stamp on the host is not the stamp of the text being delivered. The stamp is written last,
  and only after the unit is active, so a run that fails anywhere before then is followed by a run
  that restarts the stack, though no file changes the second time.

The stamp covers the compose text and the secrets text. It leaves out the pin, which moves on its own.

**First adoption of a stack that is already running restarts it once**, because it has no stamp
yet. After that, a run of the same content restarts nothing, and a role run reports zero changes.

A run also fails when a stack's unit is not active, whether or not anything changed. A unit whose pin
file is missing is inactive, not failed, so the check reads `ActiveState`.

### What is refused, and when

Everything that can refuse runs over every stack before anything is written, so a refusal on one
stack leaves the host exactly as it was. The module `tenant_compose_check` is pure: it reads text
and returns sentences that name a rule, a service or a key, never a value. It refuses:

- a slug or uid of the wrong shape (uids are 30000 to 30999), a compose `name` that is not the slug,
  a top-level key other than `name`, `services`, `networks` and `volumes`;
- a service whose image is not exactly `${IMAGE}`, or that sets `build`, `extends`, `privileged`,
  `network_mode`, `cap_add` or `devices`, or mounts the Docker socket;
- a published port that does not bind one specific address (`0.0.0.0`, `::` or none);
- a network or a volume that is not `external`;
- a `${GHOST_*}` reference with no key in the secrets text (the other direction is allowed: the
  secrets text may hold a key the compose file does not use), a referenced key whose value is empty,
  a key that does not start with `GHOST_` (so the secrets file can never override the pin), a
  duplicate key, a line that is not `KEY=value`, a control character, and a variable the role does not supply;
- a pin that is not exactly one `IMAGE=<name>@sha256:<64 hex digits>` line;
- a uid the volume program lists for another slug, or a slug it lists with another uid.

This list is deliberately smaller than the renderer's own posture checks (`assertRuntimePosture`
and `assertSpoolPosture`), which stay their one home. These are the rules that make delivering a
file unsafe, not a second copy of the renderer's.

The spool has its own profile. Its image is pinned inline by digest; its networks may be its own
(an `internal` network for each uid, and one bridge named `br-mailspool`); it has one service and
publishes one port, on `127.0.0.1`; and it takes no secrets file. It is also refused unless
`iptables -S` shows the drain bridge fenced in: the established-traffic accept first among the
rules that name the bridge in `INPUT`, a drop for the rest of `INPUT`, and a drop in `DOCKER-USER`
for what the bridge forwards out. These are the rules the app-host isolation policy writes.

### Named limits

1. **A failed restart after changed files leaves the stack down with the new files and the old
   stamp.** The role does not restore the old compose file. The checks above run before any write,
   which makes that rare, and the next run retries the restart.
2. **The test uses a stand-in for `branchleft-compose@`.** The template unit belongs to the deploy
   tooling role, and a container has no Docker engine. The stand-in has the properties the role
   depends on (the pin assertion, the environment files, a oneshot that stays active, a command that
   fails when the stack does not come up), but the real unit's properties are proven only by the
   first live run.
3. **The module needs PyYAML** on the host's `python3`. It uses `safe_load` and no other
   third-party import.
4. **The checks do not inspect bind mounts other than the Docker socket, or `pid` and `ipc`
   modes.** The renderer's posture checks own those.
5. **The firewall read-back covers IPv4 only,** and the first rule that names the bridge must be the
   established accept; a rule of another tool ahead of it is not examined. The spool's drain
   bridge carries no IPv6 network.
6. **The values in the secrets text are written as given.** How systemd and Compose each parse a
   quote, a backslash or a `$` in a value is not checked.
7. **The role cannot tell a stack the owner stopped on purpose from a failed one.** Both fail the
   active check.

## How to run its test

From the repository root, with the tools installed as `ansible/README.md` describes, one command runs
lint, yamllint, the interface checks and the container test:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/tenant_compose
```

The module's unit tests, type check and lint run from the role's directory and need no container;
CI runs them (`ansible/checks/run_role_unit_tests.sh` and the module lint step):

```text
PYTHONPATH=library ../../../.venv/bin/python -m unittest discover -b -s tests/unit -p "test_*.py"
../../../.venv/bin/mypy --config-file pyproject.toml library tests
../../../.venv/bin/ruff check .
../../../.venv/bin/ruff format --check .
```

The container test (`molecule/default/`) starts a Debian 13 container with systemd, installs stand-ins
for the volume program and the compose template unit (they record what they are asked and never
touch a container), and fences the spool's drain bridge with real `iptables`. It then:

- applies the role to two placeholder tenants and a spool, and edits one stack at a time, counting the
  starts the unit stand-in recorded: only the stack whose content changed restarts;
- advances a pin as the deploy wrapper does and applies the old pin again: the pin stays, nothing restarts;
- makes the stand-in unit fail, so the restart fails and the run stops, and applies the same values
  again: the stack restarts (the stamp was not recorded), then once more: nothing;
- drops a tenant out of the list and puts it back: nothing is removed, nothing restarts;
- refuses, in turn, an image tag, a port on every address, a missing secret key, a uid another tenant
  holds, a spool whose firewall rule is gone, a host without the volume program and a stopped unit,
  and checks that each refusal started nothing and changed no file, though another stack's edit was in the same run;
- scans the whole run's log for the throwaway secrets, with a control (the converge prints a value
  on purpose, and the scan must find it).

Every secret in the test is a throwaway made for the run from the harness's run id.

### What breaks which step

Each row was done by an edit, one run, and a restore.

| Edit to the role                                                  | Step that fails                                                   |
| ----------------------------------------------------------------- | ----------------------------------------------------------------- |
| Take `no_log` off the task that judges each tenant's stack        | `verify`: the log scan finds a throwaway secret in the run's log  |
| Let the module accept an image tag and a port on every address    | the unit tests, and `converge` at the image-tag refusal           |
| Replace the image pin on every run (`force: true`)                | `converge`, at the pin the deploy wrapper advanced                |
| Record the stamp before the restart, not after the unit is active | `converge`, at the run that retries after a failed restart        |
| Skip the read-back of the spool's firewall rules                  | `converge`, at the refusal of a spool whose firewall rule is gone |

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17): a plan job in check mode, the
approval of the protected environment, `ansible-pull` of that exact commit of `main`, and a second
run that must report zero changes. **Only `app1` applies this role.** `playbooks/app1.yml` applies
it as its last role, and `app1` is the only host with it on its list in `ansible/checks/host_roles.yml`.
It is last because it restarts the tenants' live stacks: a failure there must not hold the website
role back.

The wiring has three requirements:

- The role runs after the deploy tooling role, which makes the directories, installs the template
  unit and, on an app host, the isolation policy that fences in the spool's drain bridge. The role
  reads that policy back, but the order is the playbook's to keep. A test
  (`ansible/checks/test_tenant_compose_wiring.py`) fails when `tenant_compose` is applied before
  `deploy_tooling` in a playbook that applies both.
- The role runs after the tenant onboarding role, which installs the volume program. **That role
  is not applied to app1 yet:** today the program is the hand-installed one, and the role fails
  closed, naming it, when the program is absent.
- The stacks' text and the secrets reach a host that pulls its own commit with no extra variables
  through the `host_inputs` loader, which sets `tenant_compose_stacks` from the host's one
  root-only file (`/etc/branchleft/host-inputs.json`, root:root, `0600`; the file's shape is in
  `ansible/roles/host_inputs/README.md`). The role takes them as an argument with no default, so a
  host without the key stops at `host_inputs[missing-key]` before any role runs.
  `ansible/tools/seed_host_inputs.py --host app1 --set tenant_compose_stacks` fills the key from
  the tenants' live files and leaves every other key of the file as it was, so the first apply
  changes no file. Do not use `--replace` on a file that already holds keys with no live source (it
  rebuilds the whole file and would ask for them again).

Named limits of this wiring:

1. **The mail spool is not wired.** `tenant_compose_mail_spool_text` keeps its role default (empty),
   because the loader refuses an input that has a default and an empty value. Wiring the spool
   needs its own change; the spool on app1 stays as it is.
2. **A new tenant's stack does not reach the file by itself.** The seed reads the stacks that exist
   today. Getting a newly rendered stack into the file is the renderer path's change, a separate
   one; until it exists, a new site needs the file edited by the owner.
3. **The pin in the file goes stale by design.** The role writes a tenant's pin once and never
   replaces it, so the pin in the file only matters for a tenant that has none.
4. **The first apply restarts every tenant stack once** (see "When a stack is restarted"), and
   the plan job's check-mode output is the preview.

In a plan (check mode) the role reads everything it needs and says, in a line, which stacks it
would restart and which tenants' volumes it would make; the restart, the volume program and the
unit's state are not run, and the plan says so.

### Rotating a tenant secret or changing its compose

After the first apply, the role is the only writer of a tenant's files. Every gated or nightly
apply writes the text in `host-inputs.json` over `/etc/branchleft/<slug>.env` and
`/opt/branchleft/<slug>/compose.yml`, and restarts the stack if they differ. So an edit made on the
host to either file, however it was made, is put back by the next apply, and the stack restarts on
the old value. The plan job hides the secret's diff, so the revert shows only as "changed".

A rotation, or a change to a compose file, must therefore go through `host-inputs.json`, in one
sitting, as root on app1:

1. Change the live file (`/etc/branchleft/<slug>.env` or `/opt/branchleft/<slug>/compose.yml`).
2. At once, run the command below. It reads every tenant's live files again, changes that key only,
   and prints tenant names and never a text.
3. Only then let an apply run. It finds the file and the host agree, and restarts that one stack
   once, because the stamp on the host is not the stamp of the new text.

```text
python3 -I /var/lib/pull-trigger/current/ansible/tools/seed_host_inputs.py --host app1 --set tenant_compose_stacks
```

The command refuses, and writes nothing, when a tenant would drop out of the list: a slug already
in the file that the new read does not return, or a claimed tenant with no stack on the host. It
names the slugs and never a text. Without this the role would stop managing that tenant, silently.
The tool has no path to remove a tenant on purpose; that is a later change, and until it exists a
tenant stays listed (decommissioning is a different job, and the role never removes a stack). If a
stack is unusable, mend its files and run the command again.

If an apply runs between steps 1 and 2 it writes the old text back, and step 2 would then seed the
old text too; check the file is as you left it before you seed. Never use `--replace` for this: it
rebuilds the whole file, and a key that only ever had a typed value (such as
`deploy_slot_keys_slots`) is asked for again, or lost if the tool run does not know it.

## How to change it safely

- A change to a rule is a change to the module and its tests together. Every rule has a unit test that
  fails when the rule is loosened; keep each one red when you break its control, then restore it.
- Keep the split in the module between the pure judgement (`judge`) and the role's tasks, which are
  the only code that changes the host. The module must never write a file or run a command.
- Never log a secret. Every task that reads, templates or passes `secrets_env_text`, or the stamp
  that is derived from it, sets `no_log: true` and `diff: false`. Never loop over the list of stacks
  in a task that can fail and is not `no_log`: a failed looped task prints the whole item.
- The stamp is written last. A task added after the restart must not be able to fail without the stamp
  being left behind, and nothing may be recorded before the unit is shown active.
- A new input is added to `meta/argument_specs.yml` and `defaults/main.yml` together, with the role's prefix.
- Run the harness, the unit tests and the type check before every push, and never loosen
  `verify.yml` or a unit test to make a change pass.
