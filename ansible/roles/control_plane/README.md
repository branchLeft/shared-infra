# control_plane

This role puts the control-plane Compose stack on a host and brings it up in
the order a person would follow by hand: the host configuration directories,
the environment file and the master key (each written once), the stack's
files, the database, the one-off init phase of the sign-in service, the sign-in
service, the stack's unit, the deploy wrapper, and the DOCKER-USER isolation
policy. On a host where the stack already runs it starts nothing itself and
leaves the containers to the unit (see "A host where the stack already runs").
It is the second service role built on the monitoring stack's shape
(`ansible/roles/monitoring_stack`), and the differences from that role are
listed below.

This README follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does these, in order:

0. Settles its inputs before it writes anything (see "Inputs"): a secret file
   that holds no value needs its content given, and an image is read from the
   running stack when none is given. A missing input that is needed stops the run
   here, with nothing written.
1. Creates three directories: `/etc/branchleft`, `/etc/branchleft/control-plane`
   and the sign-in service's state directory. Their owners and modes are in
   `vars/main.yml`.
2. Writes `/etc/branchleft/control-plane.env` and the sign-in service's master
   key, each only while the file is absent or empty. The content comes from the
   inputs `control_plane_env_content` and `control_plane_masterkey`, both secrets
   supplied at run time, and needed only for a file that holds no value. A file
   that holds a value is never replaced, and its input is then never read. How the
   file is written without a window of wider access is under "Writing a secret
   without an exposure window" below. On every run it also sets the owner, group
   and mode of both files back to the values in `control_plane_secret_files`
   (`vars/main.yml`), so a file widened by hand is corrected. It never changes
   the content of either file.
3. Copies `compose.yml`, `compose.init.yml` and `pg_hba.conf` from
   `hetzner/control-plane/stack/` into `/opt/branchleft/control-plane`, as
   `root:root` mode `0644` in a `0755` directory.
4. Only where the stack is not yet deployed: starts the database alone and
   waits until it is healthy.
5. Only where the stack is not yet deployed: runs the sign-in service's init
   phase once, when the stamp file `/etc/branchleft/control-plane/zitadel-init.done`
   is absent, and then writes the stamp. The init phase is the only place the
   database administrator's credential is used.
6. Only where the stack is not yet deployed: starts the sign-in service alone and
   waits until it is healthy.
7. Enables `branchleft-compose@control-plane.service`, runs the deploy wrapper
   with the pinned image, and fails if the unit is not `active` afterwards.
8. Installs the DOCKER-USER isolation reconciler and its unit byte for byte from
   `hetzner/provision/`, enables the unit, and restarts it only when the
   reconciler or the unit changed.

The role never removes a volume, a file, an environment file, a master key or a
container. The sign-in service's data lives in a Docker volume, and
`docker compose down -v` is not run by any task.

### What the role does not do

- It does not generate the secrets. The runbook generated them on the host with
  `openssl`. Here they are inputs, so the value that reaches the host is the one
  the gated run was given. Where those values come from is a decision for the
  secrets pattern (`ansible/patterns/secrets_and_no_log`), not this role.
- It does not render or write the identity outputs file, the mail provider
  configuration, the identity reconciler or the owner's own sign-in. Those are
  later steps of the runbook and are not in this role.
- It does not install the deploy wrapper, the shared Compose unit template
  `branchleft-compose@.service`, or the Docker engine. Those are the deploy
  tooling and host baseline roles. The role calls the wrapper and enables the
  unit; it does not provide either.
- It does not delete a file that was removed from the stack directory. The
  runbook's rsync used `--delete`; this role copies, and a removed file stays on
  the host until someone removes it by hand.

## Interface

`meta/argument_specs.yml` declares the inputs. None is required. They are
`control_plane_app_image` (a digest-pinned reference, not a secret),
`control_plane_env_content` and `control_plane_masterkey` (secrets, `no_log: true`).
Two switches, `control_plane_bring_up` and `control_plane_start_units`, default to
`true`. `vars/main.yml` holds the paths of the stack. They are not inputs.

### Inputs

An empty string counts as not given.

- **The two secrets** are write-once, so the role needs a value only for a file that
  holds none. If `/etc/branchleft/control-plane.env` (or the master key file) is absent
  or empty and its content was not given, the run stops first with
  `control_plane[env-missing]` (or `control_plane[masterkey-missing]`), before any
  directory, file or container is touched. The message names the input and the
  path and never a value. A host that already runs the stack needs neither input.
  A fresh host needs both, once.
- **The image** is not a secret. When `control_plane_app_image` is given it is used
  as given: it is the way to upgrade. When it is not given, the role reads the image
  the stack's running portal container was created from, with two read-only
  commands (`docker ps` filtered on the Compose project `control-plane`, the service
  `portal` and `oneoff=False`, then `docker inspect` of that container), which run
  in check mode too and change nothing. The image used is then the one already
  running, so a run changes no image. The host is the source of truth for the image
  until a pin is given. With no pin and no portal container the run stops with
  `control_plane[image-missing]`; an image that is not `NAME@sha256:` and 64 hex digits
  stops it with `control_plane[image-not-pinned]`, as the deploy wrapper would.

### A host where the stack already runs

A stack is deployed when its portal container exists. Then the role does not run
Compose itself: no `up` of the database, no init phase, no `up` of the sign-in service.
The deploy wrapper restarts the stack's unit, and the unit starts the stack with its
own environment: the `EnvironmentFile` pair of `branchleft-compose@.service` read by
systemd, the project name in `compose.yml` and the project directory. That is by
construction the configuration the containers were started with, so Compose finds
every container unchanged and recreates none. The role's own `docker compose
--env-file` reads the same file with Compose's parser, and a password with a `$`, a `#`
or a quote in it parses differently there. That would be a changed config and Compose
would recreate the database, so the role leaves a running stack to the unit. A fresh host
still uses the direct commands, because the unit cannot start the applications before the
database and the sign-in service exist.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin` and the `ansible.builtin` modules
  named above. The Docker bring-up uses `ansible.builtin.command` with explicit
  arguments, so no Docker collection is needed.
- Target: Debian 13 with Docker Compose v2, systemd and the DOCKER-USER chain
  present (the app-host baseline). The role runs as root.
- The files come from this repository through the links in `files/`, so it must
  run from a checkout of the whole repository, which is what the gated pull
  delivers (ANS-17).
- Before the first run, the deploy wrapper, the shared unit template and the
  Docker daemon must already be on the host.

## What it changes on a host

- `/etc/branchleft` (`0755`), `/etc/branchleft/control-plane` (`0750`),
  `/var/lib/branchleft/control-plane/zitadel-state` (`0700`, owned `1000:1000`).
- `/etc/branchleft/control-plane.env` (`0600`, root) and
  `/etc/branchleft/control-plane/zitadel-masterkey` (`0400`, `1000:1000`), each
  created once, with their content written once. On every run their owner, group
  and mode are set back to these values, and their content is not changed.
- `/opt/branchleft/control-plane` (`0755`) and its three files (`0644`).
- Containers: the database and the sign-in service are started and healthy;
  the init phase runs once on a fresh database.
- The stack's unit is enabled and active; the deploy wrapper writes its image pin.
- `/usr/local/sbin/branchleft-docker-user-policy` (`0755`) and
  `/etc/systemd/system/branchleft-docker-user-policy.service` (`0644`). The
  policy is applied when either changed, and at every boot after.

### Writing a secret without an exposure window

Ansible's `copy` moves a new file into place at the mode `0666` minus the umask
(`0644`), and only then applies the role's mode. The environment file sits in
`/etc/branchleft`, which is `0755`, so a file created with its content would be
readable by anyone for that moment. The runbook closed this with `umask 077`.

The chosen approach is create-empty-then-fill. For each of the two secrets:

1. `copy` with empty content and `force: false` creates the file empty, at its
   final owner and mode (`root` `0600`; `1000:1000` `0400`). If the file exists
   it is left alone. A brief wider mode on an empty file exposes nothing.
2. The content is then written into the existing file. Ansible's `atomic_move`
   keeps an existing destination's mode and owner, so the new content is never
   at a wider mode than the file it replaces.
3. The content write has the condition "the file is absent or zero bytes long".
   That condition is the write-once rule: a file that holds a value is never
   written again. A run that stopped between steps 1 and 2 leaves an empty file,
   which the next run fills.

The directory `/etc/branchleft` stays `0755`: other roles' units and the deploy
tooling read files in it, so its mode is not this role's to narrow. A person who
puts a file in it by hand can still choose a wider mode. The task "Set the owner,
group and mode of each secret file on every run" corrects the owner, group and
mode of the two files it owns at every run, from the one list in
`control_plane_secret_files`. The create-empty and fill tasks read their owner
and mode from that list too, so the values are not written twice.

### Differences from the runbook

- On a host where the stack already runs (ops1 today) the init phase is not run
  and no stamp is written: the stack's existence is the evidence that it ran.
  Where the stack is not deployed, the init phase runs when the stamp is absent,
  which is the check the runbook made by hand.
- The isolation reconciler is restarted only when it or its unit changed. The
  installer the runbook ran restarted it on every run. The unit reasserts the
  policy at boot and after a Docker restart either way.
- Compose is started with `changed_when: false`. Compose's `--wait` fails the
  task when a service is unhealthy, and that is the check; Compose reports the
  containers it changed, and the task does not record them as Ansible changes.
  This keeps a second apply of one commit at zero changes.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/control_plane
```

The scenario in `molecule/default/` runs one systemd container with the Docker
and systemd bring-up switched off. `converge.yml` applies the role. The second
converge is the idempotence step. `verify.yml` checks:

- the owner and mode of every directory and file the role writes;
- that each stack file and each isolation file is byte-equal to its source in
  the repository, read by the controller and not through the role's links;
- that the environment file and the master key hold exactly the first apply's
  throwaway values;
- the write-once rule: the role is applied again with different values and both
  files must still hold the first values;
- the widened files: both files are widened by hand (owner, group and mode), the
  role is applied again, and each file's owner, group and mode must be back to
  the declared values, with the first values still in place;
- the interrupted run: both files are emptied by hand, the role is applied
  again, and both must be filled with the new values at the same owner and mode;
- the optional secrets: a run given empty contents leaves both files as they were;
- the refusals: with a secret file absent and its content not given, the run stops
  with its own code naming the input, and a stack file removed beforehand is still
  absent, so nothing was written;
- the image cases, with a stand-in for the `docker` command that answers the two reads:
  a given pin is used as given and `docker` is not called; with no image the one the
  stand-in reports is used, and the calls carry the project, service and one-off
  filters; with no portal container the run stops with `control_plane[image-missing]`;
  with a running image that is a tag it stops with `control_plane[image-not-pinned]`;
- that no throwaway value, from any apply, appears in the run's log.

`tests/unit/` reads `tasks/main.yml` and holds the structure the safety depends on:
every input refusal is before the first write, every task that runs Compose directly
is gated on a stack that is not yet deployed, the two reads of the running stack run in
check mode and change nothing, and no task uses the image as given.

The container does not run Docker, so the bring-up tasks, the stack's health and
the isolation policy's effect on the firewall are not proven by this scenario.

## Named limits

- **The Docker bring-up is not exercised.** No container of the stack is started
  in the test, and the reads of the running stack are answered by a stand-in, so
  the real output of `docker inspect` is not seen. The first live run through the
  gated pull is the proof.
- **Check mode does not run the deploy.** The compose commands and the deploy
  wrapper are `command` tasks that check mode skips; it shows the owner, group and mode
  corrections, the stack files and the isolation files only.
- **The host is the source of the image until a pin is given.** With no pin the role
  deploys whatever the portal container runs, so it cannot upgrade or roll back the
  image. A pin does.
- **The owner and mode of the secret files are corrected at each run, not
  continuously.** A file widened between two runs stays wider until the next run
  that reaches this role.
- **The absence of the exposure window is by construction, not observed.** The
  scenario proves the final owner, mode and content and the write-once rule. It
  cannot see the mode a file has for the moment a write takes, so it does not
  prove that no wider mode occurred.
- **The DOCKER-USER policy is not applied in the test.** The reconciler refuses
  on a host that is not an app host, and the test container has no DOCKER-USER
  chain.
- **The deploy wrapper and the unit template are not provided.** The role relies
  on them being present, as the runbook did.
- **Compose's state is not read back by Ansible.** `--wait` is the check; no task
  reads the container list after it.
