# control_plane

This role puts the control-plane Compose stack on a host and brings it up in
the order a person would follow by hand: the host configuration directories,
the environment file and the master key (each written once), the stack's
files, the database, the one-off init phase of the sign-in service, the sign-in
service, the stack's unit, the deploy wrapper, and the DOCKER-USER isolation
policy. It is the second service role built on the monitoring stack's shape
(`ansible/roles/monitoring_stack`), and the differences from that role are
listed below.

This README follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does these, in order:

1. Creates three directories: `/etc/branchleft`, `/etc/branchleft/control-plane`
   and the sign-in service's state directory. Their owners and modes are in
   `vars/main.yml`.
2. Writes `/etc/branchleft/control-plane.env` and the sign-in service's master
   key, each only when the file is absent. The content comes from the inputs
   `control_plane_env_content` and `control_plane_masterkey`, both secrets
   supplied at run time. A file that exists is never replaced.
3. Copies `compose.yml`, `compose.init.yml` and `pg_hba.conf` from
   `hetzner/control-plane/stack/` into `/opt/branchleft/control-plane`, as
   `root:root` mode `0644` in a `0755` directory.
4. Starts the database alone and waits until it is healthy.
5. Runs the sign-in service's init phase once, when the stamp file
   `/etc/branchleft/control-plane/zitadel-init.done` is absent, and then writes
   the stamp. The init phase is the only place the database administrator's
   credential is used.
6. Starts the sign-in service alone and waits until it is healthy.
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

`meta/argument_specs.yml` declares the inputs. The required ones are
`control_plane_app_image` (a digest-pinned reference), `control_plane_env_content`
and `control_plane_masterkey`. The two secrets carry `no_log: true`. Two switches,
`control_plane_bring_up` and `control_plane_start_units`, default to `true`.
`vars/main.yml` holds the paths of the stack. They are not inputs.

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
  created once.
- `/opt/branchleft/control-plane` (`0755`) and its three files (`0644`).
- Containers: the database and the sign-in service are started and healthy;
  the init phase runs once on a fresh database.
- The stack's unit is enabled and active; the deploy wrapper writes its image pin.
- `/usr/local/sbin/branchleft-docker-user-policy` (`0755`) and
  `/etc/systemd/system/branchleft-docker-user-policy.service` (`0644`). The
  policy is applied when either changed, and at every boot after.

### Differences from the runbook

- The init phase runs only when the stamp is absent. The runbook skipped it on
  an initialised host by hand; the stamp does the same check.
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
- that the environment file and the master key hold a throwaway secret, and
  that the same secret does not appear in the run's log.

The container does not run Docker, so the bring-up tasks, the stack's health and
the isolation policy's effect on the firewall are not proven by this scenario.

## Named limits

- **The Docker bring-up is not exercised.** No container of the stack is started
  in the test. The first live run through the gated pull is the proof.
- **The write-once rule is reviewed, not run.** The copy with `force: false` is
  the control; the scenario writes once with fixed inputs and cannot show a
  second, different value being refused.
- **The DOCKER-USER policy is not applied in the test.** The reconciler refuses
  on a host that is not an app host, and the test container has no DOCKER-USER
  chain.
- **The deploy wrapper and the unit template are not provided.** The role relies
  on them being present, as the runbook did.
- **Compose's state is not read back by Ansible.** `--wait` is the check; no task
  reads the container list after it.
