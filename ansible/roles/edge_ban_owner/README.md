# edge_ban_owner

This role installs the edge ban classifier on edge1: a program, a systemd service
and a systemd timer. The classifier decides, for each CrowdSec ban on the edge,
whether the banned address is one of the owner's own, and writes the answer as a
textfile that the monitoring stack's alert rules read.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the classifier decides

A ban is owned when its address made a verified staff request through the edge in
the last 30 days, or when the ban is a range that contains such an address. Every
other ban is unowned. If the classifier cannot read its signal (the access log is
missing, unreadable or empty, or no address is trusted), every ban is written as
owned, so that it pages. If the classifier cannot read CrowdSec, it writes nothing,
and the staleness alert fires.

The alert rules and the routes that act on this are in `hetzner/monitoring`; this
role only puts the classifier on the host.

## What the role does

It runs in this order, and each step changes only what it names.

1. Checks its inputs and refuses, before any change, a value of the wrong type or
   shape. No refusal message names a value.
2. Creates `/var/lib/branchleft/edge-ban-owner` (root, 0700): the directory of the
   state file, which holds the addresses. Nothing outside the classifier reads it.
3. Creates `/var/lib/branchleft/snds-exporter` (root, 0755) if it is absent. Other
   roles make the same directory with the same owner and mode.
4. Creates `/usr/local/lib/branchleft-edge-ban-owner` (root, 0755), the directory
   the program is installed into.
5. Installs `branchleft_edge_ban_owner.py` into that directory (root, 0755). The
   copy is checked by the program's own `--check` before it replaces the installed
   file, so a broken program is never installed.
6. Renders `branchleft-edge-ban-owner.service` and `branchleft-edge-ban-owner.timer`
   into `/etc/systemd/system` (root, 0644), and reloads systemd when they changed.
7. Enables and starts `branchleft-edge-ban-owner.timer` once its unit file exists.

The service runs the program as root with every option set from the role's
defaults. Its hardening: `Type=oneshot`, `TimeoutStartSec=240`, `UMask=0077`,
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict` with the state directory and
the textfile directory writable, and `After=docker.service`. The timer fires on
`*:0/5` (every five minutes) with `Persistent=true`.

The program reads the Caddy container's access log and CrowdSec's decisions through
the Docker command, not through a host path. Its textfile is
`edge_ban_owner.prom` in the directory node_exporter reads. The textfile holds no
address. Only the state file holds addresses.

## Interface

The variables the role reads, their types and defaults are in
`meta/argument_specs.yml`. `defaults/main.yml` holds the same defaults. The
defaults name the edge's Compose project and its container services, the access
log's directory and stem, the 30-day window, the state and textfile paths, the
program directory, the unit name, and the timer schedule.

No variable of this role is a secret. The role reads no token and no credential
file.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- On the target, `/usr/bin/python3` (Python 3.12 or later), the Docker command at
  `edge_ban_owner_docker_binary`, and the edge's Compose containers running.
- Target systems: edge1 only, through the edge play in `ansible/playbooks/edge1.yml`.

## What it changes on a host

- `/var/lib/branchleft/edge-ban-owner` (root, 0700), created if absent.
- `/var/lib/branchleft/snds-exporter` (root, 0755), created if absent.
- `/usr/local/lib/branchleft-edge-ban-owner` (root, 0755), created if absent, and
  `branchleft_edge_ban_owner.py` in it (root, 0755).
- `/etc/systemd/system/branchleft-edge-ban-owner.service` and `.timer` (root, 0644).
- The timer is enabled and started.

The classifier writes two files at run time, not through this role: the state file
`trusted.json` (root, 0600) and the textfile `edge_ban_owner.prom` (0644). Both are
written atomically.

## How to test it

The static checks run from `ansible/`, with the virtual environment that holds the
pinned tools:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/edge_ban_owner
```

The harness runs lint, yamllint, the argument-spec check and the container test.
The container test needs a local Docker daemon. The program's own unit tests run
from the role directory, as `ansible/checks/run_role_unit_tests.py` runs them.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. Nothing applies this role to a host from this change.
Merging the change does not alter edge1; the gated apply does, and the owner
decides when.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the spec
   and the defaults must agree.
2. Keep every task able to run under `--check --diff`.
3. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
4. A change to the program's CLI options changes the unit's `ExecStart` and the
   program together, in one commit.
5. Run the test command above before opening a pull request.
