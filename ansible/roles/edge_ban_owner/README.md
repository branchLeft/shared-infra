# edge_ban_owner

This role installs the edge ban classifier on edge1: a program, a systemd service
and a systemd timer. The classifier decides, for each CrowdSec ban on the edge,
whether the banned address is one of the owner's own, and writes the answer as a
textfile that the monitoring stack's alert rules read.

The role ships disabled. While `edge_ban_owner_enabled` is false, which is its
default, it installs nothing on the host. See "The toggle" below.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the classifier decides

A ban is owned when its address made a verified staff request through the edge in
the last 30 days, or when the ban is a range that contains such an address. Every
other ban is unowned. If the classifier cannot read its signal (the access log is
missing, unreadable or empty, or no address is trusted), every ban is written as
owned, so that it pages. If the classifier cannot read CrowdSec, it writes nothing,
and the staleness alert fires.

"Owned" is wider than the owner's own addresses. A verified staff request is any
Ghost staff session the edge confirmed, so the staff addresses of every tenant's
Ghost count as owned, not only the owner's. Those addresses are held only in the
root-only state file, `/var/lib/branchleft/edge-ban-owner/trusted.json` (mode
0600), for at most 30 days, the edge's log retention. The textfile and the alerts
carry no address. Each owned ban is one sample labelled with CrowdSec's decision
id, which is an integer and holds no address, so a second owned ban of the same
scenario is a new alert. Unowned bans are counted per scenario.

The alert rules and the routes that act on this are in `hetzner/monitoring`; this
role only puts the classifier on the host.

## The toggle

`edge_ban_owner_enabled` is a boolean and defaults to false, in
`defaults/main.yml` and in `meta/argument_specs.yml`. The role still checks its
inputs when the toggle is false, and a value that is not a real boolean (a string
such as `"false"`, for example) is refused. After the checks it stops: it creates no
directory, installs no program, writes no unit, enables no timer and queues no
handler.

The role ships disabled until the owner has answered which addresses count as
theirs, because "owned" includes every tenant's staff addresses (see above). Until
the toggle is true on the host, every ban pages as before: the owned-only alerts
exist in the rules, but no classifier writes the textfile, the staleness alert goes
to the `discard` receiver, and the fallback of the ban alert pages every ban at once,
because the textfile series has never existed. The 10-minute hold applies only after a
classifier has reported and then gone quiet.

Turning it on is one later data commit. Set `edge_ban_owner_enabled: true` for the
edge host, and set the constant `EDGE_BAN_OWNER_ENABLED` in
`hetzner/monitoring/render.ts` to true in the same commit, then run
`pnpm run render` in `hetzner/`. The two values must agree: a test in `hetzner/monitoring`
fails when the constant and this role's default differ. After the gated apply the
timer writes the textfile within five minutes, and from then on only owned bans
page, the staleness alert is routed, and unowned bans go to email.

## What the role does

When the toggle is true, it runs in this order, and each step changes only what it
names.

1. Checks its inputs and refuses, before any change, a value of the wrong type or
   shape. No refusal message names a value. With the toggle false, the role ends
   here.
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
`meta/argument_specs.yml`. `defaults/main.yml` holds the same defaults. The toggle
is described above. The other defaults name the edge's Compose project and its container services, the access
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

With the toggle false: nothing. With the toggle true:

- `/var/lib/branchleft/edge-ban-owner` (root, 0700), created if absent.
- `/var/lib/branchleft/snds-exporter` (root, 0755), created if absent.
- `/usr/local/lib/branchleft-edge-ban-owner` (root, 0755), created if absent, and
  `branchleft_edge_ban_owner.py` in it (root, 0755).
- `/etc/systemd/system/branchleft-edge-ban-owner.service` and `.timer` (root, 0644).
- The timer is enabled and started.

The classifier writes two files at run time, not through this role: the state file
`trusted.json` (root, 0600) and the textfile `edge_ban_owner.prom` (0644). Both are
written atomically. The state file is the only place an address is kept.

## How to test it

The static checks run from `ansible/`, with the virtual environment that holds the
pinned tools:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/edge_ban_owner
```

The harness runs lint, yamllint, the argument-spec check and the container test.
The container test needs a local Docker daemon. Its scenario sets the toggle to true,
so it tests the installed role. The program's own unit tests run
from the role directory, as `ansible/checks/run_role_unit_tests.py` runs them.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. The role is in the edge play but ships disabled, so an
apply of the play changes nothing on edge1 on this role's account until the toggle
is flipped (see "The toggle"). The owner decides when.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the spec
   and the defaults must agree.
2. Keep every task able to run under `--check --diff`.
3. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
4. A change to the program's CLI options changes the unit's `ExecStart` and the
   program together, in one commit.
5. Run the test command above before opening a pull request.
