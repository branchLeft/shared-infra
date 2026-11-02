# mx1_stack

This role keeps the mail host's two Compose projects (Stalwart, and the mailgun-shim with its Caddy
front) and its local recursive resolver in step with the repository, and delivers the hourly
DNSBL check. It is Part 1 of moving the hand scripts `mail/provision/30`, `63`, `65` and `70`
into Ansible: the role, its tests and these docs. No playbook applies it yet; that wiring is
[branchLeft/shared-infra#352](https://github.com/branchLeft/shared-infra/issues/352), and until it
lands the scripts stay the way to run those four steps (`hand_installers.yml` lists them as
`pending-role`, role `mx1_stack`).

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

It keeps three classes, each with its own stamp, and acts on a class only when that class is due.

1. **Stalwart's project** (`/opt/stalwart`). It places `docker-compose.yml`, creates
   `STALWART_PROMETHEUS_SECRET` in `/opt/stalwart/.env` when it is absent (the value is generated on
   the host, written at mode `0600` and never printed), and brings the project up.
2. **The mailgun-shim's project** (`/etc/mailgun-shim`, `/var/lib/mailgun-shim`). It places
   `shim-compose.yml`, the `Caddyfile` and the shim's `env` file (rendered from the drain token
   already on the host), makes the data directory and the throttle file for the shim's user, and
   brings the project up.
3. **The local resolver.** It installs `unbound` with the three packages the host's
   `APT::Install-Recommends "false"` would otherwise leave out, places the loopback-only drop-in, has
   `unbound-checkconf` judge the assembled configuration before any restart, keeps
   `unbound-resolvconf.service` masked and `/etc/resolv.conf` untouched, and asks the resolver for a
   name at the end.

It also delivers `/root/mail-provision/check_dnsbl_blocklist.py` and `/etc/cron.d/dnsbl-check`.

A class is **due** when its stamp is missing or says `pending`, when any input differs from what
the stamp recorded or from what the repository holds, when a container does not have the current
content of a file it reads (the freshness read, below), or when its live state is not ok. When it is
due the role acts, then reads the result back, and only then writes the stamp.

It does not:

- make the shim's drain token. Its **first creation stays an owner step** (hand script 63, through
  `render_shim_env.py`, run on the host by the owner), and it stays one once a follow-up deletes
  script 63 and `render_shim_env.py`. The role reads the token on the host only, never passes it
  through the controller, and refuses to start a host that lacks it.
- reboot the host. The reboot that restores `docker exec` (`mail/RUNBOOK-mx1-reboot.md`) is a
  **precondition of the first converge**: the role reads files back out of running containers with
  `docker exec`, and stops before it writes a stamp where that fails.
- touch Stalwart's Prometheus scrape-side steps, DNS, the firewall or the MX record, remove a
  volume, an orphan container or a file, or run `docker compose down`.
- start the shim's Caddy certificate issuance beyond what bringing the project up does. The
  public-port 8443 check is not made on the host; the role checks it role-side only (a probe for
  it is [branchLeft/workspace#2888](https://github.com/branchLeft/workspace/issues/2888)).

`ansible/checks/test_mx1_stack_agree.py` holds the role in step with the hand scripts it replaces
(see "One home for every file") and fails if another role names the paths this role owns.

### Why the role does not copy script 63 or the other stack roles

Three departures, each from something that is true of Compose and not a matter of taste.

**Script 63 leaves Caddy on an old Caddyfile.** Compose decides whether to recreate a service from a
hash of its configuration. A bind mount enters that hash as a path, not as the file's content, and so
does an `env_file` (its name, not what is in it). Editing the Caddyfile therefore changes nothing in
the hash, `docker compose up` reports the service up to date, and Caddy, which reads its Caddyfile
only when it starts, goes on serving the old one. Script 63 also replaces the file with `cp`, which
keeps the destination's inode, so a container that picked the file up by inode would see the new
text; but a replacement by rename does not, and the role must not depend on which of the two its
writer used. The probe below shows the Linux behaviour that matters: a rename leaves the mount on
the old inode, an in-place write is seen only on the inode the mount holds.

```text
mounted: one inode 33773459
after rename: mount reads one inode 33773459; path reads two inode 33773764
after in-place write: mount reads one
Linux 7.0.14-linuxkit
```

That is a `mount --bind` of a file inside a privileged Debian container on Docker Desktop's Linux
VM, the kernel mechanism Docker uses on a Linux host. **On a Mac, Docker Desktop's file sharing
behaves differently**: a plain bind mount of a file from the Mac showed the rename straight away in
the same probe. So a green run on a Mac proves nothing about this on the real host, which is
Linux; the stand-in below models the Linux behaviour on purpose, and the first live apply is the
proof (ANS-17).

Script 30 (Stalwart) has no bind-mounted file, so it has no such gap; its create-time input is
the `.env`, which Compose interpolates into the configuration hash.

**`monitoring_stack` and `edge_stack` adopt a running host on file equality alone.** Here a host with no stamp is
adopted, with the stamp as the only write, only when the files are equal to the repository's **and**
the containers are running and healthy on the pinned images **and** each container has the current
content of the files it reads. A host whose files are right but whose Caddy is on an old Caddyfile is
not adopted; it is recreated.

**`compose_stack` recreates the whole project.** This role recreates exactly the services whose
input changed, with `docker compose up --force-recreate --no-deps <service>`, because
recreating Stalwart refuses mail for about two minutes and a Caddyfile edit must not cost that.
Compose's own `up` still runs first and recreates whatever its own hash says (an image pin, a
port, and Stalwart's `${STALWART_PROMETHEUS_SECRET}`, which Compose interpolates from the project's
`.env`, so editing that file does change the hash). Nothing here passes `--remove-orphans`,
`--renew-anon-volumes`, `--build` or `--pull`.

### The audit: every host input to both compose files

`mx1_stack_container_inputs` in `vars/main.yml` is the one home of what a container reads from the
host. The tasks, the probe's arguments and the CI test all read it; nothing copies it.

| Row                | Project      | Service      | Path                                 | Kind           | A change to it must                                             |
| ------------------ | ------------ | ------------ | ------------------------------------ | -------------- | --------------------------------------------------------------- |
| `stalwart_compose` | stalwart     | all          | `/opt/stalwart/docker-compose.yml`   | `compose_file` | `up` (Compose's own hash recreates)                             |
| `stalwart_env`     | stalwart     | stalwart     | `/opt/stalwart/.env`                 | `create_env`   | recreate `stalwart` (read at creation only)                     |
| `shim_compose`     | mailgun-shim | all          | `/etc/mailgun-shim/shim-compose.yml` | `compose_file` | `up` (Compose's own hash recreates)                             |
| `shim_env`         | mailgun-shim | mailgun-shim | `/etc/mailgun-shim/env`              | `create_env`   | recreate `mailgun-shim` (`env_file` is read at creation)        |
| `shim_data`        | mailgun-shim | mailgun-shim | `/var/lib/mailgun-shim` to `/data`   | `bind_dir`     | nothing: the directory is live in the container                 |
| `shim_caddyfile`   | mailgun-shim | caddy        | `/etc/mailgun-shim/Caddyfile`        | `bind_file`    | recreate `caddy` (a rename leaves the old inode; read at start) |

Named volumes (`stalwart-etc`, `stalwart-data`, `caddy-data`, `caddy-config`) hold no host file and
have no row. `test_mx1_stack_agree.py` parses both compose files and fails when one gains a bind
mount, an `env_file` or a `${VAR}` that has no row, when a row names something no compose file
holds, and when a row's service, container name or container path is wrong. It has a red fixture
with an unclassified bind mount.

### The scoped force-recreate, the freshness read and the stamp

After Compose's own `up`, the role reads each `create_env` and `bind_file` input with the module
`mx1_stack_probe`. A `bind_file` is **stale** when the SHA-256 that `docker exec` reads inside the
container differs from the host file's, or when the host file's mtime is newer than the container's
`StartedAt`. A `create_env` file is stale when its mtime is newer than the container's `Created`.
Exactly the services with a stale input get `docker_compose_v2` with `services: [<service>]`,
`dependencies: false` and `recreate: always`. A second read, the **freshness read-back**, must then
find every such container fresh, and the health check must pass, before the stamp is written. A
class that fails either stops with a message naming the services and the inputs, and leaves the
stamp `pending`.

A stamp is a file of `name sha256` lines (sorted), one per input, or the single word `pending`, at
mode `0600`. The role writes `pending` **before** it changes anything and the real lines **after**
the read-back, so a crash anywhere between leaves a class that is due on the next run. No task here
notifies a handler: a notification is lost when a later task fails and the next run would find every
file in place and do nothing.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables. There are four, all
optional, none secret: `mx1_stack_stalwart_health_tries`, `mx1_stack_health_interval`,
`mx1_stack_recursion_tries` and `mx1_stack_recursion_interval`. The role has **no secret variable**:
the drain token and Stalwart's admin credential are read on the host from
`/root/.stalwart-service-credentials`, and Stalwart's Prometheus secret is generated on the host.
`defaults/main.yml` holds the four numbers and nothing else.

`vars/main.yml` holds the constants: every path, project name, stamp, port, the resolver packages,
the cron line, the texts of the repository files and the audit table above. They are not inputs; the
hand scripts, the runbooks and the DNSBL check already agree on them, so a caller cannot move one.
A role parameter or an extra variable still outranks `vars/`, which is how the Molecule scenarios
put different texts through the role; nothing stops a caller who passes a role parameter on
purpose.

The module `mx1_stack_envfile` (actions: `mint`, `shim`, `check_token`, `reserved_keys`) writes
the two env files; `mx1_stack_stamp` reads and writes stamps; `mx1_stack_probe` reads container
state and freshness. A spike to share code between them through `module_utils` failed in this
repository's module layout, so `mx1_stack_envfile` is a single module with actions, and the shared
SHA-256 and stamp-line helpers are small enough to repeat in the stamp and probe modules.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it. No collection beyond what the
  pinned `ansible` package carries: `community.docker` (for `docker_compose_v2`) arrives with it.
- Target: Debian 13 with Python 3.13, systemd, Docker with the Compose plugin, `cron`, and the
  files under `/root/mail-provision` that script 70 expects. The role runs as root.
- The repository's files reach the role through links in `files/` (below), so it must be run from a
  checkout of the whole repository, which is what the gated pull delivers (ANS-17).
- **Before the first converge on the mail host**, the reboot of `mail/RUNBOOK-mx1-reboot.md` must
  have been done, and `/root/.stalwart-service-credentials` must hold the `shim-drain-token` line.
- The modules target Python 3.13, the host's, and use no 3.13-only standard library. The unit
  suites run on the interpreter of the tools' virtual environment (3.12 or later; 3.12 in CI), not on
  3.13, so they do not prove the modules run on the host's interpreter: the Molecule scenarios run the
  modules on 3.13.

## What it changes on a host

- `/opt/stalwart/docker-compose.yml` (`0644`) and `/opt/stalwart/.env` (`root:root`, `0600`, one
  line added if absent, an existing line never rewritten).
- `/etc/mailgun-shim/` with `shim-compose.yml`, `Caddyfile` (`0644`) and `env` (`0600`),
  `/var/lib/mailgun-shim/` owned by the shim's user and its `throttle.json`.
- The Stalwart and mailgun-shim containers, by Compose's `up`, and by the scoped recreate when an
  input is stale.
- `unbound`, `unbound-anchor`, `dns-root-data` and `bind9-dnsutils`; the masked
  `unbound-resolvconf.service`; `/etc/unbound/unbound.conf.d/10-branchleft-local-recursive.conf`
  (`0644`); the DNSSEC root anchor when absent; a restart of `unbound` only when its configuration
  changed or it is not active.
- `/root/mail-provision/check_dnsbl_blocklist.py` and `/etc/cron.d/dnsbl-check`.
- `/var/lib/branchleft/` (`0755`) and the three stamps `mx1.stalwart.applied`, `mx1.shim.applied`
  and `mx1.resolver.applied` (`0600`).
- In check mode the role writes nothing. The check-mode steps (`check-fresh`, `check-configured`)
  assert that the stamps, the files and the containers are exactly as they were.

The paths the modules write are outside `check_role_paths`, which reads the task files only: the
two env files and the stamps are named in `vars/main.yml` and written by `mx1_stack_envfile` and
`mx1_stack_stamp`. The agree test covers who else may name them.

**If a run fails after `unbound` was restarted and `/etc/resolv.conf` changed**, the role stops and
says so; it does not revert the file itself. Restore `/etc/resolv.conf` by hand from the host's
copy, then run `resolvconf -d lo.unbound`, and run the role again. **Once the role has been applied,
do not run hand script 70**: it would rewrite the cron entry with its own header and leave the
role's stamp describing a file it no longer matches.

### One home for every file

The role holds no copy of the files it delivers. `files/docker-compose.yml`,
`files/shim-compose.yml`, `files/shim.Caddyfile` and `files/check_dnsbl_blocklist.py.txt` are links into
`mail/provision/`. The resolver drop-in is the one file kept in the role (`files/10-branchleft-local-recursive.conf`),
because script 65 holds it in a heredoc, and `test_mx1_stack_agree.py` fails if it differs from that
heredoc. The same test holds the resolver packages to script 65's, the cron line to script 70's (the
path it writes to included), and the shim's env file to what `render_shim_env.py` renders. The
shape of the stack therefore changes where it always did, in `mail/provision/`, and the next apply
delivers it. The Ansible workflow watches `mail/provision/` for that reason
(`ansible/checks/ci_select.py` lists `mail` among the directories a role reads).

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes (Docker running
locally):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mx1_stack
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mx1_stack --scenario refusals
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mx1_stack --scenario lifecycle
.venv/bin/python ansible/harness/run_harness.py ansible/roles/mx1_stack --scenario adoption
cd ansible/roles/mx1_stack && PYTHONPATH=files:library:tests/unit ../../../.venv/bin/python -m unittest discover -b -s tests/unit -p 'test_*.py'
cd ansible && ../.venv/bin/python -m unittest discover -b -s checks -p 'test_mx1_stack_agree.py'
```

The four scenarios share one instance image (Debian 13 with systemd, pinned by digest) and one
`prepare.yml` and `converge.yml`; each shard has its own 25-minute limit, which is why the cases
are split:

| Scenario    | What it proves                                                                                                                                     |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `default`   | Converge, idempotence, the two check-mode plans, and an independent verify of every file, owner, mode and stamp.                                   |
| `refusals`  | A `control_accepts` case and one refusal per guard G1 to G12, each healed back to the baseline before the next.                                    |
| `lifecycle` | no change; Caddyfile-only change; shim env-only change; Stalwart `.env` edit; drift; crash leaves `pending`; unhealthy after `up`; resolver drift. |
| `adoption`  | adopt a clean host; record-only after the read-back; adopt refuses a stale mount, a down container, a wrong image.                                 |

The guards:

| Guard | The role refuses                                                        |
| ----- | ----------------------------------------------------------------------- |
| G1    | a second compose file in a project directory                            |
| G2    | a Compose override file                                                 |
| G3    | a `.env` beside the shim's compose file                                 |
| G4    | a `COMPOSE_` key in Stalwart's `.env`                                   |
| G5    | a wrong mode or owner on Stalwart's `.env`                              |
| G6    | a compose file whose image is not pinned by digest                      |
| G7    | a host without the shim's drain token                                   |
| G8    | a port 53 held by anything but `unbound`                                |
| G9    | an `unbound-checkconf` rejection (the previous drop-in is put back)     |
| G10   | a changed `/etc/resolv.conf` after the resolver restart                 |
| G11   | a stamp that cannot be read                                             |
| G12   | a container still stale after the forced recreate (no stamp is written) |

### Stand-ins and what they model

The instance has no real Docker daemon. `molecule/default/files/standin-docker` is a small Python
program that models Compose for these two projects, and `standin-dig`, `standin-openssl` and
`standin-unbound-checkconf` stand in for the network tools. The docker stand-in keeps each
container's state under `/var/lib/standin-docker`: its image, a config hash, `Created` and
`StartedAt`, its health, and for every mount the inode and SHA-256 of what the container holds. It
enforces the Linux behaviour of the probe above (a replaced file leaves the mount on the old inode),
requires the exact `docker inspect` format the probe uses, and refuses `--remove-orphans`,
`--renew-anon-volumes`, `--build`, `--pull` and `--no-start`. Its switches live in
`/var/lib/standin-docker/flags`: `fail_up`, `ignore_force_recreate`, `hash_env_file_content` and
`unhealthy.<container>`.

### Sabotage rows

A control is shown to work only by breaking it: red recorded, then green. Each row is one edit to
the role, one run of the case in a fresh instance, and the edit reverted. The assertion quoted is
the one that went red.

The lifecycle (the Caddyfile-only change):

| Edit to the role                                                                     | Where it goes red                                                                                                                             |
| ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| The forced-recreate task removed                                                     | The role stops at "Refuse a project whose container still lacks the content of a file it reads": the stamp was not written.                   |
| The forced-recreate and the read-back with its refusal both removed                  | `verify`: "The new Caddyfile is not the one the container holds, the stamp does not name it, or it was written before the container started." |
| The recreate widened to the whole project (no `services:`, no `dependencies: false`) | `verify`: the `up` calls assertion, "forced [... --force-recreate ...] expected ['caddy']".                                                   |

The refusals: for each of G1 to G12 the guard's task was made inert (usually `when: false`) and
the case went red with "Expected the role to stop at ... It finished."; G7 additionally reached the
shim env module's own refusal later, at "Render the shim's environment file"; G9 (checkconf) went
red at "The previous drop-in was not put back, a backup is left"; G11 stopped later, at "Decide
whether the class is due", instead of at the stamp refusal. Each was then restored and the case
passed.

### Named limits

- **The stand-ins prove wiring and the modelled Compose behaviour, not Docker, the kernel,
  `unbound` or Stalwart.**
- **The stand-in is not Compose.** It models, and does not prove, that Compose recreates when a
  mount path or `env_file` name changes and not when their content does, and that a recreated
  service's dependents are recreated unless `--no-deps`. Those two are stand-in assumptions
  (`hash_env_file_content` switches the first off for the `.env` case). The first live apply is the
  proof (ANS-17).
- **Linux inode behaviour is modelled, not run.** See the probe and the Mac caveat above.
- **Time.** `StartedAt` and `Created` come from the stand-in's clock, which is the instance's.
- **The network tools are canned.** `dig`, `openssl` and `unbound-checkconf` answer from flags;
  `unbound` itself is real in the instance.
- **A silent skip passes.** The harness does not catch a task that skips when it should not
  (ANS-10); the reviewer reads for it.
- CI runs all four scenarios: the Ansible workflow runs the harness over every directory under
  `ansible/roles/`, and every scenario under `molecule/` is its own shard.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the approval of its
protected environment. A plan job shows the host's diff in check mode first; after the approval the
host pulls that exact commit and applies it, and a second run must report zero changes. Nothing is
applied from a laptop. This role is applied by no playbook yet
([branchLeft/shared-infra#352](https://github.com/branchLeft/shared-infra/issues/352)). The first
gated apply is after the reboot of `mail/RUNBOOK-mx1-reboot.md`, outside a send window; the owner
chooses its date. The hand scripts stay the documented path until then, and `hand_installers.yml`
keeps them as `pending-role` against this role.

## How to change it safely

1. To change what a stack is, change the files under `mail/provision/`; the role delivers them as
   they are, and a changed file is acted on by the class it belongs to. To add a bind mount, an
   `env_file` or a `${VAR}` to a compose file, add its row to `mx1_stack_container_inputs` and say
   what a change to it must do; `test_mx1_stack_agree.py` fails until you do.
2. Keep every task able to run under `--check --diff`, make no write in check mode, and keep the
   modes explicit. Every task that handles a secret sets `no_log: true` and `diff: false` (ANS-16).
3. Do not add a handler, and do not move the stamp write before the read-back.
4. If a task reports changed on a second run, fix the task with a module, `changed_when`,
   `creates` or `removes`. Never weaken the idempotence step.
5. When you touch a guard, break it and see the case in `refusals` go red, then restore it.
