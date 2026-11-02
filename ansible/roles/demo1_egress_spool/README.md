# demo1_egress_spool

This role gives the demo host (demo1) two things the demo cannot run safely without: a firewall
policy that stops every demo container opening a connection of its own, and the one mail spool
that holds the mail the demo sites try to send. It installs the policy from the files that
`branchLeft/ghost-platform` publishes for it, places the spool's Compose file, starts the spool,
and then reads the firewall and the running container back from the host and refuses to finish
if either is not what the demo's safety depends on.

This README is self-contained and is written for a maintainer new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

In this order, and it stops at the first refusal:

1. **Inputs.** A wrong shape fails by name before anything else happens. Then
   **the vendored files** (`_vendored.yml`): each of the three files under
   `files/ghost-platform` is hashed on the machine that runs the role and must be a plain
   file with its pinned sha256, or the run stops and names the file, before the host is read
   or written.
2. **The host.** Read only. The host's own name is `demo1` (under the pull the inventory name is
   `localhost`, so the role reads the name from the host itself). Docker is running. `DOCKER-USER`
   exists in both `iptables` and `ip6tables`. `/etc/branchleft`, `/opt/branchleft` and
   `/usr/local/sbin` are real directories owned by root and not writable by group or others. The
   shared Compose template unit is loaded from its one path and is a regular file owned by root.
   (Debian 13's `base-files` creates `/usr/local/sbin` as `root:root` mode `0755` on a new install,
   and sets group `staff` with mode `2775` only where an old release left the marker file
   `/etc/staff-group-for-usr-local`. The test image is `debian:trixie` underneath, so it has the
   first. A host with the second is refused, because the program in that directory runs as root at
   every boot: change its group and mode, or remove the group's write bit, and run again.)
3. **The egress policy.** Copies the egress program to `/usr/local/sbin/branchleft-demo-egress`
   (mode 0755) and its unit to `/etc/systemd/system/` (0644) from the role's own copies, which
   step 1 held to their sha256. Enables the
   unit, and runs the program again only when either file changed. Then reads the loaded rules
   back, in both families (the table below says what is asserted).
4. **The spool.** Checks the drain token file, copies the Compose file and places the override
   that takes the image from the pin file and sets `pull_policy: never`, checks their posture,
   creates the image pin file once, **checks that the image the pin file names is already on the
   host** (`_image.yml`), creates the queue volume and gives it to the spool's account, orders the
   spool's unit after the egress unit with a drop-in, enables and starts the spool's unit. Then
   reads the running container back, and its image against the pin file.

The role makes no request to the network. The host has no route to GitHub or to the container
registry, so it never pulls the spool's image: the shared Compose unit runs
`docker compose pull` before every start, which fails with no registry, and the override's
`pull_policy: never` makes Compose skip it (observed with an unresolvable registry: without the
setting `docker compose pull` exits 1; with it, it reports the image skipped and exits 0).
How the image gets onto the host is not decided yet. **Until it is, step 4 refuses on a host
that does not hold the image**: in a real run with a message saying the host never pulls, and in
a plan with a visible "Spool image NOT on host" line.

What it does **not** do, each on purpose:

- It does not write the drain token. `/etc/branchleft/mail-spool.env` is a root-only file
  (mode 0600) the owner places once. The role asserts that it exists, is a regular file owned by
  `root:root`, is not empty and holds a `SHIM_DRAIN_TOKEN=` line with a value, using `grep -q`
  with `no_log`. The token is never an input, never read into a variable and never written.
- It does not write the shared Compose template unit (`branchleft-compose@.service`). That unit
  is installed on the host by hand and has no owner in this repository; a second writer is
  refused by `test_deploy_tooling_single_owner.py`. The role asserts it and names it when it is
  missing.
- It does not install Docker (`host_baseline` does, and `ansible/playbooks/demo1.yml` does not
  apply that role: demo1's baseline is its own step), create `/etc/branchleft` or `/opt/branchleft`,
  open a port, add a firewall rule of its own, or reboot the host. The only rules on the host are
  the ones the pinned egress program builds.
- It does not apply `egress_nat`. The demo containers must not reach the network, and a NAT rule
  would give them a way. `ansible/checks/test_demo1_egress_spool_agree.py` holds that
  `ansible/playbooks/demo1.yml` never lists it.

### One owner for the egress program and its unit

This role is the only pin of the egress program and its unit in this repository. `demo1_build`
does not pin or install either of them (its README marks the program as not a role step), and
the agree test fails if `demo1_build` ever names them. There is therefore nothing to keep in step
with another role: to bump them, change the pin below and nothing else.

### What the program does, and the jump

The pinned egress program loads two chains (`BRANCHLEFT-DEMO-EGRESS` for forwarded traffic and
`BRANCHLEFT-DEMO-INPUT` for traffic to the host), puts a jump to the first into `DOCKER-USER`, and
puts a jump to the second into `INPUT` for `docker0` and every `br-` bridge. The host keeps its
own egress. Docker evaluates `DOCKER-USER` before its own rules, so the jump has to be the first
rule there: anything ahead of it that accepts would outrank the policy. In `INPUT` the jumps are
read for position too: a rule ahead of them is accepted unless it accepts what a bridge sends (an
accept with no interface that is not only established traffic, or one that names a bridge), since
a tool such as `fail2ban` may insert its own rule at the top later. An `ACCEPT` ahead of the jumps
that would match a container is refused.

The program inserts the jump only when it is absent, and a restart does not move one that is
already there. So when the read-back reports the jump is present but not first, the repair is an
operator step: delete the jump with `iptables -D DOCKER-USER -j BRANCHLEFT-DEMO-EGRESS` (and
`ip6tables` for the other family), then restart `branchleft-demo-egress.service`, which inserts it
first. The role's message says the same, and does not do it itself: a role that rewrote
`DOCKER-USER` would be a second writer of rules it does not own.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable and
[`defaults/main.yml`](defaults/main.yml) holds them. There is no required input and no secret.

- `demo1_egress_spool_source_sha`: the ghost-platform commit the vendored files were taken from.
- `demo1_egress_spool_files`: the three files, each with its path from the repository root and
  its sha256: the egress program, the egress unit and the rendered Compose file.
- `demo1_egress_spool_drain_port`: the host port of the drain endpoint (default 8095). It is
  published on `127.0.0.1` only. The pinned Compose file publishes exactly this port, and the
  role refuses a file that publishes another.

`vars/main.yml` holds the constants (paths, the uid and gid 31000, the volume, the chain names,
the networks, the patterns). A caller cannot override them.

### The pin

The files are copies of the ones in `branchLeft/ghost-platform` at commit
`19622ee9c88bf918949f675a85897cfb64c65a24`, carried under `files/ghost-platform` at the paths they
have there. The Compose file is the committed golden of the renderer in that repository, so the
image digest, the networks and the one published port are written there and nowhere else here.
Each file is held to its sha256 on the machine that runs the role before anything is written, so a
file changed without its checksum, or a checksum changed without its file, stops the role at
`_vendored.yml` and names the file. CI runs the same comparison without a container
(`ansible/checks/test_demo1_no_github_fetch.py`).

### Vendored files

The files arrive on the demo host in the signed commit it checks out, so the host needs no route
to GitHub and its egress allowlist holds the package mirrors only. To bump them, in one change:

1. In ghost-platform, at the new commit, compute each checksum with
   `git show <commit>:<path> | shasum -a 256`.
2. Write each file into `files/ghost-platform` with
   `git show <commit>:<path> > ansible/roles/demo1_egress_spool/files/ghost-platform/<path>`, so
   the bytes are the commit's and nothing re-wraps them.
3. Change `demo1_egress_spool_source_sha` and every checksum in `defaults/main.yml`, and the same
   values in `meta/argument_specs.yml`.

Named limit: CI no longer compares the carried bytes with ghost-platform. It holds them to the pin
in this repository, so a change to a file and its pin together passes. The review of such a change
is a review of file content, not of a commit sha; a CI step that checks out ghost-platform at the
pinned commit and diffs is filed as follow-up. The vendored files are not scanned by the no-fetch
check, which reads the role's own tasks and variables: they are upstream's text, and root runs
them. `ansible/checks/test_demo1_egress_spool_agree.py` leaves them out of the text it reads for
the same reason.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3, systemd, `iptables`, `ip6tables`, `ss` and `grep`. The role
  runs as root.
- Docker running (installed by the `host_baseline` role, applied to the host as a step of its
  own), the shared Compose template unit, the two root-owned directories, and the owner's token
  file, all in place before the role runs.
- No network from the host: the role fetches nothing and pulls no image (the spool's image must
  already be on the host).

## What it changes on a host

- `/usr/local/sbin/branchleft-demo-egress`: `root:root` `0755`. `/etc/systemd/system/branchleft-demo-egress.service`:
  `root:root` `0644`. The unit is enabled for boot, and active.
- The rules the program builds: the two policy chains in both families, the jump in
  `DOCKER-USER` and the jumps in `INPUT`. The role itself writes no rule.
- `/opt/branchleft/mail-spool/` (`root:root` `0755`), the Compose file in it (`0644`) and beside
  it `compose.override.yml` (`0644`), which sets the image from the pin file and sets
  `pull_policy: never`.
- `/etc/branchleft/mail-spool.image.env` (`root:root` `0600`), created once with one line,
  `IMAGE=<the image in the Compose file>`. See below for why it is never rewritten.
- `/etc/systemd/system/branchleft-compose@mail-spool.service.d/10-egress-first.conf` (`0644`), a
  drop-in that makes the spool's unit `Requires=` and start `After=` the egress unit.
- The Docker volume `branchleft-mail-spool-data`, created only if absent, and its data directory
  under `/var/lib/docker/volumes/`, given to `31000:31000` (mode 0755) with the `file` module on
  the path `docker volume inspect` reports, after its shape is checked.
- The unit `branchleft-compose@mail-spool.service`: enabled, started, and restarted only when the
  Compose file or its override changed.

### The image pin file is the one source of the image

The shared Compose template unit refuses to start without `/etc/branchleft/<stack>.image.env`,
loads it as environment, and the deploy wrapper writes it as one `IMAGE=` line for every image
bump. The pinned Compose file carries its image as a literal, so left alone it would be a second
source: a bump written to the pin file would change nothing that runs. The role therefore places
`compose.override.yml` beside the Compose file, with `image: ${IMAGE:?...}`, which Compose merges
over the literal. The literal is then only the first value: the role writes it into the pin file
once, with `force: false`, so a later converge never puts the golden's image back over a bump the
wrapper made. The read-back holds three things together: the pin file is exactly one line,
`IMAGE=<name>@sha256:<64 hex digits>`; the override is exactly the text the role writes (lists such
as `ports` and `networks` add up when Compose merges, so an override that said more could publish a
port); and the running container's image (`docker inspect`, `Config.Image`) equals the one in the
pin file. A container left on the old image after a bump, or started without the override, is
refused, and the message says to restart the unit.

### The spool waits for the egress policy

The drop-in gives the spool's unit `Requires=` and `After=branchleft-demo-egress.service`, so the
spool cannot start with the policy not loaded, and a restart of the egress unit (a changed file,
or Docker restarting, which the egress unit follows) restarts the spool's unit with it. That
re-runs `docker compose up -d`, which recreates only what changed. The read-back asks systemd for
the unit's effective `After` and `Requires`, which include the drop-in. The shared template unit
itself is not touched: the drop-in is the way to order one instance.

## Check mode

Every read runs in check mode. A plan on a host that has not yet been given the egress files or
the spool has nothing loaded or running to read, so the read-back says so in a visible line
(`Egress policy NOT verified` or `Running spool NOT verified`) and skips, and a plan that is clean
does read the host. An apply always reads. A plan therefore cannot be mistaken for a pass.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes:

```text
python3 ansible/harness/run_harness.py ansible/roles/demo1_egress_spool
python3 ansible/harness/run_harness.py ansible/roles/demo1_egress_spool --scenario refusals
```

Both need Docker and are what CI runs, one shard each. The container is a Debian 13 systemd image,
trusted by digest, named `demo1` and given the one added capability `NET_ADMIN`, so the
firewall is real: the egress program loads real rules into the container's own network namespace
and the role reads them back with real `iptables`. The things that are not real are stand-ins, and
`prepare.yml` installs them: Docker (`/usr/bin/docker`, a script that answers `volume`, `inspect`,
`port` and `compose` from files that a case can change), `docker.service` (an active no-op) and
the spool's drain endpoint (a small HTTP server on `127.0.0.1:8095`). The shared Compose template
unit is the real one, copied from `hetzner/provision`.

Without Docker, what runs anywhere: the agree test and the contract tests,

```text
python3 -m unittest discover -s ansible/checks -p test_demo1_egress_spool_agree.py
python3 -m unittest discover -s hetzner/provision -p test_compose_unit_contract.py
```

and the lint steps of the harness (`ansible-lint` at the production profile and `yamllint`).

### What `default` proves

`converge.yml` applies the role, moves the image pin file the way the deploy wrapper would (the
stand-in docker is told the container now runs that image, as the wrapper's restart would make
it), and applies the role again. The idempotence step then applies the whole converge once more and fails
on any change.
`verify.yml` reads the result with its own commands, not the role's: the jumps with `iptables -C`
and the first rule with `-L`, each file's owner and mode, the token file unchanged, the bumped
pin file untouched, the Compose file carrying the golden's image and port, the volume owned by
31000, one listener on `127.0.0.1`, a `401` from the drain endpoint, and in the stand-in's call
log the volume made once, the spool started once and never taken down.

### What `refusals` proves

`converge.yml` applies the role once, then runs one step of the role at a time against a state it
makes bad, and checks the step refuses with its own message. Every group starts with a control:
the same step on the good state must be accepted. Without it a step that refused everything would
pass every case. Whatever a case changed is put back in every outcome.

| Control                                                    | Bad value that must be refused                                                                              | How the bad value is made                |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| The jump is the first rule in `DOCKER-USER`                | No jump (`refused_no_jump.yml`); an accept ahead of it                                                      | `iptables -D` and `-I` on the real chain |
| Both policy chains hold their rules once, in both families | A missing established return, a missing REJECT per bridge                                                   | `-D` by rule number on the real chains   |
| `INPUT` jumps to the input policy for each bridge          | A missing jump; a missing chain                                                                             | `-D`, `-F`, `-X` on the real chains      |
| The egress unit is active and enabled                      | A unit that is not enabled                                                                                  | `systemctl disable`                      |
| Docker is active; `DOCKER-USER` exists in both families    | Docker stopped; no `DOCKER-USER` in `ip6tables`                                                             | `systemctl stop`; `-X` on the real chain |
| The directories the role relies on are root's              | `/usr/local/sbin` writable by others                                                                        | `chmod`                                  |
| The token file is 0600, root's and holds a value           | Mode 0644; no value; no line; absent                                                                        | `chmod`, a replaced file, `mv`           |
| `docker port` is exactly `127.0.0.1:<port>`                | `0.0.0.0:8095`; a second published port                                                                     | The stand-in docker prints it            |
| The container joins the drain and slot networks only       | An extra network; a missing slot network                                                                    | The stand-in docker reports it           |
| The root filesystem is read-only; the container healthy    | A writable root; a container still starting                                                                 | The stand-in docker reports it           |
| One listener, on `127.0.0.1`                               | A listener on `0.0.0.0`                                                                                     | The stand-in endpoint binds there        |
| An unauthenticated `GET /drain` returns 401                | A `200`                                                                                                     | The stand-in endpoint answers it         |
| The image pin file is one digest-pinned `IMAGE=` line      | A tag; two lines                                                                                            | A replaced file                          |
| The Compose file posture                                   | Published on `0.0.0.0`; a second port; the token as a value; an extra or missing network; a tag; no service | `replace` on the file on the host        |
| The inputs; the host name; the template path               | A branch for the commit; a short file list; port 80; another host name; a template elsewhere                | The step run with the bad variable       |
| The vendored files are held to their pins                  | A pin that is not the egress program's; a pin that is not the Compose file's (the control is the real pins) | The step run with another pin            |
| The spool's image is on the host                           | No image on the host; a pin file naming an image the host lacks (the control is the host as delivered)      | The stand-in docker holds no such image  |
| The override sets `pull_policy: never`                     | An override without it (the control is the override as the role writes it)                                  | `replace` on the file on the host        |

Also covered, each with its control on the good value:

- The container's image against the pin file, both ways: a container that reports another image
  than the file names, and a file that names another image than the container runs.
- The override beside the Compose file: one that adds a port is refused.
- The spool's unit ordered after, and bound to, the egress unit: a drop-in with both lines taken
  out is refused.
- Where the `INPUT` jumps sit: an accept for the loopback, or for established traffic, ahead of
  them is accepted; an accept for every source, or for a bridge, ahead of them is refused.
- `/usr/local/sbin` writable by its group (mode `2775`, as an old Debian leaves it) is refused;
  the control is the directory as the image has it, `root:root` `0755`.

## Named limits

- **The stand-ins prove the role's logic, not Docker's.** The refusals cases show that the role
  refuses a bad value when the host reports one. That the real container is healthy, that the
  real published port is `127.0.0.1:8095`, that the real listener is not on every address and
  that the real endpoint answers `401` are proved only by a live run on the host.
- **The behavioural proof that a demo container has no route off the host belongs to
  ghost-platform's CI.** This role is tied to it only by the pinned sha256 of the program and unit
  it tests. The role asserts the rules are loaded; it does not open a connection from a container.
- **There is a boot window.** The egress unit runs after Docker starts, so for a few seconds at
  boot the policy is not yet loaded. That is a property of the pinned unit, not of this role.
- **The role cannot see a token it has not read.** It asserts the file's owner, mode and a
  non-empty `SHIM_DRAIN_TOKEN=` line. Whether the value is the right one is the owner's.
- **The nftables backend.** The program needs the `DOCKER-USER` chain from Docker's iptables
  backend. A host whose Docker uses the nftables backend has no such chain and the role refuses it
  by name.
- **A restart of the program rebuilds the policy chains but does not move a jump** (above).
- **The listener check depends on `docker-proxy`.** The role reads the listeners on the drain port
  with `ss -ltn`, and what it sees on `127.0.0.1` is the listener of Docker's userland proxy. If
  the Docker daemon runs with the userland proxy off (`"userland-proxy": false`), a published port
  is a firewall translation with no listener to see, the check finds none, and the role refuses
  the host instead of guessing. The `docker port` and unauthenticated-call checks do not depend
  on it.

## Gaps the role names and does not close

- The shared Compose template unit has no owner in this repository. The role only asserts it.
- `ansible/playbooks/demo1.yml` applies `demo1_build` and this role, and not `host_baseline`.
  Docker must already be running on the host; if it is not, the role refuses by name. The host's
  baseline (sshd, unattended upgrades, fail2ban) is a separate step under demo1's enrolment.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. Nothing applies this role to demo1 yet. `ansible/playbooks/demo1.yml`
enrols the host and lists this role after `demo1_build`, and demo1 takes its commit by push, not by
a pull. The bundle that carries it is sent by CI through edge1 and arrives with shared-infra#511,
which is not yet merged, so until it lands no run reaches this role. A bootstrap run of demo1.yml
applies all four of its roles as root, because the roles carry no tags, so the bootstrap waits for
the broker_deploy precondition and for the spool image to be on the host (the egress decision,
Desk decision demo1-github-files, is made: the files travel in the signed commit and the
allowlist stays at the package mirrors). What the owner provides before a run, once:
the token file `/etc/branchleft/mail-spool.env` (root, mode 0600, one `SHIM_DRAIN_TOKEN=` line),
if the host holds none. The role asserts it and never writes it.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the spec and the
   defaults must agree.
2. To bump the pin, change the commit, the vendored files and every checksum in one change
   (above, "Vendored files").
3. Keep every task able to run under `--check --diff`.
4. If a task reports changed on a second run, fix the task with a module, `changed_when`,
   `creates` or `removes`. Never weaken the idempotence step.
5. Add a case to `molecule/refusals/converge.yml` for every assertion you add, and a control that
   passes on the good value. A new assertion with no case that fails it is not tested.
6. Run the test commands above before opening a pull request.
