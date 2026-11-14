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
   host and that docker lists the pinned digest for it** (`_image.yml`; an image that arrived
   unnamed, as the signed image push leaves it, is first given the pin's name as a local tag by
   `_image_carry.yml`, only if its own id is the pinned digest), creates the queue volume and gives it to the spool's account, orders the
   spool's unit after the egress unit with a drop-in, enables and starts the spool's unit. Then
   reads the running container back, and its image against the pin file.

The role makes no request to the network. The host has no route to GitHub or to the container
registry, so it never pulls the spool's image: the shared Compose unit runs
`docker compose pull` before every start, which fails with no registry, and the override's
`pull_policy: never` makes Compose skip it (observed with an unresolvable registry: without the
setting `docker compose pull` exits 1; with it, it reports the image skipped and exits 0).
The image is sent to the host by the signed image push (or carried once by the owner), and the role checks what arrived by digest
(below, "How the spool's image gets onto the host"). **Step 4 refuses on a host that does not
hold the pinned image**: in a real run with a message saying the host never pulls, or saying the
image listed is not the pinned one, and in a plan with a visible "Spool image NOT on host" line.

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

Named limit: the role's pins hold the carried bytes to the sha256 values in this repository, so
a change to a file and its pin together passes the role and `test_demo1_no_github_fetch.py`. What
compares them with ghost-platform is a CI step in `ci.yml`
(`ansible/checks/check_vendored_ghost_platform.py`): it fetches ghost-platform at
`demo1_egress_spool_source_sha` (and the build role's own pin, for its files) and fails, naming the
file, on any carried byte that differs from the commit's. The limit that is left is the commit
itself: the step proves the files are ghost-platform's at the pinned commit, not that the commit is
the one to run, so a bump of the sha is still a review of which commit. The vendored files are not
scanned by the no-fetch check, which reads the role's own tasks and variables: they are upstream's
text, and root runs them. `ansible/checks/test_demo1_egress_spool_agree.py` leaves them out of the
text it reads for the same reason.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3, systemd, `iptables`, `ip6tables`, `ss` and `grep`. The role
  runs as root.
- Docker running (installed by the `host_baseline` role, applied to the host as a step of its
  own), the shared Compose template unit, the two root-owned directories, and the owner's token
  file, all in place before the role runs.
- No network from the host: the role fetches nothing and pulls no image. The spool's image must
  already be on the host, sent by the signed image push or carried once by the owner as "How the
  spool's image gets onto the host" describes, on a Docker that uses the containerd image store.
  The one write the role makes for it is a local tag on an image that arrived unnamed.

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

| Control                                                    | Bad value that must be refused                                                                                           | How the bad value is made                |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------- |
| The jump is the first rule in `DOCKER-USER`                | No jump (`refused_no_jump.yml`); an accept ahead of it                                                                   | `iptables -D` and `-I` on the real chain |
| Both policy chains hold their rules once, in both families | A missing established return, a missing REJECT per bridge                                                                | `-D` by rule number on the real chains   |
| `INPUT` jumps to the input policy for each bridge          | A missing jump; a missing chain                                                                                          | `-D`, `-F`, `-X` on the real chains      |
| The egress unit is active and enabled                      | A unit that is not enabled                                                                                               | `systemctl disable`                      |
| Docker is active; `DOCKER-USER` exists in both families    | Docker stopped; no `DOCKER-USER` in `ip6tables`                                                                          | `systemctl stop`; `-X` on the real chain |
| The directories the role relies on are root's              | `/usr/local/sbin` writable by others                                                                                     | `chmod`                                  |
| The token file is 0600, root's and holds a value           | Mode 0644; no value; no line; absent                                                                                     | `chmod`, a replaced file, `mv`           |
| `docker port` is exactly `127.0.0.1:<port>`                | `0.0.0.0:8095`; a second published port                                                                                  | The stand-in docker prints it            |
| The container joins the drain and slot networks only       | An extra network; a missing slot network                                                                                 | The stand-in docker reports it           |
| The root filesystem is read-only; the container healthy    | A writable root; a container still starting                                                                              | The stand-in docker reports it           |
| One listener, on `127.0.0.1`                               | A listener on `0.0.0.0`                                                                                                  | The stand-in endpoint binds there        |
| An unauthenticated `GET /drain` returns 401                | A `200`                                                                                                                  | The stand-in endpoint answers it         |
| The image pin file is one digest-pinned `IMAGE=` line      | A tag; two lines                                                                                                         | A replaced file                          |
| The Compose file posture                                   | Published on `0.0.0.0`; a second port; the token as a value; an extra or missing network; a tag; no service              | `replace` on the file on the host        |
| The inputs; the host name; the template path               | A branch for the commit; a short file list; port 80; another host name; a template elsewhere                             | The step run with the bad variable       |
| The vendored files are held to their pins                  | A pin that is not the egress program's; a pin that is not the Compose file's (the control is the real pins)              | The step run with another pin            |
| The spool's image is on the host                           | No image on the host; a pin file naming an image the host lacks (the control is the host as delivered)                   | The stand-in docker holds no such image  |
| The image docker lists is the pinned one, by digest        | An image that lists another digest, none, or two images (the control lists the pinned digest, also beside a second name) | The stand-in docker lists them           |
| The override sets `pull_policy: never`                     | An override without it (the control is the override as the role writes it)                                               | `replace` on the file on the host        |

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

## How the spool's image gets onto the host

**The route, once the control plane sends it: the signed image push.** The control plane pulls the
image where it may, checks its attestation and its digest, and sends it to demo1's broker over the
link it already dials in on (`POST /image`, the same edge1 route as the push of the commit). The
broker stages the archive and runs the slot wrapper's `load` verb, which is `docker load`. The
archive is made with `docker save <digest>`, so the loaded image has **no name**: its own id is the
manifest digest on the containerd image store. The host opens no connection and its allowlist is
not touched. The sender, the control plane's call to `pushOciImage`, is not in this repository.
What this role does for it (`_image_carry.yml`): where the pinned reference `name@sha256:<digest>`
is not found, it looks the image up by the bare digest, and only if exactly one image comes back
whose own id **is** the pinned digest does it run `docker tag <digest> <name>:carried`, a local
tag that makes the pinned reference resolve (a pull is never made: the override sets
`pull_policy: never`). `_image.yml` then holds the image to the pinned digest by that reference,
as it does an image that arrived any other way. An image of any other id is not named and the run
refuses it as not on the host. Observed with a real Docker 29.9.2 (containerd image store):
`docker save <digest>`, remove, `docker load` gives an unnamed image; `name@sha256:<digest>` then
exits 1 "No such image"; after `docker tag <digest> name:carried` it resolves and lists
`name@sha256:<digest>` in `RepoDigests`; `name@sha256:<other digest>` still exits 1.

**The first-run route, a one-off carry, then a check by digest.** The host has no route to a registry, and
its egress allowlist holds the package mirrors only. So the owner pulls the pinned image
on a workstation, checks it there with
`ansible/tools/spool_image_gate.py`, tags it with a name, and streams `docker save` into
`docker load` on demo1 over the same edge1 jump every other bootstrap step uses. The gate runs again
on demo1, and a `docker create` probe (below) follows it. The host opens no connection and its
allowlist is not touched. The commands are in the demo1 bootstrap runbook (Part 2, step 2.4), and
only there: this README does not copy them, so there is one home for them.

**What the trust rests on.** The digest in the pin file, which is the digest in the vendored
Compose file, which `_vendored.yml` holds to its sha256 inside the signed commit. The workstation
is only a carrier. The check on demo1 is made again from what is on demo1, and `_image.yml` makes it
a third time, in the role, before the spool starts: it asks docker for the image by the pinned
reference, wants exactly one image back, and wants the pinned digest in its `RepoDigests`.

**Reused, not rebuilt:** the edge1 route the runbook already uses for every step, `docker load`
(the primitive the demo slot wrapper runs), and the gate tool, which is the one home of the gate
rule used at both ends of the carry.

**Rejected, with the reason:**

1. _The broker's signed-image route from a workstation_ (the control plane signs a descriptor, the
   slot wrapper's `load` verb streams a tar into `docker load`). It needs the control plane's
   private signing key, which authorises everything the broker does, on a workstation, so the owner's
   hand carry does not use it. The control plane's own sender is the route above. The digest the
   push signs is that of the tar's bytes, not the image's, so the image's identity is checked again
   after the load, by `_image.yml`. The image lands without a name, which `_image_carry.yml` fixes
   in this role and not in the broker.
2. _A registry pull on demo1._ It widens the allowlist beyond package mirrors.
3. _The image inside the signed commit._ An image is hundreds of megabytes of git.
4. _Using the CI account to stream it._ That widens a forced-command account on a privileged host.

**Four traps, each observed with a real Docker (29.8.2, containerd image store).** They fix the
commands, so they are named here and not found again:

- A save by tag then a load keeps the manifest digest, and the loaded image lists
  `name@sha256:<same>` in `RepoDigests`. A save **by digest reference carries no name**, so the
  loaded image is unnamed and the Compose reference does not resolve. The runbook tags first.
- **`docker save --platform` rewrites the archive's index to the one platform's manifest, so the
  digest changes.** It is never used. The pull takes `--platform linux/amd64` (a workstation may be
  arm64; demo1 is amd64) and the save has no platform flag.
- A wrong digest under the right name is found: `docker image inspect name@sha256:<other>` exits 1,
  "No such image". The lookup by digest is a real check.
- **A tar with one changed layer loads with exit 0 and prints "Loaded image", with "Error
  unpacking" among the output, and `docker image inspect`, `docker save` and `docker image
history` still pass.** Only `docker create --pull=never` fails ("apply layer error"). A gate on
  metadata alone passes a half-loaded image. So the runbook ends with a `docker create` and a
  `docker rm`, and the role's last read-back (the running container's image against the pin file)
  is the backstop: it fails closed.

**Limits, named:**

- **The hand carry is a bootstrap route.** A bump of the pin before the control plane sends the
  image needs the same steps again. The image cannot ride beside the signed bundle: the push
  receiver reads one git bundle on standard input, up to 200 MiB, and the image is about 190 MB.
  The sender of the signed image push (the control plane's call) is not in this repository; the
  role only accepts what the push leaves.
- **The plan says it would tag, and cannot show more.** `docker tag` does not run in check mode.
  A plan on a host that holds the image unnamed prints one line saying the apply will tag it. The
  tag itself is covered by the refusals scenario, not by a plan.
- **It fails closed on a classic image store.** Docker's classic store does not record the digest
  the way the containerd store does, so the digest check finds none and refuses. The runbook reads
  the store on both ends first.
- **The gate proves identity, not completeness** (the third and fourth traps). The `docker create`
  probe covers completeness. The role does not run it: `docker create` writes to the host, and
  `_image.yml` only reads.
- **The stand-in docker proves the role's reading, not Docker's.** The refusal cases show that
  the role refuses an image whose listing is wrong. That a real load keeps the digest is what the
  four traps above were observed against, and the live run on the host is the last proof.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. `ansible/playbooks/demo1.yml`
enrols the host and lists this role after `demo1_build`, and demo1 takes its commit by push, not by
a pull. The bundle that carries it is sent by CI through edge1. A bootstrap run of demo1.yml
applies all four of its roles as root, because the roles carry no tags, so the bootstrap waits for
the broker_deploy precondition and for the spool image to be on the host (the files travel in the
signed commit and the allowlist stays at the package mirrors; the image's route is the section
above). What the owner provides before a run, once:
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
