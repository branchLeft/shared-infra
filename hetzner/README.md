# Hetzner foundations

The private network every platform host attaches to, and the estate that
network builds. Both stacks are applied and live, in the estate hcloud
project. The VM-create pattern itself —
`Host`, its firewall rule sets, its cloud-init and the shared address plan —
is no longer part of this directory: it is the published package
`@branchleft/hetzner-host`, in the sibling `hetzner-host/` directory. See
"The published package" below for the boundary and why it sits outside this
one.

This file covers what is in this directory and why it is shaped the way it
is.

| File                                  | What it is                                                                                     |
| ------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `RUNBOOK-new-stack.md`                | Object Storage state backend + passphrase secrets provider, for new stacks                     |
| `RUNBOOK-provision-host.md`           | Delivering and running `provision/` against a newly created host                               |
| `RUNBOOK-estate-project-move.md`      | Rebuilding both stacks in the estate hcloud project, once                                      |
| `scripts/probe-object-storage.py`     | Writes to a **scratch** bucket to settle Hetzner Object Storage's actual semantics             |
| `scripts/check-hetzner-projects.py`   | Structural checks over the Pulumi projects here — see "Two Pulumi projects" below              |
| `scripts/check-address-plan-drift.py` | Gates the address plan against the shell-side and runbook literals that copy it                |
| `projectGuard.ts`                     | Refuses either stack if `hcloud:token` addresses the mail project — see below                  |
| `network.ts`                          | The private network, its subnet, and the estate's default route out to the internet            |
| `egress.ts`                           | Validates the default route's gateway against the constraints the route API enforces           |
| `estate.ts`, `estate/`                | The estate stack — `edge1` today; see "The estate stack" for what it does not create           |
| `provision/`                          | Idempotent host base provisioning, the Compose systemd template, and the deploy wrapper        |
| `../hetzner-host/`                    | The published `@branchleft/hetzner-host` package — `Host`, firewalls, cloud-init, address plan |

## Three projects, and why the boundary matters

hcloud has no fine-grained IAM. An API token has full power over everything in
its project — there is no read-only scope, no per-resource grant, no
conditions. **The project boundary is the entire isolation mechanism**, which
is why these are separate projects rather than separate label sets, and why
networks not spanning projects is a feature here rather than a limitation.

| Project | Holds                                                               | Token used by                                              |
| ------- | ------------------------------------------------------------------- | ---------------------------------------------------------- |
| mail    | `mx1` alone                                                         | `mail/`'s stack                                            |
| estate  | The `platform` network, `edge1`, and later `db1`, `app1..N`, `mon1` | `hetzner/`'s two stacks, and `ghost-platform`'s host stack |
| lab     | Spikes and scratch tenants; no production data ever                 | Local work only — never a repository secret                |

The estate and the mail host were one project until 2026-08-21. They were
split because the estate's token count is about to multiply — a token per
applying pipeline, across more than one repository — and every one of those
tokens would otherwise have had full power over `mx1`. mx1's sending
reputation is the asset here that is rebuildable in months rather than in an
afternoon, so it is the one that gets the boundary drawn around it. The
reasoning, the alternatives and the costs accepted are in
`ghost-platform-docs` doc 14 §3.4.

**What the split costs, recorded so it is not rediscovered as a surprise:**
Ghost's bulk-mail hop to the shim stays on the public internet permanently —
`10.20.1.40` is left unallocated in `addressPlan.ts` for that reason — and a
Prometheus scrape of `mx1` from `edge1` crosses the public internet too, so it
needs TLS and authentication or a source-IP allowance on mx1's firewall rather
than a private scrape.

**The boundary is not total, and one thing deliberately crosses it:** Pulumi
state. Both estate stacks and the mail stack keep their state in the one
Object Storage bucket, addressed by an S3 credential that is a separate
credential from any Cloud API token. Splitting the bucket too is tracked
separately; it is not something this split did.

`projectGuard.ts` is what keeps an estate stack out of the mail project. It
lists the servers the token can see, on every preview, and refuses the program
if `mx1` is among them. It cannot read a project identity — hcloud exposes no
project API at all, and nothing in a token says which project minted it — so
the check is a sentinel, not an identity assertion: it rules out the mail
project rather than confirming the estate one. That is enough here, because
that is the one direction where the mistake is
silent: the estate's state is empty before its first apply, so a mail-project
token plans a clean create of the whole estate inside the mail project and
every create succeeds. The reverse mistake needs no guard — the mail stack's
state names `mx1` by id, so an estate token makes the provider miss that id
and plan a replacement, which nobody confirms by accident.

The lab project does not exist yet. Projects are console-only; there is no
API for creating one — which is also why creating the estate project is a
platform-owner step and not something a stack can do for itself.

## The network

One network, one subnet and one route, the first two `protect: true` in
Pulumi. The **network** additionally carries `deleteProtection: true` at the API; the **subnet does
not**, because `hcloud.NetworkSubnet` exposes no such input — a console click
or any token in the project can delete it and detach every host, and only this
program's own `protect` stands in the way. A network cannot be resized
in place, so any change to its range is a replacement, and replacing it
detaches every host in the estate in a single operation. It therefore lives in
its own Pulumi project, applied approximately never, rather than sharing a
stack with anything on a delivery cadence.

The **route** is the estate's default, `0.0.0.0/0` via `edge1`. It is what
gives a host created without public networking any outbound path at all: such
a host's only route off the subnet is the network's own gateway, and Hetzner
resolves that against this table. It is unprotected on purpose — deleting it
detaches nothing and loses no state, and moving the gateway to another host
has to stay an ordinary apply. The forwarding at the far end is not Pulumi's:
`provision/nat-gateway.sh` installs it, and
`RUNBOOK-provision-host.md` carries the order the two have to happen in.

Addresses are static and listed in `@branchleft/hetzner-host`'s `addressPlan.ts`
(`../hetzner-host/addressPlan.ts`). Hetzner's DHCP allocates in creation
order, so a host rebuilt at any point would move — and firewall rules,
reverse-proxy upstreams, database grants and scrape targets all name peers
by address.

## The published package

`Host`, its per-role firewall rule sets, its cloud-init template and the
shared address plan (`host.ts`, `firewalls.ts`, `cloudInit.ts`,
`addressPlan.ts`) live in the sibling `hetzner-host/` directory as
`@branchleft/hetzner-host` — its own npm package, versioned and published to
GitHub Packages independently of this one. Two things drove that split:

- **Reach.** `ghost-platform` homes the database and app hosts and needs
  `Host` and the address plan to build them, but it cannot import a file from
  a repository it does not depend on. Publishing is what makes the pattern
  reachable there without duplicating it — duplication is explicitly
  rejected because the address plan needs exactly one source of truth: two
  independently edited copies of `HOST_IPS`/`APP_HOST_IPS` disagreeing is a
  host unreachable at the address its peers already use.
- **Statelessness.** Every export in `hetzner-host/` is a class, a function or
  a constant — importing the package constructs nothing. `network.ts` is the
  opposite: it builds the network and subnet at module scope and holds Pulumi
  state nothing else may duplicate. That is why `network.ts` (and `index.ts`,
  which pulls it in) stays here rather than moving with the rest — a
  published package that constructed infrastructure on import would create it
  in every consumer's stack, not once.

`estate.ts` depends on `@branchleft/hetzner-host` the same way `ghost-platform`
will: as a package dependency, not a relative import. See
`hetzner-host/README.md` for the package's own surface and versioning
discipline.

## Two Pulumi projects, one npm package

`hetzner/` is a single npm package holding two Pulumi projects: the network at
the package root, and the estate in `estate/`. That is deliberate on both
counts, and the second one has a trap that `scripts/check-hetzner-projects.py`
exists to catch.

**One package here**, so there is one `node_modules` and therefore one
`@pulumi/hcloud` version between `network.ts` and `estate.ts`. A provider
version is part of every resource's URN, and the estate's hosts attach to a
network the other project owns — two packages would put the two halves of one
topology behind two provider instances, and make a provider bump
indistinguishable from a resource change in a preview meant to be read as a
gate. `@branchleft/hetzner-host` keeps the same discipline from outside this
package: it pins `@pulumi/hcloud` to the identical exact version, so a
resource `Host` creates through the dependency and a resource `network.ts`
creates directly resolve the same provider — the property this section
describes is preserved across the package boundary, not just within it.

**Two projects**, because the network is replaced approximately never and
replacing it detaches every host in one operation, while the estate is applied
whenever a host is added or resized. Sharing a stack would put the first inside
the blast radius of the second.

The consequence is that `estate/` holds a `Pulumi.yaml` but no `package.json`,
so Pulumi walks up to the package root's when it looks for an entry point.
**A project in that position must set `main` explicitly.** Without it Pulumi
reads `../package.json`'s `"main": "index.ts"` and resolves it against the
_package_ root, so the estate project runs the network program: it previews a
create plan for a second network and subnet, exits 0, and reports nothing
wrong. Observed directly against Pulumi v3.255.0 while this layout was being
chosen — which is why it is a checked invariant and not a comment.

The checker also requires every project here to pin its own `backend.url`, and
all of them to pin the same one. `pulumi login` is global state on a
workstation, and a stack reference resolves inside a single backend.

## The estate stack

`estate.ts` is the first caller of the create pattern. It builds the hosts this
repository owns, against the network stack's `networkId` read through a stack
reference rather than copied into config.

| Host    | Role   | Public addresses | Private address | Created by       |
| ------- | ------ | ---------------- | --------------- | ---------------- |
| `edge1` | `edge` | IPv4 + IPv6      | `10.20.1.10`    | this stack       |
| `app1`  | `app`  | undecided        | `10.20.1.100`   | `ghost-platform` |
| `db1`   | `db`   | none             | `10.20.1.20`    | `ghost-platform` |

**Only `edge1` today, and that boundary is the placement rule rather than a
staging convenience.** The edge and monitoring hosts are this repository's; the
application and database hosts are the Ghost platform's, and the stack that
creates them lives there. It cannot yet: `@branchleft/hetzner-host` exists as
a package, but publishing it and setting its GitHub Packages visibility to
public are platform-owner-gated steps that have not run, so `ghost-platform`
cannot yet depend on it. Creating `app1` and `db1` is separately scoped once
it can. The monitoring host is a later addition to this stack, and not yet:
monitoring shares `edge1` until the first external tenant.

**The location is a shared constant, not this stack's config.** `location` is
create-time-only on `hcloud.Server`, the `cx` line's availability moves per
location, and the application and database hosts are the latency-sensitive
pairing that must be colocated. Two stacks in two repositories each carrying
their own `location` config value is exactly the shape in which the second
apply lands somewhere the first did not, permanently, with a clean preview.
`ESTATE_LOCATION` in `@branchleft/hetzner-host`'s `addressPlan.ts` is
therefore the single source, reached the same way by every consumer of the
package.

Two narrower types do part of the work. `HostArgs.location` is
`EuCentralLocation`, so a location outside the subnet's network zone is a
compile error rather than the apply-time attachment failure it would otherwise
be — that only holds because nothing widens it back to `string` on the way to
`hcloud.Server`, which is why the narrowing lives on `HostArgs` and not only on
the constant. `ESTATE_LOCATION` is typed narrower still, `EstateLocation`, which
is `nbg1 | hel1`: `fsn1` is in the zone and reaches the subnet, but no host in
this estate is sanctioned there.

Be honest about what none of that buys. A constant is weaker than a single
apply in two distinct ways. Nothing stops a stack passing some other
zone-valid location to `Host`. And **a stack that has already applied does not
follow a later edit to the constant** — its hosts stay where they were created,
so changing the line after any host exists silently describes an estate that is
already split.

That second gap is why the stack exports `estateLocation` from
`edge1.server.location` rather than re-exporting the constant. The constant is
the intention; the output is where the host actually is. A `ghost-platform`
stack reading the output through a stack reference can compare the two and see
a divergence; one reading the constant would be told what both stacks already
believed.

**Base pattern only.** No Caddy, no CrowdSec, no MySQL, no Prometheus. This
stack creates hosts; the per-role stacks deliver services onto them over SSH
and Compose, which is not Pulumi at all.

## The VM create pattern lives in `@branchleft/hetzner-host`

`host.ts` is what `mail/` does not provide — that stack _imports_ a
hand-provisioned server and is written to never create or replace it, which
does not generalise to a machine Pulumi creates. The pattern itself (`Host`,
its firewall rule sets, its cloud-init template, and the address plan every
host and its peers are named from), what each of its four resources does,
its create-time-only fields, the lab-host escape hatch, and why cloud-init is
a beachhead rather than configuration management, are all documented in
[`hetzner-host/README.md`](../hetzner-host/README.md) — read it there, not
here, since that is where the code now lives and where a future editor will
actually be working.

`estate.ts` is the worked example of consuming it: `import { Host, ... } from
'@branchleft/hetzner-host'`, a package dependency rather than a relative
import. It is currently a `file:` dependency on `../hetzner-host`, pending
the platform owner's publish (see "The published package" above) — once that
lands, `ghost-platform` consumes the identical package the same way, and
neither repository imports the other's files directly.

**Nothing runs `provision/` automatically, so a freshly created host is not
yet a hardened one** — no `fail2ban`, no unattended security upgrades, no
Docker, no deploy wrapper. `RUNBOOK-provision-host.md` is the step that closes
that, it is manual, and it belongs in the same session as the apply that
created the host. The first run cannot come from the deploy path, because the
deploy account it installs does not exist until it has run. This stays here
rather than moving with the pattern: it operates on a created host, not on
the create pattern itself.

## Identity: three keys, three jobs

| Identity           | Key                                                                                        | Reaches                                               | Held by                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| `root`             | The platform owner's key, registered in the hcloud project and injected at server creation | Everything                                            | The platform owner only — never CI                                             |
| `deploy`, unscoped | A per-host keypair generated for CI                                                        | One command, via sudo — but **any stack on the host** | Private half is a GitHub Actions secret; public half is stack config           |
| `deploy`, slotted  | A per-stack keypair, installed by `provision/provision_deploy_slot.py`                     | One image pin and restart, on **one** stack           | Private half is a GitHub Actions secret in the repository that owns that stack |

The `deploy` account is deliberately **not** in the `docker` group. Docker
group membership is root-equivalent — the socket will happily build a
container that mounts the host filesystem — so a deploy user placed in it is
unrestricted no matter how carefully its sudoers entry is written. Instead its
sudoers entry names exactly one binary, `/usr/local/sbin/branchleft-deploy`,
with no wildcard: a wildcard in a sudoers command matches spaces, which turns
any pattern-based restriction into argument injection.

**One binary is a sufficient bound on a host running one stack, and not on a
host running ten.** The unscoped form lets the caller name the stack, so on a
bin-packed app host every repository holding that key can pin an arbitrary
image into every other tenant's Compose slot and restart it. That is complete
takeover of a co-tenant's site by a credential meant only to redeploy its own,
and it is the primitive the move off per-service Cloud Run identities
introduces. Slot keys are the replacement.

### Slot keys

A slot key's `authorized_keys` entry carries `restrict` **and a forced
command**, and the stack name lives inside that forced command:

```text
restrict,command="/usr/bin/sudo -n /usr/local/sbin/branchleft-deploy --slot blog" ssh-ed25519 AAAA… branchleft-slot:blog
```

sshd runs exactly that whatever the client asked for, so the key's entire
capability is one image pin and one restart on `blog`. The image reference
arrives on stdin — the only channel a forced command leaves open once the
client's argv is discarded, short of opening sudo's `env_reset` for
`SSH_ORIGINAL_COMMAND`, which would mean editing the privileged sudoers grant
on every live host in order to add a control.

**The binding comes from the forced command because that removes the name
rather than checking it.** The alternative — one shared account, and the
wrapper deciding from which key authenticated — is not impossible, and it is
worth being accurate about why it loses. sshd _can_ be told to expose the
authenticating credential: `ExposeAuthInfo` writes the accepted key to a file
named by `SSH_USER_AUTH`, and `AuthorizedKeysCommand` receives its fingerprint
as `%f`. Both are server-side and neither is writable by the account. What
every such design still has is a comparison — caller-supplied stack name
against identity — that has to stay correct through every future edit, and
whose failure is silent, because a wrong comparison still deploys something. A
forced command has no comparison to get wrong. (`environment=` in
`authorized_keys` is a third option and a bad one: it needs
`PermitUserEnvironment`, which also lets anything holding the account set
`BASH_ENV` for the non-interactive shell every forced command runs under.)

`provision/provision_deploy_slot.py` is the only writer, and holds three
properties worth naming:

- **One key, one slot.** sshd stops at the first matching `authorized_keys`
  line, so a key installed twice always resolves to the same one. A grant is
  refused if the key already holds another slot, or matches a key on a line
  this script does not manage — that second case is the sharp one, because the
  unmanaged line renders first, so the slot would be cosmetic while the
  register reported it as scoped.
- **Rendered from a register, reconciled before every write.**
  `/etc/branchleft/deploy-slots/<stack>.pub` is the source of truth, and one
  `reconcile()` is the single arbiter that grant, revoke and `--list-slots` all
  call. A marked line the register cannot explain stops the run instead of
  being dropped by the re-render. That matters because the marker is a plain
  last field: an unrelated key whose comment happened to end in one would
  otherwise be deleted, and on this estate the unrelated key is the host-level
  one the marketing site deploys through.
- **The deploy account cannot write anything in its own home.** The home,
  `.ssh`, `authorized_keys` and every file beneath them move to root. Recursive
  is not tidiness: sshd runs a forced command through `$SHELL -c`, Debian
  builds bash with `SSH_SOURCE_BASHRC`, so a writable `~/.bashrc` runs ahead of
  every slot key on the host. It also closes `~/.ssh/authorized_keys2`, which
  sshd's default `AuthorizedKeysFile` still includes.

**What a slot key does not bound, stated rather than implied.** The sudoers
grant still names `branchleft-deploy` with no argument restriction, so the
forced command is the only layer: anything obtaining arbitrary execution as
`deploy` reaches every stack on the host regardless of which key it arrived on.
A second layer means per-slot sudoers entries with exact arguments, and those
buy nothing while a broader rule still matches — sudo takes the last matching
rule.

**Exactly one caller keeps that broader rule alive, and it is not the three you
would guess.** `edge` and `monitoring` are deployed by an operator over SSH
**as root** (`RUNBOOK-edge.md` §6, `RUNBOOK-monitoring.md`), which needs no
sudoers grant at all. The single remaining user of the `deploy` account is
`branchLeft/website`'s CI, which calls
`sudo -n /usr/local/sbin/branchleft-deploy website <image>@<digest>`. That same
workflow then runs an arbitrary `curl` over the same key as its smoke test —
so the website deploy key is a **shell** on the `deploy` account, not a scoped
credential, and it is the concrete instance of "arbitrary execution as
`deploy`" above. Slotting `website` therefore needs its smoke test rehomed
first; a forced command would break it.

Root stays key-reachable over SSH because it is the provisioning identity for
`provision/run-all.sh`. The break-glass path if that is ever lost is the
Hetzner console and rescue system, not a password.

## Deploys

`branchleft-deploy <stack> <image@sha256:...>` — or `branchleft-deploy --slot
<stack>` with the reference on stdin, for a slot key — is the whole of what CI
can do as root. It refuses anything but a digest-pinned reference, refuses a
`compose.yml` that does not resolve its image from `${IMAGE}` — a validated
digest the Compose file never reads is a pin in name only — writes
`/etc/branchleft/<stack>.image.env` atomically, restarts
`branchleft-compose@<stack>`, and rolls the pin back if the restart fails. A
rollback restart that also fails is reported as what it actually is -- the
unit `failed` on both pins -- rather than a claimed recovery that did not
happen, or an outage that a failed exit code alone does not prove: the unit
is `Type=oneshot`, so a failed restart never runs `ExecStop`, and `docker ps`
is what actually tells the two states apart.

This is the replacement for the website's `imageTag` mechanism, not a port of
it. The stack's Pulumi config carries no image reference at all, so there is
no committed placeholder for a local apply to revert production to.

Stack secrets live in `/etc/branchleft/<stack>.env`, which no automated path
writes — the unit loads both files and only the image pin is machine-managed.

**A stack that pins every image inline is outside this mechanism entirely, and
has to say so.** `branchleft-deploy` refuses it by design, so nothing writes its
`/etc/branchleft/<stack>.image.env`, and the template's mandatory
`EnvironmentFile=` for that file would then stop the unit starting at all. Such
a stack carries an instance drop-in resetting `EnvironmentFile=` and re-adding
its own secrets file — `monitoring` is the first, and
`hetzner/provision/test_compose_unit_contract.py` holds every stack to whichever
half of the contract it falls under. Deploying a new image to one of these means
editing the committed digest and re-copying `stack/`, not calling
`branchleft-deploy`.

### Which instances the health-wait contract actually reaches

`--wait` is a deploy signal only for a service that declares a `healthcheck:`.
Without one Compose waits for _running_, which a crash-looping container
transiently is, so the unit start succeeds in front of the crash loop and the
rollback above never fires.

`provision/test_compose_unit_contract.py` holds every service in this
repository's stacks to declaring one, or to carrying one in its own image. No
service is excused from both. It cannot hold anything else: the unit template is installed on every host role by
the base provisioning sequence, and `branchleft-deploy` restarts
`branchleft-compose@<stack>` for any stack name, while that test globs
`hetzner/*/stack/compose.yml`.

| Instance                                                   | Compose file committed in                                                    | Read by that test |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------- |
| `branchleft-compose@edge`                                  | here, `hetzner/edge/stack/`                                                  | yes               |
| `branchleft-compose@monitoring`                            | here, `hetzner/monitoring/stack/`                                            | yes               |
| `branchleft-compose@website`                               | `branchLeft/website`, `deploy/compose.yml`                                   | no                |
| `branchleft-compose@db`                                    | `branchLeft/ghost-platform`, `db/stack/compose.yml`                          | no                |
| `branchleft-compose@blog`, and one per further tenant slug | nowhere: rendered by `branchLeft/ghost-platform`'s `infra/tenant/compose.ts` | no                |

**No means unread, not failed.** Nothing in this repository has an opinion
about whether those stacks declare a health signal, so a service in one that
declares none is deployed unwatched, with `--wait` reporting a clean start over
it. The two registers in that test module are the machine-checked copy of this
table: a stack this repository names anywhere and classifies in neither of them
fails the suite, and so does a row here whose last column disagrees with them.
They are
a floor rather than a census — a tenant slug granted a deploy slot is written
down in no file here at all, so nothing here can discover it.

`branchleft_deploy.py` is the one piece here with real logic, and it is the
sum total of the CI account's privilege, so its argument validation and its
rollback path are unit-tested rather than left to a live deploy to discover.

```bash
python3 -m unittest discover -s provision -p 'test_*.py'
```

The TypeScript suites for the two pieces that are not declarative —
`cloudInit.ts` renders the document that installs the deploy account's key
beside its sudoers grant, from a value that arrives as stack config, and
`host.ts` decides from that same config whether a host gets public addresses
at all — live in `hetzner-host/`, alongside the code. `network.ts` and
`estate.ts` both construct resources at module scope, so `pulumi preview` is
what covers them, not Vitest. This project's own suite is
`hetznerHost.test.ts`, which does not test either file directly: it
constructs a `Host` from `@branchleft/hetzner-host` under this project's own
Pulumi mocks, proving the two packages' separate copies of the Pulumi SDK
interoperate across the boundary — see the file's own comment for why that is
not guaranteed for free.

```bash
nvm use && npm test          # from hetzner/ (hetznerHost.test.ts)
nvm use && npm test          # from hetzner-host/ (cloudInit.ts, host.ts)
python3 -m unittest discover -s scripts -p 'test_*.py'
```

## The edge stack

`edge/` is the first per-role service stack: Caddy terminating TLS in front of
CrowdSec, replacing the GCP load balancer's Cloud Armor policy and rate limit.
It is not a Pulumi project — nothing in it is a cloud resource. It is a
renderer, its tests, and the directory those tests produce.

- `edge/render.ts` derives the Caddy configuration and the CrowdSec acquisition
  files from the hostname registry in the repository root's `sites.ts`. The
  registry is the only hostname list; a hostname written directly into a Caddy
  configuration is one the retiring GCP edge does not know about, which is the
  class of stray record a cutover has to hunt for.
- `edge/posture.ts` is the one place enforcement changes. Both switches start
  non-enforcing, and each is flipped by a pull request: the rendered files are
  committed, so a flip is a diff in the exact configuration the host will run,
  and a redeploy of an unchanged tree cannot change it.
- `edge/stack/` is what is copied to `/opt/branchleft/edge`. Its three generated
  files are written by the test suite, which is also what fails when the
  committed copy no longer matches the registry:

```bash
nvm use && npm run render    # from hetzner/, rewrites edge/stack/
nvm use && npm test          # from hetzner/, fails if it is stale
```

Both need the **repository root's** `npm ci` to have been run as well as this
project's. The suite imports the root's `sites.ts`, Vitest loads the tsconfig
nearest to that file to transform it, and that tsconfig extends a package that
only resolves from a `node_modules` beside it. Without the root install the
failure is `Tsconfig not found`, which reads like a missing file rather than a
missing install.

Deploying it, verifying detect-only, and turning enforcement on:
[`RUNBOOK-edge.md`](RUNBOOK-edge.md).

## Firewalls filter the public interface only, and live in `hetzner-host/`

`firewalls.ts`'s `EDGE_RULES`/`INTERNAL_RULES` moved with the rest of the
pattern — see [`hetzner-host/README.md`](../hetzner-host/README.md) for what
they cover. The one fact worth restating here because it shapes how
`provision/` and every Compose file in this repository are written: **a
Hetzner Cloud firewall never sees traffic arriving over the private
network.** Nothing at that layer isolates one host from another; that comes
from what a service binds to. A database or an exporter binds its private
address, never `0.0.0.0`, and a host no deploy path reaches should be created
with `publicNetworking: false` rather than relying on a filtered public
address.

## Duplication with `mail/provision/`

Three of the base scripts here are near-copies of their `mail/` equivalents.
That is deliberate. `mail/provision/` provisions one host with a specific job
and a deliberately manual apply path; coupling it to the platform's base image
would mean every change to the platform base is a change with mx1 in its blast
radius. The duplicated surface is small, and the shared parts are the ones
least likely to change.
