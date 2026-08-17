# Hetzner foundations

The private network every platform host attaches to, and the estate that
network builds. Nothing here has been applied — both stacks are written and
reviewable before any resource exists. The VM-create pattern itself —
`Host`, its firewall rule sets, its cloud-init and the shared address plan —
is no longer part of this directory: it is the published package
`@branchleft/hetzner-host`, in the sibling `hetzner-host/` directory. See
"The published package" below for the boundary and why it sits outside this
one.

This file covers what is in this directory and why it is shaped the way it
is.

| File                                | What it is                                                                                     |
| ----------------------------------- | ---------------------------------------------------------------------------------------------- |
| `RUNBOOK-new-stack.md`              | Object Storage state backend + passphrase secrets provider, for new stacks                     |
| `RUNBOOK-provision-host.md`         | Delivering and running `provision/` against a newly created host                               |
| `scripts/probe-object-storage.py`   | Writes to a **scratch** bucket to settle Hetzner Object Storage's actual semantics             |
| `scripts/check-hetzner-projects.py` | Structural checks over the Pulumi projects here — see "Two Pulumi projects" below              |
| `network.ts`                        | The private network — the only resource this stack creates                                     |
| `estate.ts`, `estate/`              | The estate stack — `edge1` today; see "The estate stack" for what it does not create           |
| `provision/`                        | Idempotent host base provisioning, the Compose systemd template, and the deploy wrapper        |
| `../hetzner-host/`                  | The published `@branchleft/hetzner-host` package — `Host`, firewalls, cloud-init, address plan |

## Two projects, and why the boundary matters

hcloud has no fine-grained IAM. An API token has full power over everything in
its project — there is no read-only scope, no per-resource grant, no
conditions. **The project boundary is the entire isolation mechanism**, which
is why production and lab are separate projects rather than separate label
sets, and why networks not spanning projects is a feature here rather than a
limitation.

The lab project does not exist yet. Projects are console-only; there is no
API for creating one.

## The network

One network and one subnet, both `protect: true` in Pulumi. The **network**
additionally carries `deleteProtection: true` at the API; the **subnet does
not**, because `hcloud.NetworkSubnet` exposes no such input — a console click
or any token in the project can delete it and detach every host, and only this
program's own `protect` stands in the way. A network cannot be resized
in place, so any change to its range is a replacement, and replacing it
detaches every host in the estate in a single operation. It therefore lives in
its own Pulumi project, applied approximately never, rather than sharing a
stack with anything on a delivery cadence.

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

## Identity: two keys, two jobs

| Identity | Key                                                                                        | Reaches               | Held by                                                              |
| -------- | ------------------------------------------------------------------------------------------ | --------------------- | -------------------------------------------------------------------- |
| `root`   | The platform owner's key, registered in the hcloud project and injected at server creation | Everything            | The platform owner only — never CI                                   |
| `deploy` | A per-host keypair generated for CI                                                        | One command, via sudo | Private half is a GitHub Actions secret; public half is stack config |

The `deploy` account is deliberately **not** in the `docker` group. Docker
group membership is root-equivalent — the socket will happily build a
container that mounts the host filesystem — so a deploy user placed in it is
unrestricted no matter how carefully its sudoers entry is written. Instead its
sudoers entry names exactly one binary, `/usr/local/sbin/branchleft-deploy`,
with no wildcard: a wildcard in a sudoers command matches spaces, which turns
any pattern-based restriction into argument injection.

Its `authorized_keys` entry carries `restrict` and nothing added back. A
forced command is the tighter option and is the next step once the deploy verb
set stops moving.

Root stays key-reachable over SSH because it is the provisioning identity for
`provision/run-all.sh`. The break-glass path if that is ever lost is the
Hetzner console and rescue system, not a password.

## Deploys

`branchleft-deploy <stack> <image@sha256:...>` is the whole of what CI can do
as root. It refuses anything but a digest-pinned reference, refuses a
`compose.yml` that does not resolve its image from `${IMAGE}` — a validated
digest the Compose file never reads is a pin in name only — writes
`/etc/branchleft/<stack>.image.env` atomically, restarts
`branchleft-compose@<stack>`, and rolls the pin back if the restart fails,
reporting a failed rollback as the outage it is rather than claiming a
recovery that did not happen.

This is the replacement for the website's `imageTag` mechanism, not a port of
it. The stack's Pulumi config carries no image reference at all, so there is
no committed placeholder for a local apply to revert production to.

Stack secrets live in `/etc/branchleft/<stack>.env`, which no automated path
writes — the unit loads both files and only the image pin is machine-managed.

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
