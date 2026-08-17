# Hetzner foundations

The private network every platform host attaches to, the reusable pattern by
which those hosts are created, and the estate that pattern builds. Nothing here
has been applied — both stacks are written and reviewable before any resource
exists.

This file covers what is in this directory and why it is shaped the way it
is.

| File                                      | What it is                                                                              |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `RUNBOOK-new-stack.md`                    | Object Storage state backend + passphrase secrets provider, for new stacks              |
| `RUNBOOK-provision-host.md`               | Delivering and running `provision/` against a newly created host                        |
| `scripts/probe-object-storage.py`         | Writes to a **scratch** bucket to settle Hetzner Object Storage's actual semantics      |
| `scripts/check-hetzner-projects.py`       | Structural checks over the Pulumi projects here — see "Two Pulumi projects" below       |
| `network.ts`, `addressPlan.ts`            | The private network and its static addressing — the only resources that stack creates   |
| `host.ts`, `firewalls.ts`, `cloudInit.ts` | The VM create pattern                                                                   |
| `estate.ts`, `estate/`                    | The estate stack — `edge1` today; see "The estate stack" for what it does not create    |
| `provision/`                              | Idempotent host base provisioning, the Compose systemd template, and the deploy wrapper |

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

Addresses are static and listed in `addressPlan.ts`. Hetzner's DHCP allocates
in creation order, so a host rebuilt at any point would move — and firewall
rules, reverse-proxy upstreams, database grants and scrape targets all name
peers by address.

## Two Pulumi projects, one npm package

`hetzner/` is a single npm package holding two Pulumi projects: the network at
the package root, and the estate in `estate/`. That is deliberate on both
counts, and the second one has a trap that `scripts/check-hetzner-projects.py`
exists to catch.

**One package**, so there is one `node_modules` and therefore one
`@pulumi/hcloud` version. A provider version is part of every resource's URN,
and the estate's hosts attach to a network the other project owns — two
packages would put the two halves of one topology behind two provider
instances, and make a provider bump indistinguishable from a resource change
in a preview meant to be read as a gate.

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
creates them lives there. It cannot yet, because the create pattern is not
published as a package for that repository to consume — so those hosts do not
exist and their capacity is not held. The monitoring host is a later addition
to this stack, and not yet: monitoring shares `edge1` until the first external
tenant.

**The location is a shared constant, not this stack's config.** `location` is
create-time-only on `hcloud.Server`, the `cx` line's availability moves per
location, and the application and database hosts are the latency-sensitive
pairing that must be colocated. Two stacks in two repositories each carrying
their own `location` config value is exactly the shape in which the second
apply lands somewhere the first did not, permanently, with a clean preview.
`ESTATE_LOCATION` in `addressPlan.ts` is therefore the single source, and it
travels with the pattern when the pattern is published.

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

## The VM create pattern

`host.ts` is what `mail/` does not provide. That stack _imports_ a
hand-provisioned server, and its `ignoreChanges` on `publicNets` and
`firewallIds`, plus `protect: true` on the server itself, exist to make a
pre-existing machine reconcile without proposing to touch it. None of that
generalises to a machine Pulumi creates. `sshKeys` and `image` are ignored
here too, but for a different reason: both are create-time-only at the
provider whatever the server's provenance.

A `Host` produces five resources: the server, a role-scoped firewall, a
private-network attachment at its fixed address, and — unless
`publicNetworking` is off — an IPv4 and an IPv6 primary IP of its own. Four
properties are worth knowing before using it:

- **The firewall is declared on the server, not attached afterwards.** An
  attachment applied as a following step leaves a window in which a freshly
  created host is on the public internet with no filter.
- **`userData` is in `ignoreChanges`.** Cloud-init runs once, on first boot,
  so a later edit to the template cannot affect a running host — but the
  provider treats the field as replacing, and without this an edit here
  proposes rebuilding the whole estate for no effect. The corollary is the
  rule below, and the consequence for the deploy key is a rotation that
  cannot go through Pulumi at all — `RUNBOOK-provision-host.md` carries the
  procedure that does work.
- **Primary IPs are declared, not allocated.** Left to server creation they
  carry `auto_delete`, so a rebuild releases the address. With a manual DNS
  zone and HTTP-01 issuance, an address that changes cannot be repaired by
  any program — every record is hand-edited and has to propagate before a
  single hostname can reissue.
- **`publicNetworking` is a create-time decision.** Flipping it from `true`
  to `false` on a live host asks Pulumi to delete two delete-protected
  primary IPs, the API refuses, and the stack wedges mid-update. Changing it
  afterwards means applying once with `protection: false` and then again with
  `publicNetworking: false`.

**Lab hosts set `protection: false` and `environment: 'lab'`.** With
protection on, `pulumi destroy` cannot tear a spike down without editing the
component, which turns every throwaway host into manual console cleanup; and
a lab host labelled `env: production` corrupts cost attribution and any
label-selector rule that reads it. Both default to the production values, so
a lab stack has to say so — which is the right way round.

**Cloud-init is a beachhead, not configuration management.** It creates the
deploy account, closes password authentication, and makes the directories the
rest needs. Everything that must _stay_ true belongs in `provision/`, whose
scripts are idempotent and re-runnable. If you find yourself wanting to add a
package or a config file to `cloudInit.ts`, it almost certainly belongs in a
provision script instead.

**Nothing runs `provision/` automatically, so a freshly created host is not
yet a hardened one** — no `fail2ban`, no unattended security upgrades, no
Docker, no deploy wrapper. `RUNBOOK-provision-host.md` is the step that closes
that, it is manual, and it belongs in the same session as the apply that
created the host. The first run cannot come from the deploy path, because the
deploy account it installs does not exist until it has run.

**Importing the pattern.** Import `./host`, `./firewalls`, `./cloudInit` and
`./addressPlan` directly — never the package root. `index.ts` pulls in
`./network`, which constructs the network and subnet at module scope, so a
stack that imported the root to get `Host` would find a network in its own
state. `estate.ts` is the worked example. The package is also `private: true`
and unpublished, so a consumer in another repository cannot reach any of it.

The programme homes the database and app hosts in `ghost-platform`, reached by
publishing `host.ts`, `firewalls.ts`, `cloudInit.ts` and `addressPlan.ts` as a
package that repository consumes. Until that package exists there is no
supported way for a stack there to import any of this, which is why the estate
stack creates the edge host and nothing else.

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

The TypeScript side has two suites, for the two pieces that are not declarative.
`cloudInit.ts` renders the document that installs the deploy account's key
beside its sudoers grant, from a value that arrives as stack config — and
`userData` is create-time-only _and_ in `ignoreChanges`, so an injected
cloud-config would be permanent and absent from every later diff. `host.ts`
decides from that same config whether a host gets public addresses at all.

```bash
nvm use && npm test          # from hetzner/
python3 -m unittest discover -s scripts -p 'test_*.py'
```

## Firewalls filter the public interface only

A Hetzner Cloud firewall never sees traffic arriving over the private
network. Nothing in `firewalls.ts` isolates one host from another; that comes
from what a service binds to, and belongs in each host's Compose file. A
database or an exporter binds its private address, never `0.0.0.0`.

A host that no deploy path reaches — the database host is the clear case —
should be created with `publicNetworking: false`, which gives it no public
address at all rather than a filtered one. `Host` defaults it on because the
deploy path is SSH from GitHub-hosted runners, and a host CI must reach needs
an address to reach; the default is the common case, not the recommendation.

Egress is unrestricted deliberately. With only inbound rules present Hetzner
allows all outbound; adding any outbound rule flips the host to default-deny
and silently breaks package updates, ACME, registry pulls and outbound mail at
the moment it applies. That is a change to make with a specific per-role
allow-list, not as a side effect.

## Duplication with `mail/provision/`

Three of the base scripts here are near-copies of their `mail/` equivalents.
That is deliberate. `mail/provision/` provisions one host with a specific job
and a deliberately manual apply path; coupling it to the platform's base image
would mean every change to the platform base is a change with mx1 in its blast
radius. The duplicated surface is small, and the shared parts are the ones
least likely to change.
