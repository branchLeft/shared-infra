# estate.ts

## Header

The hosts this repository owns: the edge, the monitoring host once it
splits off it, and `ops1` — a shared, product-agnostic operations host
(today self-hosted Calendly-equivalent booking + video calling), which
belongs here rather than in `ghost-platform` precisely because it has
nothing to do with the Ghost platform. The Ghost application and database
hosts are still homed in the Ghost platform repository and created by a
stack there, not by this one — `ops1` is not one of those; it is
shared estate infrastructure like `edge1`, just not edge-role.

`Host` and the address plan come from `@branchleft/hetzner-host` — the same
package `ghost-platform` depends on for its own hosts — never from
`./index`, which constructs the network at module scope; importing it here
would put a second network in this stack's state.

The program file sits in the package root while its Pulumi project sits in
`estate/`, so that both projects share one `node_modules`. That resolves
one `@pulumi/hcloud` version for `network.ts`'s own resources, and this
project's `@branchleft/hetzner-host` dependency exact-pins the same
version, so `Host`'s resources resolve it too. A provider version is part
of every resource's URN, and these resources attach to a network another
project owns.

## ops1

Runs self-hosted Nextcloud (Calendar/Appointments booking + Talk video) —
shared collaboration infrastructure, not a Ghost tenant, so it is not
homed in `ghost-platform`. Private-only, like `db1`: reached through the
`edge1` jump host over the private network, per
`RUNBOOK-provision-host.md` §5, rather than carrying its own public IPs.
That keeps the estate's public attack surface unchanged by this host's
addition.

**No container on this host may ever hold the Docker socket.** Nextcloud
AIO's master container needs exactly that to manage its own sibling
containers, which is root-equivalent host access — and `DOCKER-USER`
(what `app-host-isolation.sh` writes to) only filters Docker's _forward_
chain. It cannot bound a process with host root: that process can reach
any interface directly or simply flush the rules, so it is not a
containment boundary against this specific risk, whatever else it is
doing for a Ghost tenant's published ports. **Deploy plain Nextcloud
instead** — the official image(s) over ordinary Docker Compose, no
Docker-in-Docker orchestrator, no socket mount anywhere on this host.
That is what actually removes the risk, not an isolation policy layered
on top of accepting it.

`app-host-isolation.sh` is still installed here, exactly as on any other
app host — nothing about running it here differs. `branchleft_docker_user_policy.sh`
self-identifies this host by its own address (`10.20.1.50`, the
`NO_DB_EXCEPTION_ADDRESSES` default) the same way it already
self-identifies `edge1` as the gateway, and skips the `db1` exception for
it automatically — not from a one-off environment variable, which
`branchleft-docker-user-policy.service` carries none of and which
therefore cannot survive to the next boot. That bounds an ordinary
container compromise; it was never being asked to bound a host-rooted
one, and nothing here claims it does.
