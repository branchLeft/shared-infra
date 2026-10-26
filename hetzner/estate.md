# estate.ts

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
(what `app-host-isolation.sh` writes to) only filters Docker's *forward*
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
