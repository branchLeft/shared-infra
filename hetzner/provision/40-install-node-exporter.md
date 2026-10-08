# 40-install-node-exporter.sh

## Module overview

Installs Prometheus's node_exporter as a native binary and systemd unit --
not a Compose service -- and the unit that keeps it running at boot, then
starts it once.

## Where it runs

Deliberately outside `run-all.sh`, the same way `app-host-isolation.sh` and
`nat-gateway.sh` are: this is not every host's base provisioning, it is a
named host's own addition (ops1, today). A future story pointing this same
script at app1 or db1 is exactly what it is written to allow -- nothing
below hardcodes ops1 -- but running it there is not what today's story
specifies, so `RUNBOOK-monitoring.md` is what decides which host actually
gets it run against it, the same way `RUNBOOK-provision-host.md` decides for
`app-host-isolation.sh`.

## Why native rather than a Compose service

A fourth Compose service on this host would not work. ops1 runs
`app-host-isolation.sh`'s DOCKER-USER policy (`branchleft_docker_user_policy.sh`),
which drops every _forwarded_ packet to the estate subnet with no carve-out
for this host. A published container port is reached by a DNAT, which is
forwarded traffic and is exactly what that policy blocks; a native process
bound to this host's own private address is delivered locally via INPUT,
which DOCKER-USER never inspects (see that script's own header, and
`RUNBOOK-provision-host.md`'s "Confine tenant containers on each app host").
`node-exporter.service`'s own header carries the same note for anyone
reading the unit in isolation.

## Idempotence

The binary is left alone once the installed version already matches, the
env file and unit are compared before being replaced, and the service is
only restarted when something actually changed.
