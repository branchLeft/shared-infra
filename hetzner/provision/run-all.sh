#!/usr/bin/env bash
# Runs the base provisioning sequence in order. Safe to re-run: every script
# it calls checks current state before changing anything.
#
# This is the host *base*, common to every role. Role-specific provisioning
# (Caddy and CrowdSec on the edge, MySQL on the database host, the Prometheus
# stack on the monitoring host) runs after this and lives with the stack that
# owns that role.
#
# 05-configure-host-egress.sh runs ahead of 10-harden-updates-fail2ban.sh
# deliberately: that is the first script in the set that needs apt, and apt
# is exactly what a private-only host cannot reach without it. Unlike
# nat-gateway.sh below, it belongs in this set -- it no-ops cleanly on any
# host with a public interface, so every role can run it unconditionally.
#
# nat-gateway.sh is the one script in this directory that is neither base nor
# role-specific, and it is not called below. Exactly one host in the estate is
# the gateway, and a second one masquerading the subnet builds a path nothing
# routes to -- which no guard in either script catches. The closing notice is
# there because a rebuilt gateway otherwise comes back fully provisioned, with
# no forwarding and no warning that any is missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for script in \
    00-harden-ssh.sh \
    05-configure-host-egress.sh \
    10-harden-updates-fail2ban.sh \
    20-install-docker.sh \
    30-install-deploy-tooling.sh
do
    echo "=== running $script ==="
    "$SCRIPT_DIR/$script"
done

echo "=== base provisioning complete ==="
echo "note: this set does not configure the estate's NAT gateway. If this host"
echo "      is the gateway, nat-gateway.sh has to be run as well; on every"
echo "      other host it must not be. RUNBOOK-provision-host.md says which."
