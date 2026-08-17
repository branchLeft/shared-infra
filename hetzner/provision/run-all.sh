#!/usr/bin/env bash
# Runs the base provisioning sequence in order. Safe to re-run: every script
# it calls checks current state before changing anything.
#
# This is the host *base*, common to every role. Role-specific provisioning
# (Caddy and CrowdSec on the edge, MySQL on the database host, the Prometheus
# stack on the monitoring host) runs after this and lives with the stack that
# owns that role.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for script in \
    00-harden-ssh.sh \
    10-harden-updates-fail2ban.sh \
    20-install-docker.sh \
    30-install-deploy-tooling.sh
do
    echo "=== running $script ==="
    "$SCRIPT_DIR/$script"
done
