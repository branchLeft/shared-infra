#!/usr/bin/env bash
# Runs the full provisioning sequence in order. Safe to re-run: every script
# it calls checks current state before changing anything.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for script in \
    00-harden-ssh.sh \
    10-harden-updates-fail2ban.sh \
    20-install-docker.sh \
    30-deploy-stalwart.sh \
    40-configure-stalwart.sh \
    50-provision-mailboxes.sh \
    60-provision-website-submission-credential.sh \
    61-provision-blog-submission-credential.sh \
    62-provision-shim-submission-credential.sh \
    63-deploy-mailgun-shim.sh \
    65-install-local-resolver.sh \
    70-schedule-dnsbl-check.sh
do
    echo "=== running $script ==="
    "$SCRIPT_DIR/$script"
done
