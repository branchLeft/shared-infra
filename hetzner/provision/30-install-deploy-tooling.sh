#!/usr/bin/env bash
# Installs the Compose unit template and the one binary the CI deploy account
# is allowed to run under sudo. Idempotent: both files are compared
# byte-for-byte before being replaced, and systemd is only reloaded when the
# unit actually changed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WRAPPER=/usr/local/sbin/branchleft-deploy
UNIT=/etc/systemd/system/branchleft-compose@.service

install -d -m 0755 -o root -g root /etc/branchleft /opt/branchleft

# Mode 0755 with root ownership is load-bearing, not conventional: sudo runs
# this file as root on the deploy account's behalf, so a group- or
# world-writable copy would be an unrestricted root shell for that account.
if [[ -f "$WRAPPER" ]] && cmp -s "$SCRIPT_DIR/branchleft_deploy.py" "$WRAPPER"; then
    echo "30-install-deploy-tooling: $WRAPPER already up to date, no-op"
else
    install -m 0755 -o root -g root "$SCRIPT_DIR/branchleft_deploy.py" "$WRAPPER"
    echo "30-install-deploy-tooling: wrote $WRAPPER"
fi

if [[ -f "$UNIT" ]] && cmp -s "$SCRIPT_DIR/branchleft-compose@.service" "$UNIT"; then
    echo "30-install-deploy-tooling: $UNIT already up to date, no-op"
else
    install -m 0644 -o root -g root "$SCRIPT_DIR/branchleft-compose@.service" "$UNIT"
    systemctl daemon-reload
    echo "30-install-deploy-tooling: wrote $UNIT and reloaded systemd"
fi

# The sudoers drop-in is written by cloud-init at first boot. Verified rather
# than rewritten here: a syntactically broken sudoers file locks every
# account out of sudo, and `visudo -c` is the only safe way to find out.
SUDOERS=/etc/sudoers.d/50-branchleft-deploy
if [[ ! -f "$SUDOERS" ]]; then
    echo "30-install-deploy-tooling: $SUDOERS missing -- host was not created from the platform cloud-init" >&2
    exit 1
fi
visudo -c -f "$SUDOERS" >/dev/null
echo "30-install-deploy-tooling: done"
