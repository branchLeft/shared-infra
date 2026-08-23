#!/usr/bin/env bash
# Installs the private-host-egress reconciler and the unit that reasserts it
# at boot, then runs it once. Unlike nat-gateway.sh, this belongs in
# run-all.sh: the reconciler it installs is a no-op on any host with a public
# interface, so running it everywhere is safe, and every private-only host
# needs it -- there is no single designated host the way there is for the
# NAT gateway.
#
# Placed ahead of 10-harden-updates-fail2ban.sh on purpose: that script is
# the first one in the set that needs apt, and apt is exactly what a
# private-only host cannot reach until this has run.
#
# Idempotent: both installed files are compared byte-for-byte before being
# replaced, and the reconciler it installs is itself idempotent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RECONCILER=/usr/local/sbin/branchleft-host-egress
UNIT=/etc/systemd/system/branchleft-host-egress.service

# Mode 0755 with root ownership is load-bearing rather than conventional:
# systemd runs this file as root at every boot, so a group- or world-writable
# copy is a root shell for whoever can write it.
if [[ -f "$RECONCILER" ]] && cmp -s "$SCRIPT_DIR/branchleft_host_egress.sh" "$RECONCILER"; then
    echo "05-configure-host-egress: $RECONCILER already up to date, no-op"
else
    install -m 0755 -o root -g root "$SCRIPT_DIR/branchleft_host_egress.sh" "$RECONCILER"
    echo "05-configure-host-egress: wrote $RECONCILER"
fi

if [[ -f "$UNIT" ]] && cmp -s "$SCRIPT_DIR/branchleft-host-egress.service" "$UNIT"; then
    echo "05-configure-host-egress: $UNIT already up to date, no-op"
else
    install -m 0644 -o root -g root "$SCRIPT_DIR/branchleft-host-egress.service" "$UNIT"
    systemctl daemon-reload
    echo "05-configure-host-egress: wrote $UNIT and reloaded systemd"
fi

systemctl enable branchleft-host-egress.service >/dev/null

# `restart`, not `start`. The unit is a RemainAfterExit oneshot, so once it
# has succeeded systemd considers it active and `start` is a no-op -- which
# would leave a freshly installed reconciler unrun until the next reboot.
systemctl restart branchleft-host-egress.service
systemctl --no-pager --lines=0 status branchleft-host-egress.service >/dev/null

echo "05-configure-host-egress: done"
