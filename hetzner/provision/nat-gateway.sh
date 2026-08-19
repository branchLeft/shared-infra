#!/usr/bin/env bash
# Turns this host into the estate's NAT gateway: installs the rule reconciler
# and the unit that reasserts it at boot, then runs it once.
#
# Deliberately outside run-all.sh, which is the base every role gets. Exactly
# one host in the estate is the gateway -- the address the network stack's
# default route names -- and running this anywhere else either fails the
# reconciler's own guard or, on a second public host, quietly builds a path
# nothing routes to. RUNBOOK-provision-host.md says which host and when.
#
# Idempotent: both files are compared byte-for-byte before being replaced, and
# the reconciler it installs is itself idempotent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RECONCILER=/usr/local/sbin/branchleft-nat
UNIT=/etc/systemd/system/branchleft-nat.service

# Mode 0755 with root ownership is load-bearing rather than conventional:
# systemd runs this file as root at every boot, so a group- or world-writable
# copy is a root shell for whoever can write it.
if [[ -f "$RECONCILER" ]] && cmp -s "$SCRIPT_DIR/branchleft_nat.sh" "$RECONCILER"; then
    echo "nat-gateway: $RECONCILER already up to date, no-op"
else
    install -m 0755 -o root -g root "$SCRIPT_DIR/branchleft_nat.sh" "$RECONCILER"
    echo "nat-gateway: wrote $RECONCILER"
fi

if [[ -f "$UNIT" ]] && cmp -s "$SCRIPT_DIR/branchleft-nat.service" "$UNIT"; then
    echo "nat-gateway: $UNIT already up to date, no-op"
else
    install -m 0644 -o root -g root "$SCRIPT_DIR/branchleft-nat.service" "$UNIT"
    systemctl daemon-reload
    echo "nat-gateway: wrote $UNIT and reloaded systemd"
fi

systemctl enable branchleft-nat.service >/dev/null

# `restart`, not `start`. The unit is a RemainAfterExit oneshot, so once it has
# succeeded systemd considers it active and `start` is a no-op -- which would
# leave a freshly installed reconciler unrun until the next reboot.
systemctl restart branchleft-nat.service
systemctl --no-pager --lines=0 status branchleft-nat.service >/dev/null

echo "nat-gateway: done"
