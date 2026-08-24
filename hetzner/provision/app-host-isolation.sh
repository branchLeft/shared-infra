#!/usr/bin/env bash
# Installs the app-host DOCKER-USER isolation policy and the unit that
# reasserts it at boot, then runs it once.
#
# Deliberately outside run-all.sh, the same way nat-gateway.sh is. This
# policy is scoped to app hosts: the reconciler it installs refuses to run on
# the estate's NAT gateway, so running this script there fails at the last
# step rather than silently doing nothing, and running it on db1 or mon1 is
# simply not part of what this story specifies. RUNBOOK-provision-host.md
# says which hosts.
#
# Idempotent: both files are compared byte-for-byte before being replaced,
# and the reconciler it installs is itself idempotent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RECONCILER=/usr/local/sbin/branchleft-docker-user-policy
UNIT=/etc/systemd/system/branchleft-docker-user-policy.service

# Mode 0755 with root ownership is load-bearing rather than conventional:
# systemd runs this file as root at every boot, so a group- or world-writable
# copy is a root shell for whoever can write it.
if [[ -f "$RECONCILER" ]] && cmp -s "$SCRIPT_DIR/branchleft_docker_user_policy.sh" "$RECONCILER"; then
    echo "app-host-isolation: $RECONCILER already up to date, no-op"
else
    install -m 0755 -o root -g root "$SCRIPT_DIR/branchleft_docker_user_policy.sh" "$RECONCILER"
    echo "app-host-isolation: wrote $RECONCILER"
fi

if [[ -f "$UNIT" ]] && cmp -s "$SCRIPT_DIR/branchleft-docker-user-policy.service" "$UNIT"; then
    echo "app-host-isolation: $UNIT already up to date, no-op"
else
    install -m 0644 -o root -g root "$SCRIPT_DIR/branchleft-docker-user-policy.service" "$UNIT"
    systemctl daemon-reload
    echo "app-host-isolation: wrote $UNIT and reloaded systemd"
fi

systemctl enable branchleft-docker-user-policy.service >/dev/null

# `restart`, not `start`. The unit is a RemainAfterExit oneshot, so once it
# has succeeded systemd considers it active and `start` is a no-op -- which
# would leave a freshly installed reconciler unrun until the next reboot.
systemctl restart branchleft-docker-user-policy.service
systemctl --no-pager --lines=0 status branchleft-docker-user-policy.service >/dev/null

echo "app-host-isolation: done"
