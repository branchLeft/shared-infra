#!/bin/sh
# Test scaffolding, not part of the role. A container's /proc/sys is read-only
# whatever capability it holds, so the real sysctl fails there. This stands in
# for it: it records its arguments, and answers the one question the NAT
# reconciler asks of it (`sysctl -n net.ipv4.ip_forward`) with 1, or with 0
# while /run/egress-nat-forwarding-off exists, so that the scenario can show the
# reconciler refusing a host that is not forwarding. The reconciler only reads
# the value (the edge_firewall role turns forwarding on); the verify play asserts
# that no call to this stand-in ever wrote one.
printf '%s\n' "$*" >> /run/egress-nat-sysctl-calls
case "$*" in
    "-n net.ipv4.ip_forward")
        if [ -f /run/egress-nat-forwarding-off ]; then
            echo 0
        else
            echo 1
        fi
        ;;
esac
exit 0
