#!/bin/sh
# Test scaffolding, not part of the role. The NAT reconciler turns forwarding
# on with sysctl -q -w net.ipv4.ip_forward=1, and a container's /proc/sys is
# read-only whatever capability it holds, so the real command fails there. This
# stands in for it: it records its arguments and succeeds, so that the test can
# assert the reconciler made the call it makes on a host.
printf '%s\n' "$*" >> /run/egress-nat-sysctl-calls
exit 0
