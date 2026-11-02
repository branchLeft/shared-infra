#!/usr/bin/env bash
# Refuses. This script used to make the host the estate's NAT gateway by
# installing the reconciler and its unit. The gateway is now made by two Ansible
# roles, applied to edge1 through the gated pull: edge_firewall, which loads
# the masquerade in its own nftables table and turns forwarding on, and
# egress_nat, which installs the reconciler that keeps the forwarding accepts in
# DOCKER-USER. The reconciler no longer masquerades, so a host built by this
# script alone would forward packets out with private source addresses and no
# outbound internet, with every check of the reconciler's own passing.
#
# Kept as a file so that a runbook, a note or a habit that still names it meets
# this message and not "No such file". Exits 1 on every host, always.
set -euo pipefail

echo "nat-gateway: refusing. The gateway is made by the edge_firewall and egress_nat roles," >&2
echo "nat-gateway: applied to edge1 by the gated ansible-delivery run; see" >&2
echo "nat-gateway: hetzner/RUNBOOK-provision-host.md step 2. This script installs nothing." >&2
exit 1
