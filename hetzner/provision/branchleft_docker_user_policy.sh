#!/usr/bin/env bash
# Confines the forwarded reach of every tenant container on an app host to
# db1:3306, closing off the co-tenant containers, edge1's metrics/CrowdSec
# surfaces and the Hetzner metadata service that a published port would
# otherwise leave reachable across the whole private subnet.
#
# Installed as /usr/local/sbin/branchleft-docker-user-policy by
# app-host-isolation.sh and re-run at every boot by
# branchleft-docker-user-policy.service. Idempotent: every rule is checked
# before it is added.
#
# App hosts only. Refuses to run on the estate's NAT gateway, edge1, which
# forwards every private-only host's own internet egress plus its own
# reverse-proxy connections into the subnet. DOCKER-USER matches on address
# alone, not on which script wrote the rule, so installing this policy there
# would drop edge1's path to every app host and to db1.
set -euo pipefail

# Overridable so the tests can drive different values; production always
# gets the defaults, since nothing sets these in the environment. db1's
# address and the gateway's are hetzner-host/addressPlan.ts's HOST_IPS,
# restated rather than read from stack state because this script has no
# Pulumi context to read them from -- the same reason branchleft_nat.sh's
# SUBNET is a literal default.
SUBNET="${BRANCHLEFT_DOCKER_USER_POLICY_SUBNET:-10.20.1.0/24}"
DB_HOST="${BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST:-10.20.1.20}"
DB_PORT="${BRANCHLEFT_DOCKER_USER_POLICY_DB_PORT:-3306}"
GATEWAY_PRIVATE_IP="${BRANCHLEFT_DOCKER_USER_POLICY_GATEWAY_IP:-10.20.1.10}"

# The metadata service's own address, hardcoded because it is Hetzner's, not
# the estate's -- the same reasoning branchleft_host_egress.sh uses for it.
METADATA_ADDRESS="169.254.169.254"

# Debian ships no iptables in the cloud image; it arrives as a dependency of
# docker-ce. Named explicitly because the alternative is exit 127 from inside
# a systemd oneshot, which reads as a broken unit rather than a missing step.
if ! command -v iptables >/dev/null 2>&1; then
    echo "branchleft-docker-user-policy: iptables is not installed -- run 20-install-docker.sh first" >&2
    exit 1
fi

# The role guard. "Does this host hold a public address" is NOT the test:
# app1 is also created with publicNetworking: true, deliberately, so that
# GitHub-hosted CI runners can reach it over SSH to deploy
# (ghost-platform/infra/hosts/index.ts) -- a host with no public address
# cannot be reached by a runner at all, and first provisioning needs the same
# door before the deploy account exists. So the estate has at least two hosts
# with a public interface, and only one of them is the gateway.
#
# What actually identifies edge1 is its address: 10.20.1.10 is assigned to
# it alone (hetzner-host/addressPlan.ts's HOST_IPS.edge1), the same address
# RUNBOOK-provision-host.md's own gateway instructions and `hetzner/network.ts`'s
# route already name it by. Checking for that address is checking the one
# fact about this host that is actually load-bearing for "is this the
# gateway", rather than a network property two different roles both have.
holds_gateway_address=0
while read -r address; do
    [[ "$address" == "$GATEWAY_PRIVATE_IP" ]] && holds_gateway_address=1
done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')

if [[ "$holds_gateway_address" -eq 1 ]]; then
    echo "branchleft-docker-user-policy: this host holds the estate's gateway address ($GATEWAY_PRIVATE_IP) -- it is edge1, not an app host, and this policy is scoped to app hosts only" >&2
    exit 1
fi

# DOCKER-USER exists only under dockerd's iptables firewall backend. The
# nftables backend is opt-in today and a stated future default, and
# 20-install-docker.sh installs Docker CE deliberately unpinned under
# unattended-upgrades, so the backend can change without a change on this
# side. There is no safe substitute chain the way FORWARD is for
# branchleft_nat.sh: that script's fallback exists because a host with no
# Docker at all still needs a working NAT path, but a policy that bounds
# container traffic has nothing to bound on a host where Docker is not
# enforcing through iptables, and writing it into FORWARD would filter
# forwarded traffic that has nothing to do with any container.
if ! iptables -t filter -S DOCKER-USER >/dev/null 2>&1; then
    echo "branchleft-docker-user-policy: no DOCKER-USER chain in iptables -- either Docker is not installed yet (run 20-install-docker.sh first) or its nftables firewall backend is active instead of iptables, and there is no safe substitute chain for this policy" >&2
    exit 1
fi

ensure_rule() {
    local table="$1" chain="$2"
    shift 2
    if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        echo "branchleft-docker-user-policy: $table/$chain already carries: $*"
    else
        iptables -t "$table" -I "$chain" 1 "$@"
        echo "branchleft-docker-user-policy: inserted into $table/$chain: $*"
    fi
}

# Written in the reverse of the order the rules must be evaluated in: each
# insert lands at position 1, so whichever call runs *last* ends up matched
# *first*. The two drops go in before either accept, so neither accept is
# ever pushed below them by a later insert; db1 goes in before the conntrack
# accept for the same reason. The decided order -- (1) established traffic,
# (2) db1, (3) drop the rest -- is what the chain actually carries only
# because the calls below run in the opposite order.

# DOCKER-USER sees every forwarded packet on the host, including a tenant's
# own outbound traffic to the public internet, so the drop has to name the
# subnet and the metadata address specifically rather than default-denying
# everything that isn't db1 -- a blanket deny is the outbound-egress rule
# this programme has already ruled out on cost grounds (breaks updates, ACME
# and registry pulls the moment it is applied).
ensure_rule filter DOCKER-USER -d "$METADATA_ADDRESS" -j DROP
ensure_rule filter DOCKER-USER -d "$SUBNET" -j DROP

# The one destination a tenant legitimately opens. Scoped to TCP and the
# port MySQL listens on, not merely the address: db1 also carries an
# exporter and administrative sockets no tenant container needs, and this
# script is the one reviewed, tested place that allow-list is meant to live.
ensure_rule filter DOCKER-USER -d "$DB_HOST" -p tcp --dport "$DB_PORT" -j ACCEPT

# Has to be the first rule DOCKER-USER evaluates. A published port is a DNAT,
# so an inbound flow's reply (edge1 -> a tenant's Ghost, or a scrape -> a
# tenant's metrics port) leaves the container with dst inside this subnet --
# exactly what the drop above matches -- and conntrack state is the only
# thing that tells that reply apart from a tenant-initiated connection to a
# co-tenant. Reversing this against the drops is the outage this script
# exists to not ship.
ensure_rule filter DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "branchleft-docker-user-policy: app-host isolation applied in DOCKER-USER"
