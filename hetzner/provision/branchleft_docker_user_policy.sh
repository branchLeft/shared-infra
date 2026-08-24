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
# App hosts only. Refuses to run on the estate's NAT gateway: edge1 is the
# only host in the estate with a public interface (hetzner/estate.ts), and
# it forwards every private-only host's own internet egress plus its own
# reverse-proxy connections into the subnet. DOCKER-USER matches on address
# alone, not on which script wrote the rule, so installing this policy there
# would drop edge1's path to every app host and to db1.
set -euo pipefail

# Overridable so the tests can drive different values; production always
# gets the defaults, since nothing sets these in the environment. db1's
# address is hetzner-host/addressPlan.ts's HOST_IPS.db1, restated rather than
# read from stack state because this script has no Pulumi context to read it
# from -- the same reason branchleft_nat.sh's SUBNET is a literal default.
SUBNET="${BRANCHLEFT_DOCKER_USER_POLICY_SUBNET:-10.20.1.0/24}"
DB_HOST="${BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST:-10.20.1.20}"
DB_PORT="${BRANCHLEFT_DOCKER_USER_POLICY_DB_PORT:-3306}"

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

is_private_v4() {
    case "$1" in
        10.*|192.168.*|127.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        *) return 1 ;;
    esac
}

# The role guard. Every app host is created with publicNetworking: false, and
# edge1 is the one host in the estate created with it true -- so "does this
# host hold a public address at all" is an exact test for "is this the
# gateway", not a heuristic that happens to work today.
has_public_interface=0
while read -r address; do
    [[ -z "$address" ]] && continue
    if ! is_private_v4 "$address"; then
        has_public_interface=1
    fi
done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')

if [[ "$has_public_interface" -eq 1 ]]; then
    echo "branchleft-docker-user-policy: this host has a public interface -- it is the estate's NAT gateway, not an app host, and this policy is scoped to app hosts only" >&2
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
