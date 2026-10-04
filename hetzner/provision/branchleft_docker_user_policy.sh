#!/usr/bin/env bash
# App-host DOCKER-USER isolation: confines every container's forwarded reach to
# db1:3306 (skipped on hosts in NO_DB_EXCEPTION_ADDRESSES), and refuses
# everything a container on the mail spool's drain bridge opens, over IPv4 and
# IPv6. Installed by app-host-isolation.sh, re-run at boot by its unit with no
# arguments or environment. Refuses to run on edge1. Idempotent.
# Procedures (re-run, read-back, undo) live in ghost-platform-docs, not here.
set -euo pipefail

# Overridable so the tests can drive different values; production always
# gets the defaults, since nothing sets these in the environment. db1's
# address and the gateway's are hetzner-host/addressPlan.ts's HOST_IPS,
# restated rather than read from stack state because this script has no
# Pulumi context to read them from -- the same reason branchleft_nat.sh's
# SUBNET is a literal default.
SUBNET="${BRANCHLEFT_DOCKER_USER_POLICY_SUBNET:-10.20.1.0/24}"
DB_PORT="${BRANCHLEFT_DOCKER_USER_POLICY_DB_PORT:-3306}"
GATEWAY_PRIVATE_IP="${BRANCHLEFT_DOCKER_USER_POLICY_GATEWAY_IP:-10.20.1.10}"

# Space-separated so a second non-tenant app host is one value away, not a
# script change. ops1 (hetzner-host/addressPlan.ts's HOST_IPS) is the
# only one today. A host in this list gets the db1 exception skipped below,
# purely from recognising its own address -- see the header comment for why
# that, and not an env var a caller passes once, is what has to decide this.
NO_DB_EXCEPTION_ADDRESSES="${BRANCHLEFT_DOCKER_USER_POLICY_NO_DB_EXCEPTION_ADDRESSES:-10.20.1.50}"

# The spool's one non-internal network, a bridge with this fixed name so a
# host rule can match it (render-core's MAIL_SPOOL_DRAIN_BRIDGE). Docker needs
# it only to publish the spool's drain port on host loopback; the spool opens
# no connection of its own, so everything it opens off this bridge is refused.
MAIL_SPOOL_BRIDGE="${BRANCHLEFT_DOCKER_USER_POLICY_MAIL_SPOOL_BRIDGE:-br-mailspool}"

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

# The role guard. "Holds a public address" is not the test: app1 has one too,
# for CI SSH deploys. What identifies edge1 is its address, 10.20.1.10
# (hetzner-host/addressPlan.ts HOST_IPS.edge1), which no app host holds.
holds_gateway_address=0
holds_no_db_exception_address=0
while read -r address; do
    [[ "$address" == "$GATEWAY_PRIVATE_IP" ]] && holds_gateway_address=1
    for candidate in $NO_DB_EXCEPTION_ADDRESSES; do
        [[ "$address" == "$candidate" ]] && holds_no_db_exception_address=1
    done
done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')

if [[ "$holds_gateway_address" -eq 1 ]]; then
    echo "branchleft-docker-user-policy: this host holds the estate's gateway address ($GATEWAY_PRIVATE_IP) -- it is edge1, not an app host, and this policy is scoped to app hosts only" >&2
    exit 1
fi

# `${VAR+x}`, not `-v`: bash 3.2 (the tests run under macOS) has no `-v`. It
# separates "set, even to empty" from "unset". An explicit caller override,
# empty included, wins over self-identification, which only supplies the
# default for a host that was never told anything (every real boot).
if [[ -n "${BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST+x}" ]]; then
    DB_HOST="$BRANCHLEFT_DOCKER_USER_POLICY_DB_HOST"
elif [[ "$holds_no_db_exception_address" -eq 1 ]]; then
    DB_HOST=""
else
    DB_HOST="10.20.1.20"
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

ensure_rule_at() {
    local tool="$1" pos="$2" table="$3" chain="$4"
    shift 4
    if "$tool" -t "$table" -C "$chain" "$@" 2>/dev/null; then
        echo "branchleft-docker-user-policy: $tool $table/$chain already carries: $*"
    else
        "$tool" -t "$table" -I "$chain" "$pos" "$@"
        echo "branchleft-docker-user-policy: $tool inserted into $table/$chain at $pos: $*"
    fi
}

ensure_rule() {
    local table="$1" chain="$2"
    shift 2
    ensure_rule_at iptables 1 "$table" "$chain" "$@"
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

# The one destination a Ghost tenant legitimately opens -- not every app host
# is one. Scoped to TCP and the port MySQL listens on, not merely the
# address: db1 also carries an exporter and administrative sockets no tenant
# container needs, and this script is the one reviewed, tested place that
# allow-list is meant to live. Skipped entirely when DB_HOST is explicitly
# empty, which is what turns this into a deny-all-to-the-subnet policy with
# no exception for a host that has no legitimate reason to reach db1 or
# anything else here.
if [[ -n "$DB_HOST" ]]; then
    ensure_rule filter DOCKER-USER -d "$DB_HOST" -p tcp --dport "$DB_PORT" -j ACCEPT
fi

# Has to be the first rule DOCKER-USER evaluates. A published port is a DNAT,
# so an inbound flow's reply (edge1 -> a tenant's Ghost, or a scrape -> a
# tenant's metrics port) leaves the container with dst inside this subnet --
# exactly what the drop above matches -- and conntrack state is the only
# thing that tells that reply apart from a tenant-initiated connection to a
# co-tenant. Reversing this against the drops is the outage this script
# exists to not ship.
ensure_rule filter DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# The spool's drain bridge may open nothing, forwarded or to the host itself.
# Written after the conntrack accept so a failure here cannot drop replies, and
# the forward drop is inserted at position 2, directly beneath it, so a re-run
# on a host that already has the policy gives the same order as a boot.
ensure_spool_rules() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1 || {
        echo "branchleft-docker-user-policy: $tool is not installed" >&2
        return 1
    }
    if "$tool" -t filter -S DOCKER-USER >/dev/null 2>&1; then
        ensure_rule_at "$tool" 2 filter DOCKER-USER -i "$MAIL_SPOOL_BRIDGE" ! -o "$MAIL_SPOOL_BRIDGE" -j DROP
    else
        echo "branchleft-docker-user-policy: no $tool DOCKER-USER chain, so Docker forwards no such traffic yet; forward drop skipped"
    fi
    ensure_rule_at "$tool" 1 filter INPUT -i "$MAIL_SPOOL_BRIDGE" -j DROP
    ensure_rule_at "$tool" 1 filter INPUT -i "$MAIL_SPOOL_BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}
ensure_spool_rules iptables
ensure_spool_rules ip6tables

echo "branchleft-docker-user-policy: app-host isolation applied in DOCKER-USER"
