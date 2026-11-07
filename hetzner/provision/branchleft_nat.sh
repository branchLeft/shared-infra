#!/usr/bin/env bash
# The forwarding half of the estate's NAT gateway: accepts the estate's private
# subnet in DOCKER-USER, in and out of this host's public interface, so that
# hosts created without public networking have an outbound internet path at all.
#
# It no longer masquerades and no longer writes the forwarding sysctl. Both
# moved to the edge_firewall role (ansible/roles/edge_firewall), which loads the
# masquerade in its own nftables table and sets net.ipv4.ip_forward, and which
# runs before the role that installs this script. A rule in an nftables forward
# chain cannot rescue a packet that Docker's iptables FORWARD policy drops, so
# the accepts stay here, in the chain Docker guarantees it will not flush.
#
# Installed as /usr/local/sbin/branchleft-nat by the egress_nat role and re-run at
# every boot by branchleft-nat.service. Idempotent: every rule is checked
# before it is added, and re-running it is the correct response to "is that
# host still the gateway".
#
# Refuses (exit 1, loudly) when forwarding is off or when no masquerade exists
# anywhere, so that a gateway with the accepts and no masquerade, which has no
# outbound internet, fails the apply and the unit instead of reporting success.
#
# This is only the host half. The network half is the default route declared
# in the network stack; without it nothing is ever sent here to forward.
set -euo pipefail

# Overridable so the tests can drive a different range; production always gets
# the default, since nothing sets these in the environment.
SUBNET="${BRANCHLEFT_NAT_SUBNET:-10.20.1.0/24}"

# The membership test below is a string prefix, which is only equivalent to a
# subnet match at /24. Refusing anything else is deliberate: a widened range
# would otherwise silently narrow the guard rather than fail.
case "$SUBNET" in
    *.0/24) subnet_prefix="${SUBNET%.0/24}." ;;
    *)
        echo "branchleft-nat: only a /24 subnet is understood, got $SUBNET" >&2
        exit 1
        ;;
esac

# Debian ships no iptables in the cloud image; it arrives as a dependency of
# docker-ce. Named explicitly because the alternative is exit 127 from inside
# a systemd oneshot, which reads as a broken unit rather than a missing step.
if ! command -v iptables >/dev/null 2>&1; then
    echo "branchleft-nat: iptables is not installed -- run 20-install-docker.sh first" >&2
    exit 1
fi

is_private_v4() {
    case "$1" in
        10.*|192.168.*|127.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        *) return 1 ;;
    esac
}

uplink="$(ip -4 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
if [[ -z "$uplink" ]]; then
    echo "branchleft-nat: this host has no default route, so it has nothing to forward to" >&2
    exit 1
fi

uplink_is_public=0
attached_to_subnet=0
while read -r ifname address; do
    if [[ "$address" == "$subnet_prefix"* ]]; then
        attached_to_subnet=1
    fi
    if [[ "$ifname" == "$uplink" ]] && ! is_private_v4 "$address"; then
        uplink_is_public=1
    fi
done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print $2, a[1] }')

# The failure this refuses is a routing loop that takes the whole estate's
# egress with it: a private-only host's own default route is the network
# gateway, so a private-only host told to masquerade sends every packet it is
# given straight back into the network it came from.
if [[ "$uplink_is_public" -ne 1 ]]; then
    echo "branchleft-nat: the default route leaves through $uplink, which holds no public address" >&2
    echo "branchleft-nat: only a host that terminates public traffic can be the estate's gateway" >&2
    exit 1
fi

if [[ "$attached_to_subnet" -ne 1 ]]; then
    echo "branchleft-nat: this host holds no address in $SUBNET, so nothing routed there reaches it" >&2
    exit 1
fi

# Forwarding is the edge_firewall role's to turn on and persist. Read here, not
# set, so that a host where that role has not run (a hand-built gateway) fails
# visibly instead of carrying the accepts with the kernel not forwarding.
if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]]; then
    echo "branchleft-nat: net.ipv4.ip_forward is not 1 -- the edge_firewall role sets it; apply it first" >&2
    exit 1
fi

# The masquerade has two possible homes. The edge_firewall role's nftables table
# is where it lives now. The iptables rule is the one this script used to insert,
# and it stays on a host until the role has confirmed its own table. With neither
# there is a gateway that forwards packets out with private source addresses and
# no outbound internet, so refuse.
masquerade_home=""
if command -v nft >/dev/null 2>&1 \
    && nft list table ip branchleft_edge_nat 2>/dev/null | grep -q "masquerade"; then
    masquerade_home="the edge_firewall nftables table"
elif iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$uplink" -j MASQUERADE 2>/dev/null; then
    masquerade_home="the legacy iptables rule"
fi
if [[ -z "$masquerade_home" ]]; then
    echo "branchleft-nat: no masquerade for $SUBNET exists (neither the edge_firewall role's nftables table nor the legacy iptables rule), so forwarding would give the estate no outbound internet" >&2
    echo "branchleft-nat: apply the edge_firewall role before this one" >&2
    exit 1
fi

# dockerd sets the filter table's FORWARD policy to DROP, and a rule in any
# other table cannot rescue a packet that chain drops -- so forwarded traffic
# has to be accepted inside that chain rather than alongside it. DOCKER-USER
# is the chain Docker guarantees it will jump to first and will not flush, so
# it is preferred wherever it exists; FORWARD itself is the fallback on a host
# where Docker is not installed and the policy is still ACCEPT.
forward_chain=FORWARD
if iptables -t filter -S DOCKER-USER >/dev/null 2>&1; then
    forward_chain=DOCKER-USER
elif systemctl is-active --quiet docker.service; then
    # dockerd creates DOCKER-USER unconditionally at startup under the
    # iptables backend, so its absence with the daemon already running means
    # iptables is not what dockerd enforces through -- its nftables firewall
    # backend (opt-in today, a stated future default) manages its own tables
    # instead, and a rule written into FORWARD is one Docker's own DROP
    # policy never consults.
    echo "branchleft-nat: docker.service is active but iptables carries no DOCKER-USER chain -- Docker is not enforcing through iptables here (its nftables firewall backend, most likely), and FORWARD is not a safe substitute" >&2
    exit 1
fi

ensure_rule() {
    local table="$1" chain="$2"
    shift 2
    if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        echo "branchleft-nat: $table/$chain already carries: $*"
    else
        iptables -t "$table" -I "$chain" 1 "$@"
        echo "branchleft-nat: inserted into $table/$chain: $*"
    fi
}

# Directional on purpose. Outbound is accepted unconditionally; the return
# direction is accepted only for a flow conntrack already knows, so
# forwarding stays a one-way capability and nothing on the internet can
# initiate a connection into a host that has no public address.
ensure_rule filter "$forward_chain" -s "$SUBNET" -o "$uplink" -j ACCEPT
ensure_rule filter "$forward_chain" -d "$SUBNET" -i "$uplink" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# No MSS clamp. The private link's MTU is lower than the uplink's, which is
# the usual reason one is needed -- but every flow here is opened by the
# private host, so the MSS it advertises is already derived from the lower of
# the two and the remote end never sends more than fits.

echo "branchleft-nat: forwarding $SUBNET out of $uplink, filtered in $forward_chain, masqueraded by $masquerade_home"
