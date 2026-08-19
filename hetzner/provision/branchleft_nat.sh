#!/usr/bin/env bash
# Makes this host forward and source-NAT the estate's private subnet out of
# its own public interface, so that hosts created without public networking
# have an outbound internet path at all.
#
# Installed as /usr/local/sbin/branchleft-nat by nat-gateway.sh and re-run at
# every boot by branchleft-nat.service. Idempotent: every rule is checked
# before it is added, and re-running it is the correct response to "is that
# host still the gateway".
#
# This is only the host half. The network half is the default route declared
# in the network stack; without it nothing is ever sent here to forward.
set -euo pipefail

# Overridable so the tests can drive a different range; production always gets
# the default, since nothing sets these in the environment.
SUBNET="${BRANCHLEFT_NAT_SUBNET:-10.20.1.0/24}"
SYSCTL_CONF="${BRANCHLEFT_NAT_SYSCTL_CONF:-/etc/sysctl.d/99-branchleft-nat.conf}"

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

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Written as well as set, because the running value is not ours: dockerd turns
# forwarding on for its own bridges at start and would turn this into a
# setting that survives only while Docker happens to be installed.
printf 'net.ipv4.ip_forward = 1\n' > "$TMP"
if [[ -f "$SYSCTL_CONF" ]] && cmp -s "$TMP" "$SYSCTL_CONF"; then
    echo "branchleft-nat: $SYSCTL_CONF already up to date"
else
    install -m 644 "$TMP" "$SYSCTL_CONF"
    echo "branchleft-nat: wrote $SYSCTL_CONF"
fi
sysctl -q -w net.ipv4.ip_forward=1

# dockerd sets the filter table's FORWARD policy to DROP, and a rule in any
# other table cannot rescue a packet that chain drops -- so forwarded traffic
# has to be accepted inside that chain rather than alongside it. DOCKER-USER
# is the chain Docker guarantees it will jump to first and will not flush, so
# it is preferred wherever it exists; FORWARD itself is the fallback on a host
# where Docker is not installed and the policy is still ACCEPT.
forward_chain=FORWARD
if iptables -t filter -S DOCKER-USER >/dev/null 2>&1; then
    forward_chain=DOCKER-USER
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

# Scoped to the subnet as source and the uplink as output, so private-to-
# private traffic is never rewritten and no other source can be laundered
# through this host's public address.
ensure_rule nat POSTROUTING -s "$SUBNET" -o "$uplink" -j MASQUERADE

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

echo "branchleft-nat: forwarding $SUBNET out of $uplink, filtered in $forward_chain"
