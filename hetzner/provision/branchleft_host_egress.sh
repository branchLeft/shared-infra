#!/usr/bin/env bash
# Gives a private-only host (no public interface) a default route via the
# estate's private network gateway, plus Hetzner's own recursive resolvers.
#
# Installed as /usr/local/sbin/branchleft-host-egress by
# 05-configure-host-egress.sh and re-run at every boot by
# branchleft-host-egress.service. Neither the route nor the resolver config
# survives a reboot on its own -- the route is kernel state nothing persists,
# and cloud-init's own first-boot fix for the resolver (see
# hetzner-host/cloudInit.ts) runs once and never again -- so this is what
# keeps both true for the rest of the host's life.
#
# A no-op, and the only thing it does, on any host that already has a public
# interface: nothing here is meant to touch such a host's routing at all.
#
# This is only the host half. The network half is the default route declared
# for the estate's private network (hetzner/egress.ts), and the far end is
# `provision/branchleft_nat.sh` on the gateway host.
set -euo pipefail

# Hetzner's own recursive resolvers -- documented, estate-independent
# addresses, not a value this repo derives. Overridable so the tests can
# point the write at a throwaway path; production always gets the default,
# since nothing sets these in the environment.
NAMESERVER_1="${BRANCHLEFT_EGRESS_NAMESERVER_1:-185.12.64.1}"
NAMESERVER_2="${BRANCHLEFT_EGRESS_NAMESERVER_2:-185.12.64.2}"
RESOLVER_HEAD="${BRANCHLEFT_EGRESS_RESOLVER_HEAD:-/etc/resolvconf/resolv.conf.d/head}"

# The metadata service's own address, which DHCP delivers as a host route
# alongside the subnet route this script wants -- hardcoded because it is
# Hetzner's, not the estate's, the same reasoning `egress.ts` uses for the
# public-interface gateway address it refuses.
METADATA_ADDRESS="169.254.169.254"

is_private_v4() {
    case "$1" in
        10.*|192.168.*|127.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        *) return 1 ;;
    esac
}

has_public_interface=0
while read -r address; do
    [[ -z "$address" ]] && continue
    if ! is_private_v4 "$address"; then
        has_public_interface=1
    fi
done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')

if [[ "$has_public_interface" -eq 1 ]]; then
    echo "branchleft-host-egress: this host has a public interface, no-op"
    exit 0
fi

# Checked before anything is mutated, not left to fail where it is used.
# `resolvconf -u` runs unguarded under `set -euo pipefail`, invoked by a
# systemd unit that 05-configure-host-egress.sh starts inside run-all.sh's
# own `set -euo pipefail` -- a missing binary there is exit 127 from a
# command whose name never appears in run-all.sh's output, which reads as a
# broken script rather than a missing package.
if ! command -v resolvconf >/dev/null 2>&1; then
    echo "branchleft-host-egress: resolvconf is not installed -- install the resolvconf package on this host and re-run" >&2
    exit 1
fi

# The subnet route DHCP delivers alongside the metadata route above -- the
# only other gateway-bearing entry a private-only host's table carries.
# Read from the table rather than assumed: the hand-repair this script
# replaces pointed at 10.20.0.1 because that happened to be live when it was
# written, and restating that address here would be exactly the hardcoding
# this script exists to avoid.
# A plain variable rather than an array (`mapfile`/`readarray` need bash 4,
# and the only guarantee about the bash on a Debian cloud image is that it is
# *a* bash) -- `set -e` would otherwise abort here on a host with no
# candidate at all, since an empty match makes `grep` itself the pipeline's
# failing last command inside a plain command substitution.
candidate_routes="$(
    ip -4 route show \
        | grep ' via ' \
        | grep -v '^default ' \
        | grep -v "^${METADATA_ADDRESS} " \
        || true
)"

if [[ -z "$candidate_routes" ]]; then
    echo "branchleft-host-egress: no private subnet route found to derive a gateway from" >&2
    exit 1
fi

if [[ "$(printf '%s\n' "$candidate_routes" | grep -c '^')" -gt 1 ]]; then
    echo "branchleft-host-egress: more than one candidate subnet route, refusing to guess:" >&2
    printf '%s\n' "$candidate_routes" | sed 's/^/  /' >&2
    exit 1
fi

route="$candidate_routes"
gateway="$(awk '{ for (i = 1; i <= NF; i++) if ($i == "via") { print $(i + 1); exit } }' <<< "$route")"
iface="$(awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }' <<< "$route")"

if [[ -z "$gateway" || -z "$iface" ]]; then
    echo "branchleft-host-egress: subnet route carries no gateway or device: $route" >&2
    exit 1
fi

current_default="$(ip -4 route show default)"
if [[ "$current_default" == "default via $gateway dev $iface"* ]]; then
    echo "branchleft-host-egress: default route already via $gateway dev $iface, no-op"
else
    ip route replace default via "$gateway" dev "$iface"
    echo "branchleft-host-egress: default route set via $gateway dev $iface"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
printf 'nameserver %s\nnameserver %s\n' "$NAMESERVER_1" "$NAMESERVER_2" > "$TMP"
if [[ -f "$RESOLVER_HEAD" ]] && cmp -s "$TMP" "$RESOLVER_HEAD"; then
    echo "branchleft-host-egress: $RESOLVER_HEAD already up to date, no-op"
else
    install -d -m 0755 "$(dirname "$RESOLVER_HEAD")"
    install -m 0644 "$TMP" "$RESOLVER_HEAD"
    resolvconf -u
    echo "branchleft-host-egress: wrote $RESOLVER_HEAD and refreshed resolv.conf"
fi

echo "branchleft-host-egress: private-only host egress configured"
