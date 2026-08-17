#!/usr/bin/env bash
# Installs unbound as a loopback-only, fully recursive resolver for mx1.
#
# Spamhaus's free DNSBL tier answers 127.255.255.254 -- "query blocked" -- to
# anything arriving from a high-volume shared resolver, which Hetzner's own
# and every public one (8.8.8.8, 1.1.1.1) are. Only a resolver that walks the
# root servers itself, from mx1's own address, gets real reputation data
# back. So this config has no forwarders at all: adding one silently
# reintroduces the exact failure this script exists to remove.
#
# /etc/resolv.conf is deliberately left as-is -- Debian's
# unbound-resolvconf.service would otherwise point the whole box at unbound
# on install, a far wider blast radius than the DNSBL check needs. It is
# masked before the package is installed and the file is verified unchanged
# afterwards. See mail/RUNBOOK-mx1-provision.md's "Local recursive resolver"
# section.
#
# Idempotent: package install skipped when present, config compared
# byte-for-byte before writing, service only restarted when something
# actually changed.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

CONF=/etc/unbound/unbound.conf.d/10-branchleft-local-recursive.conf
RESOLVCONF_UNIT=unbound-resolvconf.service
ROOT_ANCHOR=/var/lib/unbound/root.key
SMOKE_TEST_NAME=deb.debian.org

TMP="$(mktemp)"
PREV="$(mktemp)"
RESOLV_BEFORE="$(mktemp)"
trap 'rm -f "$TMP" "$PREV" "$RESOLV_BEFORE"' EXIT

# 127.0.0.53 is systemd-resolved's stub, which does not collide with a
# 127.0.0.1 listener; anything else on port 53 would make this install a
# silent no-op or a service flap, so refuse rather than fight it.
conflicts="$(ss -H -lntup 'sport = :53' 2>/dev/null | grep -vE 'unbound|127\.0\.0\.53' || true)"
if [[ -n "$conflicts" ]]; then
    echo "65-install-local-resolver: refusing to install -- port 53 is already held:" >&2
    echo "$conflicts" >&2
    exit 1
fi

# Masked before the package lands, so the unit never gets the chance to
# repoint the box at a resolver that isn't serving yet. dpkg then logs a
# "systemctl preset failed" line for this unit during the install -- that is
# the mask working, not a failure.
if [[ "$(systemctl is-enabled "$RESOLVCONF_UNIT" 2>/dev/null || true)" != "masked" ]]; then
    systemctl mask "$RESOLVCONF_UNIT" >/dev/null
    echo "65-install-local-resolver: masked $RESOLVCONF_UNIT"
fi

cp /etc/resolv.conf "$RESOLV_BEFORE"

# unbound-anchor and dns-root-data are Recommends, and this image sets
# APT::Install-Recommends "false" -- without them named explicitly the
# DNSSEC trust anchor unbound's own Debian drop-in requires is never
# created and the service will not start at all.
need_install=()
for pkg in unbound unbound-anchor dns-root-data; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        need_install+=("$pkg")
    fi
done

if [[ ${#need_install[@]} -gt 0 ]]; then
    apt-get update -qq
    apt-get install -yqq "${need_install[@]}"
    echo "65-install-local-resolver: installed ${need_install[*]}"
else
    echo "65-install-local-resolver: unbound already installed, no-op"
fi

# unbound-anchor exits non-zero when it had to write or update the anchor,
# which is the normal first-run path, so its status says nothing about
# success -- the file existing does.
if [[ ! -s "$ROOT_ANCHOR" ]]; then
    unbound-anchor -a "$ROOT_ANCHOR" || true
    if [[ ! -s "$ROOT_ANCHOR" ]]; then
        echo "65-install-local-resolver: could not bootstrap the DNSSEC root anchor at $ROOT_ANCHOR" >&2
        exit 1
    fi
    chown unbound:unbound "$ROOT_ANCHOR"
    echo "65-install-local-resolver: bootstrapped the DNSSEC root anchor"
fi

cat > "$TMP" <<'EOF'
# Managed by shared-infra/mail/provision/65-install-local-resolver.sh --
# re-running that script overwrites hand edits here.
#
# No forward-zone anywhere in this file, by design: forwarding to a shared
# resolver is what makes Spamhaus refuse to answer.
server:
    interface: 127.0.0.1
    interface: ::1
    port: 53
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::/0 refuse
    access-control: ::1 allow
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    qname-minimisation: yes
    prefetch: yes
    num-threads: 1
    msg-cache-size: 32m
    rrset-cache-size: 64m
    # Blocklist answers are reputation data with deliberately short TTLs;
    # nothing here may extend one, and an hour is the longest this resolver
    # will hold any answer.
    cache-max-ttl: 3600
    serve-expired: no
    edns-buffer-size: 1232
EOF

config_changed=0
if [[ -f "$CONF" ]] && cmp -s "$TMP" "$CONF"; then
    echo "65-install-local-resolver: $CONF already up to date, no-op"
else
    if [[ -f "$CONF" ]]; then
        cp "$CONF" "$PREV"
    fi
    install -m 644 "$TMP" "$CONF"
    config_changed=1
    echo "65-install-local-resolver: wrote $CONF"
fi

# Validate against the whole assembled config, not the drop-in alone -- a
# conflict with a distro drop-in only shows up here, and on a live mail host
# a bad config must never reach a restart.
if ! unbound-checkconf >/dev/null; then
    if [[ -s "$PREV" ]]; then
        install -m 644 "$PREV" "$CONF"
    else
        rm -f "$CONF"
    fi
    echo "65-install-local-resolver: unbound-checkconf rejected the config, reverted it" >&2
    exit 1
fi

systemctl enable unbound >/dev/null 2>&1 || true
if [[ "$config_changed" -eq 1 ]] || ! systemctl is-active --quiet unbound; then
    systemctl restart unbound
    echo "65-install-local-resolver: restarted unbound"
fi

if ! cmp -s "$RESOLV_BEFORE" /etc/resolv.conf; then
    resolvconf -d lo.unbound >/dev/null 2>&1 || true
    if ! cmp -s "$RESOLV_BEFORE" /etc/resolv.conf; then
        echo "65-install-local-resolver: /etc/resolv.conf changed and could not be reverted -- \
the system resolver was meant to be untouched; restore it by hand before relying on this box" >&2
        exit 1
    fi
    echo "65-install-local-resolver: reverted an unbound-resolvconf edit to /etc/resolv.conf"
fi

if command -v dig >/dev/null 2>&1; then
    answer=""
    for _ in 1 2 3 4 5; do
        answer="$(dig +short +time=3 +tries=1 @127.0.0.1 A "$SMOKE_TEST_NAME" 2>/dev/null || true)"
        if [[ -n "$answer" ]]; then
            break
        fi
        sleep 2
    done
    if [[ -z "$answer" ]]; then
        echo "65-install-local-resolver: unbound is running but did not resolve $SMOKE_TEST_NAME \
via 127.0.0.1 -- recursion is not working, do not trust DNSBL results until this is fixed" >&2
        exit 1
    fi
    echo "65-install-local-resolver: 127.0.0.1 resolved $SMOKE_TEST_NAME, recursion works"
else
    echo "65-install-local-resolver: dig not present, skipped the recursion smoke test"
fi

echo "65-install-local-resolver: done"
