#!/usr/bin/env bash
# Deploys the mailgun-shim + Caddy stack via shim-compose.yml -- a SEPARATE
# compose project from Stalwart's own (docker-compose.yml /
# 30-deploy-stalwart.sh). This script never reads or writes /opt/stalwart,
# and re-running 30-deploy-stalwart.sh never touches anything installed
# here. Idempotent: installing the compose file/Caddyfile is a
# byte-compare-then-copy (same pattern as 30-deploy-stalwart.sh), the
# throttle-state seed is write-once (an operator's own tuning is never
# clobbered), render_shim_env.py's own output is deterministic given the
# same credential, and `docker compose up -d --wait` is a no-op once the
# running containers already match. Safe to run twice in a row -- see
# mail/RUNBOOK-mx1-provision.md's "Mailgun shim" section.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR=/etc/mailgun-shim
DEST_COMPOSE="$DEST_DIR/shim-compose.yml"
DEST_CADDYFILE="$DEST_DIR/Caddyfile"
DATA_DIR=/var/lib/mailgun-shim
THROTTLE_FILE="$DATA_DIR/throttle.json"

mkdir -p "$DATA_DIR" "$DEST_DIR"

# The shim image runs as the unprivileged `node` user (uid 1000), and the
# sqlite database lives on this bind mount -- without this the container
# crash-loops with SQLITE_CANTOPEN on a fresh host. Files inside stay
# root-owned (throttle.json is operator-edited, shim only reads it).
chown 1000:1000 "$DATA_DIR"

# Seed only if absent -- an operator's own throttle tuning (see the
# RUNBOOK's "Throttle tuning" section) must never be overwritten by a
# re-run of this script.
if [[ -f "$THROTTLE_FILE" ]]; then
    echo "63-deploy-mailgun-shim: $THROTTLE_FILE already exists, leaving operator state untouched"
else
    printf '{}\n' > "$THROTTLE_FILE"
    echo "63-deploy-mailgun-shim: seeded empty $THROTTLE_FILE"
fi

for src_dst in "$SCRIPT_DIR/shim-compose.yml|$DEST_COMPOSE" "$SCRIPT_DIR/Caddyfile|$DEST_CADDYFILE"; do
    src="${src_dst%%|*}"
    dst="${src_dst##*|}"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        echo "63-deploy-mailgun-shim: $dst already up to date"
    else
        cp "$src" "$dst"
        echo "63-deploy-mailgun-shim: updated $dst"
    fi
done

# Refuse to run against an unfilled image digest. Scoped to `image:` lines
# specifically, not the whole file -- an earlier version of this guard
# grepped the whole compose file for the literal string "PLACEHOLDER",
# which also matched shim-compose.yml's own explanatory header comment; the
# documented fill step (RUNBOOK's digest-fill step) only rewrites the
# `image:` line itself, so the file-wide grep kept matching that comment
# forever and refused to deploy even after a real digest was filled in.
# This form catches both IMAGE_DIGEST_PLACEHOLDER (the shim image, built by
# a parallel PR and not yet resolvable) and any future placeholder left in
# the caddy image pin (e.g. if a later edit reverts it to one because
# offline digest resolution failed), without ever matching prose.
if grep -qE '^\s*image:.*PLACEHOLDER' "$DEST_COMPOSE"; then
    echo "63-deploy-mailgun-shim: $DEST_COMPOSE has an image line with an unfilled PLACEHOLDER digest -- fill it in before deploying (see mail/RUNBOOK-mx1-provision.md's 'Mailgun shim' section)" >&2
    exit 1
fi

python3 "$SCRIPT_DIR/render_shim_env.py"

docker compose -p mailgun-shim -f "$DEST_COMPOSE" up -d --wait

echo "63-deploy-mailgun-shim: verifying the shim answers on its host-side port"
curl -fsS http://127.0.0.1:8825/healthz
echo
echo "63-deploy-mailgun-shim: shim healthcheck OK"

# GENTLE means once, for both checks below: Stalwart's own scan-ban treats
# a bare TLS connect with no protocol command as a port-scan signal (see
# the RUNBOOK's "Scan-ban" section) and will block the source IP, including
# the operator's own repeated verification attempts. A single connection
# each is enough to confirm the certificate is being served; neither check
# is fatal on failure, since a fresh ACME issuance can still be in flight
# for a few seconds after the container reports healthy.
echo "63-deploy-mailgun-shim: one gentle TLS check against Caddy on 8443"
shim_tls_output="$(openssl s_client -connect 127.0.0.1:8443 -servername mx1.branchleft.co.uk </dev/null 2>/dev/null || true)"
if echo "$shim_tls_output" | grep -q 'mx1\.branchleft\.co\.uk' && echo "$shim_tls_output" | grep -q 'Verify return code: 0'; then
    echo "63-deploy-mailgun-shim: 8443 is serving a verified mx1.branchleft.co.uk certificate"
else
    echo "63-deploy-mailgun-shim: WARNING -- could not confirm the mx1.branchleft.co.uk certificate on 8443 (a fresh ACME issuance can take a few seconds after the container reports healthy; re-check by hand before treating this as a real failure)" >&2
fi

echo "63-deploy-mailgun-shim: one gentle check that 443 still serves Stalwart, unaffected by this stack"
stalwart_tls_output="$(openssl s_client -connect 127.0.0.1:443 -servername mx1.branchleft.co.uk </dev/null 2>/dev/null || true)"
if echo "$stalwart_tls_output" | grep -q 'mx1\.branchleft\.co\.uk' && echo "$stalwart_tls_output" | grep -q 'Verify return code: 0'; then
    echo "63-deploy-mailgun-shim: 443 is still serving Stalwart's own verified certificate"
else
    echo "63-deploy-mailgun-shim: WARNING -- could not confirm Stalwart's own certificate on 443 -- investigate before assuming mail delivery is unaffected" >&2
fi

echo "63-deploy-mailgun-shim: done"
