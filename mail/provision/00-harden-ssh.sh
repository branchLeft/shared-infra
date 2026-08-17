#!/usr/bin/env bash
# Locks SSH to key-only auth. Idempotent: compares byte-for-byte against a
# temp file and only writes/reloads when the drop-in actually needs to
# change.
set -euo pipefail

DROPIN=/etc/ssh/sshd_config.d/99-branchleft-hardening.conf
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Debian's stock sshd_config already sets `PermitRootLogin without-password`
# (pubkey-only for root) but leaves the global PasswordAuthentication at its
# compiled-in default of "yes" -- `sshd -T` on a stock image confirms the
# effective value is yes despite root already being key-only. This drop-in
# closes that gap for every account, not just root.
cat > "$TMP" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF

if [[ -f "$DROPIN" ]] && cmp -s "$TMP" "$DROPIN"; then
    echo "00-harden-ssh: $DROPIN already up to date, no-op"
    exit 0
fi

install -m 644 "$TMP" "$DROPIN"
echo "00-harden-ssh: wrote $DROPIN"

# `Include /etc/ssh/sshd_config.d/*.conf` sits near the top of the stock
# sshd_config, so first-match-wins semantics mean the drop-in overrides the
# defaults below it. sshd -T resolves the config exactly as the running
# daemon would without restarting anything, so this is a config check, not
# a live-service check yet.
if ! sshd -t -f /etc/ssh/sshd_config; then
    echo "00-harden-ssh: sshd -t reported a config error, refusing to reload" >&2
    exit 1
fi

systemctl reload ssh
echo "00-harden-ssh: sshd reloaded"
