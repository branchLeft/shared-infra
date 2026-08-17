#!/usr/bin/env bash
# Ensures unattended-upgrades and fail2ban are installed, enabled, and
# configured from a file this repo owns rather than the distro default.
# Idempotent: package installs are skipped when already present, and both
# config files are compared byte-for-byte before being rewritten.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

need_install=()
for pkg in unattended-upgrades apt-listchanges fail2ban; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        need_install+=("$pkg")
    fi
done

if [[ ${#need_install[@]} -gt 0 ]]; then
    apt-get update -qq
    apt-get install -yqq "${need_install[@]}"
    echo "10-harden-updates-fail2ban: installed ${need_install[*]}"
else
    echo "10-harden-updates-fail2ban: unattended-upgrades and fail2ban already installed, no-op"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

AUTO_UPGRADES=/etc/apt/apt.conf.d/20auto-upgrades
cat > "$TMP" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
if [[ -f "$AUTO_UPGRADES" ]] && cmp -s "$TMP" "$AUTO_UPGRADES"; then
    echo "10-harden-updates-fail2ban: $AUTO_UPGRADES already up to date, no-op"
else
    install -m 644 "$TMP" "$AUTO_UPGRADES"
    echo "10-harden-updates-fail2ban: wrote $AUTO_UPGRADES"
fi

systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

# fail2ban guards SSH specifically (port 22 is the one service this box
# exposes that fail2ban already knows how to filter out of the box; SMTP/
# IMAP brute-force protection is Stalwart's own built-in auto-ban -- see
# mail/RUNBOOK-mx1-provision.md's hardening section for why two mechanisms
# split this way instead of one covering everything).
JAIL_LOCAL=/etc/fail2ban/jail.local
cat > "$TMP" <<'EOF'
[sshd]
enabled = true
port = ssh
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
if [[ -f "$JAIL_LOCAL" ]] && cmp -s "$TMP" "$JAIL_LOCAL"; then
    echo "10-harden-updates-fail2ban: $JAIL_LOCAL already up to date, no-op"
else
    install -m 644 "$TMP" "$JAIL_LOCAL"
    systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban
    echo "10-harden-updates-fail2ban: wrote $JAIL_LOCAL and reloaded fail2ban"
fi

systemctl enable --now fail2ban >/dev/null 2>&1 || true
echo "10-harden-updates-fail2ban: done"
