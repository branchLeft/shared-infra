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
    echo "10-harden-updates-fail2ban: already installed, no-op"
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

# Debian's stock origins list covers the Debian security suites and nothing
# else, so the container runtime -- installed from Docker's own apt repo by
# 20-install-docker.sh -- would receive no unattended security updates at
# all. Every tenant's isolation rests on that runtime, so a container-escape
# fix in runc or containerd reaching the host is not optional.
#
# An APT configuration block appends to the list it names rather than
# replacing it, which is what is wanted here: Debian's own entries stay, and
# Docker's origin is added alongside them. The file sorts after
# 50unattended-upgrades so the default list exists by the time this is read.
#
# Consequence worth knowing: an unattended docker-ce upgrade restarts the
# daemon. Containers carry `restart: unless-stopped` and come back, but a
# stack mid-request loses it.
ORIGINS=/etc/apt/apt.conf.d/51branchleft-unattended-origins
cat > "$TMP" <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Docker";
};
EOF
if [[ -f "$ORIGINS" ]] && cmp -s "$TMP" "$ORIGINS"; then
    echo "10-harden-updates-fail2ban: $ORIGINS already up to date, no-op"
else
    install -m 644 "$TMP" "$ORIGINS"
    echo "10-harden-updates-fail2ban: wrote $ORIGINS"
fi

# A malformed drop-in makes every apt invocation fail, including the ones
# that would fix it, so it is parsed here rather than discovered at the next
# unattended run.
if ! apt-config dump >/dev/null 2>&1; then
    echo "10-harden-updates-fail2ban: apt rejected $ORIGINS, removing it" >&2
    rm -f "$ORIGINS"
    exit 1
fi

# SSH is the only service reachable on the public interface of a non-edge
# host, and on the edge the HTTP-facing protection is CrowdSec's rather than
# fail2ban's. So this jail is deliberately the only one.
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
