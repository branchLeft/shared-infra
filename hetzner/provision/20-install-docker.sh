#!/usr/bin/env bash
# Installs Docker CE from Docker's own apt repo (trixie's stable branch ships
# no docker.io package, and the distro package lags upstream). Idempotent.
#
# Versions are deliberately unpinned. That is only defensible because
# 10-harden-updates-fail2ban.sh adds Docker's origin to the
# unattended-upgrades list -- without that, this repo is outside Debian's
# security origins and the container runtime under every tenant would freeze
# at whatever version first provisioning happened to install. Pin here only
# alongside a mechanism that surfaces the pin falling behind.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# The keyring is re-fetched and compared on every run, before the
# already-installed check below, and replaced when it differs. Gating it on
# the file merely existing would mean a host where Docker is already running
# can never have a rotated signing key repaired by re-running this script --
# which is the one situation where re-running it is the obvious remedy, and
# the one this script is pointed at when `apt-get update` starts failing
# verification.
KEYRING=/etc/apt/keyrings/docker.asc
TMP_KEY="$(mktemp)"
trap 'rm -f "$TMP_KEY"' EXIT

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o "$TMP_KEY"
if [[ ! -s "$TMP_KEY" ]]; then
    echo "20-install-docker: fetched an empty signing key, refusing to install it" >&2
    exit 1
fi

# The primary key fingerprint is pinned: a key served over HTTPS that is not
# this one is refused. A rotated Docker key therefore stops this script until
# EXPECTED_FPR is updated from the new key, deliberately.
EXPECTED_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
if ! command -v gpg >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -yqq gnupg
fi
GNUPG_HOME="$(mktemp -d)"
trap 'rm -rf "$GNUPG_HOME"; rm -f "$TMP_KEY"' EXIT
key_listing="$(gpg --homedir "$GNUPG_HOME" --batch --with-colons --show-keys "$TMP_KEY" 2>/dev/null || true)"
key_count="$(printf '%s\n' "$key_listing" | awk -F: '$1 == "pub" {n++} END {print n + 0}')"
actual_fpr="$(printf '%s\n' "$key_listing" | awk -F: '/^fpr:/ {print $10; exit}' | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
if [[ "$key_count" != "1" || "$actual_fpr" != "$EXPECTED_FPR" ]]; then
    echo "20-install-docker: signing key holds $key_count key(s), primary fingerprint '${actual_fpr:-unreadable}', expected exactly one key with $EXPECTED_FPR; refusing to install it" >&2
    exit 1
fi

if [[ -f "$KEYRING" ]] && cmp -s "$TMP_KEY" "$KEYRING"; then
    echo "20-install-docker: $KEYRING already current, no-op"
else
    install -m 0644 "$TMP_KEY" "$KEYRING"
    chmod a+r "$KEYRING"
    echo "20-install-docker: wrote $KEYRING"
fi

LIST=/etc/apt/sources.list.d/docker.list
# shellcheck source=/dev/null
codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
arch="$(dpkg --print-architecture)"
want_list="deb [arch=${arch} signed-by=${KEYRING}] https://download.docker.com/linux/debian ${codename} stable"
if [[ ! -f "$LIST" ]] || [[ "$(cat "$LIST")" != "$want_list" ]]; then
    echo "$want_list" > "$LIST"
    echo "20-install-docker: wrote $LIST"
fi

if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
    echo "20-install-docker: docker already installed and running, no-op"
    exit 0
fi

apt-get update -qq
apt-get install -yqq docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable --now docker >/dev/null 2>&1

docker --version
echo "20-install-docker: done"
