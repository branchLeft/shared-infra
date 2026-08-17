#!/usr/bin/env bash
# Installs Docker CE from Docker's own apt repo (Debian ships no docker.io
# package on trixie's stable branch at time of writing, and the distro
# package lags upstream releases regardless). Idempotent: every step checks
# current state before acting.
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
