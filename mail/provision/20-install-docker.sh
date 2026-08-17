#!/usr/bin/env bash
# Installs Docker CE from Docker's own apt repo (Debian ships no docker.io
# package on trixie's stable branch at time of writing, and the distro
# package lags upstream releases regardless). Idempotent: every step checks
# current state before acting.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
    echo "20-install-docker: docker already installed and running, no-op"
    exit 0
fi

KEYRING=/etc/apt/keyrings/docker.asc
if [[ ! -f "$KEYRING" ]]; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o "$KEYRING"
    chmod a+r "$KEYRING"
fi

LIST=/etc/apt/sources.list.d/docker.list
# shellcheck source=/dev/null
codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
arch="$(dpkg --print-architecture)"
want_list="deb [arch=${arch} signed-by=${KEYRING}] https://download.docker.com/linux/debian ${codename} stable"
if [[ ! -f "$LIST" ]] || [[ "$(cat "$LIST")" != "$want_list" ]]; then
    echo "$want_list" > "$LIST"
fi

apt-get update -qq
apt-get install -yqq docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable --now docker >/dev/null 2>&1

docker --version
echo "20-install-docker: done"
