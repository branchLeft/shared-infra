#!/usr/bin/env bash
# Installs every committed systemd instance drop-in onto a host, replacing
# the hand-typed ssh/scp block RUNBOOK-monitoring.md step 5 used to carry.
#
# Generic over the *set* of committed drop-ins, not a fixed list of stacks:
# it walks `*/systemd/*.override.conf` under hetzner/, the same search
# drop_in_for() in test_compose_unit_contract.py uses. A drop-in that test
# can find is a drop-in this script installs, with no code change needed
# when a new one is committed.
#
# Run from the workstation, from a branchLeft/shared-infra checkout -- the
# scripts in this directory that run *on* a host only ever see a copy of
# hetzner/provision/ itself (RUNBOOK-provision-host.md's `scp -r
# hetzner/provision/.`), which never carries the drop-ins committed under
# hetzner/*/systemd/. Reaching them means reading the full checkout, which
# only a workstation-invoked script can do.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <user@host>" >&2
    exit 1
fi
TARGET="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HETZNER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Overridable so tests can point this at a fake binary; production always
# gets the default since nothing sets SSH_KEY in the environment.
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_hetzner}"

shopt -s nullglob
drop_ins=("$HETZNER_ROOT"/*/systemd/*.override.conf)
shopt -u nullglob

if [[ ${#drop_ins[@]} -eq 0 ]]; then
    echo "install-systemd-drop-ins: no */systemd/*.override.conf found under $HETZNER_ROOT" >&2
    exit 1
fi

unit_dirs=()
for drop_in in "${drop_ins[@]}"; do
    stack="$(basename "$drop_in" .override.conf)"
    unit_dirs+=("/etc/systemd/system/branchleft-compose@${stack}.service.d")
done

# The directories are created in one round trip before any copy, same as the
# runbook step this replaces. $TARGET and $unit_dirs are our own values, not
# remote-controlled input, so expanding them client-side into the command
# string is intended, not the injection shellcheck normally warns about.
# shellcheck disable=SC2029
ssh -i "$SSH_KEY" "$TARGET" "install -d -m 0755 ${unit_dirs[*]}"

for drop_in in "${drop_ins[@]}"; do
    stack="$(basename "$drop_in" .override.conf)"
    dest="/etc/systemd/system/branchleft-compose@${stack}.service.d/override.conf"
    scp -i "$SSH_KEY" "$drop_in" "$TARGET:$dest"
    echo "install-systemd-drop-ins: installed $drop_in -> $TARGET:$dest"
done

# shellcheck disable=SC2029
ssh -i "$SSH_KEY" "$TARGET" "systemctl daemon-reload"
echo "install-systemd-drop-ins: reloaded systemd on $TARGET"
