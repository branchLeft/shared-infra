#!/usr/bin/env bash
# Installs every committed systemd instance drop-in onto a host. Runs from
# the workstation against the full checkout, not on the host itself: the
# scripts run-all.sh drives only ever see a copy of hetzner/provision/,
# which never carries hetzner/*/systemd/.
#
# Installs everything it finds onto whichever single $TARGET it's given, with
# no per-stack host mapping -- the same property the four hand-typed
# commands this replaces already had, just generalised past a fixed list of
# two files.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <user@host>" >&2
    exit 1
fi
TARGET="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Both overridable so tests can point this at a throwaway tree and a fake
# binary; production always gets these defaults since nothing sets
# HETZNER_ROOT or SSH_KEY in the environment.
HETZNER_ROOT="${HETZNER_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_hetzner}"

shopt -s nullglob
drop_ins=("$HETZNER_ROOT"/*/systemd/*.override.conf)
shopt -u nullglob

if [[ ${#drop_ins[@]} -eq 0 ]]; then
    echo "install-systemd-drop-ins: no */systemd/*.override.conf found under $HETZNER_ROOT" >&2
    exit 1
fi

# Two committed drop-ins for the same instance name would otherwise both
# match `install -d`'s target and silently race for the same scp
# destination, with whichever ran last winning. drop_in_for() in
# test_compose_unit_contract.py already refuses this for the same reason;
# matched here rather than trusted, since this script does not import that
# one. Built as a delimited string rather than an associative array so this
# still runs under bash 3.2, the workstation default on macOS.
seen=""
unit_dirs=""
for drop_in in "${drop_ins[@]}"; do
    stack="$(basename "$drop_in" .override.conf)"
    case "$seen" in
        *" $stack "*)
            echo "install-systemd-drop-ins: more than one drop-in for $stack" >&2
            exit 1
            ;;
    esac
    seen="$seen $stack "
    unit_dirs="$unit_dirs /etc/systemd/system/branchleft-compose@${stack}.service.d"
done

# The directories are created in one round trip before any copy, same as the
# runbook step this replaces. $unit_dirs is built above by literal
# concatenation rather than `${array[*]}` so the result cannot vary with the
# caller's inherited $IFS. $TARGET and $unit_dirs are our own values, not
# remote-controlled input, so expanding them client-side into the command
# string is intended, not the injection shellcheck normally warns about.
# shellcheck disable=SC2029
ssh -i "$SSH_KEY" "$TARGET" "install -d -m 0755${unit_dirs}"

for drop_in in "${drop_ins[@]}"; do
    stack="$(basename "$drop_in" .override.conf)"
    dest="/etc/systemd/system/branchleft-compose@${stack}.service.d/override.conf"
    scp -i "$SSH_KEY" "$drop_in" "$TARGET:$dest"
    echo "install-systemd-drop-ins: installed $drop_in -> $TARGET:$dest"
done

# shellcheck disable=SC2029
ssh -i "$SSH_KEY" "$TARGET" "systemctl daemon-reload"
echo "install-systemd-drop-ins: reloaded systemd on $TARGET"
