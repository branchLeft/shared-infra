#!/usr/bin/env bash
# db1's half of the replica tunnel: a dedicated key, the pinned replica host
# key, and branchleft-db-tunnel.service. Run by hand on db1 only.
# See 45-install-db-tunnel.md for the two subcommands and their order.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Overridable so the tests can point every write at a throwaway tree.
DB_TUNNEL_DIR="${DB_TUNNEL_DIR:-/etc/branchleft/db-tunnel}"
DB_TUNNEL_UNIT_PATH="${DB_TUNNEL_UNIT_PATH:-/etc/systemd/system/branchleft-db-tunnel.service}"
DB_TUNNEL_SUBNET_PREFIX="${DB_TUNNEL_SUBNET_PREFIX:-10.20.1.}"
DB_TUNNEL_OWNER="${DB_TUNNEL_OWNER:-root}"
DB_TUNNEL_GROUP="${DB_TUNNEL_GROUP:-root}"
DB_TUNNEL_METRICS_PORT="${DB_TUNNEL_METRICS_PORT:-9105}"
DB_TUNNEL_USER="dbtunnel"
DB_TUNNEL_KEY_OWNER="${DB_TUNNEL_KEY_OWNER:-$DB_TUNNEL_USER:$DB_TUNNEL_USER}"

KEY_PATH="$DB_TUNNEL_DIR/id_ed25519"
KNOWN_HOSTS_PATH="$DB_TUNNEL_DIR/known_hosts"
TARGET_ENV_PATH="$DB_TUNNEL_DIR/target.env"
UNIT_NAME="branchleft-db-tunnel.service"

die() {
    echo "45-install-db-tunnel: $*" >&2
    exit 1
}

usage() {
    die "usage: $0 keygen | $0 install <replica-host-ipv4> '<ssh-ed25519 host key>'"
}

is_ipv4() {
    local value="$1" octet
    [[ "$value" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for octet in "${BASH_REMATCH[@]:1}"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
        ((octet <= 255)) || return 1
    done
}

is_private_or_reserved_ipv4() {
    case "$1" in
        0.*|10.*|127.*|169.254.*|192.168.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*) return 0 ;;
        *) return 1 ;;
    esac
}

# The private address mysqld binds, found on this host rather than passed in.
source_address() {
    local address
    while read -r address; do
        case "$address" in
            "$DB_TUNNEL_SUBNET_PREFIX"*) printf '%s' "$address"; return 0 ;;
        esac
    done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')
    return 1
}

write_if_changed() {
    local path="$1" mode="$2" content="$3" tmp
    if [[ -f "$path" ]] && [[ "$(cat "$path")" == "$content" ]]; then
        echo "45-install-db-tunnel: $path already up to date"
        return 1
    fi
    tmp="$(mktemp)"
    printf '%s\n' "$content" > "$tmp"
    install -m "$mode" -o "$DB_TUNNEL_OWNER" -g "$DB_TUNNEL_GROUP" "$tmp" "$path"
    rm -f "$tmp"
    echo "45-install-db-tunnel: wrote $path"
    return 0
}

ensure_service_user() {
    local entry shell
    if entry="$(getent passwd "$DB_TUNNEL_USER")"; then
        shell="${entry##*:}"
        [[ "$shell" == /usr/sbin/nologin ]] \
            || die "user $DB_TUNNEL_USER exists with shell $shell; refusing to reuse it"
        echo "45-install-db-tunnel: user $DB_TUNNEL_USER already exists, no-op"
    else
        useradd --system --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "$DB_TUNNEL_USER"
        echo "45-install-db-tunnel: created system user $DB_TUNNEL_USER"
    fi
}

cmd_keygen() {
    ensure_service_user
    install -d -m 0755 -o "$DB_TUNNEL_OWNER" -g "$DB_TUNNEL_GROUP" "$DB_TUNNEL_DIR"
    if [[ -f "$KEY_PATH" ]]; then
        echo "45-install-db-tunnel: $KEY_PATH already exists, keeping it"
    else
        ssh-keygen -q -t ed25519 -N '' -C db1-replica-tunnel -f "$KEY_PATH"
        echo "45-install-db-tunnel: generated $KEY_PATH"
    fi
    # Readable by the unit's own user and root only; nothing else on db1.
    chown "$DB_TUNNEL_KEY_OWNER" "$KEY_PATH"
    chmod 0600 "$KEY_PATH"
    echo "45-install-db-tunnel: public key for the replica host's tunnel account:"
    ssh-keygen -y -f "$KEY_PATH"
}

cmd_install() {
    local replica_host="$1" host_key="$2" source changed=0

    is_ipv4 "$replica_host" || die "replica host '$replica_host' is not an IPv4 address"
    if is_private_or_reserved_ipv4 "$replica_host"; then
        die "replica host $replica_host is not a public address; db1 reaches it through the NAT"
    fi
    [[ "$host_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/]{68}$ ]] \
        || die "host key must be 'ssh-ed25519 <base64>' exactly, as the replica host printed it"
    [[ -f "$KEY_PATH" ]] || die "no key at $KEY_PATH -- run '$0 keygen' first"
    source="$(source_address)" \
        || die "no address in ${DB_TUNNEL_SUBNET_PREFIX}0/24 on this host -- is this db1?"
    ensure_service_user

    if write_if_changed "$KNOWN_HOSTS_PATH" 0644 "$replica_host $host_key"; then changed=1; fi
    if write_if_changed "$TARGET_ENV_PATH" 0644 \
        "$(printf 'DB_TUNNEL_REPLICA_HOST=%s\nDB_TUNNEL_SOURCE_ADDRESS=%s' "$replica_host" "$source")"; then
        changed=1
    fi

    if [[ -f "$DB_TUNNEL_UNIT_PATH" ]] && cmp -s "$SCRIPT_DIR/$UNIT_NAME" "$DB_TUNNEL_UNIT_PATH"; then
        echo "45-install-db-tunnel: $DB_TUNNEL_UNIT_PATH already up to date"
    else
        install -m 0644 -o "$DB_TUNNEL_OWNER" -g "$DB_TUNNEL_GROUP" \
            "$SCRIPT_DIR/$UNIT_NAME" "$DB_TUNNEL_UNIT_PATH"
        echo "45-install-db-tunnel: wrote $DB_TUNNEL_UNIT_PATH"
        changed=1
    fi

    systemctl daemon-reload
    systemctl enable "$UNIT_NAME" >/dev/null
    if [[ "$changed" -eq 1 ]] || ! systemctl is-active --quiet "$UNIT_NAME"; then
        systemctl restart "$UNIT_NAME"
        echo "45-install-db-tunnel: (re)started $UNIT_NAME"
    else
        echo "45-install-db-tunnel: $UNIT_NAME already running and up to date"
    fi
    echo "45-install-db-tunnel: done; metrics forward on ${source}:${DB_TUNNEL_METRICS_PORT} once connected"
}

[[ $# -ge 1 ]] || usage
case "$1" in
    keygen)
        [[ $# -eq 1 ]] || usage
        cmd_keygen
        ;;
    install)
        [[ $# -eq 3 ]] || usage
        cmd_install "$2" "$3"
        ;;
    *) usage ;;
esac
