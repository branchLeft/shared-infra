#!/usr/bin/env bash
# Installs Prometheus's node_exporter as a native binary and systemd unit --
# not a Compose service -- and the unit that keeps it running at boot, then
# starts it once.
#
# Deliberately outside run-all.sh, the same way app-host-isolation.sh and
# nat-gateway.sh are: this is not every host's base provisioning, it is a
# named host's own addition (ops1, today). A future story pointing this same
# script at app1 or db1 is exactly what it is written to allow -- nothing
# below hardcodes ops1 -- but running it there is not what today's story
# specifies, so RUNBOOK-monitoring.md is what decides which host actually
# gets it run against it, the same way RUNBOOK-provision-host.md decides for
# app-host-isolation.sh.
#
# Why native rather than a fourth Compose service on this host: ops1 runs
# app-host-isolation.sh's DOCKER-USER policy (branchleft_docker_user_policy.sh),
# which drops every *forwarded* packet to the estate subnet with no carve-out
# for this host. A published container port is reached by a DNAT, which is
# forwarded traffic and is exactly what that policy blocks; a native process
# bound to this host's own private address is delivered locally via INPUT,
# which DOCKER-USER never inspects (see that script's own header, and
# RUNBOOK-provision-host.md's "Confine tenant containers on each app host").
# node-exporter.service's own header carries the same note for anyone
# reading the unit in isolation.
#
# Idempotent: the binary is left alone once the installed version already
# matches, the env file and unit are compared before being replaced, and the
# service is only restarted when something actually changed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Overridable so tests can point this at a throwaway tree, a fake download
# and a fake systemd; production gets these defaults, since nothing sets any
# of them in the environment. The version and checksum are the upstream
# release this estate already runs elsewhere: v1.12.1 is the tag
# hetzner/monitoring/stack/compose.yml pins for edge1's own node-exporter
# container, and the checksum is copied from that release's own
# sha256sums.txt, not computed locally.
NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION:-1.12.1}"
NODE_EXPORTER_SHA256="${NODE_EXPORTER_SHA256:-b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63}"
NODE_EXPORTER_DOWNLOAD_URL="${NODE_EXPORTER_DOWNLOAD_URL:-https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz}"
NODE_EXPORTER_BIN_PATH="${NODE_EXPORTER_BIN_PATH:-/usr/local/bin/node_exporter}"
NODE_EXPORTER_UNIT_PATH="${NODE_EXPORTER_UNIT_PATH:-/etc/systemd/system/node_exporter.service}"
# /etc/default/, the Debian convention for a native systemd service's own
# environment file -- deliberately not /etc/branchleft/<name>.env, which
# test_compose_unit_contract.py reserves for `branchleft-compose@<stack>`
# Compose instances. This unit is neither, and reusing that shape would
# misregister it as one.
NODE_EXPORTER_ENV_FILE="${NODE_EXPORTER_ENV_FILE:-/etc/default/node-exporter}"
NODE_EXPORTER_USER="${NODE_EXPORTER_USER:-node-exporter}"
# Overridable for the same reason every path above is: production always
# gets root:root, since nothing sets these in the environment, but a test
# process has no privilege to chown to root and needs to install as itself.
NODE_EXPORTER_OWNER="${NODE_EXPORTER_OWNER:-root}"
NODE_EXPORTER_GROUP="${NODE_EXPORTER_GROUP:-root}"
# hetzner-host/addressPlan.ts's SUBNET_CIDR, restated as a prefix rather than
# read from Pulumi state, the same reason branchleft_docker_user_policy.sh's
# own SUBNET default is a literal: this script has no Pulumi context.
NODE_EXPORTER_SUBNET_PREFIX="${NODE_EXPORTER_SUBNET_PREFIX:-10.20.1.}"

changed=0

# Self-identifies the host's own estate-private address rather than taking
# one on the command line, the same discipline
# branchleft_docker_user_policy.sh uses for edge1/nextcloud1's addresses:
# whatever this script decides on a one-off manual run has to be re-derivable
# at the next boot with no arguments, because the unit that reasserts this at
# boot carries none. The first match is used; every host in this estate
# carries exactly one address in this subnet.
private_address=""
while read -r address; do
    case "$address" in
        "$NODE_EXPORTER_SUBNET_PREFIX"*)
            private_address="$address"
            break
            ;;
    esac
done < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')

if [[ -z "$private_address" ]]; then
    echo "40-install-node-exporter: no address in ${NODE_EXPORTER_SUBNET_PREFIX}0/24 found on this host -- refusing to bind node_exporter to a public interface" >&2
    exit 1
fi

# --- 1. The binary ---------------------------------------------------------
#
# Skipped entirely once the installed binary already reports the pinned
# version -- no network call on the common re-run, unlike a script that
# re-downloads and re-verifies every time regardless.
installed_version=""
if [[ -x "$NODE_EXPORTER_BIN_PATH" ]]; then
    installed_version="$("$NODE_EXPORTER_BIN_PATH" --version 2>&1 | head -n1 || true)"
fi

if [[ "$installed_version" == *"node_exporter, version ${NODE_EXPORTER_VERSION}"* ]]; then
    echo "40-install-node-exporter: $NODE_EXPORTER_BIN_PATH already at version $NODE_EXPORTER_VERSION, no-op"
else
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    tarball="$tmp_dir/node_exporter.tar.gz"

    curl -fsSL -o "$tarball" "$NODE_EXPORTER_DOWNLOAD_URL"

    # Verified against the pinned checksum before anything is extracted or
    # installed -- a corrupted or substituted download must fail closed, not
    # install whatever arrived. `sha256sum` (Debian, every real host this
    # runs against) or `shasum -a 256` (macOS, the workstation this is also
    # tested from) -- neither is assumed, the same portability this
    # directory's other scripts already carry for bash 3.2.
    if command -v sha256sum >/dev/null 2>&1; then
        actual_sha256="$(sha256sum "$tarball" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual_sha256="$(shasum -a 256 "$tarball" | awk '{print $1}')"
    else
        echo "40-install-node-exporter: neither sha256sum nor shasum is available -- cannot verify the download, refusing to install it" >&2
        exit 1
    fi
    if [[ "$actual_sha256" != "$NODE_EXPORTER_SHA256" ]]; then
        echo "40-install-node-exporter: downloaded tarball does not match the pinned checksum -- refusing to install it" >&2
        exit 1
    fi

    tar -xzf "$tarball" -C "$tmp_dir"
    extracted="$tmp_dir/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64/node_exporter"
    if [[ ! -f "$extracted" ]]; then
        echo "40-install-node-exporter: expected $extracted after extraction -- upstream tarball layout has changed" >&2
        exit 1
    fi

    install -m 0755 -o "$NODE_EXPORTER_OWNER" -g "$NODE_EXPORTER_GROUP" "$extracted" "$NODE_EXPORTER_BIN_PATH"
    changed=1
    echo "40-install-node-exporter: installed $NODE_EXPORTER_BIN_PATH at version $NODE_EXPORTER_VERSION"
fi

# --- 2. The unprivileged user -----------------------------------------------
#
# `id -u`, not `getent passwd`: this needs to work identically under the
# fake `id`/`useradd` a test substitutes, and both tools are already on
# every Debian base image.
if id -u "$NODE_EXPORTER_USER" >/dev/null 2>&1; then
    echo "40-install-node-exporter: system user $NODE_EXPORTER_USER already exists, no-op"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$NODE_EXPORTER_USER"
    echo "40-install-node-exporter: created system user $NODE_EXPORTER_USER"
fi

# --- 3. The environment file -------------------------------------------------
#
# Regenerated from this run's self-identified address every time rather than
# left alone once written -- a host that changes its private address (a
# rebuild) must not keep serving metrics on a stale one silently. Compared
# before being replaced so an unchanged value does not mark the service
# `changed` and force an avoidable restart.
env_line="NODE_EXPORTER_LISTEN_ADDRESS=${private_address}"
install -d -m 0755 -o "$NODE_EXPORTER_OWNER" -g "$NODE_EXPORTER_GROUP" "$(dirname "$NODE_EXPORTER_ENV_FILE")"
if [[ -f "$NODE_EXPORTER_ENV_FILE" ]] && [[ "$(cat "$NODE_EXPORTER_ENV_FILE")" == "$env_line" ]]; then
    echo "40-install-node-exporter: $NODE_EXPORTER_ENV_FILE already carries $private_address, no-op"
else
    tmp_env="$(mktemp)"
    printf '%s\n' "$env_line" > "$tmp_env"
    install -m 0644 -o "$NODE_EXPORTER_OWNER" -g "$NODE_EXPORTER_GROUP" "$tmp_env" "$NODE_EXPORTER_ENV_FILE"
    rm -f "$tmp_env"
    changed=1
    echo "40-install-node-exporter: wrote $NODE_EXPORTER_ENV_FILE ($private_address)"
fi

# --- 4. The unit --------------------------------------------------------------
#
# Byte-identical install, same pattern as 05-configure-host-egress.sh: the
# committed file never varies by host, only the env file above does.
if [[ -f "$NODE_EXPORTER_UNIT_PATH" ]] && cmp -s "$SCRIPT_DIR/node-exporter.service" "$NODE_EXPORTER_UNIT_PATH"; then
    echo "40-install-node-exporter: $NODE_EXPORTER_UNIT_PATH already up to date, no-op"
else
    install -m 0644 -o "$NODE_EXPORTER_OWNER" -g "$NODE_EXPORTER_GROUP" "$SCRIPT_DIR/node-exporter.service" "$NODE_EXPORTER_UNIT_PATH"
    systemctl daemon-reload
    changed=1
    echo "40-install-node-exporter: wrote $NODE_EXPORTER_UNIT_PATH and reloaded systemd"
fi

systemctl enable node_exporter.service >/dev/null

# `restart` only when something actually changed or the service is not
# already running -- Type=simple, unlike the oneshot reconcilers elsewhere in
# this directory, so an unconditional restart on every idempotent re-run
# would otherwise bounce a healthy scrape target for no reason.
if [[ "$changed" -eq 1 ]] || ! systemctl is-active --quiet node_exporter.service; then
    systemctl restart node_exporter.service
    echo "40-install-node-exporter: (re)started node_exporter.service"
else
    echo "40-install-node-exporter: node_exporter.service already running and up to date, no-op"
fi

systemctl --no-pager --lines=0 status node_exporter.service >/dev/null

echo "40-install-node-exporter: done, listening on ${private_address}:9100"
