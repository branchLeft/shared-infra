#!/usr/bin/env bash
# Writes the monitoring stack as a tar archive on stdout, in the shape
# branchleft-sync-stack expects: the files of hetzner/monitoring/stack/, then an
# empty END-OF-STACK member so a truncated upload is recognisable.
# Used by both the delivery workflow and the rehearsal, so they ship the same bytes.
# Usage: hetzner/scripts/monitoring-stack-archive.sh > stack.tar
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK="$HERE/monitoring/stack"

[[ -f "$STACK/compose.yml" ]] || { echo "monitoring-stack-archive: $STACK/compose.yml not found" >&2; exit 1; }

marker_dir="$(mktemp -d)"
trap 'rm -rf "$marker_dir"' EXIT
: > "$marker_dir/END-OF-STACK"

# The three files the host renders from its own secrets are never sent, even if
# a local render left them in a working copy.
tar -cf - \
    --exclude=./alertmanager/alertmanager.yml \
    --exclude=./ntfy/server.yml \
    --exclude=./prometheus/mx1-metrics-password \
    --exclude=__pycache__ \
    -C "$STACK" . \
    -C "$marker_dir" END-OF-STACK
