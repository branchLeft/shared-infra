#!/usr/bin/env bash
# Thin wrapper so run-all.sh has a uniform per-step interface. All the
# actual logic (and its idempotency) lives in configure_stalwart.py --
# see that file and mail/RUNBOOK-mx1-provision.md for why Stalwart's
# settings are reconciled via its own JMAP-style API rather than a TOML
# file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SCRIPT_DIR/configure_stalwart.py"
