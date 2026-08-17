#!/usr/bin/env bash
# Thin wrapper so run-all.sh has a uniform per-step interface. All the
# actual logic (and its idempotency) lives in
# provision_website_submission_credential.py -- see that file and
# mail/RUNBOOK-mx1-provision.md for what it provisions and why.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SCRIPT_DIR/provision_website_submission_credential.py"
