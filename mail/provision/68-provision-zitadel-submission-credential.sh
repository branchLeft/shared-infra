#!/usr/bin/env bash
# Thin wrapper, same interface as the 6x credential steps. Not in run-all.sh:
# it needs the publicpress.co.uk sending domain created first, which
# run-all.sh does not do, and its secret is shown once to a person at a
# terminal. See provision_zitadel_submission_credential.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CREDENTIAL_LABEL=zitadel-smtp \
    python3 "$SCRIPT_DIR/provision_zitadel_submission_credential.py" "$@"
