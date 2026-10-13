#!/usr/bin/env bash
# Installs /usr/local/sbin/branchleft-sync-stack, and optionally grants or
# revokes the one SSH key that may call it. Idempotent: the wrapper is compared
# byte-for-byte before it is replaced, and the key line is rewritten only if it
# differs. Run as root on the host, once, by the owner:
#
#   50-install-stack-sync.sh                          install the wrapper
#   50-install-stack-sync.sh --grant-key FILE.pub     ... and authorise that key
#   50-install-stack-sync.sh --revoke-key             remove the authorisation
#
# Design and trust boundary: branchleft_sync_stack.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Overridable only so the tests can run this as a normal user.
SBIN_DIR="${SBIN_DIR:-/usr/local/sbin}"
AUTHORIZED_KEYS="${AUTHORIZED_KEYS:-/root/.ssh/authorized_keys}"

STACK=monitoring
WRAPPER="$SBIN_DIR/branchleft-sync-stack"
MARKER="branchleft-stack-sync:$STACK"

grant_file=""
revoke=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --grant-key)
            [[ $# -ge 2 ]] || { echo "50-install-stack-sync: --grant-key needs a public key file" >&2; exit 2; }
            grant_file="$2"
            shift 2
            ;;
        --revoke-key)
            revoke=1
            shift
            ;;
        *)
            echo "50-install-stack-sync: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done
if [[ -n "$grant_file" && "$revoke" -eq 1 ]]; then
    echo "50-install-stack-sync: --grant-key and --revoke-key are exclusive" >&2
    exit 2
fi

install -d -m 0755 "$SBIN_DIR"
if [[ -f "$WRAPPER" ]] && cmp -s "$SCRIPT_DIR/branchleft_sync_stack.py" "$WRAPPER"; then
    echo "50-install-stack-sync: $WRAPPER already up to date, no-op"
else
    install -m 0755 "$SCRIPT_DIR/branchleft_sync_stack.py" "$WRAPPER"
    echo "50-install-stack-sync: wrote $WRAPPER"
fi

# The authorized_keys file minus any line this script manages. The marker is
# the last field, matched as a whole field, so an unrelated key whose comment
# merely contains the text is left alone.
unmanaged_lines() {
    if [[ -f "$AUTHORIZED_KEYS" ]]; then
        awk -v m="$MARKER" '$NF != m' "$AUTHORIZED_KEYS"
    fi
}

write_keys() {
    local candidate="$1" dir tmp
    if [[ -f "$AUTHORIZED_KEYS" ]] && cmp -s "$candidate" "$AUTHORIZED_KEYS"; then
        echo "50-install-stack-sync: $AUTHORIZED_KEYS already up to date, no-op"
        return 0
    fi
    dir="$(dirname "$AUTHORIZED_KEYS")"
    install -d -m 0700 "$dir"
    tmp="$(mktemp "$dir/.authorized_keys.XXXXXX")"
    cat "$candidate" > "$tmp"
    chmod 0600 "$tmp"
    mv "$tmp" "$AUTHORIZED_KEYS"
    echo "50-install-stack-sync: wrote $AUTHORIZED_KEYS"
}

if [[ "$revoke" -eq 1 ]]; then
    if [[ ! -f "$AUTHORIZED_KEYS" ]]; then
        echo "50-install-stack-sync: no $AUTHORIZED_KEYS, nothing to revoke"
        exit 0
    fi
    candidate="$(mktemp)"
    trap 'rm -f "$candidate"' EXIT
    unmanaged_lines > "$candidate"
    write_keys "$candidate"
    echo "50-install-stack-sync: done"
    exit 0
fi

if [[ -z "$grant_file" ]]; then
    echo "50-install-stack-sync: done (no key granted)"
    exit 0
fi

[[ -f "$grant_file" ]] || { echo "50-install-stack-sync: $grant_file is not a file" >&2; exit 1; }
[[ "$(grep -c . "$grant_file")" -eq 1 ]] || {
    echo "50-install-stack-sync: $grant_file must hold exactly one public key line" >&2
    exit 1
}
ssh-keygen -l -f "$grant_file" > /dev/null || {
    echo "50-install-stack-sync: $grant_file is not a valid public key" >&2
    exit 1
}

# Only the key type and its base64 blob are re-emitted; the comment is free text
# that could carry a quote or a space and is discarded rather than escaped.
read -r key_type key_blob _ < "$grant_file"
[[ "$key_type" == "ssh-ed25519" ]] || {
    echo "50-install-stack-sync: only ssh-ed25519 keys are accepted, got '$key_type'" >&2
    exit 1
}
[[ "$key_blob" =~ ^[A-Za-z0-9+/]{1,200}={0,2}$ ]] || {
    echo "50-install-stack-sync: the key blob has unexpected characters" >&2
    exit 1
}

candidate="$(mktemp)"
trap 'rm -f "$candidate"' EXIT
unmanaged_lines > "$candidate"
printf 'restrict,command="%s %s" %s %s %s\n' "$WRAPPER" "$STACK" "$key_type" "$key_blob" "$MARKER" >> "$candidate"
write_keys "$candidate"
echo "50-install-stack-sync: done"
